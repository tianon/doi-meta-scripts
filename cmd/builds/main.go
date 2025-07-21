package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"

	"github.com/docker-library/meta-scripts/om"
	"github.com/docker-library/meta-scripts/registry"
	"github.com/docker-library/meta-scripts/sm"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

var concurrency = 1000

type MetaSource struct {
	SourceID string `json:"sourceId"`
	Arches   map[string]struct {
		Tags    []string `json:"tags"`
		Parents om.OrderedMap[struct {
			SourceID *string `json:"sourceId"`
			Pin      *string `json:"pin"`
		}]
	}
}

type BuildIDParts struct {
	SourceID string                `json:"sourceId"`
	Arch     string                `json:"arch"`
	Parents  om.OrderedMap[string] `json:"parents"`
}

type MetaBuild struct {
	BuildID string `json:"buildId"`
	Build   struct {
		Img      string            `json:"img"`
		Ignore   []registry.Digest `json:"ignore,omitempty"` // a list of digests to explicitly ignore / treat as if they don't exist (for example, if signature verification fails)
		Resolved *ocispec.Index    `json:"resolved"`
		BuildIDParts
		ResolvedParents om.OrderedMap[ocispec.Index] `json:"resolvedParents"`

		ProdSignatures []ocispec.Descriptor `json:"prodSignatures,omitempty"`
	} `json:"build"`
	Source json.RawMessage `json:"source"`

	// this is used below for passing bits of data from jq into Go, and gets zero'd out before we write the final JSON 👀
	BonusData *struct {
		ArchSignKeys []struct {
			Label string `json:"label"`
			PEM   string `json:"pem"`
		} `json:"archSignPublicKeys"`
	} `json:"DELETE-ME,omitempty"`
}

// this gets passed to "jq" in order to generate a stream of objects to fill up the "MetaBuild" struct above from "sources.json" entries (so Go can process them further and eventually write them out to "builds.json")
const jqQuery = `
	include "system-config";
	.[]
	| (.arches | to_entries[]) as { key: $arch, value: $archMeta }
	| .arches = { ($arch): $archMeta }
	| {
		build: {
			sourceId,
			arch: $arch,
		},
		source: .,
	}
	| .["DELETE-ME"] = {
		archSignPublicKeys: (
			build_arch_sign_public_keys // {}
			| to_entries
			| map(
				{
					label: .key,
					pem: (
						.value
						| gsub("^[[:space:]]+|[[:space:]]+$"; "") # trim whitespace
						| gsub("\n[[:space:]]+"; "\n") # strip extra tabs (these are in PEM format, but likely with funny indentation that'll throw off the parser)
					),
				}
			)
		),
	}
`

var metaScripts string = func() string {
	metaScripts := os.Getenv("BASHBREW_META_SCRIPTS")
	if metaScripts == "" {
		panic("BASHBREW_META_SCRIPTS is not set (or empty) and is required")
	} else if fi, err := os.Stat(metaScripts); err != nil {
		panic(err)
	} else if !fi.Mode().IsDir() {
		panic("invalid BASHBREW_META_SCRIPTS: '" + metaScripts + "' (not a directory)")
	}
	return metaScripts
}()

var (
	// keys are image/tag names, values are functions that return either *ocispec.Index or error
	cacheResolve = sm.Map[string, func() (*ocispec.Index, error)]{}

	// keys are digests (of "simple signing" payloads), values are (base64 string) "prod" signatures
	// this is treated as read-only ("loadCacheFromFile" is the only function that should ever write to this variable)
	cacheSignatures = map[registry.Digest]string{}
	// (the writing half of this dataset is covered by "saveCacheMutex")

	cacheFile string
)

func diskCacheNormalizeRefForCacheKey(img string) (registry.Reference, error) {
	ref, err := registry.ParseRef(img)
	if err != nil {
		return ref, fmt.Errorf("failed to parse ref %q: %w", img, err)
	}
	if ref.Digest != "" {
		// we use "ref" as a cache key, so if we have an explicit digest, ditch any tag data
		ref.Tag = ""
	} else if ref.Tag == "" {
		ref.Tag = "latest"
	}
	return ref, nil
}

func removeImageFromCache(_ context.Context, img string) error {
	ref, err := diskCacheNormalizeRefForCacheKey(img)
	if err != nil {
		return err
	}

	saveCacheMutex.Lock()
	if saveCache != nil {
		delete(saveCache.Indexes, ref)
	}
	saveCacheMutex.Unlock()

	return nil
}

func resolveIndex(ctx context.Context, img string, diskCacheForSure bool) (*ocispec.Index, error) {
	ref, err := diskCacheNormalizeRefForCacheKey(img)
	if err != nil {
		return nil, err
	}
	refString := ref.String()

	cacheFunc, wasCached := cacheResolve.LoadOrStore(refString, sync.OnceValues(func() (*ocispec.Index, error) {
		index, err := registry.SynthesizeIndex(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("failed to synthesize index: %w", err) // we don't decorate this with "ref" because SynthesizeIndex already decorates all the errors it returns with an appropriate ref
		}
		return index, nil
	}))

	index, err := cacheFunc()
	if err != nil {
		return nil, err
	}
	if index == nil {
		return nil, nil
	}

	if !wasCached {
		fmt.Fprintf(os.Stderr, "NOTE: lookup %s -> %s\n", img, strings.TrimPrefix(index.Annotations[ocispec.AnnotationRefName], refString))
	}

	if !diskCacheForSure {
		// if we don't know we should cache this lookup for sure, the answer is whether it's a by-digest lookup :)
		diskCacheForSure = (ref.Digest != "")
	}
	if diskCacheForSure {
		saveCacheMutex.Lock()
		if saveCache != nil {
			saveCache.Indexes[ref] = index
		}
		saveCacheMutex.Unlock()
	}

	// janky "deep copy" to avoid ever mutating the original index (and screwing up our cache / other arch lookups of the same image)
	// we abuse the fact that we know Index has a sane JSON encoding *and* these objects are all ~small to round-trip through JSON for a simple deep copy that's 100% all-inclusive
	var indexCopy ocispec.Index
	if b, err := json.Marshal(index); err != nil {
		return nil, err
	} else if err := json.Unmarshal(b, &indexCopy); err != nil {
		return nil, err
	} else {
		index = &indexCopy
	}

	return index, nil
}

func resolveArchIndex(ctx context.Context, img string, arch string, diskCacheForSure bool) (*ocispec.Index, error) {
	index, err := resolveIndex(ctx, img, diskCacheForSure)
	if err != nil {
		return nil, err
	}
	if index == nil {
		return index, nil
	}

	i := 0 // https://go.dev/wiki/SliceTricks#filter-in-place (used to delete references that don't belong to the selected architecture)
	for _, m := range index.Manifests {
		if m.Annotations[registry.AnnotationBashbrewArch] != arch {
			continue
		}
		index.Manifests[i] = m
		i++
	}
	index.Manifests = index.Manifests[:i] // https://go.dev/wiki/SliceTricks#filter-in-place

	if len(index.Manifests) == 0 {
		return nil, nil
	}

	// TODO if we have more than one *actual* image match for arch (not just an attestation), this should error!! (would mean something like index/manifest list with multiple os.version values for Windows - we avoid this in DOI today, but we don't have any automated *checks* for it, so the current state is a little precarious)

	return index, nil
}

func parsePublicKey(keyPEM string) (*ecdsa.PublicKey, error) {
	// Tianon considered a cache for parsing pubkeys because they're going to have a lot of overlap (but with mutexes because this all happens heavily in parallel) -- in prod, we'll probably have like 4-5 unique pubkeys total across all ~7000 images -- but ultimately decided against it because the mutexes will make everything *slower* instead of faster, and the "heavy" part of this whole thing is verified *not* the pem/x509/ASN1 parsing, but the verification (which makes sense, as that's where the BigNum math that makes the Cryptography Magic ✨ happens)
	pubKeyBlock, _ := pem.Decode([]byte(keyPEM))
	if pubKeyBlock == nil || pubKeyBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid public key (type %q vs PUBLIC KEY):\n\n%s", pubKeyBlock.Type, keyPEM)
	}
	pubKeyX509, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w\n\n%s", err, keyPEM)
	}
	pubKey, ok := pubKeyX509.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key valid but not ECDSA (%T)\n\n%s", pubKeyX509, keyPEM)
	}
	if params := pubKey.Params(); params.BitSize < 256 {
		return nil, fmt.Errorf("public key (%s; %d bits) not P-256 (or larger) curve:\n\n%s", params.Name, params.BitSize, keyPEM)
	}
	return pubKey, nil
}

func validateSignatureBase64(pubKey *ecdsa.PublicKey, digest registry.Digest, signature string) (bool, error) {
	rawSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	return validateSignature(pubKey, digest, rawSignature)
}

func validateSignature(pubKey *ecdsa.PublicKey, digest registry.Digest, rawSignature []byte) (bool, error) {
	if digest.Algorithm() != "sha256" { // TODO allow more algorithms as long as pubKey.Params().BitSize is large enough?
		return false, fmt.Errorf("digest not sha256: %s", digest)
	}
	rawDigest, err := hex.DecodeString(digest.Encoded())
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(pubKey, rawDigest, rawSignature), nil
}

var (
	prodPublicKey = sync.OnceValue(func() *ecdsa.PublicKey {
		if publicKeyPEM := strings.TrimSpace(os.Getenv("BASHBREW_META_SIGN_PROD_PUBLIC_KEY")); publicKeyPEM != "" {
			// we know what the public key is supposed to be, so let's validate the cached signature before using/trusting it
			pubKey, err := parsePublicKey(publicKeyPEM)
			if err != nil {
				// panic instead of return because this is bad CI job configuration, not bad data, so it should blow up ASAP
				panic(fmt.Sprintf("BASHBREW_META_SIGN_PROD_PUBLIC_KEY is broken/wrong?  %v\n\n%s", err, publicKeyPEM))
			}
			return pubKey
		}
		return nil
	})
	verifyProdPublicKeyOnce sync.Once
)

func prodSignDigest(ctx context.Context, digest registry.Digest) (string, error) {
	var signature string
	if cache, ok := cacheSignatures[digest]; ok {
		if pubKey := prodPublicKey(); pubKey != nil {
			// we know what the public key is supposed to be, so let's validate the cached signature before using/trusting it
			if valid, err := validateSignatureBase64(pubKey, digest, cache); err == nil && valid {
				signature = cache
			}
		} else {
			signature = cache
		}
	}

	if signature == "" {
		cmd := exec.CommandContext(ctx, metaScripts+"/helpers/sign-digest.sh", string(digest))
		cmd.Stderr = os.Stderr
		if cmdOut, err := cmd.Output(); err != nil {
			return "", fmt.Errorf("failed to sign %q: %w", digest, err)
		} else {
			signature = strings.TrimSpace(string(cmdOut))

			if pubKey := prodPublicKey(); pubKey != nil {
				// if the public key env variable is set, we should validate that what we got matches it, but only the first time (as a rough sanity check that our "sign-digest" method's output matches our configured public key)
				verifyProdPublicKeyOnce.Do(func() {
					if valid, err := validateSignatureBase64(pubKey, digest, signature); err != nil {
						panic(fmt.Sprintf("error attempting to validate generated signature against BASHBREW_META_SIGN_PROD_PUBLIC_KEY: %v\n\n%s", err, strings.TrimSpace(os.Getenv("BASHBREW_META_SIGN_PROD_PUBLIC_KEY"))))
					} else if !valid {
						panic(fmt.Sprintf("the output of `sign-digest.sh` doesn't match the configured BASHBREW_META_SIGN_PROD_PUBLIC_KEY! 😬\n\ndigest: %s\nsignature: %s\npublic key:\n\n%s", digest, signature, strings.TrimSpace(os.Getenv("BASHBREW_META_SIGN_PROD_PUBLIC_KEY"))))
					}
				})
			}
		}
	}

	saveCacheMutex.Lock()
	if saveCache != nil {
		if saveCacheSignature, ok := saveCache.Signatures[digest]; ok {
			// if we have *somehow* signed the same digest twice in this one process, that's both unusual and we should be consistent up-front and return that previous signature (not wait for the next round to load from the cache to make us consistent) -- yes this throws away work we've already done, but it's small and will be cached next time we run (and the likelihood of us even hitting this specific codepath is practically zero)
			signature = saveCacheSignature
		} else {
			saveCache.Signatures[digest] = signature
		}
	}
	saveCacheMutex.Unlock()

	return signature, nil
}

type cacheFileContents struct {
	Indexes    map[registry.Reference]*ocispec.Index `json:"indexes"`
	Signatures map[registry.Digest]string            `json:"signatures,omitempty"`
}

var (
	saveCache      *cacheFileContents
	saveCacheMutex sync.Mutex
)

func loadCacheFromFile() error {
	if cacheFile == "" {
		return nil
	}

	// now that we know we have a file we want cache to go into (and come from), let's initialize the "saveCache" (which will be written when the whole process is done / we're successful, and *only* caches staging images)
	saveCacheMutex.Lock()
	saveCache = &cacheFileContents{
		Indexes:    map[registry.Reference]*ocispec.Index{},
		Signatures: map[registry.Digest]string{},
	}
	saveCacheMutex.Unlock()

	f, err := os.Open(cacheFile)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()

	var cache cacheFileContents
	err = json.NewDecoder(f).Decode(&cache) // *technically*, this will silently ignore garbage (or extra documents) at the end of the file, but it's for our cache file so it's not really an issue for us (the only input to this should be our own output)
	if err != nil {
		return err
	}

	for img, index := range cache.Indexes {
		index := index // https://github.com/golang/go/issues/60078
		fun, _ := cacheResolve.LoadOrStore(img.String(), sync.OnceValues(func() (*ocispec.Index, error) {
			return index, nil
		}))
		index2, err := fun()
		if err != nil {
			// this should never happen (hence panic vs return) 🙈
			panic(err)
		}
		if index2 != index {
			panic("index2 != index??? " + img.String())
		}
	}

	if cache.Signatures != nil {
		cacheSignatures = cache.Signatures
	}

	return nil
}

func saveCacheToFile() error {
	saveCacheMutex.Lock()
	defer saveCacheMutex.Unlock()

	if saveCache == nil || cacheFile == "" {
		return nil
	}

	f, err := os.Create(cacheFile)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "\t")

	err = enc.Encode(saveCache)
	if err != nil {
		return err
	}

	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	sourcesJsonFile := os.Args[1] // "sources.json"

	// support "--cache foo.json" and "--cache=foo.json"
	if sourcesJsonFile == "--cache" && len(os.Args) >= 4 {
		cacheFile = os.Args[2]
		sourcesJsonFile = os.Args[3]
	} else if cf, ok := strings.CutPrefix(sourcesJsonFile, "--cache="); ok && len(os.Args) >= 3 {
		cacheFile = cf
		sourcesJsonFile = os.Args[2]
	}
	if err := loadCacheFromFile(); err != nil {
		panic(err)
	}

	stagingTemplate := os.Getenv("BASHBREW_STAGING_TEMPLATE") // "oisupport/staging-ARCH:BUILD"
	if !strings.Contains(stagingTemplate, "BUILD") {
		panic("invalid BASHBREW_STAGING_TEMPLATE (missing BUILD)")
	}

	type out struct {
		buildId string
		json    []byte
	}
	outs := make(chan chan out, concurrency) // we want the end result to be "in order", so we have a channel of channels of outputs so each output can be generated async (and write to the "inner" channel) and the outer channel stays in the input order

	go func() {
		// Go does not have ordered maps *and* is complicated to read an object, make a tiny modification, write it back out (without modelling the entire schema), so we'll let a single invocation of jq solve both problems (munging the documents in the way we expect *and* giving us an in-order stream)
		// doing this *also* lets us source our "system-config" to pull in useful values like whether and how a particular should be signed (so those can be maintained in the single source-of-truth that is our jq), and clean up a bunch of gnarly Go by writing slightly more logic in jq instead
		jq := exec.CommandContext(ctx, "jq", "-L"+metaScripts, "--compact-output", jqQuery, sourcesJsonFile)
		jq.Stderr = os.Stderr

		stdout, err := jq.StdoutPipe()
		if err != nil {
			panic(err)
		}
		if err := jq.Start(); err != nil {
			panic(err)
		}

		sourceArchResolved := map[string](func() *ocispec.Index){}
		sourceArchResolvedMutex := sync.RWMutex{}

		decoder := json.NewDecoder(stdout)
		for decoder.More() {
			var build MetaBuild

			if err := decoder.Decode(&build); err == io.EOF {
				break
			} else if err != nil {
				panic(err)
			} else if build.BonusData == nil {
				panic("missing 'bonus' data somehow??")
				// now we can just assume build.BonusData is valid to deref until we remove it right before we write the data back out 🤌
			}

			// the "source" field gets read in as a "json.RawMessage" so that it can be written verbatim (to be absolutely sure we don't accidentally modify it or have to parse too much of it just to make sure we write *all* of it back out), so we have to explicitly parse the bits of it we care about/need
			var source MetaSource
			if err := json.Unmarshal(build.Source, &source); err != nil {
				panic(err)
			}

			outChan := make(chan out, 1)
			outs <- outChan

			sourceArchResolvedFunc := sync.OnceValue(func() *ocispec.Index {
				for _, from := range source.Arches[build.Build.Arch].Parents.Keys() {
					if from == "scratch" {
						continue
					}
					var resolved *ocispec.Index
					parent := source.Arches[build.Build.Arch].Parents.Get(from)
					if parent.SourceID != nil {
						sourceArchResolvedMutex.RLock()
						resolvedFunc, ok := sourceArchResolved[*parent.SourceID+"-"+build.Build.Arch]
						if !ok {
							panic("parent of " + source.SourceID + " on " + build.Build.Arch + " should be " + *parent.SourceID + " but that sourceId is unknown to us!")
						}
						sourceArchResolvedMutex.RUnlock()
						resolved = resolvedFunc()
					} else {
						lookup := from
						if parent.Pin != nil {
							lookup += "@" + *parent.Pin
						}

						resolved, err = resolveArchIndex(ctx, lookup, build.Build.Arch, false)
						if err != nil {
							panic(err)
						}
					}
					if resolved == nil {
						fmt.Fprintf(os.Stderr, "%s (%s) -> not yet! [%s]\n", source.SourceID, source.Arches[build.Build.Arch].Tags[0], build.Build.Arch)
						close(outChan)
						return nil
					}
					build.Build.ResolvedParents.Set(from, *resolved)
					build.Build.Parents.Set(from, string(resolved.Manifests[0].Digest))
				}

				// buildId calculation
				buildIDJSON, err := json.Marshal(&build.Build.BuildIDParts)
				if err != nil {
					panic(err)
				}
				buildIDJSON = append(buildIDJSON, byte('\n')) // previous calculation of buildId included a newline in the JSON, so this preserves compatibility (it's also easier to add a newline than it is to remove it in some languages like Bash/Shell, so it's harmless and even safer to leave it in long-term)

				build.BuildID = fmt.Sprintf("%x", sha256.Sum256(buildIDJSON))
				fmt.Fprintf(os.Stderr, "%s (%s) -> %s [%s]\n", source.SourceID, source.Arches[build.Build.Arch].Tags[0], build.BuildID, build.Build.Arch)

				build.Build.Img = strings.ReplaceAll(strings.ReplaceAll(stagingTemplate, "BUILD", build.BuildID), "ARCH", build.Build.Arch) // "oisupport/staging-amd64:xxxx"

				build.Build.Resolved, err = resolveArchIndex(ctx, build.Build.Img, build.Build.Arch, true)
				if err != nil {
					panic(err)
				}

				// if we have any signatures on this build, we need to validate them (and throw out the image / treat it as 404 if the signature is invalid/wrong)
				signatures, err := registry.CosignSignatures(ctx, build.Build.Resolved)
				if err != nil {
					// TODO most errors here probably just mean we should treat it like bad signatures, but not 100%, so we need to sort through that instead of just bailing ("panic: illegal base64 data at input byte 4" for example is clearly "badsig", but failures to fetch objects from the registry should explode instead)
					panic(err)
				}

				// if we have *any* signatures, we need to validate that every object in Manifests that we might *want* to sign has a corresponding entry
				missingSignatures := false
				if len(signatures) > 0 {
					expectedSignatureCount := 0
				ManifestsHaveSignaturesLoop:
					for _, manifest := range build.Build.Resolved.Manifests {
						// TODO should this logic for whether/what to sign live in "system-config.jq" too?
						if manifest.ArtifactType == registry.ArtifactTypeCosignSignature {
							// we don't sign signatures 😂
							continue ManifestsHaveSignaturesLoop
						}
						if manifest.Annotations[registry.AnnotationBuildkitReferenceType] == registry.AnnotationBuildkitReferenceTypeAttestation {
							// we don't (currently) sign BuildKit's attestations
							continue ManifestsHaveSignaturesLoop
						}

						for _, signature := range signatures {
							if signature.ManifestDigest != manifest.Digest {
								// signature is not a match for manifest, keep looking
								continue
							}

							if desc := signature.Descriptor; desc != nil {
								// if our signed payload specifies a descriptor, we should validate at least MediaType, Digest, and Size are a valid match
								if desc.MediaType != manifest.MediaType || desc.Digest != manifest.Digest || desc.Size != manifest.Size {
									// signature is not a match for manifest, keep looking
									continue
								}
							}

							expectedSignatureCount++

							// we found a signature that matches this manifest, move on to checking the next manifest
							continue ManifestsHaveSignaturesLoop
						}

						// TODO print out a warning that we have signatures, but we're missing a signature for "manifest"
						missingSignatures = true
						break ManifestsHaveSignaturesLoop
					}

					// we also need to validate the reverse - that we don't have any signatures for other things (and since we counted how many we *should* have based on how many things we epxect to be signed, that's a simple equality check)
					if !missingSignatures && len(signatures) != expectedSignatureCount {
						panic(fmt.Sprintf("too *many* signatures?? have %d vs %d expected", len(signatures), expectedSignatureCount))
					}
				}

				if build.Build.Resolved != nil {
					// explicitly clear out the annotations we'll use to record "signed by" information (so they can't possibly leak in from anywhere and we can rely on "if they're set here, we set them after verification")
					delete(build.Build.Resolved.Annotations, registry.AnnotationBashbrewSignedByLabel)
					delete(build.Build.Resolved.Annotations, registry.AnnotationBashbrewSignedByPEM)
				}

				// if we have no signatures and no keys to validate against, we're "valid" already (otherwise we have to dig deeper to know)
				validSignatureState := !missingSignatures && len(signatures) == 0 && len(build.BonusData.ArchSignKeys) == 0

				// TODO move more of this code into a library or function so we can write a boatload of tests over it
				if !missingSignatures {
					// loop over every public key we have configured to see if it's signed all our signatures
				ArchSignKeysLoop:
					for _, key := range build.BonusData.ArchSignKeys {
						if key.PEM == "" {
							// empty string in configuration means "unsigned is fine!"
							if len(signatures) == 0 {
								// we have no signatures, all is well
								validSignatureState = true
								break ArchSignKeysLoop
							} else {
								// we have signatures that need to be verified, keep looking
								continue ArchSignKeysLoop
							}
						}
						if len(signatures) == 0 {
							// we don't have any signatures, so this key can't possibly be "the one" that created them 😶
							continue ArchSignKeysLoop
							// (but we continue instead of break because a later key might be the explicitly empty "unsigned is fine" case above)
						}

						pubKey, err := parsePublicKey(key.PEM)
						if err != nil {
							panic(err)
						}

						for _, signature := range signatures {
							if valid, err := validateSignature(pubKey, signature.Digest, signature.Signature); err != nil {
								// TODO this should probably just be treated like a "bad" signature (and thus cause the image to be considered invalid)
								panic(err)
							} else if !valid {
								// this key's not the one! (TODO should we print a debug log here?)
								continue ArchSignKeysLoop
							}

							// we're only valid if *all* signatures are valid (and signed by the same key), so we have to keep looping
						}

						// "we did it, fam" - record which key successfully validated every signature we have (and we verified above that we have signatures for everything we expect to)
						build.Build.Resolved.Annotations[registry.AnnotationBashbrewSignedByLabel] = key.Label
						build.Build.Resolved.Annotations[registry.AnnotationBashbrewSignedByPEM] = key.PEM

						validSignatureState = true
						break ArchSignKeysLoop
					}
				}

				if !validSignatureState {
					// if we have signatures but they aren't valid (or aren't complete), this build is completely dead to us
					if build.Build.Resolved != nil {
						// TODO consider embedding in build.Build.Resolved an easier lookup for the original digest?  even if only for in-code not written in the JSON 🤔  (reparsing a string WE CREATED as a ref feels ... wrong)
						ref, err := registry.ParseRef(build.Build.Resolved.Annotations[ocispec.AnnotationRefName])
						if err != nil {
							panic(err) // TODO what
						}
						if ref.Digest == "" {
							panic("ref " + ref.String() + " does not have a digest and should??")
						}
						// we have to record the digest of any image we *did* find as "invalid" so that the "build" code can know to ignore it too (when it does a pre-flight "does this build already exist?" check)
						build.Build.Ignore = append(build.Build.Ignore, ref.Digest)
					}
					build.Build.Resolved = nil
					// we also need to clear the "lookup" cache as if this one never was looked up or we'll just ignore this image forever in a tight loop
					if err := removeImageFromCache(ctx, build.Build.Img); err != nil {
						panic(err)
					}
				} else {
					// this is the appropriate place to generate some fresh new "production key" signatures for the "Raw" payloads we just verified
					// for "deploy" to create these "signatures" from nothing, we just have to sign the payload digest and note where to find the payload, since it needs to push the payload directly to a :sha256-xxx.sig, so we only need to record each "signed payload" digest, which manifest digest it's a signature for (which we use to pull a full descriptor from "resolved"), and the signature, and deploy can synthesize a full manifest to wrap it ✨
					for _, signaturePayload := range signatures {
						prodSignature, err := prodSignDigest(ctx, signaturePayload.Digest)
						if err != nil {
							panic(fmt.Sprintf("prod signing of %q failed: %v", build.Build.Img, err))
						}
						build.Build.ProdSignatures = append(build.Build.ProdSignatures, ocispec.Descriptor{
							MediaType: registry.MediaTypeCosignSimpleSigning,
							Digest:    signaturePayload.Digest,
							Size:      int64(len(signaturePayload.Raw)),
							Annotations: map[string]string{
								registry.AnnotationCosignSignature:         prodSignature,
								registry.AnnotationBuildkitReferenceDigest: string(signaturePayload.ManifestDigest),
							},
							// TODO ? (we can copy this object from the ".build.img" repo so we don't need it here too unless we actually want/need to sign something different here than we did during build, and it's non-trivial in size when we have thousands of them) -- Data: signaturePayload.Raw,
						})
					}
				}
				// TODO now that I have this all mostly written and working, I realize it could actually be a fully separate process that surgically filters/hacks up builds.json (and cache-builds.json) but I need to figure out how I'm going to actually push/share the prod signatures

				build.BonusData = nil
				json, err := json.Marshal(&build)
				if err != nil {
					panic(err)
				}
				outChan <- out{
					buildId: build.BuildID,
					json:    json,
				}

				return build.Build.Resolved
			})
			sourceArchResolvedMutex.Lock()
			sourceArchResolved[source.SourceID+"-"+build.Build.Arch] = sourceArchResolvedFunc
			sourceArchResolvedMutex.Unlock()
			go sourceArchResolvedFunc()
		}

		if err := stdout.Close(); err != nil {
			panic(err)
		}
		if err := jq.Wait(); err != nil {
			panic(err)
		}

		close(outs)
	}()

	fmt.Print("{")
	first := true
	for outChan := range outs {
		out, ok := <-outChan
		if !ok {
			continue
		}
		if !first {
			fmt.Print(",")
		} else {
			first = false
		}
		fmt.Println()
		buildId, err := json.Marshal(out.buildId)
		if err != nil {
			panic(err)
		}
		fmt.Printf("\t%s: %s", string(buildId), string(out.json))
	}
	fmt.Println()
	fmt.Println("}")

	if err := saveCacheToFile(); err != nil {
		panic(err)
	}
}

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
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
		Img      string         `json:"img"`
		Resolved *ocispec.Index `json:"resolved"`
		BuildIDParts
		ResolvedParents om.OrderedMap[ocispec.Index] `json:"resolvedParents"`
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

var (
	// keys are image/tag names, values are functions that return either *ocispec.Index or error
	cacheResolve = sync.Map{}
	cacheFile    string
)

func diskCacheNormalizeRefForCacheKey(img string) (registry.Reference, error) {
	ref, err := registry.ParseRef(img)
	if err != nil {
		return ref, err
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
		return registry.SynthesizeIndex(ctx, ref)
	}))

	index, err := cacheFunc.(func() (*ocispec.Index, error))()
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

type cacheFileContents struct {
	Indexes map[registry.Reference]*ocispec.Index `json:"indexes"`
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
	saveCache = &cacheFileContents{Indexes: map[registry.Reference]*ocispec.Index{}}
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
		index2, err := fun.(func() (*ocispec.Index, error))()
		if err != nil {
			// this should never happen (hence panic vs return) 🙈
			panic(err)
		}
		if index2 != index {
			panic("index2 != index??? " + img.String())
		}
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
		metaScripts := os.Getenv("BASHBREW_META_SCRIPTS")
		if metaScripts == "" {
			panic("BASHBREW_META_SCRIPTS is not set (or empty) and is required")
		} else if fi, err := os.Stat(metaScripts); err != nil {
			panic(err)
		} else if !fi.Mode().IsDir() {
			panic("invalid BASHBREW_META_SCRIPTS: '" + metaScripts + "' (not a directory)")
		}
		jq := exec.Command("jq", "-L"+metaScripts, "--compact-output", jqQuery, sourcesJsonFile)
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
				buildIDJSON = append(buildIDJSON, byte('\n')) // previous calculation of buildId included a newline in the JSON, so this preserves compatibility
				// TODO if we ever have a bigger "buildId break" event (like adding major base images that force the whole tree to rebuild), we should probably ditch this newline

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
					// TODO most errors here probably just mean we should treat it like bad signatures, but not 100%, so we need to sort through that instead of just bailing
					panic(err)
				}

				// if we have *any* signatures, we need to validate that every object in Manifests that we might *want* to sign has a corresponding entry
				missingSignatures := false
				if len(signatures) > 0 {
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

							// we found a signature that matches this manifest, move on to checking the next manifest
							continue ManifestsHaveSignaturesLoop
						}

						// TODO print out a warning that we have signatures, but we're missing a signature for "manifest"
						missingSignatures = true
						break ManifestsHaveSignaturesLoop
					}
				}

				// explicitly clear out the annotations we'll use to record "signed by" information (so they can't possibly leak in from anywhere and we can rely on "if they're set here, we set them after verification")
				delete(build.Build.Resolved.Annotations, registry.AnnotationBashbrewSignedByLabel)
				delete(build.Build.Resolved.Annotations, registry.AnnotationBashbrewSignedByPEM)

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

						// TODO consider cache for parsing pubkeys because they're going to have a lot of overlap (but with mutexes because this all happens heavily in parallel) -- in prod, we'll probably have like 4-5 unique pubkeys total across all ~7000 images
						pubKeyBlock, _ := pem.Decode([]byte(key.PEM))
						if pubKeyBlock == nil || pubKeyBlock.Type != "PUBLIC KEY" {
							panic("invalid public key in config:\n\n" + key.PEM)
						}
						pubKeyX509, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
						if err != nil {
							panic("invalid public key in config: " + err.Error() + "\n\n" + key.PEM)
						}
						pubKey, ok := pubKeyX509.(*ecdsa.PublicKey)
						if !ok {
							panic("public key in config valid, but not ecdsa:\n\n" + key.PEM)
						}
						if pubKey.Params().Name != "P-256" {
							panic("public key not P-256 curve:\n\n" + key.PEM)
						}

						for _, signature := range signatures {
							if signature.Digest.Algorithm() != "sha256" {
								// TODO this should probably just be greated like a "bad" signature (and thus cause the image to be considered invalid)
								panic("signed payload not sha256: " + signature.Digest)
							}
							digest, err := hex.DecodeString(signature.Digest.Encoded())
							if err != nil {
								// TODO this should probably just be greated like a "bad" signature (and thus cause the image to be considered invalid)
								panic("invalid signature digest, somehow: " + err.Error())
							}
							// https://github.com/sigstore/sigstore/blob/a9d80542815fe834b51b17c6291feb61864f2ffb/pkg/signature/ecdsa.go#L171
							if !ecdsa.VerifyASN1(pubKey, digest, signature.Signature) {
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
					build.Build.Resolved = nil
					// we also need to clear the "lookup" cache as if this one never was looked up or we'll just ignore this image forever in a tight loop
					if err := removeImageFromCache(ctx, build.Build.Img); err != nil {
						panic(err)
					}
				} else {
					// TODO if we have validSignatureState, this is the appropriate place to generate some fresh new "production key" signatures for the "Raw" payloads we just verified
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

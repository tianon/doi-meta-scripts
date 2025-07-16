package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"cuelabs.dev/go/oci/ociregistry"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type CosignedPayload struct {
	Signature           []byte             // decoded from base64 in annotation
	Digest              ociregistry.Digest // the digest of the signed payload itself
	Raw                 json.RawMessage    // the raw JSON form of the signed payload itself
	CosignSimpleSigning                    // the parsed form of the signed payload (but accessible directly so all the code using these gets simpler)
}
type CosignSimpleSigning struct {
	// https://github.com/sigstore/cosign/blob/v2.5.0/specs/SIGNATURE_SPEC.md#simple-signing
	CosignSimpleSigningCrit `json:"critical"`
	CosignSimpleSigningOpt  `json:"optional"`
	// I *really* wish Go would let me define anonymous embedded structs (struct { struct { ... } `json:"foo"`, struct { ... } `json:"bar"`, ... }) because I really do not care one single bit about all these layers in between and would happily extract just the nested values into a flat struct instead but have to create all of these explicit structs just because Go is picky -Tianon, 2025-07-02
}
type CosignSimpleSigningCrit struct {
	SimpleSigningType string `json:"type"` // "cosign container image signature"

	CosignSimpleSigningCritImage `json:"image"`
}
type CosignSimpleSigningCritImage struct {
	ManifestDigest ociregistry.Digest `json:"docker-manifest-digest"` // this is the digest of the image we're signing with this payload
}
type CosignSimpleSigningOpt struct {
	Descriptor *ocispec.Descriptor `json:"descriptor"`
}

func CosignSignatures(ctx context.Context, index *ocispec.Index) ([]CosignedPayload, error) {
	if index == nil {
		// no index? no signatures (easy)
		return nil, nil
	}

	ref, err := ParseRef(index.Annotations[ocispec.AnnotationRefName])
	if err != nil {
		return nil, err // TODO annotate error
	}

	ret := []CosignedPayload{}
	for _, manifestDesc := range index.Manifests {
		if manifestDesc.ArtifactType != ArtifactTypeCosignSignature {
			continue
		}
		r := descriptorDataReader(manifestDesc)
		if r == nil {
			ref.Digest = manifestDesc.Digest
			r, err = Lookup(ctx, ref, nil)
			if err != nil {
				return nil, err // TODO annotate error
			}
		}
		var manifest ocispec.Manifest
		if err := readJSONHelper(r, &manifest); err != nil {
			return nil, err // TODO annotate error
		}
		for _, layerDesc := range manifest.Layers {
			signatureBase64 := layerDesc.Annotations[AnnotationCosignSignature]
			if layerDesc.MediaType != MediaTypeCosignSimpleSigning || signatureBase64 == "" {
				continue
			}
			var payload CosignedPayload
			if payload.Signature, err = base64.StdEncoding.DecodeString(signatureBase64); err != nil {
				return nil, err // TODO annotate error
			}
			payload.Digest = layerDesc.Digest
			r := descriptorDataReader(layerDesc)
			if r == nil {
				ref.Digest = layerDesc.Digest
				r, err = Lookup(ctx, ref, &LookupOptions{Type: LookupTypeBlob})
				if err != nil {
					return nil, err // TODO annotate error
				}
			}
			if err := readJSONHelper(r, &payload.Raw); err != nil {
				return nil, err // TODO annotate error
			}
			if err := json.Unmarshal(payload.Raw, &payload.CosignSimpleSigning); err != nil {
				return nil, err // TODO annotate error
			}
			if payload.SimpleSigningType != "cosign container image signature" {
				return nil, fmt.Errorf("invalid signed payload type: %q", payload.SimpleSigningType)
			}
			if err := payload.ManifestDigest.Validate(); err != nil {
				return nil, err // TODO annotate error
			}
			if payload.Descriptor != nil && payload.Descriptor.Digest != payload.ManifestDigest {
				return nil, fmt.Errorf("payload descriptor digest does not match payload digest: %q vs %q", payload.Descriptor.Digest, payload.ManifestDigest)
			}
			ret = append(ret, payload)
		}
	}
	return ret, nil
}

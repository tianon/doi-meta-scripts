#!/usr/bin/env bash
set -Eeuo pipefail

# given an OCI image layout (https://github.com/opencontainers/image-spec/blob/v1.1.1/image-layout.md), adds a cosign-compatible signature manifest to the image index (to be split back out into a tag in the appropriate place by a separate process)

layout="$1"; shift

[ -d "$layout" ]
[ -d "$BASHBREW_META_SCRIPTS" ]
[ -s "$BASHBREW_META_SCRIPTS/oci.jq" ]
BASHBREW_META_SCRIPTS="$(cd "$BASHBREW_META_SCRIPTS" && pwd -P)"

cd "$layout"

# verify that index contains a single image index
indexDigest="$(jq -L"$BASHBREW_META_SCRIPTS" --raw-output '
	include "validate";
	include "oci";
	validate_oci_index({
		indexPlatformsOptional: true,
	})
	| validate_length(.manifests; 1)
	| validate(.manifests[0];
		validate_IN(.mediaType; media_types_index)
	)
	| .manifests[0]
	| .digest
' index.json)"
# ... which contains a single image manifest (optionally also attestation manifest)
imageDescriptor="$(jq -L"$BASHBREW_META_SCRIPTS" --compact-output '
	include "validate";
	include "oci";
	validate_oci_index
	| validate_IN(.manifests[].mediaType; media_types_image)
	# either a single image, or exactly one image manifest + one "attestation" (in that order, and with the relevant relational annotation on the latter)
	| validate_length(.manifests; 1, 2)
	| validate(.manifests[0];
		(.annotations["vnd.docker.reference.type"] | not)
		and (.annotations["vnd.docker.reference.digest"] | not)
	; "one actual, valid image is required")
	| if .manifests[1] then
		validate(.manifests[1]; .annotations["vnd.docker.reference.type"] == "attestation-manifest"; "second image in index must be attestation for first image")
	else . end
	| .manifests[0]
' "blobs/${indexDigest/://}")"

# https://github.com/sigstore/cosign/blob/56d51141bdcfddc45609f17c73fd90fc40e965f3/specs/SIGNATURE_SPEC.md#payloads
# https://github.com/containers/image/blob/a5061e5a5f00333ea3a92e7103effd11c6e2f51d/docs/containers-signature.5.md#json-data-format
jq <<<"$imageDescriptor" --tab '
	{
		critical: {
			type: "cosign container image signature",
			image: { "docker-manifest-digest": .digest },
			identity: { "docker-reference": "TODO" }, # TODO XXXXXXXXXXXXXXX (need to somehow get at least the final repo name, if not also a meaningful tag)
		},
		optional: {
			creator: "https://github.com/docker-library/meta-scripts",
			timestamp: (now | floor), # TODO SOURCE_DATE_EPOCH? 🤔  probably not? leave this out completely?
			descriptor: ., # full descriptor because just the digest leaves too much to interpretation
		},
	}
' | tee cosine-payload.json

# https://github.com/sigstore/cosign/blob/56d51141bdcfddc45609f17c73fd90fc40e965f3/specs/SIGNATURE_SPEC.md#signature-schemes
# TODO sign the payload (potentially with AWS KMS)

# https://github.com/sigstore/cosign/blob/56d51141bdcfddc45609f17c73fd90fc40e965f3/specs/SIGNATURE_SPEC.md#oci-image-manifest-v1
# TODO create a new image manifest for the signature (https://oci.dag.dev/?image=tianon/test:cosign) - with "subject" (https://oci.dag.dev/?image=tianon/test:cosign-oci1.1 - https://github.com/sigstore/cosign/issues/3935#issuecomment-2546052439)
# maybe steal that "config" mediaType as artifactType and use the explicit OCI "empty" config instead ("{}") so it's simpler

# TODO add that to the image index
# TODO update index.json

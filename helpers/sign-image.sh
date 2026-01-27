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
shell="$(jq -L"$BASHBREW_META_SCRIPTS" --raw-output '
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
	| @sh "export indexDigest=\(.digest)",
		@sh "export indexRefName=\(
			.annotations
			| .["io.containerd.image.name"]
				// .["org.opencontainers.image.ref.name"]
			# TODO this is "normalize_ref_to_docker" from "meta.jq" that I do not want to import here but probably should move to a different file so it can be used here
			| ltrimstr("docker.io/")
			| ltrimstr("library/")
		)"
' index.json)"
eval "$shell"
[ -n "$indexDigest" ]

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
# TODO also sign the attestation manifest?
# TODO if the index already contains a signature, should we strip it and resign?

# oci-put some-file.json someFileDigest someFileSize [someFileBase64]
oci-put() {
	local file="$1"; shift
	local digestVar="$1"; shift
	local sizeVar="$1"; shift
	local dataVar="${1:-}"

	local digest
	digest="$(sha256sum "$file")"
	digest="sha256:${digest%% *}"
	[ "${#digest}" = 71 ] # 64 byte hash plus 7 byte prefix
	export "$digestVar=$digest"

	local size
	size="$(stat --format '%s' "$file")"
	export "$sizeVar=$size"

	if [ -n "$dataVar" ]; then
		local data
		data="$(base64 --wrap=0 "$file")"
		export "$dataVar=$data"
	fi

	mkdir -p "blobs/${digest%%:*}"
	cp -alfT "$file" "blobs/${digest/://}"
	# TODO oci-put: cp vs mv vs ln ? (maybe prefer symlink if it's inside the OCI dir but prefer hard link otherwise?)
}

# create a "cosign" payload for signing
# https://github.com/sigstore/cosign/blob/56d51141bdcfddc45609f17c73fd90fc40e965f3/specs/SIGNATURE_SPEC.md#payloads
# https://github.com/containers/image/blob/a5061e5a5f00333ea3a92e7103effd11c6e2f51d/docs/containers-signature.5.md#json-data-format
jq <<<"$imageDescriptor" --tab '
	{
		critical: {
			type: "cosign container image signature",
			image: { "docker-manifest-digest": .digest },
			identity: { "docker-reference": (env.indexRefName // "") },
		},
		optional: {
			creator: "https://github.com/docker-library/meta-scripts", # TODO is this a good value?  no, for Tianon builds it needs to be different, and it is probably a good idea to embed the full commit, so maybe this is only a reasonable default and it needs to be set explicitly in the pipelines?
			timestamp: (now | floor), # TODO SOURCE_DATE_EPOCH? 🤔  probably not? leave this out completely?
			descriptor: ., # full descriptor because just the digest leaves too much to interpretation
		},
	}
' | tee cosine-payload.json

oci-put cosine-payload.json payloadDigest payloadSize payloadBase64

# sign the payload
# https://github.com/sigstore/cosign/blob/56d51141bdcfddc45609f17c73fd90fc40e965f3/specs/SIGNATURE_SPEC.md#signature-schemes
payloadSignature="$("$BASHBREW_META_SCRIPTS/helpers/sign-digest.sh" "$payloadDigest")"
export payloadSignature

# https://github.com/opencontainers/image-spec/blob/v1.1.1/manifest.md#guidance-for-an-empty-descriptor
if [ ! -s blobs/sha256/44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a ]; then
	mkdir -p blobs/sha256
	echo -n '{}' > blobs/sha256/44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
fi

# create cosign "image manifest" to hold our signature in the registry
# https://github.com/sigstore/cosign/blob/56d51141bdcfddc45609f17c73fd90fc40e965f3/specs/SIGNATURE_SPEC.md#oci-image-manifest-v1
jq <<<"$imageDescriptor" -L"$BASHBREW_META_SCRIPTS" --tab '
	include "oci";
	{
		schemaVersion: 2,
		mediaType: media_type_oci_image,
		artifactType: media_type_cosign_artifact,
		subject: .,
		layers: [ {
			mediaType: "application/vnd.dev.cosign.simplesigning.v1+json",
			digest: env.payloadDigest,
			size: (env.payloadSize | tonumber),
			annotations: {
				"dev.cosignproject.cosign/signature": env.payloadSignature,
			},
			data: env.payloadBase64,
		} ],
		config: oci_empty_descriptor,
	}
' | tee cosine-manifest.json

oci-put cosine-manifest.json cosineDigest cosineSize

# add our signature to the image index
jq --slurp --tab '
	(.[0] | {
		mediaType,
		artifactType,
		digest: env.cosineDigest,
		size: (env.cosineSize | tonumber),
		platform: { os: "unknown", architecture: "unknown" },
		annotations: {
			# borrow the "attestation" annotation for which subject this points to
			"vnd.docker.reference.digest": .subject.digest,
		},
	}) as $cosineDescriptor
	| .[1]
	| .manifests += [ $cosineDescriptor ]
' "blobs/${cosineDigest/://}" "blobs/${indexDigest/://}" > cosine-index.json

oci-put cosine-index.json newIndexDigest newIndexSize

# update index.json with our new image index
jq --tab '
	# TODO scan for "indexDigest" and update that one specifically? validate our assumption? (it should not have changed here from when we validated it above, but if we wanted to update this script to support more than one image inside the OCI layout, we need to consider more here)
	.manifests[0] |= (
		.digest = env.newIndexDigest
		| .size = (env.newIndexSize | tonumber)
	)
' index.json > new-index.json
mv -f new-index.json index.json

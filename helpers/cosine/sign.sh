#!/usr/bin/env bash
set -Eeuo pipefail

# TODO oci layout output? just signature here?
# TODO AWS KMS? ("aws kms sign -signing-algorithm ECDSA_SHA_256" which is also "ECC_NIST_P256 (secp256r1)" and I have no idea if this needs to be specified while signing or just during key creation; https://awscli.amazonaws.com/v2/documentation/api/latest/reference/kms/sign.html)

# as-is, this is essentially "cosign sign-blob"

# TODO verify:
#
# openssl dgst -verify hosign.pub -signature hey-adora.txt.sig hey-adora.txt
#
# ~/aws-home/cli.sh kms get-public-key --key-id alias/tianontesting | jq --raw-output '"-----BEGIN PUBLIC KEY-----\n" + (.PublicKey | gsub("(?<line>.{64})"; "\(.line)\n") | rtrimstr("\n")) + "\n-----END PUBLIC KEY-----"' > cosign.pub
# ~/aws-home/cli.sh kms sign --key-id alias/tianontesting --message "$(openssl dgst -sha256 -binary cli.sh | base64 --wrap=0)" --message-type DIGEST --signing-algorithm ECDSA_SHA_256 | jq --raw-output '.Signature' | base64 -d > cli.sh.sig
# openssl dgst -verify cosign.pub -signature cli.sh.sig cli.sh

# sign a digest instead of generating/signing in one (useful because we have to generate a digest for OCI layout, which is the whole reason cosign made the choice to lean on the OCI digest in the first place):
# sha256sum payload.json | cut -d' ' -f1 | xxd -revert -plain | openssl pkeyutl -sign -inkey cosign.key -pkeyopt digest:sha256 > payload.sig

# a cute payload proposal (Tianon *really* wants to include the *full* descriptor in here, because it's stupid that it's not included)
# crane manifest tianon/true:oci | jq '.manifests[0] | { critical: { type: "cosign container image signature", image: { "docker-manifest-digest": .digest }, identity: { "docker-reference": "tianon/true:oci" } }, optional: { creator: "https://github.com/docker-library/meta-scripts", timestamp: (now | floor), descriptor: . } }' --tab

# https://oci.dag.dev/?image=tianon/test:cosign
# https://oci.dag.dev/?image=tianon/test@sha256:dcfd46ba9035de992ea182990e1e76a294c29fce4bfb7ef046a4cf301e86f79e

key="$1"
payload="$2"
[ -s "$key" ]
[ -s "$payload" ]

openssl dgst -sign "$key" "$payload" | base64 --wrap=0
echo

#!/usr/bin/env bash
set -Eeuo pipefail

# given a digest (in OCI format), returns a "signature" string using key parameters from the environment

# usage:
#  .../sign-digest.sh sha256:xxx

digest="$1"; shift # input OCI digest

[ -n "$digest" ]
[ -d "$BASHBREW_META_SCRIPTS" ]
[ -s "$BASHBREW_META_SCRIPTS/oci.jq" ]
BASHBREW_META_SCRIPTS="$(cd "$BASHBREW_META_SCRIPTS" && pwd -P)"

jq <<<"$digest" -L"$BASHBREW_META_SCRIPTS" --slurp --raw-input '
	include "oci";
	rtrimstr("\n")
	| validate_oci_digest
	| empty
'
algorithm="${digest%%:*}"
[ "$algorithm" = 'sha256' ] # TODO support more algorithms?
hex="${digest#$algorithm:}"

if [ -n "${!YUBECDSA_*}" ]; then
	# https://github.com/tianon/yubecdsa
	exec yubecdsa sign "$hex"
elif [ -n "${BASHBREW_META_SIGN_AWS_KMS_KEY:-}" ]; then
	base64="$(xxd -revert -plain <<<"$hex" | base64 --wrap=0)"
	args=(
		--key-id "$BASHBREW_META_SIGN_AWS_KMS_KEY"
		--message-type DIGEST
		--message "$base64"
		--signing-algorithm ECDSA_SHA_256
		--query Signature
		--output text
	)
	exec aws kms sign "${args[@]}"
else
	echo >&2 "error: expected signing method for '$digest' is unknown (need BASHBREW_META_SIGN_AWS_KMS_KEY, etc set)"
	exit 1
fi

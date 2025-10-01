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

if [ "${BASHBREW_META_SCRIPTS_RUNNING_TESTS:-}" = 'vigorously' ]; then
	cat >&2 <<-EOWW

		WARNING: performing integration test signing!

		 digest: $digest

	EOWW
	# for the integration tests, we have a hard-coded list of digests we'll be willing to sign
	# we hard-code the signatures instead of signing here for two reasons:
	# 1. we *really* don't want to accidentally enter this codepath and (successfully) get testing signatures in production
	# 2. we need them to be determinsitic for the tests (and ECDSA isn't supposed to be deterministic)
	case "$digest" in
		# xxd <<<'ffffHEXGOESHERE' -revert -plain | openssl pkeyutl -sign -inkey cmd/builds/signing/testdata/test.key -pkeyopt digest:sha256 | base64 -w0; echo
		'sha256:1c21574ddd9735be594e618981f98103969196c827aee0395c0233be019a33d6') # infosiftr/moby:amd64 cosign payload; https://oci.dag.dev/?blob=infosiftr/moby@sha256:1c21574ddd9735be594e618981f98103969196c827aee0395c0233be019a33d6&mt=application%2Fvnd.dev.cosign.simplesigning.v1%2Bjson&size=1308
			exec echo 'MEYCIQCzO9X6BJ70TYnVpdHfCgyIUYpQjSNbx6LdvUS5I6xA7gIhANkJPJeZjRGX9yDWrzA9xm3I9c0wrB0Qx/aMJLPeJi/y'
			;;
	esac
	echo >&2 "error: running integration tests, but '$digest' is an unsupported digest"
	exit 1
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
elif [ -n "${!YUBECDSA_*}" ]; then
	# https://github.com/tianon/yubecdsa
	exec yubecdsa sign "$hex"
else
	echo >&2 "error: expected signing method for '$digest' is unknown (need BASHBREW_META_SIGN_AWS_KMS_KEY, etc set)"
	exit 1
fi

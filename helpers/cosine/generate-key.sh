#!/usr/bin/env bash
set -Eeuo pipefail

# ./generate-key.sh cosign.key
# ./generate-pub.sh cosign.key cosign.pub

key="$1"
[ ! -s "$key" ]

# TODO allow specifying the algorithm or the bits? ("Put simply: implementations MUST use the same hash algorithm used by the underlying registry to reference the payload. Any future algorithmic-agility will come from the storage layer as part of the OCI specification." https://github.com/sigstore/cosign/blob/56d51141bdcfddc45609f17c73fd90fc40e965f3/specs/SIGNATURE_SPEC.md#signature-schemes)

openssl ecparam -out "$key" -name secp256r1 -genkey

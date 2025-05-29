#!/usr/bin/env bash
set -Eeuo pipefail

# ./generate-key.sh cosign.key
# ./generate-pub.sh cosign.key cosign.pub

key="$1"
pub="$2"
[ -s "$key" ]
[ ! -s "$pub" ]

openssl ec -in "$key" -pubout -out "$pub"

package signing

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/docker-library/meta-scripts/registry"
)

func ValidateSignatureBase64(pubKey *ecdsa.PublicKey, digest registry.Digest, signature string) (bool, error) {
	rawSignature, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	return ValidateSignature(pubKey, digest, rawSignature)
}

func ValidateSignature(pubKey *ecdsa.PublicKey, digest registry.Digest, rawSignature []byte) (bool, error) {
	if digest.Algorithm() != "sha256" { // TODO allow more algorithms as long as pubKey.Params().BitSize is large enough?
		return false, fmt.Errorf("digest not sha256: %s", digest)
	}
	rawDigest, err := hex.DecodeString(digest.Encoded())
	if err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(pubKey, rawDigest, rawSignature), nil
}

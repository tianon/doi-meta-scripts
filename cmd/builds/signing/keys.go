package signing

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func ParsePublicKey(keyPEM string) (*ecdsa.PublicKey, error) {
	// Tianon considered a cache for parsing pubkeys because they're going to have a lot of overlap (but with mutexes because this all happens heavily in parallel) -- in prod, we'll probably have like 4-5 unique pubkeys total across all ~7000 images -- but ultimately decided against it because the mutexes will make everything *slower* instead of faster, and the "heavy" part of this whole thing is confirmed (via benchmarks) *not* the pem/x509/ASN1 parsing, but the verification (which makes sense, as that's where the BigNum math that makes the Cryptography Magic ✨ happens)
	pubKeyBlock, _ := pem.Decode([]byte(keyPEM))
	if pubKeyBlock == nil || pubKeyBlock.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid public key (type %q vs PUBLIC KEY):\n\n%s", pubKeyBlock.Type, keyPEM)
	}
	pubKeyX509, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w\n\n%s", err, keyPEM)
	}
	pubKey, ok := pubKeyX509.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key valid but not ECDSA (%T)\n\n%s", pubKeyX509, keyPEM)
	}
	if params := pubKey.Params(); params.BitSize < 256 {
		return nil, fmt.Errorf("public key (%s; %d bits) not P-256 (or larger) curve:\n\n%s", params.Name, params.BitSize, keyPEM)
	}
	return pubKey, nil
}

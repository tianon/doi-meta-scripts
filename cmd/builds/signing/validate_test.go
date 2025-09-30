package signing_test

import (
	"testing"

	"github.com/docker-library/meta-scripts/cmd/builds/signing"
	"github.com/docker-library/meta-scripts/registry"
)

func TestValidateSignature(t *testing.T) {
	/*
		$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1
		-----BEGIN PRIVATE KEY-----
		MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfKZeloQdBRCpEzVh
		WJRkCLXVlGpHKyLoipBqDP3ZVYyhRANCAARL+0q63ixJP3Fl4wkIz8jbmVDmMg5k
		3YWFwVro9qg/rtVr1yTaNI+rZHjHDIwoRcsEtJJIttUluVqRGtsn2wNO
		-----END PRIVATE KEY-----

		$ openssl ec -pubout
	*/
	pubKey, err := signing.ParsePublicKey(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES/tKut4sST9xZeMJCM/I25lQ5jIO
ZN2FhcFa6PaoP67Va9ck2jSPq2R4xwyMKEXLBLSSSLbVJblakRrbJ9sDTg==
-----END PUBLIC KEY-----
`)
	if err != nil {
		t.Fatalf("signing.ParsePublicKey failed and should not have! %s", err)
	}
	digest := registry.Digest("sha256:f847d5d104fd0bdd4d8db27aa882ba0dec9415c54f4b5af7dab6c89e7b180017")

	for _, tc := range []struct {
		name   string
		base64 string
		valid  bool
		err    bool

		digest registry.Digest
	}{
		{
			name: "valid",
			// xxd <<<'f847d5d104fd0bdd4d8db27aa882ba0dec9415c54f4b5af7dab6c89e7b180017' -revert -plain | openssl pkeyutl -sign -inkey <(cat <<<$'-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgfKZeloQdBRCpEzVh\nWJRkCLXVlGpHKyLoipBqDP3ZVYyhRANCAARL+0q63ixJP3Fl4wkIz8jbmVDmMg5k\n3YWFwVro9qg/rtVr1yTaNI+rZHjHDIwoRcsEtJJIttUluVqRGtsn2wNO\n-----END PRIVATE KEY-----') -pkeyopt digest:sha256 | base64 -w0; echo
			base64: "MEYCIQDBopxkkKfobWNsCe30WETk4qqhbmk72QD8uXjGt4pN9wIhAIB86Y/uCsjGYOD5QUOx9PGaoiGzdxg3VIa8FDaW5aL8",
			valid:  true,
		},

		{
			name:   "valid base64, not a signature",
			base64: "dGlhbm9uIGlzIHdyaXRpbmcgdGVzdHMsIGFuZCBoZSBoYXRlcyB0aGF0LCBidXQgaXQgbXVzdCBuZWVkcyBiZSBkb25lIEZPUiBUSEUgQ09WRVJBR0Ug8J+YrfCfkpYK",
		},

		{
			name:   "invalid base64",
			base64: "😂",
			err:    true,
		},

		{
			name:   "valid digest, invalid algorithm",
			digest: "sha512:a4d9ffd3c29d9fadff007aeb1ab64a3653c494db86c5fbcbe6fd7345f03a7bbb51b89ea3b82bcc648b8422546287b42ce70cb17af0464d2ed5108f69aa0cf406",
			err:    true,
		},

		{
			name:   "invalid digest",
			digest: "sha256:00000",
			err:    true,
		},
	} {
		tc := tc // https://github.com/golang/go/issues/60078
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.digest == "" {
				tc.digest = digest
			}

			ok, err := signing.ValidateSignatureBase64(pubKey, tc.digest, tc.base64)
			if tc.err && err == nil {
				t.Fatalf("expected error, but got success\n%s", tc.base64)
			} else if !tc.err && err != nil {
				t.Fatalf("expected success, but got error: %s\n%s", err, tc.base64)
			}
			if tc.valid != ok {
				t.Fatalf("validity of signature is wrong (expected %v, got %v)", tc.valid, ok)
			}
		})
	}
}

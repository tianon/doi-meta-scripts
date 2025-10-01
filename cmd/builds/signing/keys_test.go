package signing_test

import (
	"testing"

	"github.com/docker-library/meta-scripts/cmd/builds/signing"
)

func TestParsePublicKey(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		err   bool
	}{
		{
			name: "valid key",
			input: testPublicKey,
		},

		{
			name: "invalid block type",
			input: `
-----BEGIN TIANON PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcpFvgj6wI3I4P/+VJraOzT4wtteD
qaWjAqsKlRHM9ME++HiTw51shM2E/YYNXGIOfUHJkhiNSfuyeSBHe9J9jw==
-----END TIANON PUBLIC KEY-----
`,
			err: true,
		},

		{
			name: "valid base64, invalid key",
			input: `
-----BEGIN PUBLIC KEY-----
dGlhbm9uIGlzIHdyaXRpbmcgdGVzdHMsIGFuZCBoZSBoYXRlcyB0aGF0LCBidXQgaXQgbXVzdCBu
ZWVkcyBiZSBkb25lIEZPUiBUSEUgQ09WRVJBR0Ug8J+YrfCfkpYK
-----END PUBLIC KEY-----
`,
			err: true,
		},

		{
			name: "valid key, not enough bits (only 224)",
			// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp224r1 | openssl ec -pubout
			input: `
-----BEGIN PUBLIC KEY-----
ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAElO0PQMWCkSpnCx7TqNFUJGzxtJJp2VjE
FdEW/0sqyqqJSKPPTTxu1ijPvjAal+SUZqTmqUOSWE8=
-----END PUBLIC KEY-----
`,
			err: true,
		},

		{
			name: "valid RSA key (not ECDSA)",
			// openssl genpkey -algorithm RSA | openssl rsa -pubout
			input: `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAozjCKJiAMKl6vzBpCQGx
c7M7qKyhq4xu9JRmcspAyc5S53+0/IXMh9B2j6UzEFe++e6MqzXoduwipZy6aVvi
qZuS+0npyYLHwEZZWYKUERmNAr+SMq+VOAVszIMRRST4rRu+soTVyLX8Ao13erUr
X9jA4WWHN9AEPbMFxDXdJceAS9RYYCQC6YuVQsiE8ylUVllvJGTM17rgJV4KceHs
3rmpIPbTU3LJwJ8KQnyLYEmcZgG9yHtK13hjxzloNviDNEhQPjEg12J6/Fwyndle
IOOTfChP4e/z4aUJ0Z937iHd/q2bxZuyi6z0t6PYdWOYeAO4qwmZSUCmROU9mwrN
jQIDAQAB
-----END PUBLIC KEY-----
`,
			err: true,
		},
	} {
		tc := tc // https://github.com/golang/go/issues/60078
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pub, err := signing.ParsePublicKey(tc.input)
			if tc.err && err == nil {
				t.Fatalf("expected error, but got successful parsing:\n%s\n\n%+v", tc.input, pub)
			} else if !tc.err && err != nil {
				t.Fatalf("expected success, but got error: %s\n%s", err, tc.input)
			}
		})
	}
}

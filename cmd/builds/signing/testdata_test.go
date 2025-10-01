package signing_test

import (
	_ "embed"
)

// $ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out testdata/test.key
// $ openssl ec -in testdata/test.key -text -pubout -out testdata/test.pub
//
//go:embed testdata/test.pub
var testPublicKey string

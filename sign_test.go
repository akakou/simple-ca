package simplecertify

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	caTempl := CATemplate()
	ca, err := Init(&caTempl, &caTempl)
	assert.NoError(t, err)

	serverTempl := ServerTemplate()
	serverCert, err := ca.Certify(&serverTempl)
	assert.NoError(t, err)

	roots := x509.NewCertPool()

	roots.AddCert(ca.Certificate)

	_, err = serverCert.Verify(x509.VerifyOptions{
		Roots: roots,
	})

	assert.NoError(t, err)

	test := []byte("test")
	signature, err := ca.Sign(test)
	assert.NoError(t, err)

	err = ca.Certificate.CheckSignature(x509.SHA256WithRSA, test, signature)
	assert.NoError(t, err)
}

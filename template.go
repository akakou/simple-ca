package simplecertify

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func CATemplate() x509.Certificate {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(2019),
		Subject:               pkix.Name{Organization: []string{"SimpleCertify CA"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	return template
}

func ServerTemplate() x509.Certificate {
	template := x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject:      pkix.Name{Organization: []string{"SimpleCertify Server"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	return template
}

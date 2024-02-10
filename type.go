package simplecertify

import (
	"crypto/rsa"
	"crypto/x509"
)

type Certifier struct {
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

type CertifierConfig struct {
	PrivateKey  []byte `json:"private_key"`
	Certificate []byte `json:"certificate"`
}

func NewCertifier(privateKey *rsa.PrivateKey, certificate *x509.Certificate) *Certifier {
	return &Certifier{
		PrivateKey:  privateKey,
		Certificate: certificate,
	}
}

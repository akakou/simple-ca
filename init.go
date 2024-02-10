package simplecertify

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
)

func Init(template, parent *x509.Certificate) (*Certifier, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, &privateKey.PublicKey, privateKey)

	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return NewCertifier(privateKey, certificate), nil
}

func LoadOrInit(template, parent *x509.Certificate) (*Certifier, error) {
	_, err := os.Stat(CERTIFIER_CONFIG_PATH)

	if os.IsNotExist(err) {
		return Init(template, parent)
	}

	return Load()
}

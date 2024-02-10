package simplecertify

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

func (certifier *Certifier) Certify(target *x509.Certificate) (*x509.Certificate, error) {
	buf, err := x509.CreateCertificate(rand.Reader, target, certifier.Certificate, certifier.Certificate.PublicKey, certifier.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error creating certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(buf)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %v", err)
	}

	return cert, nil
}

func (certifier *Certifier) Sign(target []byte) ([]byte, error) {
	hash := sha256.Sum256(target)
	return certifier.PrivateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
}

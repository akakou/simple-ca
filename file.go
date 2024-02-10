package simplecertify

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
)

var CERTIFIER_CONFIG_PATH = "certifier.json"

func Save(ca *Certifier) error {
	raw := ca.Certificate.Raw

	config := &CertifierConfig{
		PrivateKey:  x509.MarshalPKCS1PrivateKey(ca.PrivateKey),
		Certificate: raw,
	}

	file, err := os.OpenFile(CERTIFIER_CONFIG_PATH, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	buf, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("error marshalling config: %v", err)
	}

	_, err = file.Write(buf)
	if err != nil {
		fmt.Println("error writing to file:", err)
		return err
	}

	return nil
}

func Load() (*Certifier, error) {
	file, err := os.Open(CERTIFIER_CONFIG_PATH)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	config := &CertifierConfig{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return nil, fmt.Errorf("error decoding config: %v", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key: %v", err)
	}

	certificate, err := x509.ParseCertificate(config.Certificate)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate: %v", err)
	}

	return NewCertifier(privateKey, certificate), nil
}

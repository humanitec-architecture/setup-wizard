package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type KeyPair struct {
	Public  []byte
	Private []byte
}

func Generate() (*KeyPair, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key: %w", err)
	}

	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	priv := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKey,
		},
	)

	publicKey, err := x509.MarshalPKIXPublicKey(key.Public().(*rsa.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pub := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKey,
		},
	)
	return &KeyPair{
		Public:  pub,
		Private: priv,
	}, nil
}

package badkeys

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
)

var (
	errNoPEM          = errors.New("no PEM data found")
	errUnsupportedKey = errors.New("unsupported key type")
	errInvalidVersion = errors.New("invalid version")
)

// parsePrivateKeyPEM decodes a PEM private key in PKCS#1, SEC1, PKCS#8 or the
// legacy "DSA PRIVATE KEY" form and returns the corresponding public key.
func parsePrivateKeyPEM(data []byte) (any, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errNoPEM
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &key.PublicKey, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &key.PublicKey, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return publicOf(key), nil
	}
	// Fall back to trying PKCS#8 for unusual block types.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return publicOf(key), nil
	}
	return nil, errUnsupportedKey
}

// classifyErr turns a parse error into an unparseable/unsupported KeyResult,
// mirroring the split badkeys makes between malformed and unsupported inputs.
func classifyErr(err error) KeyResult {
	msg := strings.ToLower(err.Error())
	// A recognized-but-unsupported algorithm/curve maps to "unsupported"; a
	// malformed structure (including algorithms Go does not recognize at all,
	// like DH) maps to "unparseable", matching upstream badkeys behavior.
	if errors.Is(err, errUnsupportedKey) || strings.Contains(msg, "unsupported") {
		return unsupported(err)
	}
	return unparseable(err)
}

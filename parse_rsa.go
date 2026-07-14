package badkeys

import (
	"encoding/asn1"
	"math/big"
)

// oidRSA is the RSA encryption algorithm identifier.
var oidRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

// bkRSAKey is an RSA public key parsed without the size limits crypto/rsa
// imposes on the exponent (which must fit in an int). badkeys deliberately
// checks keys with unusual exponents, so we parse n and e as big integers.
type bkRSAKey struct {
	N, E *big.Int
}

type pkcs1Pub struct {
	N *big.Int
	E *big.Int
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

// parseRSAFromSPKI parses an RSA key from a SubjectPublicKeyInfo DER. It
// returns (nil, false) if der is not an RSA SPKI structure.
func parseRSAFromSPKI(der []byte) (*bkRSAKey, bool) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	if !spki.Algorithm.Algorithm.Equal(oidRSA) {
		return nil, false
	}
	return parseRSAFromPKCS1(spki.PublicKey.RightAlign())
}

// parseRSAFromPKCS1 parses a PKCS#1 RSAPublicKey (SEQUENCE { n, e }).
func parseRSAFromPKCS1(der []byte) (*bkRSAKey, bool) {
	var k pkcs1Pub
	rest, err := asn1.Unmarshal(der, &k)
	if err != nil || len(rest) != 0 || k.N == nil || k.E == nil {
		return nil, false
	}
	if k.N.Sign() <= 0 || k.E.Sign() < 0 {
		return nil, false
	}
	return &bkRSAKey{N: k.N, E: k.E}, true
}

// pkcs1Priv is a PKCS#1 RSAPrivateKey. Only the public fields are used; the
// remaining private components are parsed as big integers so keys with an
// oversized exponent (which crypto/x509 rejects) still load.
type pkcs1Priv struct {
	Version       int
	N, E, D, P, Q *big.Int
	Dp, Dq, Qinv  *big.Int
}

// parseRSAPrivFromPKCS1 extracts the public part (n, e) of a PKCS#1
// RSAPrivateKey without crypto/rsa's exponent size limits.
func parseRSAPrivFromPKCS1(der []byte) (*bkRSAKey, bool) {
	var k pkcs1Priv
	rest, err := asn1.Unmarshal(der, &k)
	if err != nil || len(rest) != 0 || k.N == nil || k.E == nil {
		return nil, false
	}
	if k.N.Sign() <= 0 || k.E.Sign() < 0 {
		return nil, false
	}
	return &bkRSAKey{N: k.N, E: k.E}, true
}

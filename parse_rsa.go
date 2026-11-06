package badkeys

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
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

// parseRSAPrivFromPKCS8 extracts (n, e) from a PKCS#8 PrivateKeyInfo holding
// an RSA key. Like upstream badkeys, the private key is not validated:
// crypto/x509 checks its consistency, which is expensive (a DoS vector) for
// huge keys and irrelevant for checking the public part.
func parseRSAPrivFromPKCS8(der []byte) (*bkRSAKey, bool) {
	input := cryptobyte.String(der)
	var info, alg, oid cryptobyte.String
	var version int
	var priv []byte
	if !input.ReadASN1(&info, cbasn1.SEQUENCE) || !input.Empty() ||
		!info.ReadASN1Integer(&version) ||
		!info.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!alg.ReadASN1(&oid, cbasn1.OBJECT_IDENTIFIER) ||
		!bytes.Equal(oid, oidRSARaw) ||
		!info.ReadASN1Bytes(&priv, cbasn1.OCTET_STRING) {
		return nil, false
	}
	return parseRSAPrivFromPKCS1(priv)
}

// parseRSAPrivFromOpenSSH extracts (n, e) from an unencrypted
// "openssh-key-v1" RSA private key without validating it (see
// parseRSAPrivFromPKCS8).
func parseRSAPrivFromOpenSSH(data []byte) (*bkRSAKey, bool) {
	const magic = "openssh-key-v1\x00"
	if !bytes.HasPrefix(data, []byte(magic)) {
		return nil, false
	}
	s := cryptobyte.String(data[len(magic):])
	var cipher, kdf, kdfOpts, pub, priv, keyType, nRaw, eRaw cryptobyte.String
	var nkeys, check1, check2 uint32
	if !readSSHString(&s, &cipher) || string(cipher) != "none" ||
		!readSSHString(&s, &kdf) || !readSSHString(&s, &kdfOpts) ||
		!s.ReadUint32(&nkeys) || nkeys != 1 ||
		!readSSHString(&s, &pub) || !readSSHString(&s, &priv) ||
		!priv.ReadUint32(&check1) || !priv.ReadUint32(&check2) || check1 != check2 ||
		!readSSHString(&priv, &keyType) || string(keyType) != "ssh-rsa" ||
		!readSSHString(&priv, &nRaw) || !readSSHString(&priv, &eRaw) {
		return nil, false
	}
	n := new(big.Int).SetBytes(nRaw)
	e := new(big.Int).SetBytes(eRaw)
	if n.Sign() == 0 || len(nRaw) > 0 && nRaw[0]&0x80 != 0 || len(eRaw) > 0 && eRaw[0]&0x80 != 0 {
		return nil, false
	}
	return &bkRSAKey{N: n, E: e}, true
}

// parseRSAPrivPEMLenient returns the public part of an RSA private key PEM
// block (PKCS#1, PKCS#8 or OpenSSH) without validating the private key.
func parseRSAPrivPEMLenient(block *pem.Block) (*bkRSAKey, bool) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return parseRSAPrivFromPKCS1(block.Bytes)
	case "PRIVATE KEY":
		return parseRSAPrivFromPKCS8(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		return parseRSAPrivFromOpenSSH(block.Bytes)
	}
	return nil, false
}

// readSSHString reads an SSH wire-format string (uint32 length + bytes).
func readSSHString(s, out *cryptobyte.String) bool {
	var n uint32
	return s.ReadUint32(&n) && s.ReadBytes((*[]byte)(out), int(n))
}

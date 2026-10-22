package badkeys

import (
	"crypto/dsa" //nolint:staticcheck // DSA is legacy but still checked
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

// checkKey dispatches on the concrete public key type, runs the selected
// checks, and computes the SubjectPublicKeyInfo hash. When spki is non-nil it
// is used directly as the SubjectPublicKeyInfo to hash; otherwise the key is
// re-marshaled.
func checkKey(pub any, spki []byte, cfg config) KeyResult {
	r := KeyResult{Findings: map[string]*Finding{}}

	switch k := pub.(type) {
	case *bkRSAKey:
		r.Type = "rsa"
		r.N = k.N
		r.E = k.E
		r.Bits = k.N.BitLen()
		r.Findings = CheckRSA(r.N, r.E, cfg.keyRecover, cfg.checks...)
	case *rsa.PublicKey:
		r.Type = "rsa"
		r.N = k.N
		r.E = big.NewInt(int64(k.E))
		r.Bits = k.N.BitLen()
		r.Findings = CheckRSA(r.N, r.E, cfg.keyRecover, cfg.checks...)
	case *ecdsa.PublicKey:
		r.Type = "ec"
		r.Curve = normalizeCurve(k.Curve.Params().Name)
		r.X, r.Y = k.X, k.Y
		r.Findings = CheckAll(minBytes(k.X), cfg.checks...)
	case ed25519.PublicKey:
		r.Type = "ec"
		r.Curve = "ed25519"
		r.Findings = CheckAll(minBytes(new(big.Int).SetBytes(k)), cfg.checks...)
	case *ecdh.PublicKey:
		r.Type = "ec"
		r.Curve = ecdhCurveName(k)
		r.Findings = CheckAll(minBytes(new(big.Int).SetBytes(k.Bytes())), cfg.checks...)
	case *dsa.PublicKey:
		r.Type = "dsa"
		r.Y = k.Y
		r.Bits = k.P.BitLen()
		r.Findings = CheckDSA(k.Y, k.P, cfg.checks...)
	default:
		r.Type = "unsupported"
		return r
	}

	if spki == nil {
		if der, err := x509.MarshalPKIXPublicKey(pub); err == nil {
			spki = der
		}
	}
	if spki != nil {
		sum := sha256.Sum256(spki)
		r.SPKISHA256 = hex.EncodeToString(sum[:])
	}
	return r
}

// checkSPKI parses a SubjectPublicKeyInfo DER (trying the size-limit-free RSA
// parser first) and checks the resulting key.
func checkSPKI(der []byte, cfg config) KeyResult {
	if k, ok := parseRSAFromSPKI(der); ok {
		return checkKey(k, der, cfg)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return classifyErr(err)
	}
	return checkKey(pub, der, cfg)
}

func normalizeCurve(name string) string {
	switch name {
	case "P-256":
		return "p256"
	case "P-384":
		return "p384"
	case "P-521":
		return "p521"
	}
	return strings.ToLower(name)
}

func ecdhCurveName(k *ecdh.PublicKey) string {
	switch k.Curve() {
	case ecdh.X25519():
		return "x25519"
	default:
		return "ec"
	}
}

func unparseable(err error) KeyResult {
	return KeyResult{Type: "unparseable", Findings: map[string]*Finding{}, Err: err}
}

func unsupported(err error) KeyResult {
	return KeyResult{Type: "unsupported", Findings: map[string]*Finding{}, Err: err}
}

// CheckPubkey parses a PEM-encoded public key (SubjectPublicKeyInfo or PKCS#1)
// and checks it.
func CheckPubkey(data []byte, opts ...Option) KeyResult {
	cfg := newConfig(opts)
	block, _ := pem.Decode(data)
	if block == nil {
		return unparseable(errNoPEM)
	}
	if block.Type == "RSA PUBLIC KEY" {
		k, ok := parseRSAFromPKCS1(block.Bytes)
		if !ok {
			return unparseable(errNoPEM)
		}
		return checkKey(k, nil, cfg)
	}
	return checkSPKI(block.Bytes, cfg)
}

// CheckPrivkey parses a PEM-encoded private key and checks its public part.
func CheckPrivkey(data []byte, opts ...Option) KeyResult {
	cfg := newConfig(opts)
	if block, _ := pem.Decode(data); block != nil && block.Type == "RSA PRIVATE KEY" {
		if k, ok := parseRSAPrivFromPKCS1(block.Bytes); ok {
			return checkKey(k, nil, cfg)
		}
	}
	pub, err := parsePrivateKeyPEM(data)
	if err != nil {
		return classifyErr(err)
	}
	return checkKey(pub, nil, cfg)
}

// CheckCert parses a PEM-encoded X.509 certificate and checks its public key.
func CheckCert(data []byte, opts ...Option) KeyResult {
	cfg := newConfig(opts)
	block, _ := pem.Decode(data)
	if block == nil {
		return unparseable(errNoPEM)
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err == nil && (crt.Version < 1 || crt.Version > 3) {
		err = errInvalidVersion
	}
	if err != nil {
		if r, ok := checkCertFallback(block.Bytes, cfg); ok {
			return r
		}
		return unparseable(err)
	}
	return checkSPKI(crt.RawSubjectPublicKeyInfo, cfg)
}

// CheckCSR parses a PEM-encoded certificate signing request and checks its
// public key.
func CheckCSR(data []byte, opts ...Option) KeyResult {
	cfg := newConfig(opts)
	block, _ := pem.Decode(data)
	if block == nil {
		return unparseable(errNoPEM)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return unparseable(err)
	}
	if csr.Version != 0 {
		return unparseable(errInvalidVersion)
	}
	return checkSPKI(csr.RawSubjectPublicKeyInfo, cfg)
}

// CheckSSHPubkey parses an OpenSSH public key line ("ssh-rsa AAAA...") and
// checks it.
func CheckSSHPubkey(data []byte, opts ...Option) KeyResult {
	cfg := newConfig(opts)
	pk, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return unparseable(err)
	}
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return unsupported(errUnsupportedKey)
	}
	return checkKey(cpk.CryptoPublicKey(), nil, cfg)
}

// CheckSSHPrivkey parses an OpenSSH private key and checks its public part.
func CheckSSHPrivkey(data []byte, opts ...Option) KeyResult {
	cfg := newConfig(opts)
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return classifyErr(err)
	}
	pub := publicOf(key)
	if pub == nil {
		return unsupported(errUnsupportedKey)
	}
	return checkKey(pub, nil, cfg)
}

// publicOf extracts the public key from a parsed private key value.
func publicOf(key any) any {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	case *dsa.PrivateKey:
		return &k.PublicKey
	case *ecdh.PrivateKey:
		return k.PublicKey()
	}
	return nil
}

// DetectAndCheck auto-detects the encoding of input (PEM key/cert/CSR, OpenSSH
// public or private key) and checks the key.
func DetectAndCheck(input []byte, opts ...Option) KeyResult {
	s := string(input)
	switch {
	case strings.Contains(s, "-----BEGIN CERTIFICATE-----"):
		return CheckCert(input, opts...)
	case strings.Contains(s, "-----BEGIN CERTIFICATE REQUEST-----"):
		return CheckCSR(input, opts...)
	case strings.Contains(s, "-----BEGIN PUBLIC KEY-----"),
		strings.Contains(s, "-----BEGIN RSA PUBLIC KEY-----"):
		return CheckPubkey(input, opts...)
	case strings.Contains(s, "-----BEGIN OPENSSH PRIVATE KEY-----"):
		return CheckSSHPrivkey(input, opts...)
	case strings.Contains(s, "-----BEGIN PRIVATE KEY-----"),
		strings.Contains(s, "-----BEGIN RSA PRIVATE KEY-----"),
		strings.Contains(s, "-----BEGIN DSA PRIVATE KEY-----"),
		strings.Contains(s, "-----BEGIN EC PRIVATE KEY-----"):
		return CheckPrivkey(input, opts...)
	case strings.HasPrefix(s, "ssh-"), strings.HasPrefix(s, "ecdsa-"):
		return CheckSSHPubkey(input, opts...)
	}
	return KeyResult{Type: "notfound", Findings: map[string]*Finding{}}
}

package badkeys

import (
	"encoding/base64"
	"math/big"
	"strings"
)

// validJWKCurves lists the accepted JWK curve names.
// See https://www.iana.org/assignments/jose/jose.xhtml
var validJWKCurves = map[string]bool{
	"P-256": true, "P-384": true, "P-521": true,
	"Ed25519": true, "Ed448": true, "X25519": true, "X448": true, "secp256k1": true,
}

// JWK is a minimal JSON Web Key. Decode JSON into this struct (or a
// map[string]any converted to it) before calling CheckJWK.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// CheckJWK checks a parsed JSON Web Key.
func CheckJWK(key JWK, opts ...Option) KeyResult {
	cfg := newConfig(opts)
	r := KeyResult{Findings: map[string]*Finding{}}
	switch key.Kty {
	case "RSA":
		if key.N == "" || key.E == "" {
			return unparseable(errNoPEM)
		}
		n, err1 := jwkInt(key.N)
		e, err2 := jwkInt(key.E)
		if err1 != nil || err2 != nil {
			return unparseable(errNoPEM)
		}
		r.Type = "rsa"
		r.N, r.E = n, e
		r.Bits = n.BitLen()
		r.Findings = CheckRSA(n, e, cfg.keyRecover, cfg.checks...)
	case "EC":
		if key.X == "" || key.Y == "" || !validJWKCurves[key.Crv] {
			return unparseable(errNoPEM)
		}
		x, err := jwkInt(key.X)
		if err != nil {
			return unparseable(errNoPEM)
		}
		r.Type = "ec"
		r.Curve = strings.ToLower(strings.ReplaceAll(key.Crv, "-", ""))
		r.X = x
		r.Findings = CheckAll(minBytes(x), cfg.checks...)
	case "OKP":
		if key.X == "" || !validJWKCurves[key.Crv] {
			return unparseable(errNoPEM)
		}
		x, err := jwkInt(key.X)
		if err != nil {
			return unparseable(errNoPEM)
		}
		r.Type = "ec"
		r.Curve = strings.ToLower(key.Crv)
		r.X = x
		r.Findings = CheckAll(minBytes(x), cfg.checks...)
	default:
		return unsupported(errUnsupportedKey)
	}
	return r
}

// jwkInt decodes a base64url (unpadded) JWK integer field.
func jwkInt(b64 string) (*big.Int, error) {
	b64 = strings.ReplaceAll(b64, " ", "")
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(b64, "="))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(raw), nil
}

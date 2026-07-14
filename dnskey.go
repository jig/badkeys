package badkeys

import (
	"encoding/base64"
	"math/big"
	"strconv"
	"strings"
)

// CheckDNSKEY checks a DNSKEY resource record given as its four
// whitespace-separated presentation fields ("flags protocol algorithm
// base64key"), optionally preceded by an owner name (5 fields total, as in a
// zone file line).
func CheckDNSKEY(rec string, opts ...Option) KeyResult {
	cfg := newConfig(opts)
	fields := strings.Fields(rec)
	// Accept either "flags proto alg key..." (4) or "name flags proto alg key..." (5+).
	var algField, keyField string
	switch {
	case len(fields) >= 5:
		algField = fields[3]
		keyField = strings.Join(fields[4:], "")
	case len(fields) == 4:
		algField = fields[2]
		keyField = fields[3]
	default:
		return unparseable(errNoPEM)
	}

	alg, err := strconv.Atoi(algField)
	if err != nil {
		return unparseable(errNoPEM)
	}
	key, err := base64.StdEncoding.DecodeString(keyField)
	if err != nil {
		return unparseable(errNoPEM)
	}

	r := KeyResult{Findings: map[string]*Finding{}}
	switch alg {
	case 1, 5, 7, 8, 10: // RSA, RFC 3110 §2
		if len(key) < 3 {
			return unparseable(errNoPEM)
		}
		var elen, eoff int
		if key[0] == 0 {
			elen = int(key[1])<<8 | int(key[2])
			eoff = 3
		} else {
			elen = int(key[0])
			eoff = 1
		}
		if len(key) < eoff+elen {
			return unparseable(errNoPEM)
		}
		e := new(big.Int).SetBytes(key[eoff : eoff+elen])
		n := new(big.Int).SetBytes(key[eoff+elen:])
		r.Type = "rsa"
		r.N, r.E = n, e
		r.Bits = n.BitLen()
		r.Findings = CheckRSA(n, e, cfg.keyRecover, cfg.checks...)
		return r
	case 3, 6: // DSA, RFC 2536 §2
		if len(key) < 213 {
			return unparseable(errNoPEM)
		}
		t := int(key[0])
		if t > 8 || len(key) != 213+t*24 {
			return unparseable(errNoPEM)
		}
		yOff := 149 + t*16
		y := new(big.Int).SetBytes(key[yOff:])
		r.Type = "dsa"
		r.Y = y
		r.Bits = 512 + t*64
		// no p available, run "all" checks on y
		r.Findings = CheckAll(minBytes(y), cfg.checks...)
		return r
	case 13, 14, 15, 16: // ECDSA P-256/P-384, Ed25519, Ed448
		var x *big.Int
		var curve string
		switch alg {
		case 13:
			if len(key) != 64 {
				return unparseable(errNoPEM)
			}
			curve, x = "p256", new(big.Int).SetBytes(key[0:32])
		case 14:
			if len(key) != 96 {
				return unparseable(errNoPEM)
			}
			curve, x = "p384", new(big.Int).SetBytes(key[0:48])
		case 15:
			if len(key) != 32 {
				return unparseable(errNoPEM)
			}
			curve, x = "ed25519", new(big.Int).SetBytes(key)
		case 16:
			if len(key) != 57 {
				return unparseable(errNoPEM)
			}
			curve, x = "ed448", new(big.Int).SetBytes(key)
		}
		r.Type = "ec"
		r.Curve = curve
		r.X = x
		r.Findings = CheckAll(minBytes(x), cfg.checks...)
		return r
	}
	return unsupported(errUnsupportedKey)
}

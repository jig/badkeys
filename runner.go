package badkeys

import "math/big"

// CheckRSA runs the named checks against an RSA public key (modulus n,
// exponent e). When keyRecover is true and a check recovers factors or the
// private exponent, the finding's PrivateKey field is populated with a PEM
// key. If checks is empty, the default checks are used.
func CheckRSA(n, e *big.Int, keyRecover bool, checks ...string) map[string]*Finding {
	if len(checks) == 0 {
		checks = DefaultChecks()
	}
	results := map[string]*Finding{}
	for _, name := range checks {
		def, ok := registry[name]
		if !ok {
			continue
		}
		var f *Finding
		switch def.Kind {
		case kindRSA:
			f = def.rsa(n, e)
		case kindAll:
			f = def.all(minBytes(n))
		default:
			continue
		}
		if f == nil {
			continue
		}
		f.Check = name
		if keyRecover {
			var pem string
			if f.P != nil && f.Q != nil {
				pem = rsaRecover(f.P, f.Q, nil, n, e)
			} else if f.D != nil {
				pem = rsaRecover(nil, nil, f.D, n, e)
			}
			if pem != "" {
				f.PrivateKey = pem
			}
		}
		results[name] = f
	}
	return results
}

// CheckDSA runs the named checks against a DSA public key (public value y,
// prime p). If checks is empty, the default checks are used.
func CheckDSA(y, p *big.Int, checks ...string) map[string]*Finding {
	if len(checks) == 0 {
		checks = DefaultChecks()
	}
	results := map[string]*Finding{}
	for _, name := range checks {
		def, ok := registry[name]
		if !ok {
			continue
		}
		var f *Finding
		switch def.Kind {
		case kindDSA:
			f = def.dsa(y, p)
		case kindAll:
			f = def.all(minBytes(y))
		default:
			continue
		}
		if f == nil {
			continue
		}
		f.Check = name
		results[name] = f
	}
	return results
}

// CheckAll runs the "all" checks (currently only the blocklist) against the
// canonical byte value of a key. If checks is empty, the default checks are
// used.
func CheckAll(val []byte, checks ...string) map[string]*Finding {
	if len(checks) == 0 {
		checks = DefaultChecks()
	}
	results := map[string]*Finding{}
	for _, name := range checks {
		def, ok := registry[name]
		if !ok || def.Kind != kindAll {
			continue
		}
		f := def.all(val)
		if f == nil {
			continue
		}
		f.Check = name
		results[name] = f
	}
	return results
}

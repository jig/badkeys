package badkeys

import "math/big"

// sharedprimes detects RSA moduli that share a prime factor with a known set
// of compromised keys (batch-GCD precomputed products).
func sharedprimes(n, e *big.Int) *Finding {
	bits := n.BitLen()
	supported := false
	for _, b := range sharedPrimeBits {
		if b == bits {
			supported = true
			break
		}
	}
	if !supported {
		return nil
	}

	m, ok := sharedModulus(bits)
	if !ok {
		return nil
	}
	g := new(big.Int).GCD(nil, nil, n, m)
	if g.Cmp(big1) == 0 {
		return nil
	}
	if isProbablePrime(g) {
		p := g
		q := new(big.Int).Div(n, p)
		if new(big.Int).Mul(p, q).Cmp(n) == 0 {
			return &Finding{P: p, Q: q}
		}
	}
	// factoring failed, but the key is still flagged
	return &Finding{}
}

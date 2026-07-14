package badkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
)

// rsaRecover reconstructs an RSA private key and returns it PEM-encoded
// (PKCS#1, "RSA PRIVATE KEY"). It accepts either the prime factors p and q, or
// the private exponent d (from which p and q are recovered). It returns an
// empty string if reconstruction is not possible.
func rsaRecover(p, q, d, n, e *big.Int) string {
	if !e.IsInt64() || e.Int64() <= 0 || e.Int64() > (1<<31-1) {
		return ""
	}
	eInt := int(e.Int64())

	if p == nil || q == nil {
		if d == nil {
			return ""
		}
		var ok bool
		p, q, ok = recoverPrimeFactors(n, e, d)
		if !ok {
			return ""
		}
	}

	// d = e^-1 mod lcm(p-1, q-1)
	pm1 := new(big.Int).Sub(p, big1)
	qm1 := new(big.Int).Sub(q, big1)
	g := new(big.Int).GCD(nil, nil, pm1, qm1)
	lcm := new(big.Int).Div(new(big.Int).Mul(pm1, qm1), g)
	dd := new(big.Int).ModInverse(e, lcm)
	if dd == nil {
		return ""
	}

	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Set(n), E: eInt},
		D:         dd,
		Primes:    []*big.Int{p, q},
	}
	// Note: we deliberately do not call priv.Validate(): it rejects keys with
	// close primes (|p-q| too small), which is exactly the Fermat weakness we
	// recover here.
	priv.Precompute()
	der := x509.MarshalPKCS1PrivateKey(priv)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

// recoverPrimeFactors recovers the RSA primes from (n, e, d) using the standard
// probabilistic algorithm (Handbook of Applied Cryptography, 8.2.2).
func recoverPrimeFactors(n, e, d *big.Int) (p, q *big.Int, ok bool) {
	// k = d*e - 1
	k := new(big.Int).Mul(d, e)
	k.Sub(k, big1)
	if k.Sign() <= 0 || k.Bit(0) == 1 {
		return nil, nil, false
	}
	// write k = 2^t * r with r odd
	t := 0
	r := new(big.Int).Set(k)
	for r.Bit(0) == 0 {
		r.Rsh(r, 1)
		t++
	}

	one := big1
	nMinus1 := new(big.Int).Sub(n, big1)
	for i := 0; i < 100; i++ {
		g, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big2))
		if err != nil {
			return nil, nil, false
		}
		g.Add(g, big2) // g in [2, n-1)

		y := new(big.Int).Exp(g, r, n)
		if y.Cmp(one) == 0 || y.Cmp(nMinus1) == 0 {
			continue
		}
		for j := 1; j < t; j++ {
			x := new(big.Int).Exp(y, big2, n)
			if x.Cmp(one) == 0 {
				candidate := new(big.Int).GCD(nil, nil, new(big.Int).Sub(y, one), n)
				return candidate, new(big.Int).Div(n, candidate), true
			}
			if x.Cmp(nMinus1) == 0 {
				break
			}
			y = x
		}
	}
	return nil, nil, false
}

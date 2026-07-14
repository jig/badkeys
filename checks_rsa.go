package badkeys

import "math/big"

// fermat detects RSA moduli whose prime factors are close together, which
// makes them factorable via Fermat's method.
func fermat(n, e *big.Int) *Finding {
	const tries = 100
	if n.Cmp(big.NewInt(5)) <= 0 {
		return nil
	}

	a := isqrt(n)
	c := 0
	sq := new(big.Int)
	for {
		sq.Mul(a, a)
		sq.Sub(sq, n)
		if isSquare(sq) {
			break
		}
		a.Add(a, big1)
		c++
		if c > tries {
			return nil
		}
	}
	bsq := new(big.Int).Mul(a, a)
	bsq.Sub(bsq, n)
	b := isqrt(bsq)
	// p is chosen as the larger prime (some implementations prefer p>q).
	p := new(big.Int).Add(a, b)
	q := new(big.Int).Sub(a, b)
	f := &Finding{P: p, Q: q, Debug: "Fermat factorization"}
	if b.Sign() == 0 {
		f.Subtest = "square"
	}
	return f
}

// rsainvalid detects RSA keys with invalid exponent values.
func rsainvalid(n, e *big.Int) *Finding {
	if e.Cmp(big.NewInt(3)) < 0 {
		return &Finding{Subtest: "invalid_e"}
	}
	if e.Cmp(n) >= 0 {
		return &Finding{Subtest: "e_too_large"}
	}
	return nil
}

// pattern detects 16 consecutive identical bytes in the modulus, mirroring the
// Python regex (.)\1{15} (RE2 has no backreferences, so we scan by hand).
func pattern(n, e *big.Int) *Finding {
	nbin := minBytes(n)
	run := 1
	for i := 1; i < len(nbin); i++ {
		if nbin[i] == nbin[i-1] {
			run++
			if run >= 16 {
				return &Finding{}
			}
		} else {
			run = 1
		}
	}
	return nil
}

// xzbackdoor detects the xz backdoor payload structure in an RSA modulus.
func xzbackdoor(n, e *big.Int) *Finding {
	nb := minBytes(n)
	if len(nb) == 0 {
		return nil
	}
	// if upper bit is set, ASN.1 encodes with a leading zero byte
	if nb[0]&0x80 != 0 {
		nb = append([]byte{0}, nb...)
	}
	if len(nb) < 16 {
		return nil
	}
	a := leUint(nb[0:4])
	b := leUint(nb[4:8])
	c := leUint(nb[8:16])
	res := (a*b + c) & 0xFFFFFFFFFFFFFFFF
	if res <= 3 {
		return &Finding{}
	}
	return nil
}

func leUint(b []byte) uint64 {
	var v uint64
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint64(b[i])
	}
	return v
}

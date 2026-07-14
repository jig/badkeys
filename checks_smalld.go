package badkeys

import "math/big"

// smalld implements Wiener's attack: it detects RSA keys with a small private
// exponent d. Based on owiener by Nao Yonashiro.
func smalld(n, e *big.Int) *Finding {
	// testing with small e makes no sense
	if e.BitLen() <= 32 {
		return nil
	}

	cf := rationalToContfrac(e, n)
	two := big.NewInt(2)
	for _, kd := range convergents(cf) {
		k, dg := kd[0], kd[1]
		if k.Sign() == 0 {
			continue
		}
		edg := new(big.Int).Mul(e, dg)
		phi := new(big.Int).Div(edg, k)

		x := new(big.Int).Sub(n, phi)
		x.Add(x, big1)
		if x.Bit(0) != 0 { // x odd
			continue
		}
		half := new(big.Int).Div(x, two)
		half.Mul(half, half)
		half.Sub(half, n)
		if isSquare(half) {
			g := new(big.Int).Mul(phi, k)
			g.Sub(edg, g)
			if g.Sign() == 0 {
				continue
			}
			return &Finding{D: new(big.Int).Div(dg, g)}
		}
	}
	return nil
}

// rationalToContfrac returns the continued fraction expansion of x/y.
func rationalToContfrac(x, y *big.Int) []*big.Int {
	x = new(big.Int).Set(x)
	y = new(big.Int).Set(y)
	var out []*big.Int
	for y.Sign() != 0 {
		a := new(big.Int)
		rem := new(big.Int)
		a.DivMod(x, y, rem) // a = x//y, rem = x - a*y
		out = append(out, a)
		x, y = y, rem
	}
	return out
}

// convergents returns the Wiener convergents [k, dg] derived from a continued
// fraction, mirroring the owiener convergents_from_contfrac generator.
func convergents(cf []*big.Int) [][2]*big.Int {
	// contfrac_to_rational_iter
	n0, d0 := big.NewInt(0), big.NewInt(1)
	n1, d1 := big.NewInt(1), big.NewInt(0)
	var rat [][2]*big.Int
	for _, q := range cf {
		n := new(big.Int).Mul(q, n1)
		n.Add(n, n0)
		d := new(big.Int).Mul(q, d1)
		d.Add(d, d0)
		rat = append(rat, [2]*big.Int{n, d})
		n0, d0 = n1, d1
		n1, d1 = n, d
	}

	// convergents_from_contfrac
	nPrev, dPrev := big.NewInt(1), big.NewInt(0)
	var out [][2]*big.Int
	for i, nd := range rat {
		n, d := nd[0], nd[1]
		if i%2 == 0 {
			out = append(out, [2]*big.Int{
				new(big.Int).Add(n, nPrev),
				new(big.Int).Add(d, dPrev),
			})
		} else {
			out = append(out, [2]*big.Int{n, d})
		}
		nPrev, dPrev = n, d
	}
	return out
}

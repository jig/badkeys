package badkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync"
)

// ecsmallpriv detects elliptic-curve keys whose private scalar d is tiny,
// i.e. Q = d·G with |d| small. This is the flaw behind the 2025 eMudhra
// intermediate CA compromise (Mozilla bug 2083449), where eight P-384
// intermediates were generated with d < 256.
//
// It runs a baby-step giant-step search over the NIST prime curves (all have
// a = -3), recovering any d in [n-ecBabySteps, n) ∪ [1, ecSearchBound()].

const (
	ecBabySteps  = 1 << 13 // baby-step table holds j·G for j in [1, ecBabySteps]
	ecGiantSteps = 1 << 9  // giant steps per key
)

// ecWindow is the giant-step stride: each step covers δ in [-M, M].
const ecWindow = 2*ecBabySteps + 1

// ecSearchBound returns the largest small d the check is guaranteed to find.
func ecSearchBound() int64 { return int64(ecGiantSteps-1)*ecWindow + ecBabySteps }

type ecPoint struct{ x, y *big.Int } // nil x means the point at infinity

type ecTable struct {
	once  sync.Once
	baby  map[string]uint32 // x(j·G) -> j<<1 | parity(y)
	giant ecPoint           // -(ecWindow·G)
}

var ecTables sync.Map // *elliptic.CurveParams -> *ecTable

func ecAdd(c *elliptic.CurveParams, a, b ecPoint) ecPoint {
	if a.x == nil {
		return b
	}
	if b.x == nil {
		return a
	}
	p := c.P
	lambda := new(big.Int)
	if a.x.Cmp(b.x) == 0 {
		if a.y.Cmp(b.y) != 0 || a.y.Sign() == 0 {
			return ecPoint{}
		}
		// λ = (3x² - 3) / 2y
		num := new(big.Int).Mul(a.x, a.x)
		num.Sub(num, big1).Mul(num, big.NewInt(3)).Mod(num, p)
		den := new(big.Int).Lsh(a.y, 1)
		if den.ModInverse(den.Mod(den, p), p) == nil {
			return ecPoint{}
		}
		lambda.Mul(num, den).Mod(lambda, p)
	} else {
		num := new(big.Int).Sub(b.y, a.y)
		den := new(big.Int).Sub(b.x, a.x)
		if den.ModInverse(den.Mod(den, p), p) == nil {
			return ecPoint{}
		}
		lambda.Mul(num, den).Mod(lambda, p)
	}
	x := new(big.Int).Mul(lambda, lambda)
	x.Sub(x, a.x).Sub(x, b.x).Mod(x, p)
	y := new(big.Int).Sub(a.x, x)
	y.Mul(y, lambda).Sub(y, a.y).Mod(y, p)
	return ecPoint{x, y}
}

func ecNeg(c *elliptic.CurveParams, a ecPoint) ecPoint {
	if a.x == nil {
		return a
	}
	return ecPoint{a.x, new(big.Int).Mod(new(big.Int).Neg(a.y), c.P)}
}

func ecScalarBaseMult(c *elliptic.CurveParams, k *big.Int) ecPoint {
	g := ecPoint{c.Gx, c.Gy}
	var r ecPoint
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = ecAdd(c, r, r)
		if k.Bit(i) == 1 {
			r = ecAdd(c, r, g)
		}
	}
	return r
}

func ecKey(c *elliptic.CurveParams, x *big.Int) string {
	return string(x.FillBytes(make([]byte, (c.BitSize+7)/8)))
}

func getECTable(c *elliptic.CurveParams) *ecTable {
	v, _ := ecTables.LoadOrStore(c, &ecTable{})
	t := v.(*ecTable)
	t.once.Do(func() {
		t.baby = make(map[string]uint32, ecBabySteps)
		g := ecPoint{c.Gx, c.Gy}
		p := g
		for j := uint32(1); j <= ecBabySteps; j++ {
			t.baby[ecKey(c, p.x)] = j<<1 | uint32(p.y.Bit(0))
			p = ecAdd(c, p, g)
		}
		t.giant = ecNeg(c, ecScalarBaseMult(c, big.NewInt(ecWindow)))
	})
	return t
}

// ecSupportedCurve returns the curve parameters for the short-Weierstrass
// curves (a = -3) this check supports, or nil.
func ecSupportedCurve(curve elliptic.Curve) *elliptic.CurveParams {
	if curve == nil {
		return nil
	}
	switch curve.Params().Name {
	case "P-224", "P-256", "P-384", "P-521":
		return curve.Params()
	}
	return nil
}

func ecsmallpriv(curve elliptic.Curve, qx, qy *big.Int) *Finding {
	c := ecSupportedCurve(curve)
	if c == nil || qx == nil || qy == nil {
		return nil
	}
	t := getECTable(c)
	r := ecPoint{new(big.Int).Set(qx), new(big.Int).Set(qy)}
	for i := int64(0); i < ecGiantSteps; i++ {
		if r.x == nil { // Q = i·W·G
			return ecSmallFinding(c, qx, qy, big.NewInt(i*ecWindow))
		}
		if v, ok := t.baby[ecKey(c, r.x)]; ok {
			delta := int64(v >> 1)
			if uint32(r.y.Bit(0)) != v&1 {
				delta = -delta
			}
			d := big.NewInt(i*ecWindow + delta)
			d.Mod(d, c.N)
			return ecSmallFinding(c, qx, qy, d)
		}
		r = ecAdd(c, r, t.giant)
	}
	return nil
}

func ecSmallFinding(c *elliptic.CurveParams, qx, qy, d *big.Int) *Finding {
	if d.Sign() == 0 {
		return nil
	}
	// Defensive: confirm d·G = Q before reporting.
	if p := ecScalarBaseMult(c, d); p.x == nil || p.x.Cmp(qx) != 0 || p.y.Cmp(qy) != 0 {
		return nil
	}
	sub := "small"
	if d.BitLen() > c.N.BitLen()/2 {
		sub = "small_negated" // d = n - small
	}
	return &Finding{Subtest: sub, D: d}
}

// ecRecover returns the PEM ("EC PRIVATE KEY") encoding of the private key d
// on curve, or an empty string on failure.
func ecRecover(curve elliptic.Curve, d *big.Int) string {
	priv, err := ecdsa.ParseRawPrivateKey(curve, d.FillBytes(make([]byte, (curve.Params().BitSize+7)/8)))
	if err != nil {
		return ""
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

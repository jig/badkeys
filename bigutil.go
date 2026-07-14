package badkeys

import "math/big"

var (
	big0 = big.NewInt(0)
	big1 = big.NewInt(1)
	big2 = big.NewInt(2)
)

// isSquare reports whether x is a perfect square (x >= 0).
func isSquare(x *big.Int) bool {
	if x.Sign() < 0 {
		return false
	}
	s := new(big.Int).Sqrt(x)
	s.Mul(s, s)
	return s.Cmp(x) == 0
}

// isqrt returns the integer square root of x (floor(sqrt(x))).
func isqrt(x *big.Int) *big.Int {
	return new(big.Int).Sqrt(x)
}

// isProbablePrime reports whether x is (probably) prime. Uses the same
// Baillie-PSW-backed test Go's standard library provides; 40 rounds gives an
// astronomically small error rate for adversarial inputs.
func isProbablePrime(x *big.Int) bool {
	if x.Sign() <= 0 {
		return false
	}
	return x.ProbablyPrime(40)
}

// bitCount returns the number of set bits in x (x >= 0).
func bitCount(x *big.Int) int {
	n := 0
	for _, w := range x.Bits() {
		n += popcount(uint64(w))
	}
	return n
}

func popcount(v uint64) int {
	c := 0
	for v != 0 {
		v &= v - 1
		c++
	}
	return c
}

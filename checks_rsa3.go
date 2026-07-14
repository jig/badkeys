package badkeys

import "math/big"

// bitPct returns the percentage of set bits in x (integer division, matching
// the Python _bitpct helper).
func bitPct(x *big.Int) int {
	bitlen := x.BitLen()
	if bitlen == 0 {
		return 0
	}
	return bitCount(x) * 100 / bitlen
}

// lowerHalf returns n mod 2^(bitlen/2), the lower half of the modulus.
func lowerHalf(n *big.Int) *big.Int {
	shift := uint(n.BitLen() / 2)
	mask := new(big.Int).Lsh(big1, shift)
	mask.Sub(mask, big1)
	return new(big.Int).And(n, mask)
}

// rsabias flags RSA moduli with an unusual ratio of 0/1 bits.
func rsabias(n, e *big.Int) *Finding {
	pct := bitPct(n)

	threshold := 17
	if n.BitLen() > 2000 {
		threshold = 10
	} else if n.BitLen() > 1000 {
		threshold = 12
	}

	if 50-threshold < pct && pct <= 50+threshold {
		return nil
	}
	if hasSmallFactor(n) {
		return nil
	}
	lowerpct := bitPct(lowerHalf(n))
	if pct < 40 && lowerpct < 40 {
		// detected by rsapoly instead
		return nil
	}
	if 50-threshold < lowerpct && lowerpct <= 50+threshold {
		return &Finding{Subtest: "vanity", BiasPct: pct}
	}
	return &Finding{BiasPct: pct}
}

// rsapoly detects a 0-byte pattern in the modulus that allows polynomial
// factoring.
func rsapoly(n, e *big.Int) *Finding {
	pct := bitPct(n)
	if pct >= 40 {
		return nil
	}
	if n.BitLen() < 500 {
		return nil
	}
	if bitPct(lowerHalf(n)) >= 40 {
		// probably a vanity key, handled by rsabias
		return nil
	}
	if hasSmallFactor(n) {
		return nil
	}
	if checkPolyBits(n, 128, mustBig("ffffffffffff0000")) {
		return &Finding{Subtest: "nautilus", BiasPct: pct}
	}
	if checkPolyBits(n, 32, big.NewInt(0x03ff00000)) {
		return &Finding{Subtest: "completeftp", BiasPct: pct}
	}
	return &Finding{BiasPct: pct}
}

func mustBig(hex string) *big.Int {
	v, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("bad hex constant")
	}
	return v
}

// checkPolyBits mirrors the Python _checkbits: it splits n into width-bit
// chunks (skipping the lowest one) and reports whether every chunk masked by
// bitmask is zero, with at most one all-zero chunk.
func checkPolyBits(n *big.Int, width uint, bitmask *big.Int) bool {
	_n := new(big.Int).Rsh(n, width)
	setBits := big.NewInt(0)
	zeroChunks := 0
	chunkMask := new(big.Int).Lsh(big1, width)
	chunkMask.Sub(chunkMask, big1)
	tmp := new(big.Int)
	for _n.Sign() != 0 {
		tmp.And(_n, bitmask)
		setBits.Or(setBits, tmp)
		_n.Rsh(_n, width)
		tmp.And(_n, chunkMask)
		if tmp.Sign() == 0 {
			zeroChunks++
		}
	}
	if zeroChunks >= 2 {
		return false
	}
	return setBits.Sign() == 0
}

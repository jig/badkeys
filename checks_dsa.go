package badkeys

import "math/big"

// dsasparse detects DSA keys with a sparse (mostly-zero) structure in the
// prime p that indicates a known weak generation.
func dsasparse(y, p *big.Int) *Finding {
	if p.BitLen() != 1024 || new(big.Int).Rsh(p, 1000).Cmp(big.NewInt(0x800000)) != 0 {
		return nil
	}
	_p := new(big.Int).Rsh(p, 168)
	_p.Xor(_p, new(big.Int).Lsh(big1, 855))

	mask := big.NewInt(0x00fffff0)
	chunk := new(big.Int)
	for _p.Sign() != 0 {
		chunk.And(_p, mask)
		if chunk.Sign() != 0 {
			return nil
		}
		_p.Rsh(_p, 32)
	}
	return &Finding{}
}

package badkeys

import (
	"embed"
	"fmt"
	"math/big"
	"sync"
)

//go:embed keydata/primes512.dat keydata/primes768.dat keydata/primes1024.dat keydata/primes2048.dat keydata/primes4096.dat
var keydataFS embed.FS

var (
	moduliMu    sync.Mutex
	moduliCache = map[int]*big.Int{}
)

var sharedPrimeBits = []int{512, 768, 1024, 2048, 4096}

// sharedModulus returns the precomputed product of known-vulnerable primes for
// the given key size, loaded from the embedded keydata.
func sharedModulus(bits int) (*big.Int, bool) {
	moduliMu.Lock()
	defer moduliMu.Unlock()
	if m, ok := moduliCache[bits]; ok {
		return m, true
	}
	data, err := keydataFS.ReadFile(fmt.Sprintf("keydata/primes%d.dat", bits))
	if err != nil {
		return nil, false
	}
	m := new(big.Int).SetBytes(data)
	moduliCache[bits] = m
	return m, true
}

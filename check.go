package badkeys

import "math/big"

// checkKind classifies which key values a check operates on.
type checkKind int

const (
	kindRSA checkKind = iota // operates on RSA (n, e)
	kindDSA                  // operates on DSA (y, p)
	kindAll                  // operates on a single canonical byte value
)

// checkGroup selects which preset a check belongs to.
type checkGroup int

const (
	groupDefault checkGroup = iota
	groupWarning
	groupExtra
)

// checkDef describes a single check. Exactly one of the func fields matching
// Kind is set.
type checkDef struct {
	Name  string
	Kind  checkKind
	Group checkGroup
	Desc  string

	rsa func(n, e *big.Int) *Finding
	dsa func(y, p *big.Int) *Finding
	// all receives the canonical byte representation of the key value.
	all func(val []byte) *Finding
}

// registry holds every known check keyed by name.
var registry = map[string]*checkDef{}

func register(c *checkDef) {
	registry[c.Name] = c
}

func init() {
	register(&checkDef{Name: "fermat", Kind: kindRSA, Group: groupDefault,
		Desc: "Fermat factorization / close prime vulnerability", rsa: fermat})
	register(&checkDef{Name: "roca", Kind: kindRSA, Group: groupDefault,
		Desc: "Return of the Coopersmith Attack (ROCA) vulnerability", rsa: roca})
	register(&checkDef{Name: "rsainvalid", Kind: kindRSA, Group: groupDefault,
		Desc: "RSA keys with invalid values", rsa: rsainvalid})
	register(&checkDef{Name: "rsapoly", Kind: kindRSA, Group: groupDefault,
		Desc: "0-byte pattern in modulus allowing polynomial factoring", rsa: rsapoly})
	register(&checkDef{Name: "sharedprimes", Kind: kindRSA, Group: groupDefault,
		Desc: "Shared prime factors (batchgcd)", rsa: sharedprimes})
	register(&checkDef{Name: "smalld", Kind: kindRSA, Group: groupDefault,
		Desc: "Small private d (Wiener's attack)", rsa: smalld})
	register(&checkDef{Name: "smallfactors", Kind: kindRSA, Group: groupDefault,
		Desc: "Small prime factors (<=65537, usually corrupt)", rsa: smallfactors})
	register(&checkDef{Name: "blocklist", Kind: kindAll, Group: groupDefault,
		Desc: "Blocklists of compromised keys", all: blocklistCheck})
	register(&checkDef{Name: "dsasparse", Kind: kindDSA, Group: groupDefault,
		Desc: "DSA sparse key vulnerability", dsa: dsasparse})

	register(&checkDef{Name: "rsawarnings", Kind: kindRSA, Group: groupWarning,
		Desc: "RSA key size and exponent warnings", rsa: rsawarnings})
	register(&checkDef{Name: "rsabias", Kind: kindRSA, Group: groupWarning,
		Desc: "RSA modulus with bias of 0/1 bits", rsa: rsabias})

	register(&checkDef{Name: "pattern", Kind: kindRSA, Group: groupExtra,
		Desc: "Implausible repetition pattern in modulus", rsa: pattern})
	register(&checkDef{Name: "xzbackdoor", Kind: kindRSA, Group: groupExtra,
		Desc: "xz backdoor payload in RSA n", rsa: xzbackdoor})
}

// checkNames returns the names of all checks in the given groups, in a stable
// order.
func checkNames(groups ...checkGroup) []string {
	want := map[checkGroup]bool{}
	for _, g := range groups {
		want[g] = true
	}
	var names []string
	// iterate registration order deterministically via the known lists
	for _, name := range allCheckOrder {
		if want[registry[name].Group] {
			names = append(names, name)
		}
	}
	return names
}

// allCheckOrder is the canonical ordering of checks (mirrors the Python dict
// insertion order for stable output).
var allCheckOrder = []string{
	"fermat", "roca", "rsainvalid", "rsapoly", "sharedprimes", "smalld",
	"smallfactors", "blocklist", "dsasparse",
	"rsawarnings", "rsabias",
	"pattern", "xzbackdoor",
}

// DefaultChecks returns the names of the default checks (the ones run when no
// explicit list is given).
func DefaultChecks() []string { return checkNames(groupDefault) }

// WarningChecks returns the names of the warning checks.
func WarningChecks() []string { return checkNames(groupWarning) }

// AllChecks returns the names of every known check, including warning and
// extra checks.
func AllChecks() []string { return checkNames(groupDefault, groupWarning, groupExtra) }

// CheckInfo describes a check for callers building UIs or help text.
type CheckInfo struct {
	Name    string
	Desc    string
	Warning bool
	Extra   bool
}

// Checks returns metadata for every known check.
func Checks() []CheckInfo {
	out := make([]CheckInfo, 0, len(allCheckOrder))
	for _, name := range allCheckOrder {
		c := registry[name]
		out = append(out, CheckInfo{
			Name: c.Name, Desc: c.Desc,
			Warning: c.Group == groupWarning, Extra: c.Group == groupExtra,
		})
	}
	return out
}

// minBytes returns the minimal big-endian byte encoding of x (no leading zero
// bytes), matching Python's int.to_bytes((bit_length+7)//8).
func minBytes(x *big.Int) []byte {
	if x.Sign() == 0 {
		return []byte{}
	}
	return x.Bytes()
}

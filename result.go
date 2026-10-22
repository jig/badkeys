package badkeys

import "math/big"

// Finding is the result of a single check that matched a key. A nil *Finding
// means the check did not flag the key.
type Finding struct {
	// Check is the name of the check that produced this finding, e.g. "fermat".
	Check string
	// Subtest is an optional sub-classification, e.g. "square" for a perfect
	// square modulus, or the blocklist name for a blocklist hit.
	Subtest string

	// P, Q and D hold recovered private key material when a check is able to
	// factor the modulus (P, Q) or recover the private exponent (D). They are
	// nil when not available.
	P, Q, D *big.Int

	// PrivateKey holds a reconstructed private key in PEM (PKCS#1) form. It is
	// only populated when the key was checked with KeyRecover enabled and
	// enough information was recovered.
	PrivateKey string

	// BiasPct is the percentage of set bits in the modulus, populated by the
	// rsabias and rsapoly checks.
	BiasPct int

	// BlockID and Lookup are populated by the blocklist check. BlockID
	// identifies the source blocklist; Lookup is the truncated hash used with
	// the optional URL lookup file.
	BlockID int
	Lookup  string

	// Debug carries a human-readable diagnostic string for some checks.
	Debug string
}

// KeyResult is the outcome of checking one key.
type KeyResult struct {
	// Type is the detected key type: "rsa", "ec", "dsa", "dh",
	// "mldsa44"/"mldsa65"/"mldsa87"/"mlkem768"/"mlkem1024", or one of the
	// sentinel values "unparseable", "unsupported" and "notfound".
	Type string
	// Bits is the key size in bits, when meaningful (RSA/DSA).
	Bits int
	// Curve is the elliptic-curve name for EC/OKP keys, e.g. "p256", "ed25519".
	Curve string

	// N, E are the RSA modulus and public exponent.
	N, E *big.Int
	// X, Y are EC coordinates. For DSA/DH, Y holds the public value.
	X, Y *big.Int

	// SPKISHA256 is the hex-encoded SHA-256 of the SubjectPublicKeyInfo
	// encoding, when the key could be re-encoded.
	SPKISHA256 string

	// Findings maps check name to the finding it produced. Empty when the key
	// is clean.
	Findings map[string]*Finding

	// Err is set for "unparseable"/"unsupported" results and carries the
	// underlying parse error.
	Err error

	// Warn is a non-fatal warning about how the key was obtained, e.g.
	// WarnFallbackParser when a certificate was only readable with the
	// lenient fallback parser.
	Warn string
}

// Flagged reports whether any check flagged the key.
func (r KeyResult) Flagged() bool { return len(r.Findings) > 0 }

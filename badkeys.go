// Package badkeys checks cryptographic public keys for known weaknesses.
//
// It is a Go port of the Python tool badkeys by Hanno Böck
// (https://github.com/badkeys/badkeys, MIT licensed). It detects keys that
// are vulnerable to known factorization or generation flaws (Fermat close
// primes, ROCA, Wiener small-d, small factors, shared primes/batch-GCD, …)
// and can match keys against downloadable blocklists of compromised keys
// (Debian OpenSSL bug, leaked test keys, …).
//
// The package works on already-parsed key material as well as on encoded
// keys (PEM/DER SubjectPublicKeyInfo, PKCS#1, PKCS#8, X.509 certificates and
// CSRs, OpenSSH public/private keys, JWK and DNSKEY records) via
// DetectAndCheck and the Check* helpers.
package badkeys

// Version is the badkeys upstream release this port tracks.
const Version = "0.0.19"

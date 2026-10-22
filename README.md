# badkeys (Go)

[![CI](https://github.com/jig/badkeys/actions/workflows/ci.yml/badge.svg)](https://github.com/jig/badkeys/actions/workflows/ci.yml)

A Go port of [badkeys](https://github.com/badkeys/badkeys) by Hanno Böck: check
cryptographic public keys for known weaknesses and match them against
blocklists of compromised keys.

This is a from-scratch reimplementation of the upstream Python package (MIT
licensed). It tracks upstream release **0.0.21**. All vulnerability checks
produce identical results to the Python version on the shared test fixtures;
the only differences are in key-parsing coverage (see *Limitations*).

## Install

```sh
go get github.com/jig/badkeys
```

Only two dependencies: `golang.org/x/crypto` (OpenSSH key parsing) and
`github.com/ulikunitz/xz` (blocklist decompression). Everything else is the Go
standard library and `math/big` — no cgo, no GMP.

## Library usage

```go
import "github.com/jig/badkeys"

// Auto-detect the encoding (PEM key/cert/CSR or OpenSSH key) and check.
r := badkeys.DetectAndCheck(pemBytes)
if r.Flagged() {
    for name, f := range r.Findings {
        fmt.Printf("%s: %s\n", name, f.Subtest)
    }
}

// Or check already-parsed values directly.
findings := badkeys.CheckRSA(n, e, false) // n, e are *big.Int

// Recover the private key of a weak (e.g. Fermat-factorable) key.
r = badkeys.DetectAndCheck(pemBytes, badkeys.WithKeyRecover())
fmt.Println(r.Findings["fermat"].PrivateKey) // PEM

// Restrict to specific checks.
r = badkeys.DetectAndCheck(pemBytes, badkeys.WithChecks("roca", "fermat"))
```

Entry points: `DetectAndCheck`, `CheckPubkey`, `CheckPrivkey`, `CheckCert`,
`CheckCSR`, `CheckSSHPubkey`, `CheckSSHPrivkey`, `CheckJWK`, `CheckDNSKEY`, and
the low-level `CheckRSA`, `CheckDSA`, `CheckAll`.

## Checks

Default checks: `fermat`, `roca`, `rsainvalid`, `rsapoly`, `sharedprimes`,
`smalld`, `smallfactors`, `blocklist`, `dsasparse`.
Warning checks: `rsawarnings`, `rsabias`.
Extra (higher false-positive) checks: `pattern`, `xzbackdoor`.

Call `badkeys.Checks()` for the full list with descriptions.

## Blocklist

The blocklist of compromised keys (Debian OpenSSL bug, leaked test keys, …) is
downloaded at runtime, not embedded:

```go
// Download (~60 MB, xz-compressed) into ~/.cache/badkeys.
badkeys.UpdateBlocklist(badkeys.UpdateOptions{})
// Load it so the "blocklist" check is active.
badkeys.LoadDefaultBlocklist("")
```

Without a loaded blocklist, the `blocklist` check is simply skipped.

## Command line

```sh
go install github.com/jig/badkeys/cmd/badkeys@latest

badkeys -update-bl                 # fetch the blocklist
badkeys key.pem                    # check a key
badkeys -checks fermat -recover *.pem
cat key.pem | badkeys              # read from stdin
```

## Limitations

The Go standard library parses fewer key encodings than Python's
`cryptography`. These inputs return `unparseable`/`unsupported` here where
upstream can parse them:

- **ML-DSA / ML-KEM** post-quantum keys (no Go stdlib support).
- **Ed448 / X448** keys.
- **EC keys with explicit (non-named) curve parameters.**

RSA keys with unusually large or invalid exponents *are* supported (parsed with
a dedicated ASN.1 path, bypassing `crypto/x509`'s exponent size limit).

Certificates that `crypto/x509` rejects (invalid version, malformed RSA
modulus, …) are retried with a lenient fallback parser that only extracts the
public key; such results carry `KeyResult.Warn == WarnFallbackParser`.

Not ported (yet): DKIM/DNSSEC record helpers beyond `CheckDNSKEY`, and the SSH/
TLS network scanners.

## License

MIT, same as upstream badkeys.

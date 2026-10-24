package badkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestECSmallPrivEmudhra checks the eight compromised eMudhra intermediates
// and their Sectigo cross-signs (Mozilla bug 2083449).
func TestECSmallPrivEmudhra(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "emudhra", "*.crt"))
	if len(files) != 16 {
		t.Fatalf("expected 16 eMudhra fixtures, got %d", len(files))
	}
	for _, f := range files {
		r := DetectAndCheck(read(t, filepath.Join("emudhra", filepath.Base(f))), WithKeyRecover())
		fd := r.Findings["ecsmallpriv"]
		if fd == nil {
			t.Errorf("%s: not detected (type=%s err=%v)", f, r.Type, r.Err)
			continue
		}
		if fd.Subtest != "small" || fd.D.Cmp(big.NewInt(256)) >= 0 {
			t.Errorf("%s: subtest=%s d=%v", f, fd.Subtest, fd.D)
		}
		block, _ := pem.Decode([]byte(fd.PrivateKey))
		if block == nil {
			t.Errorf("%s: no recovered private key", f)
			continue
		}
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			t.Errorf("%s: recovered key: %v", f, err)
			continue
		}
		if priv.X.Cmp(r.X) != 0 || priv.Y.Cmp(r.Y) != 0 {
			t.Errorf("%s: recovered key does not match certificate", f)
		}
	}
}

func ecKeyWithD(t *testing.T, c elliptic.Curve, d *big.Int) *ecdsa.PublicKey {
	t.Helper()
	priv, err := ecdsa.ParseRawPrivateKey(c, d.FillBytes(make([]byte, (c.Params().BitSize+7)/8)))
	if err != nil {
		t.Fatalf("ParseRawPrivateKey(%s, %v): %v", c.Params().Name, d, err)
	}
	return &priv.PublicKey
}

func TestECSmallPrivBounds(t *testing.T) {
	for _, c := range []elliptic.Curve{elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		n := c.Params().N
		for _, tc := range []struct {
			d   *big.Int
			sub string
		}{
			{big.NewInt(1), "small"},
			{big.NewInt(42), "small"},
			{big.NewInt(ecBabySteps), "small"},
			{big.NewInt(ecWindow), "small"},
			{big.NewInt(ecWindow*7 + 3), "small"},
			{big.NewInt(ecWindow*7 - 3), "small"},
			{big.NewInt(ecSearchBound()), "small"},
			{new(big.Int).Sub(n, big1), "small_negated"},
			{new(big.Int).Sub(n, big.NewInt(ecBabySteps)), "small_negated"},
		} {
			pub := ecKeyWithD(t, c, tc.d)
			f := CheckEC(c, pub.X, pub.Y, false, "ecsmallpriv")["ecsmallpriv"]
			if f == nil || f.D.Cmp(tc.d) != 0 || f.Subtest != tc.sub {
				t.Errorf("%s d=%v: got %+v", c.Params().Name, tc.d, f)
			}
		}
		// Just outside the search range: must not be reported.
		pub := ecKeyWithD(t, c, big.NewInt(ecSearchBound()+ecBabySteps+1))
		if f := CheckEC(c, pub.X, pub.Y, false, "ecsmallpriv")["ecsmallpriv"]; f != nil {
			t.Errorf("%s: unexpected finding beyond bound: %+v", c.Params().Name, f)
		}
	}
}

func TestECSmallPrivNoFalsePositives(t *testing.T) {
	for _, f := range []string{"ec-p256-rfc-example.key", "ecdsa-explicit-pub.key", "rsa-ok.key", "ed25519-rfc-example.key"} {
		r := DetectAndCheck(read(t, f), WithChecks("ecsmallpriv"))
		if has(r, "ecsmallpriv") {
			t.Errorf("%s: false positive", f)
		}
	}
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		for range 5 {
			k, err := ecdsa.GenerateKey(c, nil)
			if err != nil {
				t.Fatal(err)
			}
			if f := CheckEC(c, k.X, k.Y, false, "ecsmallpriv")["ecsmallpriv"]; f != nil {
				t.Errorf("%s: random key flagged: %+v", c.Params().Name, f)
			}
		}
	}
}

func TestECSmallPrivJWKAndDNSKEY(t *testing.T) {
	pub := ecKeyWithD(t, elliptic.P256(), big.NewInt(7))
	b64 := func(x *big.Int) string { return jwkB64(x.FillBytes(make([]byte, 32))) }
	r := CheckJWK(JWK{Kty: "EC", Crv: "P-256", X: b64(pub.X), Y: b64(pub.Y)})
	if f := r.Findings["ecsmallpriv"]; f == nil || f.D.Int64() != 7 {
		t.Errorf("JWK: got %+v (type=%s)", f, r.Type)
	}

	pub = ecKeyWithD(t, elliptic.P384(), big.NewInt(200))
	raw := append(pub.X.FillBytes(make([]byte, 48)), pub.Y.FillBytes(make([]byte, 48))...)
	r = CheckDNSKEY("257 3 14 " + stdB64(raw))
	if f := r.Findings["ecsmallpriv"]; f == nil || f.D.Int64() != 200 {
		t.Errorf("DNSKEY: got %+v (type=%s err=%v)", f, r.Type, r.Err)
	}
	// Oversized coordinate must be rejected, not panic.
	long := jwkB64(append([]byte{1}, make([]byte, 40)...))
	if r := CheckJWK(JWK{Kty: "EC", Crv: "P-256", X: long, Y: long}); has(r, "ecsmallpriv") {
		t.Errorf("JWK oversized coordinate: unexpected finding")
	}

	for _, f := range []string{"dnssec-p256-rfc6605.dnskey"} {
		data, _ := os.ReadFile(filepath.Join("testdata", "dnssec", f))
		if r := CheckDNSKEY(strings.TrimSpace(string(data))); has(r, "ecsmallpriv") {
			t.Errorf("%s: false positive", f)
		}
	}
}

func BenchmarkECSmallPrivP384(b *testing.B) {
	k, _ := ecdsa.GenerateKey(elliptic.P384(), nil)
	ecsmallpriv(k.Curve, k.X, k.Y) // build table outside the timed loop
	b.ResetTimer()
	for range b.N {
		ecsmallpriv(k.Curve, k.X, k.Y)
	}
}

func jwkB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func stdB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

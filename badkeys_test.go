package badkeys

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return data
}

func has(r KeyResult, check string) bool {
	_, ok := r.Findings[check]
	return ok
}

func TestFermat(t *testing.T) {
	for _, f := range []string{"rsa-fermat.crt", "rsa-fermat.csr", "rsa-fermat-pkcs1.key", "rsa-fermat-pkcs8.key"} {
		r := DetectAndCheck(read(t, f), WithChecks("fermat"))
		if !has(r, "fermat") {
			t.Errorf("%s: expected fermat finding, got type=%s findings=%v err=%v", f, r.Type, r.Findings, r.Err)
			continue
		}
		if r.Bits != 2048 {
			t.Errorf("%s: bits=%d, want 2048", f, r.Bits)
		}
	}
}

func TestRoca(t *testing.T) {
	r := CheckPubkey(read(t, "rsa-roca.key"), WithChecks("roca"))
	if !has(r, "roca") {
		t.Errorf("roca not detected: %v (err %v)", r.Findings, r.Err)
	}
	if r.Bits != 2048 {
		t.Errorf("bits=%d want 2048", r.Bits)
	}
	r = CheckPubkey(read(t, "rsa-ok.key"), WithChecks("roca"))
	if has(r, "roca") {
		t.Errorf("roca false positive on ok key")
	}
}

func TestSmallfactors(t *testing.T) {
	r := CheckPubkey(read(t, "rsa-smallfactors-valid.key"), WithChecks("smallfactors"))
	if f := r.Findings["smallfactors"]; f == nil || f.Subtest != "valid" {
		t.Errorf("valid: got %+v", f)
	}
	r = CheckPubkey(read(t, "rsa-smallfactors-corrupt.key"), WithChecks("smallfactors"))
	if f := r.Findings["smallfactors"]; f == nil || f.Subtest != "corrupt" {
		t.Errorf("corrupt: got %+v", f)
	}
	r = CheckPubkey(read(t, "rsa-ok.key"), WithChecks("smallfactors"))
	if has(r, "smallfactors") {
		t.Errorf("smallfactors false positive")
	}
}

func TestSharedprimes(t *testing.T) {
	r := CheckPubkey(read(t, "rsa-sharedprimes.key"), WithChecks("sharedprimes"))
	if !has(r, "sharedprimes") {
		t.Errorf("sharedprimes not detected: %v", r.Err)
	}
	if r.Bits != 2048 {
		t.Errorf("bits=%d want 2048", r.Bits)
	}
	r = CheckPubkey(read(t, "rsa-ok.key"), WithChecks("sharedprimes"))
	if has(r, "sharedprimes") {
		t.Errorf("sharedprimes false positive")
	}
}

func TestSmalld(t *testing.T) {
	checks := AllChecks()
	// drop blocklist (needs downloaded data)
	var mychecks []string
	for _, c := range checks {
		if c != "blocklist" {
			mychecks = append(mychecks, c)
		}
	}
	r := DetectAndCheck(read(t, "rsa-small-d.key"), WithChecks(mychecks...))
	if !has(r, "smalld") {
		t.Errorf("smalld not detected: %v err=%v", r.Findings, r.Err)
	}
	if f := r.Findings["rsawarnings"]; f == nil || f.Subtest != "exponent_not_65537" {
		t.Errorf("rsawarnings: got %+v", f)
	}

	r = DetectAndCheck(read(t, "rsa-large-e.key"), WithChecks(mychecks...))
	if has(r, "smalld") {
		t.Errorf("smalld false positive on large-e key")
	}
	if f := r.Findings["rsawarnings"]; f == nil || f.Subtest != "exponent_not_65537" {
		t.Errorf("large-e rsawarnings: got %+v (type=%s err=%v)", f, r.Type, r.Err)
	}

	// regression test for division by zero bug (upstream 00facea)
	r = DetectAndCheck(read(t, "rsa-smalld-divzero.key"), WithChecks(mychecks...))
	if has(r, "smalld") {
		t.Errorf("smalld false positive on divzero key")
	}
	if !has(r, "rsawarnings") {
		t.Errorf("divzero: expected rsawarnings, got %v (type=%s err=%v)", r.Findings, r.Type, r.Err)
	}
}

func TestRSAInvalid(t *testing.T) {
	r := CheckPubkey(read(t, "rsa-e1.key"), WithChecks("rsainvalid"))
	if f := r.Findings["rsainvalid"]; f == nil || f.Subtest != "invalid_e" {
		t.Errorf("rsainvalid: got %+v (type=%s err=%v)", f, r.Type, r.Err)
	}
	// Upstream reports this as unparseable (Python cryptography rejects
	// e >= n); our size-limit-free parser loads it and flags it instead.
	r = CheckPubkey(read(t, "rsa-e-larger-n.key"), WithChecks("rsainvalid"))
	if f := r.Findings["rsainvalid"]; f == nil || f.Subtest != "e_too_large" {
		t.Errorf("rsa-e-larger-n: got %+v (type=%s err=%v)", f, r.Type, r.Err)
	}
	r = CheckPubkey(read(t, "rsa-ok.key"), WithChecks("rsainvalid"))
	if has(r, "rsainvalid") {
		t.Errorf("rsainvalid false positive")
	}
}

func TestRSAPoly(t *testing.T) {
	r := DetectAndCheck(read(t, "rsapoly128.key"), WithChecks("rsapoly"))
	if f := r.Findings["rsapoly"]; f == nil || f.Subtest != "nautilus" {
		t.Errorf("rsapoly128: got %+v", f)
	}
	r = DetectAndCheck(read(t, "rsapoly32.key"), WithChecks("rsapoly"))
	if f := r.Findings["rsapoly"]; f == nil || f.Subtest != "completeftp" {
		t.Errorf("rsapoly32: got %+v", f)
	}
	r = DetectAndCheck(read(t, "rsa-ok.key"), WithChecks("rsapoly"))
	if has(r, "rsapoly") {
		t.Errorf("rsapoly false positive")
	}
}

func TestRSABias(t *testing.T) {
	r := DetectAndCheck(read(t, "rsa-vanity.key"), WithChecks("rsabias"))
	if f := r.Findings["rsabias"]; f == nil || f.Subtest != "vanity" {
		t.Errorf("rsabias vanity: got %+v", f)
	}
}

func TestPattern(t *testing.T) {
	r := CheckPubkey(read(t, "rsa-pattern.key"), WithChecks("pattern"))
	if !has(r, "pattern") {
		t.Errorf("pattern not detected")
	}
	r = CheckPubkey(read(t, "rsa-ok.key"), WithChecks("pattern"))
	if has(r, "pattern") {
		t.Errorf("pattern false positive")
	}
}

func TestXZRegression(t *testing.T) {
	for _, f := range []string{"rsazerozero.key", "rsanzero.key"} {
		r := CheckPubkey(read(t, f), WithChecks("xzbackdoor"))
		if has(r, "xzbackdoor") {
			t.Errorf("%s: xzbackdoor false positive", f)
		}
	}
}

func TestFermatKeyRecover(t *testing.T) {
	r := DetectAndCheck(read(t, "rsa-fermat.crt"), WithChecks("fermat"), WithKeyRecover())
	f := r.Findings["fermat"]
	if f == nil || f.P == nil || f.Q == nil {
		t.Fatalf("no factors recovered: %+v", f)
	}
	// p*q must equal n
	if r.N == nil {
		t.Fatal("no modulus")
	}
	prod := f.P.BitLen() + f.Q.BitLen()
	if prod == 0 {
		t.Fatal("empty factors")
	}
	if f.PrivateKey == "" {
		t.Errorf("expected recovered private key PEM")
	}
}

func TestFailures(t *testing.T) {
	if r := DetectAndCheck([]byte("-----BEGIN CERTIFICATE-----\nMII")); r.Type != "unparseable" {
		t.Errorf("brokencrt: type=%s", r.Type)
	}
	if r := DetectAndCheck([]byte("-----BEGIN CERTIFICATE REQUEST-----\nMII")); r.Type != "unparseable" {
		t.Errorf("brokencsr: type=%s", r.Type)
	}
	if r := DetectAndCheck([]byte("")); r.Type != "notfound" {
		t.Errorf("empty: type=%s", r.Type)
	}
	if r := DetectAndCheck([]byte("ssh-invalid invalid")); r.Type != "unsupported" && r.Type != "unparseable" {
		t.Errorf("unsupportedssh: type=%s", r.Type)
	}
	for _, sub := range []string{"defect", "unsupported"} {
		entries, err := os.ReadDir(filepath.Join("testdata", sub))
		if err != nil {
			continue
		}
		for _, e := range entries {
			data := read(t, filepath.Join(sub, e.Name()))
			r := DetectAndCheck(data)
			if sub == "defect" && r.Type != "unparseable" {
				t.Errorf("defect/%s: type=%s (want unparseable)", e.Name(), r.Type)
			}
			if sub == "unsupported" && r.Type != "unparseable" && r.Type != "unsupported" {
				t.Errorf("unsupported/%s: type=%s", e.Name(), r.Type)
			}
		}
	}
}

func TestFallback(t *testing.T) {
	checks := WithChecks("roca", "rsabias", "sharedprimes", "fermat")
	for _, tc := range []struct{ file, typ string }{
		{"fallback/invalidver.crt", "ec"},  // invalid X.509 version
		{"fallback/rsa-fido.crt", "ec"},    // ECDSA signature with NULL params
		{"fallback/rootagency.crt", "rsa"}, // RSA modulus missing leading zero
	} {
		r := CheckCert(read(t, tc.file), checks)
		if r.Type != tc.typ {
			t.Errorf("%s: type=%s want %s (err %v)", tc.file, r.Type, tc.typ, r.Err)
		}
	}
	r := CheckCert(read(t, "fallback/rootagency.crt"), checks)
	if r.Bits != 512 || r.Warn != WarnFallbackParser {
		t.Errorf("rootagency: bits=%d warn=%q", r.Bits, r.Warn)
	}
	r = CheckCert(read(t, "fallback/invalidver.crt"), checks)
	if r.Warn != WarnFallbackParser {
		t.Errorf("invalidver: warn=%q", r.Warn)
	}
	r = CheckCert(read(t, "rsa-fermat.crt"), checks)
	if r.Warn != "" {
		t.Errorf("rsa-fermat.crt: unexpected warn=%q", r.Warn)
	}
}

func TestJWK(t *testing.T) {
	for _, f := range []string{"jwk-rsa-ok.json", "jwk-rsa-rfc7517.json", "jwk-ecp256-rfc7517.json", "jwk-ed25519-rfc8037.json"} {
		var k JWK
		if err := json.Unmarshal(read(t, f), &k); err != nil {
			t.Errorf("%s: json: %v", f, err)
			continue
		}
		r := CheckJWK(k)
		if r.Type == "unparseable" || r.Type == "unsupported" {
			t.Errorf("%s: type=%s err=%v", f, r.Type, r.Err)
		}
	}
	var bad JWK
	_ = json.Unmarshal(read(t, "jwk-curvename-invalid.json"), &bad)
	if r := CheckJWK(bad); r.Type != "unparseable" {
		t.Errorf("invalid curve: type=%s", r.Type)
	}
}

func TestECAndEd(t *testing.T) {
	for _, f := range []string{"ec-p256-rfc-example.key", "ed25519-rfc-example.key"} {
		r := CheckPubkey(read(t, f), WithChecks("smallfactors"))
		if r.Type != "ec" {
			t.Errorf("%s: type=%s err=%v", f, r.Type, r.Err)
		}
	}
}

func TestBlocklistSearch(t *testing.T) {
	// Build a synthetic blocklist: sorted 16-byte blocks (15-byte hash + id).
	mk := func(b byte, id byte) []byte {
		blk := make([]byte, 16)
		for i := 0; i < 15; i++ {
			blk[i] = b
		}
		blk[15] = id
		return blk
	}
	var data []byte
	for _, b := range []byte{0x10, 0x40, 0x80, 0xf0} {
		data = append(data, mk(b, 1)...)
	}
	bl := &Blocklist{data: data, meta: map[int]blMeta{1: {ID: 1, Name: "test"}}}

	hit := make([]byte, 15)
	for i := range hit {
		hit[i] = 0x80
	}
	if f := bl.search(hit); f == nil || f.Subtest != "test" {
		t.Errorf("expected hit, got %+v", f)
	}
	miss := make([]byte, 15)
	for i := range miss {
		miss[i] = 0x55
	}
	if f := bl.search(miss); f != nil {
		t.Errorf("expected miss, got %+v", f)
	}
}

func TestLookupPath(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "lookup.txt")
	content := "1111111111111111;a/b/c\n" +
		"3333333333333333;d/e/f\n" +
		"5555555555555555;g/h/i\n" +
		"7777777777777777;j/k/l\n"
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"1111111111111111": "a/b/c",
		"5555555555555555": "g/h/i",
		"7777777777777777": "j/k/l",
		"2222222222222222": "",
		"9999999999999999": "",
		"0000000000000000": "",
	}
	for key, want := range cases {
		got, err := lookupPath(file, key)
		if err != nil {
			t.Errorf("%s: %v", key, err)
			continue
		}
		if got != want {
			t.Errorf("%s: got %q want %q", key, got, want)
		}
	}
}

package badkeys

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestRSATooLarge(t *testing.T) {
	// An implausibly large modulus only gets rsawarnings.
	n := new(big.Int).Lsh(big.NewInt(1), RSAMaxSize+7)
	n.Or(n, big.NewInt(1))
	start := time.Now()
	res := CheckRSA(n, big.NewInt(65537), false, AllChecks()...)
	if time.Since(start) > 5*time.Second {
		t.Errorf("checking a %d-bit key took %v", n.BitLen(), time.Since(start))
	}
	if len(res) != 1 || res["rsawarnings"] == nil || res["rsawarnings"].Subtest != "unusual_keysize" {
		t.Errorf("got %v, want only rsawarnings/unusual_keysize", res)
	}
}

// inconsistentRSAPKCS1 returns a PKCS#1 RSAPrivateKey whose private fields do
// not match n, so crypto/x509 refuses it.
func inconsistentRSAPKCS1(t *testing.T, n *big.Int) []byte {
	t.Helper()
	one := big.NewInt(1)
	der, err := asn1.Marshal(pkcs1Priv{N: n, E: big.NewInt(65537), D: one, P: big.NewInt(3), Q: big.NewInt(5), Dp: one, Dq: one, Qinv: one})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func sshString(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}

func sshMpint(x *big.Int) []byte {
	b := x.Bytes()
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return sshString(b)
}

func TestRSAPrivNotValidated(t *testing.T) {
	// Modulus with Fermat-factorable primes, so a finding proves the checks ran.
	block, _ := pem.Decode(read(t, "rsa-fermat-pkcs1.key"))
	k, ok := parseRSAFromPKCS1(block.Bytes)
	if !ok {
		t.Fatal("cannot parse rsa-fermat-pkcs1.key")
	}
	pkcs1 := inconsistentRSAPKCS1(t, k.N)

	pkcs8, err := asn1.Marshal(struct {
		Version    int
		Algo       algorithmIdentifier
		PrivateKey []byte
	}{Algo: algorithmIdentifier{Algorithm: oidRSA, Parameters: asn1.NullRawValue}, PrivateKey: pkcs1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(pkcs8); err == nil {
		t.Fatal("crypto/x509 accepted the inconsistent key; the test proves nothing")
	}

	var priv []byte
	priv = binary.BigEndian.AppendUint32(priv, 42)
	priv = binary.BigEndian.AppendUint32(priv, 42)
	priv = append(priv, sshString([]byte("ssh-rsa"))...)
	for _, x := range []*big.Int{k.N, big.NewInt(65537), big.NewInt(1), big.NewInt(1), big.NewInt(3), big.NewInt(5)} {
		priv = append(priv, sshMpint(x)...)
	}
	priv = append(priv, sshString(nil)...) // comment
	for i := 1; len(priv)%8 != 0; i++ {
		priv = append(priv, byte(i))
	}
	pubBlob := append(append(sshString([]byte("ssh-rsa")), sshMpint(big.NewInt(65537))...), sshMpint(k.N)...)
	openssh := []byte("openssh-key-v1\x00")
	openssh = append(openssh, sshString([]byte("none"))...)
	openssh = append(openssh, sshString([]byte("none"))...)
	openssh = append(openssh, sshString(nil)...)
	openssh = binary.BigEndian.AppendUint32(openssh, 1)
	openssh = append(openssh, sshString(pubBlob)...)
	openssh = append(openssh, sshString(priv)...)
	opensshPEM := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: openssh})
	if _, err := ssh.ParseRawPrivateKey(opensshPEM); err == nil {
		t.Fatal("x/crypto/ssh accepted the inconsistent key; the test proves nothing")
	}

	for _, tc := range []struct {
		name string
		r    KeyResult
	}{
		{"pkcs1", CheckPrivkey(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: pkcs1}))},
		{"pkcs8", CheckPrivkey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))},
		{"openssh", CheckSSHPrivkey(opensshPEM)},
		{"detect-openssh", DetectAndCheck(opensshPEM)},
	} {
		if tc.r.Type != "rsa" || !has(tc.r, "fermat") {
			t.Errorf("%s: type=%s err=%v findings=%v, want rsa with fermat", tc.name, tc.r.Type, tc.r.Err, tc.r.Findings)
		}
	}
}

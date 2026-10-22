package badkeys

import (
	"bytes"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// WarnFallbackParser is set in KeyResult.Warn when a certificate could not be
// parsed by crypto/x509 and its public key was extracted with the lenient
// fallback parser instead.
const WarnFallbackParser = "fallbackparser"

// fallbackCertSPKI extracts the raw SubjectPublicKeyInfo from a DER
// certificate by walking the TBSCertificate structure without validating any
// other field (version, signature algorithm, extensions, ...). This mirrors
// the pyOpenSSL fallback used by upstream badkeys for certificates that the
// strict parser rejects.
func fallbackCertSPKI(der []byte) ([]byte, bool) {
	input := cryptobyte.String(der)
	var cert, tbs cryptobyte.String
	if !input.ReadASN1(&cert, cbasn1.SEQUENCE) || !cert.ReadASN1(&tbs, cbasn1.SEQUENCE) {
		return nil, false
	}
	if !tbs.SkipOptionalASN1(cbasn1.Tag(0).Constructed().ContextSpecific()) || // version
		!tbs.SkipASN1(cbasn1.INTEGER) || // serialNumber
		!tbs.SkipASN1(cbasn1.SEQUENCE) || // signature
		!tbs.SkipASN1(cbasn1.SEQUENCE) || // issuer
		!tbs.SkipASN1(cbasn1.SEQUENCE) || // validity
		!tbs.SkipASN1(cbasn1.SEQUENCE) { // subject
		return nil, false
	}
	var spki cryptobyte.String
	if !tbs.ReadASN1Element(&spki, cbasn1.SEQUENCE) {
		return nil, false
	}
	return spki, true
}

// parseRSAFromSPKILenient parses an RSA SubjectPublicKeyInfo treating n and e
// as unsigned big-endian integers, accepting encodings that strict DER
// parsers reject (e.g. a modulus missing its leading zero byte).
func parseRSAFromSPKILenient(der []byte) (*bkRSAKey, bool) {
	input := cryptobyte.String(der)
	var spki, alg, oidBytes, bits cryptobyte.String
	if !input.ReadASN1(&spki, cbasn1.SEQUENCE) ||
		!spki.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!alg.ReadASN1(&oidBytes, cbasn1.OBJECT_IDENTIFIER) ||
		!spki.ReadASN1(&bits, cbasn1.BIT_STRING) {
		return nil, false
	}
	if !bytes.Equal(oidBytes, oidRSARaw) || len(bits) < 1 || bits[0] != 0 {
		return nil, false
	}
	pkcs1 := cryptobyte.String(bits[1:])
	var seq, nRaw, eRaw cryptobyte.String
	if !pkcs1.ReadASN1(&seq, cbasn1.SEQUENCE) ||
		!seq.ReadASN1(&nRaw, cbasn1.INTEGER) ||
		!seq.ReadASN1(&eRaw, cbasn1.INTEGER) {
		return nil, false
	}
	n := new(big.Int).SetBytes(nRaw)
	e := new(big.Int).SetBytes(eRaw)
	if n.Sign() == 0 {
		return nil, false
	}
	return &bkRSAKey{N: n, E: e}, true
}

// oidRSARaw is the DER content encoding of 1.2.840.113549.1.1.1.
var oidRSARaw = []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01}

// checkCertFallback runs the checks on a certificate rejected by
// crypto/x509. It returns ok=false if no public key could be extracted.
func checkCertFallback(der []byte, cfg config) (KeyResult, bool) {
	spki, ok := fallbackCertSPKI(der)
	if !ok {
		return KeyResult{}, false
	}
	r := checkSPKI(spki, cfg)
	if r.Type == "unparseable" {
		k, ok := parseRSAFromSPKILenient(spki)
		if !ok {
			return KeyResult{}, false
		}
		r = checkKey(k, spki, cfg)
	}
	if r.Type == "unsupported" {
		return r, true
	}
	r.Warn = WarnFallbackParser
	return r, true
}

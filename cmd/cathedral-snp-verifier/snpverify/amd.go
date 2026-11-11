package snpverify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

const (
	oidHWID       = "1.3.6.1.4.1.3704.1.4"
	oidBootloader = "1.3.6.1.4.1.3704.1.3.1"
	oidTEE        = "1.3.6.1.4.1.3704.1.3.2"
	oidSNP        = "1.3.6.1.4.1.3704.1.3.3"
	oidMicrocode  = "1.3.6.1.4.1.3704.1.3.8"
)

// AMDInfo is what a passing chain check reports.
type AMDInfo struct {
	Product   string `json:"product"`
	ARKSHA256 string `json:"ark_sha256"`
	TCB       TCB    `json:"tcb"`
}

// TCB holds the SPL parts of the reported TCB that the VCEK must match.
type TCB struct {
	Bootloader int `json:"bootloader"`
	TEE        int `json:"tee"`
	SNP        int `json:"snp"`
	Microcode  int `json:"microcode"`
}

// pssVerify mirrors pss_verify() in verify_receipts.py: RSA-PSS, SHA-384,
// MGF1 SHA-384, salt length 48. The certificate's own algorithm OID is not read.
func pssVerify(issuer, cert *x509.Certificate) error {
	pub, ok := issuer.PublicKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("issuer key is not RSA")
	}
	digest := sha512.Sum384(cert.RawTBSCertificate)
	return rsa.VerifyPSS(pub, crypto.SHA384, digest[:], cert.Signature, &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384})
}

// requireP384 refuses a VCEK key that is not on P-384, so a report signature is
// never checked against a weaker curve.
func requireP384(pub *ecdsa.PublicKey, isECDSA bool) error {
	if !isECDSA || pub == nil {
		return fail(CodeReportSignature, "VCEK key is not ECDSA")
	}
	if pub.Curve != elliptic.P384() {
		return fail(CodeReportSignature, "VCEK key is on curve %s, expected P-384", pub.Curve.Params().Name)
	}
	return nil
}

// product mirrors product() in verify_receipts.py plus the check in verify_amd():
// only Milan and Genoa are handled, because their TCB byte layout is the one used here.
func product(rep Report, override string) (string, error) {
	prod := override
	if prod == "" {
		switch {
		case !rep.HasCPUID:
			return "", fail(CodeUnsupportedProduct, "report version %d has no CPUID family and model; set the product", rep.Version)
		case rep.Family == 0x19 && rep.Model >= 0x10:
			prod = "Genoa"
		case rep.Family == 0x19:
			prod = "Milan"
		default:
			return "", fail(CodeUnsupportedProduct, "cannot tell the product from cpuid family %d model %d; set the product", rep.Family, rep.Model)
		}
	}
	if prod != "Genoa" && prod != "Milan" {
		return "", fail(CodeUnsupportedProduct, "only Milan and Genoa TCB layouts are handled, not %q", prod)
	}
	return prod, nil
}

// extInt mirrors ext_int(): the extension value is a DER INTEGER, 02 len value.
func extInt(cert *x509.Certificate, oid string) (int, bool) {
	for _, e := range cert.Extensions {
		if e.Id.String() != oid {
			continue
		}
		raw := e.Value
		if len(raw) < 2 || raw[0] != 0x02 || 2+int(raw[1]) > len(raw) {
			return 0, false
		}
		n := new(big.Int).SetBytes(raw[2 : 2+int(raw[1])])
		if !n.IsInt64() || n.Int64() > 1<<30 {
			return 0, false
		}
		return int(n.Int64()), true
	}
	return 0, false
}

func extValue(cert *x509.Certificate, oid string) ([]byte, bool) {
	for _, e := range cert.Extensions {
		if e.Id.String() == oid {
			return e.Value, true
		}
	}
	return nil, false
}

// VerifyAMDChain follows verify_amd() in verify_receipts.py, minus the KDS
// fetch: the caller supplies the DER certificates. It needs at least one ARK
// pin so a caller cannot trust whatever root arrives with the report.
func VerifyAMDChain(report []byte, fields Report, ark, ask, vcek []byte, arkPins []string, productOverride string) (AMDInfo, error) {
	var info AMDInfo
	if len(arkPins) == 0 {
		return info, fail(CodeARKNotPinned, "no ARK pin given: at least one is required")
	}
	prod, err := product(fields, productOverride)
	if err != nil {
		return info, err
	}
	info.Product = prod
	if len(report) < signedLen {
		return info, fail(CodeBadInput, "report is shorter than the signed range")
	}
	arkCert, err := x509.ParseCertificate(ark)
	if err != nil {
		return info, fail(CodeBadInput, "ARK is not a certificate: %v", err)
	}
	askCert, err := x509.ParseCertificate(ask)
	if err != nil {
		return info, fail(CodeBadInput, "ASK is not a certificate: %v", err)
	}
	vcekCert, err := x509.ParseCertificate(vcek)
	if err != nil {
		return info, fail(CodeBadInput, "VCEK is not a certificate: %v", err)
	}
	if err := pssVerify(arkCert, arkCert); err != nil {
		return info, fail(CodeARKSignature, "ARK is not self-signed: %v", err)
	}
	if err := pssVerify(arkCert, askCert); err != nil {
		return info, fail(CodeASKSignature, "ASK is not signed by the ARK: %v", err)
	}
	sum := sha256.Sum256(ark)
	arkFP := hex.EncodeToString(sum[:])
	pinned := false
	for _, p := range arkPins {
		if strings.ToLower(p) == arkFP {
			pinned = true
		}
	}
	if !pinned {
		return info, fail(CodeARKNotPinned, "ARK sha256 %s differs from the pinned values", arkFP)
	}
	if err := pssVerify(askCert, vcekCert); err != nil {
		return info, fail(CodeVCEKSignature, "VCEK is not signed by the ASK: %v", err)
	}
	// Milan and Genoa TCB layout: bootloader, tee, then snp and microcode at bytes 6 and 7.
	tcb := fields.ReportedTCB
	info.ARKSHA256 = arkFP
	info.TCB = TCB{Bootloader: int(tcb[0]), TEE: int(tcb[1]), SNP: int(tcb[6]), Microcode: int(tcb[7])}
	hwid, ok := extValue(vcekCert, oidHWID)
	if !ok || len(hwid) < 64 || string(hwid[len(hwid)-64:]) != string(fields.ChipID[:]) {
		return info, fail(CodeVCEKMismatch, "VCEK hwID differs from the report chip id")
	}
	for _, c := range []struct {
		oid, name string
		want      int
	}{
		{oidBootloader, "bootloader", info.TCB.Bootloader},
		{oidTEE, "tee", info.TCB.TEE},
		{oidSNP, "snp", info.TCB.SNP},
		{oidMicrocode, "microcode", info.TCB.Microcode},
	} {
		got, ok := extInt(vcekCert, c.oid)
		if !ok || got != c.want {
			return info, fail(CodeVCEKMismatch, "VCEK %s SPL differs from the report", c.name)
		}
	}
	if fields.SignatureAlg != 1 {
		return info, fail(CodeReportSignature, "report signature algorithm is not ECDSA P-384 SHA-384")
	}
	pub, ok := vcekCert.PublicKey.(*ecdsa.PublicKey)
	if err := requireP384(pub, ok); err != nil {
		return info, err
	}
	digest := sha512.Sum384(report[:signedLen])
	if !ecdsa.Verify(pub, digest[:], fields.SigR, fields.SigS) {
		return info, fail(CodeReportSignature, "report signature does not verify with the VCEK")
	}
	return info, nil
}

package snpverify

import (
	"encoding/binary"
	"testing"
)

// turinPin is the Turin ARK DER sha256 that broker/amd_chain.go lists.
const turinPin = "1f084161a44bb6d93778a904877d4819cafa5d05ef4193b2ded9dd9c73dd3f6a"

// turinChain verifies testdata/amd-turin (a real Turin report and its KDS
// certificates) after mut edits the report. tests/test_verify_receipts_turin.py
// runs the same cases against verify_amd() in verify_receipts.py.
func turinChain(t *testing.T, mut func([]byte), override string) (AMDInfo, error) {
	t.Helper()
	report := readFile(t, "testdata/amd-turin/attestation-report.bin")
	if mut != nil {
		mut(report)
	}
	fields, err := ParseReport(report)
	if err != nil {
		t.Fatal(err)
	}
	return VerifyAMDChain(report, fields, readFile(t, "testdata/amd-turin/ark.der"), readFile(t, "testdata/amd-turin/ask.der"),
		readFile(t, "testdata/amd-turin/vcek.der"), []string{turinPin}, override)
}

func TestTurinRealReportVerifies(t *testing.T) {
	info, err := turinChain(t, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// Reported TCB 01 03 02 05 00 00 00 61: FMC, bootloader, TEE, SNP, reserved x3, microcode.
	if info.Product != "Turin" || info.ARKSHA256 != turinPin || info.TCB.FMC == nil || *info.TCB.FMC != 1 ||
		info.TCB.Bootloader != 3 || info.TCB.TEE != 2 || info.TCB.SNP != 5 || info.TCB.Microcode != 0x61 {
		t.Fatalf("%+v fmc=%v", info, info.TCB.FMC)
	}
	if _, err := turinChain(t, nil, "Turin"); err != nil {
		t.Fatalf("matching override: %v", err)
	}
}

func TestTurinLayoutAndHWID(t *testing.T) {
	for name, c := range map[string]struct {
		mut  func([]byte)
		code string
	}{
		"fmc byte 0":               {func(r []byte) { r[0x180]++ }, CodeVCEKMismatch},
		"bootloader byte 1":        {func(r []byte) { r[0x181]++ }, CodeVCEKMismatch},
		"tee byte 2":               {func(r []byte) { r[0x182]++ }, CodeVCEKMismatch},
		"snp byte 3":               {func(r []byte) { r[0x183]++ }, CodeVCEKMismatch},
		"microcode byte 7":         {func(r []byte) { r[0x187]++ }, CodeVCEKMismatch},
		"reserved byte 6 not SNP":  {func(r []byte) { r[0x186] = 5 }, CodeReportSignature},
		"chip id first 8 bytes":    {func(r []byte) { r[0x1A0] ^= 1 }, CodeVCEKMismatch},
		"chip id nonzero tail":     {func(r []byte) { r[0x1A8] = 1 }, CodeVCEKMismatch},
		"model 0x12 has no layout": {func(r []byte) { r[0x189] = 0x12 }, CodeUnsupportedProduct},
		"family 0x1B":              {func(r []byte) { r[0x188] = 0x1B }, CodeUnsupportedProduct},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := turinChain(t, c.mut, "")
			wantCode(t, err, c.code)
		})
	}
	for _, o := range []string{"Genoa", "Milan"} {
		_, err := turinChain(t, nil, o)
		wantCode(t, err, CodeUnsupportedProduct)
	}
}

func TestTurinProductMap(t *testing.T) {
	for _, mod := range []uint8{0x00, 0x02, 0x11} {
		got, err := product(Report{Version: 3, HasCPUID: true, Family: 0x1A, Model: mod}, "")
		if err != nil || got != "Turin" {
			t.Fatalf("model %x: %q %v", mod, got, err)
		}
	}
	// Turin firmware writes version 3 on; a version 2 report takes only Milan or Genoa.
	_, err := product(Report{Version: 2}, "Turin")
	wantCode(t, err, CodeUnsupportedProduct)
	// A Genoa report cannot be read as Turin.
	_, err = product(Report{Version: 5, HasCPUID: true, Family: 0x19, Model: 0x11}, "Turin")
	wantCode(t, err, CodeUnsupportedProduct)
	// A version 2 edit of the real Turin report with --product Turin is refused too.
	_, err = turinChain(t, func(r []byte) { binary.LittleEndian.PutUint32(r[0:4], 2) }, "Turin")
	wantCode(t, err, CodeUnsupportedProduct)
}

// chi-ur-2 is the sealed UR hotel on engaging-loon (EPYC 9355P): the whole
// attestation path, binding to report signature, on the AB#938 target host.
func TestTurinChiUR2AttestationVerifies(t *testing.T) {
	const measurement = "1a0a6071cab3ca8b3c7cd47c868840ed10618734493e588b5c2e24a02275724e8cfa4ebfce383b04880e73dfa5c4b1fa"
	opts := Options{
		ARK: readFile(t, "testdata/amd-turin/ark.der"), ASK: readFile(t, "testdata/amd-turin/ask.der"),
		VCEK: readFile(t, "testdata/amd-turin/vcek-chi-ur-2.der"), ARKPins: []string{turinPin},
		ExpectedMeasurements: []string{measurement}, RequireMeasurement: true,
	}
	res, err := VerifyAttestation(loadAtt(t, "amd-turin/attestation-chi-ur-2.json"), opts)
	if err != nil {
		t.Fatal(err)
	}
	tcb := res.AMD.TCB
	if res.AMD.Product != "Turin" || tcb.FMC == nil || *tcb.FMC != 1 || tcb.Bootloader != 3 || tcb.TEE != 3 ||
		tcb.SNP != 8 || tcb.Microcode != 118 {
		t.Fatalf("%+v", res.AMD)
	}
}

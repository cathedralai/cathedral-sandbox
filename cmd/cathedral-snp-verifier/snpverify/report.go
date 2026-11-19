package snpverify

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
)

const (
	reportLen = 0x4A0 // 1184 bytes
	signedLen = 0x2A0 // the report body the chip signs
)

// Report holds the fields of an SNP attestation report the verifier uses.
type Report struct {
	Version      uint32
	Policy       uint64
	SignatureAlg uint32
	ReportData   [64]byte
	Measurement  [48]byte
	HostData     [32]byte
	ReportedTCB  [8]byte
	ChipID       [64]byte
	// Family and Model are the CPUID bytes at 0x188 and 0x189, present from report version 3.
	HasCPUID   bool
	Family     uint8
	Model      uint8
	SigR, SigS *big.Int
}

// ParseReport reads the fixed offsets of parse_report() in verify_receipts.py.
// Python accepts anything at least 0x4A0 bytes long, so this does too.
func ParseReport(r []byte) (Report, error) {
	var rep Report
	if len(r) < reportLen {
		return rep, fail(CodeBadInput, "report is %d bytes, expected 1184", len(r))
	}
	rep.Version = binary.LittleEndian.Uint32(r[0:4])
	rep.Policy = binary.LittleEndian.Uint64(r[0x08:0x10])
	rep.SignatureAlg = binary.LittleEndian.Uint32(r[0x34:0x38])
	copy(rep.ReportData[:], r[0x50:0x90])
	copy(rep.Measurement[:], r[0x90:0xC0])
	copy(rep.HostData[:], r[0xC0:0xE0])
	copy(rep.ReportedTCB[:], r[0x180:0x188])
	copy(rep.ChipID[:], r[0x1A0:0x1E0])
	if rep.Version >= 3 {
		rep.HasCPUID, rep.Family, rep.Model = true, r[0x188], r[0x189]
	}
	rep.SigR = littleEndianInt(r[0x2A0 : 0x2A0+72])
	rep.SigS = littleEndianInt(r[0x2E8 : 0x2E8+72])
	return rep, nil
}

func littleEndianInt(le []byte) *big.Int {
	be := make([]byte, len(le))
	for i, b := range le {
		be[len(le)-1-i] = b
	}
	return new(big.Int).SetBytes(be)
}

func (r Report) MeasurementHex() string { return hex.EncodeToString(r.Measurement[:]) }
func (r Report) HostDataHex() string    { return hex.EncodeToString(r.HostData[:]) }
func (r Report) ChipIDHex() string      { return hex.EncodeToString(r.ChipID[:]) }
func (r Report) TCBHex() string         { return hex.EncodeToString(r.ReportedTCB[:]) }

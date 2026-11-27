// Package bootstrap validates owner-signed launch bytes before a reference init
// may consume them. It does not equate a valid document with observed hardware.
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

const documentLimit = 16384
const signatureDomain = "cathedral-custom-guest-bootstrap/v1\x00"
const hostDomain = "cathedral-dedicated-v2\x00"

var fileNames = []string{"OVMF.amdsev.fd", "vmlinuz", "initrd", "cmdline", "root.raw"}
var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Manifest struct {
	Version         int64             `json:"version"`
	Schema          string            `json:"schema"`
	Kind            string            `json:"kind"`
	SHA256          map[string]string `json:"sha256"`
	Bytes           map[string]int64  `json:"bytes"`
	Cmdline         string            `json:"cmdline"`
	RootVerity      string            `json:"root_verity"`
	RootDataBytes   int64             `json:"root_data_bytes"`
	VCPUs           int64             `json:"vcpus"`
	CPUModel        string            `json:"cpu_model"`
	MemGiB          int64             `json:"mem_gib"`
	DataDiskGiB     int64             `json:"data_disk_gib"`
	Policy          string            `json:"policy"`
	QEMUVersion     string            `json:"qemu_version"`
	MeasureVersion  string            `json:"sev_snp_measure"`
	ReferenceInitrd string            `json:"reference_initrd"`
}

type Port struct {
	Guest  int64  `json:"guest"`
	Public int64  `json:"public"`
	Proto  string `json:"proto"`
}
type Network struct {
	GuestIP    string `json:"guest_ip"`
	HostIP     string `json:"host_ip"`
	Prefix     int64  `json:"prefix"`
	GuestMAC   string `json:"guest_mac"`
	PublicHost string `json:"public_host"`
}
type Bootstrap struct {
	Version      int64   `json:"version"`
	Schema       string  `json:"schema"`
	LaunchID     string  `json:"launch_id"`
	Hotel        string  `json:"hotel"`
	OwnerScope   string  `json:"owner_scope"`
	OwnerKey     string  `json:"owner_ed25519_b64"`
	ManifestHash string  `json:"manifest_sha256"`
	SSHPublicKey string  `json:"ssh_public_key"`
	LaunchNonce  string  `json:"launch_nonce_hex"`
	Ports        []Port  `json:"ports"`
	Network      Network `json:"network"`
}
type Launch struct {
	Manifest  Manifest
	Bootstrap Bootstrap
	HostData  [32]byte
	Owner     [32]byte
}

func ascii(s string) bool {
	for _, b := range []byte(s) {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}
func canonicalValue(value any) error {
	switch v := value.(type) {
	case string:
		if !ascii(v) {
			return errors.New("non-ASCII or control string")
		}
	case json.Number:
		n, err := strconv.ParseInt(string(v), 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != string(v) {
			return errors.New("noncanonical integer")
		}
	case map[string]any:
		for key, child := range v {
			if !ascii(key) {
				return errors.New("invalid key")
			}
			if err := canonicalValue(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := canonicalValue(child); err != nil {
				return err
			}
		}
	default:
		return errors.New("only strings, integers, arrays and objects permitted")
	}
	return nil
}

func decode(raw []byte, dst any) error {
	if len(raw) == 0 || len(raw) > documentLimit {
		return errors.New("document size invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	if _, ok := value.(map[string]any); !ok {
		return errors.New("document must be an object")
	}
	if err := canonicalValue(value); err != nil {
		return err
	}
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	canonical := bytes.TrimSuffix(encoded.Bytes(), []byte("\n"))
	if !bytes.Equal(raw, canonical) {
		return errors.New("document is not canonical JSON")
	}
	decoder = json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}

// Cmdline accepts only the measured launch allowlist, never an alternate init/root.
func Cmdline(line string, rootBytes int64) (map[string]string, error) {
	if len(line) == 0 || len(line) > 2033 || !ascii(line) || strings.TrimSpace(line) != line || strings.Contains(line, "  ") {
		return nil, errors.New("cmdline bytes invalid")
	}
	values := map[string]string{}
	for _, token := range strings.Split(line, " ") {
		key, value, separator := strings.Cut(token, "=")
		if _, ok := values[key]; ok {
			return nil, errors.New("duplicate cmdline token")
		}
		values[key] = value
		valid := false
		switch key {
		case "cathedral.owner":
			raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
			valid = err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == value
		case "cathedral.root_verity":
			valid = hexDigest.MatchString(value)
		case "cathedral.root_data_bytes":
			n, err := strconv.ParseInt(value, 10, 64)
			valid = err == nil && regexp.MustCompile(`^[1-9][0-9]{0,11}$`).MatchString(value) && n%4096 == 0 && n < rootBytes
		case "systemd.import_credentials":
			valid = value == "no"
		case "console":
			valid = value == "ttyS0" || value == "ttyS0,115200"
		case "quiet":
			valid = !separator
		case "loglevel":
			valid = regexp.MustCompile(`^[0-7]$`).MatchString(value)
		case "panic":
			n, err := strconv.ParseInt(value, 10, 64)
			valid = value == "-1" || (err == nil && n >= 0 && n <= 3600 && strconv.FormatInt(n, 10) == value)
		case "cathedral.note":
			valid = separator && value != ""
		}
		if !valid {
			return nil, fmt.Errorf("cmdline token refused: %s", key)
		}
	}
	for _, key := range []string{"cathedral.owner", "cathedral.root_verity", "cathedral.root_data_bytes", "systemd.import_credentials"} {
		if _, ok := values[key]; !ok {
			return nil, errors.New("required cmdline token missing")
		}
	}
	return values, nil
}

func validateManifest(raw []byte) (Manifest, map[string]string, error) {
	var m Manifest
	bad := func() (Manifest, map[string]string, error) { return m, nil, errors.New("manifest contract invalid") }
	if err := decode(raw, &m); err != nil {
		return m, nil, err
	}
	if m.Version != 1 || m.Schema != "cathedral.custom_guest.manifest/v1" || m.Kind != "custom_guest" {
		return bad()
	}
	if len(m.SHA256) != len(fileNames) || len(m.Bytes) != len(fileNames) {
		return bad()
	}
	for _, name := range fileNames {
		if !hexDigest.MatchString(m.SHA256[name]) || m.Bytes[name] < 1 || m.Bytes[name] > 200<<30 {
			return bad()
		}
	}
	if m.VCPUs < 1 || m.VCPUs > 56 || m.MemGiB < 4 || m.MemGiB > 640 || m.DataDiskGiB < 0 || m.DataDiskGiB > 400 {
		return bad()
	}
	if (m.CPUModel != "EPYC-Genoa-v1" && m.CPUModel != "EPYC-v4") || m.Policy != "0x30000" || m.QEMUVersion != "10.2.1" || m.MeasureVersion != "0.0.12" {
		return bad()
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`).MatchString(m.ReferenceInitrd) {
		return bad()
	}
	values, err := Cmdline(m.Cmdline, m.Bytes["root.raw"])
	if err != nil {
		return m, nil, err
	}
	if m.RootVerity != values["cathedral.root_verity"] || strconv.FormatInt(m.RootDataBytes, 10) != values["cathedral.root_data_bytes"] {
		return bad()
	}
	hash := sha256.Sum256([]byte(m.Cmdline))
	if hex.EncodeToString(hash[:]) != m.SHA256["cmdline"] || int64(len(m.Cmdline)) != m.Bytes["cmdline"] {
		return bad()
	}
	return m, values, nil
}

func validateBootstrap(raw []byte) (Bootstrap, []byte, error) {
	var b Bootstrap
	bad := func() (Bootstrap, []byte, error) { return b, nil, errors.New("bootstrap contract invalid") }
	if err := decode(raw, &b); err != nil {
		return b, nil, err
	}
	if b.Version != 1 || b.Schema != "cathedral.custom_guest.bootstrap/v1" {
		return bad()
	}
	if !regexp.MustCompile(`^cg-[0-9a-f]{12}$`).MatchString(b.LaunchID) || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`).MatchString(b.Hotel) {
		return bad()
	}
	if !regexp.MustCompile(`^(user|org):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(b.OwnerScope) {
		return bad()
	}
	owner, err := base64.StdEncoding.Strict().DecodeString(b.OwnerKey)
	if err != nil || len(owner) != 32 || base64.StdEncoding.EncodeToString(owner) != b.OwnerKey {
		return bad()
	}
	if !hexDigest.MatchString(b.ManifestHash) || !hexDigest.MatchString(b.LaunchNonce) {
		return bad()
	}
	parts := strings.Split(b.SSHPublicKey, " ")
	if len(parts) != 2 {
		return bad()
	}
	kinds := map[string]bool{"ssh-ed25519": true, "ssh-rsa": true, "ecdsa-sha2-nistp256": true, "ecdsa-sha2-nistp384": true, "ecdsa-sha2-nistp521": true, "sk-ssh-ed25519@openssh.com": true, "sk-ecdsa-sha2-nistp256@openssh.com": true}
	if !kinds[parts[0]] {
		return bad()
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(parts[1])
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(parts[0])))
	prefix = append(prefix, parts[0]...)
	if err != nil || len(blob) <= len(prefix) || !bytes.HasPrefix(blob, prefix) || base64.StdEncoding.EncodeToString(blob) != parts[1] {
		return bad()
	}
	if len(b.Ports) < 1 || len(b.Ports) > 8 {
		return bad()
	}
	seen := map[int64]bool{}
	for i, p := range b.Ports {
		if p.Proto != "tcp" || p.Public < 20000 || p.Public > 29999 || p.Guest < 1 || p.Guest > 65535 || seen[p.Public] || (p.Guest == 22) != (i == 0) {
			return bad()
		}
		seen[p.Public] = true
	}
	n := b.Network
	guest, e1 := netip.ParseAddr(n.GuestIP)
	host, e2 := netip.ParseAddr(n.HostIP)
	public, e3 := netip.ParseAddr(n.PublicHost)
	if e1 != nil || e2 != nil || e3 != nil || !guest.Is4() || !host.Is4() || !public.Is4() || n.Prefix != 30 || guest == host {
		return bad()
	}
	g, h := guest.As4(), host.As4()
	if binary.BigEndian.Uint32(g[:])>>2 != binary.BigEndian.Uint32(h[:])>>2 || (g[3]&3) != 1 && (g[3]&3) != 2 || (h[3]&3) != 1 && (h[3]&3) != 2 {
		return bad()
	}
	if !regexp.MustCompile(`^52:54:00(:[0-9a-f]{2}){3}$`).MatchString(n.GuestMAC) {
		return bad()
	}
	return b, owner, nil
}

// Validate anchors the signing key in the measured /proc/cmdline, not fw_cfg.
// It must be followed by guest-observed state and native boot-report checks.
func Validate(manifestRaw, bootstrapRaw, signature []byte, procCmdline string) (Launch, error) {
	var launch Launch
	m, tokens, err := validateManifest(manifestRaw)
	if err != nil {
		return launch, err
	}
	b, owner, err := validateBootstrap(bootstrapRaw)
	if err != nil {
		return launch, err
	}
	// /proc adds one newline; a second newline, truncation or an extra token fails.
	procCmdline = strings.TrimSuffix(procCmdline, "\n")
	if len(procCmdline) > 2047 || procCmdline != "initrd=initrd "+m.Cmdline {
		return launch, errors.New("measured cmdline differs")
	}
	if base64.RawURLEncoding.EncodeToString(owner) != tokens["cathedral.owner"] {
		return launch, errors.New("owner differs from measured cmdline")
	}
	mh, bh := sha256.Sum256(manifestRaw), sha256.Sum256(bootstrapRaw)
	if b.ManifestHash != hex.EncodeToString(mh[:]) {
		return launch, errors.New("manifest hash differs")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(owner, append([]byte(signatureDomain), bh[:]...), signature) {
		return launch, errors.New("owner signature invalid")
	}
	input := append([]byte(hostDomain), mh[:]...)
	input = append(input, owner...)
	input = append(input, bh[:]...)
	launch.Manifest = m
	launch.Bootstrap = b
	launch.HostData = sha256.Sum256(input)
	copy(launch.Owner[:], owner)
	return launch, nil
}

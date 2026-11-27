// Customer VMs on VM hosts (AB#991). Operator key only; off by default.
//
//	POST   /v1/broker/vms                  {"account", "vcpus", "mem_gib", "disk_gib", "ssh_public_key", optional "host", optional "request_id"}
//	GET    /v1/broker/vms                  every VM, merged with its host's list
//	GET    /v1/broker/vms/{id}             one VM, merged with its host's status
//	POST   /v1/broker/vms/{id}/authorize   {"paid_through": <unix seconds>, "generation": n}
//	POST   /v1/broker/vms/{id}/start       optional {"generation": n}
//	POST   /v1/broker/vms/{id}/stop        {"generation": n}
//	POST   /v1/broker/vms/{id}/reboot      optional {"generation": n}
//	POST   /v1/broker/vms/{id}/rebundle    {"generation", "expect_revision", "op_id", "to"} (stopped VM; vm_rebundle.go)
//	POST   /v1/broker/vms/{id}/rewrap      {"generation", "answer": {...}} (running VM; the answer on stdin; vm_rewrap.go)
//	DELETE /v1/broker/vms/{id}             {"confirm": "<id>"}
//	GET    /v1/broker/vms/{id}/runs/{n}    the closed run n: started_at, stopped_at (vm_history.go)
//
// The broker runs vm-ctl.sh on the VM host over SSH. The host's
// authorized_keys line for the broker key forces `vm-ctl.sh --from-broker`,
// which parses SSH_ORIGINAL_COMMAND, so the broker only sends validated
// tokens (ids, integers, fixed flags) as argv and the customer key on stdin.
// Each host command prints one JSON line.
//
// Credit (polariscomputer#2290 rules 3, 5, 6): the host enforces
// paid_through on its own. The broker keeps the generation of the current
// run. A stopped VM accepts an authorization only for generation+1, a
// running one only for its own; paid_through never goes down within one
// generation (a new run may be funded for less). start needs the
// generation+1 authorization installed on the host first, records
// starting in that generation, and is running once the host confirms; a
// start whose answer was lost may be repeated. stop names its generation,
// so a late Stop of an older run never stops a newer one, and answers the
// host's stopped_at, the settlement evidence. start, stop and reboot pass
// --generation to the host. Nothing here deletes a disk except DELETE with the id
// repeated in the body.
//
// State: state_dir/vms.json, written with writeFileDurable (drains.go). An
// operation records its intent before the host call; a host call that
// timed out or could not connect leaves that intent and answers 502, since a
// timeout is never taken as success or as failure.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	vmsFile    = "vms.json"
	vmsBodyMax = 16 << 10

	// Sane maxima for one VM and one host, whatever a host entry says.
	vmMaxVCPUs   = 64
	vmMaxMemGiB  = 512
	vmMinDiskGiB = 10
	vmMaxDiskGiB = 2048

	vmStateCreating = "creating" // create sent, host answer not confirmed
	vmStateStopped  = "stopped"
	vmStateStarting = "starting" // start sent in a new generation, host answer not confirmed
	vmStateRunning  = "running"

	// Exit codes of vm-ctl.sh the broker maps to 409.
	vmExitStale  = 3 // authorize: older generation or lower paid_through; start/stop/reboot: not the host's generation
	vmExitUnpaid = 4 // start: now >= paid_through
	// Exit 5 is also "no such VM" or "exists" (502 as before); only its host_capacity refusal is a 409.
	vmExitConflict = 5 // create/start: {"error":"host_capacity","resource":...} from the host ledger (AB#999)

	vmHostAnswerMax = 256 << 10
)

// vmHostConfig is one VM host in the config file's vm_hosts.
type vmHostConfig struct {
	ID             string `json:"id"`
	SSHTarget      string `json:"ssh_target"` // user@host
	SSHKeyFile     string `json:"ssh_key_file"`
	KnownHostsFile string `json:"known_hosts_file"`
	PublicIP       string `json:"public_ip"`
	PortMin        int    `json:"port_min"`
	PortMax        int    `json:"port_max"`
	MaxVCPUs       int    `json:"max_vcpus"`
	MaxMemGiB      int    `json:"max_mem_gib"`
	MaxDiskGiB     int    `json:"max_disk_gib"`
	// Sealed is the host's class: only a sealed host may hold a VM. SNPVMRuntime
	// says the host runs VMs as SEV-SNP guests. Both default to false, so a host
	// entry that does not state them takes no VM (AB#999, no unsealed VMs).
	Sealed       bool `json:"sealed"`
	SNPVMRuntime bool `json:"snp_vm_runtime"`
}

// takesVMs is the one gate for a new VM: sealed class and an SNP VM runtime.
func (h vmHostConfig) takesVMs() bool { return h.Sealed && h.SNPVMRuntime }

var (
	vmHostIDRE     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	vmSSHTargetRE  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}@[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	vmIDRE         = regexp.MustCompile(`^vm-[0-9a-f]{12}$`)
	vmAccountRE    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	vmKeyCommentRE = regexp.MustCompile(`^[A-Za-z0-9@._+:=-]{1,100}$`)
	vmRequestIDRE  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
)

// vmKeyTypes are the SSH public key types a customer may give.
var vmKeyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"ssh-rsa":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

func validateVMConfig(c config) error {
	if c.VMsEnabled {
		if c.StateDir == "" {
			return errors.New("config: vms_enabled needs state_dir (vms.json)")
		}
		if c.OperatorKeySHA256 == "" {
			return errors.New("config: vms_enabled needs operator_key_sha256 (the VM routes are operator only)")
		}
		if len(c.VMHosts) == 0 {
			return errors.New("config: vms_enabled needs at least one vm_hosts entry")
		}
	}
	seen := map[string]bool{}
	for i, h := range c.VMHosts {
		where := fmt.Sprintf("config: vm_hosts[%d]", i)
		if !vmHostIDRE.MatchString(h.ID) {
			return fmt.Errorf("%s: id must match %s", where, vmHostIDRE)
		}
		if seen[h.ID] {
			return fmt.Errorf("%s: duplicate id %q", where, h.ID)
		}
		seen[h.ID] = true
		if !vmSSHTargetRE.MatchString(h.SSHTarget) {
			return fmt.Errorf("%s: ssh_target must be user@host", where)
		}
		if !filepath.IsAbs(h.SSHKeyFile) || !filepath.IsAbs(h.KnownHostsFile) {
			return fmt.Errorf("%s: ssh_key_file and known_hosts_file must be absolute paths", where)
		}
		if net.ParseIP(h.PublicIP) == nil {
			return fmt.Errorf("%s: public_ip must be an IP address", where)
		}
		if h.PortMin < 1024 || h.PortMax > 65535 || h.PortMin > h.PortMax {
			return fmt.Errorf("%s: need 1024 <= port_min <= port_max <= 65535", where)
		}
		if h.MaxVCPUs < 1 || h.MaxVCPUs > 1024 || h.MaxMemGiB < 1 || h.MaxMemGiB > 16384 || h.MaxDiskGiB < vmMinDiskGiB || h.MaxDiskGiB > 1<<20 {
			return fmt.Errorf("%s: max_vcpus, max_mem_gib and max_disk_gib must be positive and sane", where)
		}
	}
	return nil
}

// vmRecord is one VM in vms.json. Times are unix seconds.
type vmRecord struct {
	ID      string `json:"id"`
	Account string `json:"account"`
	Host    string `json:"host"`
	SSHPort int    `json:"ssh_port"`
	VCPUs   int    `json:"vcpus"`
	MemGiB  int    `json:"mem_gib"`
	DiskGiB int    `json:"disk_gib"`
	// Generation is the run the VM is in (0: never started). start bumps it.
	Generation uint64 `json:"generation"`
	// AuthorizedGeneration and PaidThrough are the last authorization the
	// host accepted.
	AuthorizedGeneration uint64 `json:"authorized_generation"`
	PaidThrough          int64  `json:"paid_through"`
	DesiredState         string `json:"desired_state"`
	CreatedAt            int64  `json:"created_at"`
	StoppedAt            int64  `json:"stopped_at,omitempty"` // the host's effective stop time
	// LegacyStoppedAt: a stopped_at an older broker kept for this run that the
	// host's close record did not match. Kept for audit; the run is disputed.
	LegacyStoppedAt int64 `json:"legacy_stopped_at,omitempty"`
	// Ran: the host confirmed this generation running (start answer or GET
	// reconcile). A run that never ran may be closed at now when the host
	// never held it; one that ran keeps its host stop time only.
	Ran bool `json:"ran,omitempty"`
	// LastError: the last host call whose outcome is unknown (timeout,
	// connection). Cleared by the next confirmed call.
	LastError string `json:"last_error,omitempty"`
	// RequestID is the optional create idempotency key (Idempotency-Key header
	// or request_id body field); RequestHash is the sha256 of the create body
	// it came with. Both are saved with the record, so they survive a restart.
	RequestID   string `json:"request_id,omitempty"`
	RequestHash string `json:"request_hash,omitempty"`
}

type vmsFileDoc struct {
	Version int        `json:"version"`
	VMs     []vmRecord `json:"vms"`
}

// vmExecutor runs one vm-ctl.sh subcommand on a host. exitCode is the
// remote command's exit status; err is set when the outcome is unknown
// (could not run ssh, ssh failed (255), timeout).
type vmExecutor interface {
	Run(ctx context.Context, h vmHostConfig, stdin []byte, args ...string) (stdout []byte, exitCode int, err error)
}

type vmStore struct {
	mu    sync.Mutex
	dir   string
	hosts map[string]vmHostConfig
	order []string // host ids in config order
	recs  map[string]*vmRecord
	busy  map[string]bool // a host call in flight for this VM
	exec  vmExecutor
	now   func() time.Time

	// Run history (vm_history.go): receipts and tombstones from vm-runs.jsonl,
	// the host's closed answers from vm-history.jsonl. Guarded by mu.
	receipts map[vmRunKey]vmRunLine
	tombs    map[string]vmRunLine
	hist     map[vmRunKey]vmHistoryLine
	// Intents of vm-runs.jsonl: a close is open until its receipt exists, an
	// authorize until its answer (authRes: accepted) or a receipt.
	closeIntents map[vmRunKey]vmRunLine
	closeRefused map[vmRunKey]bool
	authIntents  map[vmRunKey]vmRunLine
	authRes      map[vmRunKey]bool
	authAccepted map[vmRunKey]bool // sticky: an authorize the host accepted stays outstanding until its receipt
	// closeRefusing: the host refused this close, but its refusal line is not
	// on disk yet. Memory only, never reloaded from the journal (refuseCloseLocked).
	closeRefusing map[vmRunKey]bool
	dirty         map[string]bool // journals with an append that may have half happened

	newID      func() string                        // newVMID; a test makes it repeat an id
	appendHook func(file string, line []byte) error // tests: fail an append before it writes
	saveHook   func() error                         // tests: fail a vms.json save before it writes
}

func (b *broker) loadVMs() error {
	if !b.cfg.VMsEnabled {
		return nil
	}
	s := &vmStore{dir: b.cfg.StateDir, hosts: map[string]vmHostConfig{}, recs: map[string]*vmRecord{}, busy: map[string]bool{}, exec: sshVMExecutor{}, now: time.Now, newID: newVMID}
	for _, h := range b.cfg.VMHosts {
		for _, f := range []string{h.SSHKeyFile, h.KnownHostsFile} {
			if _, err := os.Stat(f); err != nil {
				return fmt.Errorf("vm host %s: %w", h.ID, err)
			}
		}
		s.hosts[h.ID] = h
		s.order = append(s.order, h.ID)
	}
	raw, err := os.ReadFile(filepath.Join(s.dir, vmsFile))
	switch {
	case os.IsNotExist(err):
	case err != nil:
		return fmt.Errorf("%s: %w", vmsFile, err)
	default:
		var doc vmsFileDoc
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			return fmt.Errorf("%s: %w", vmsFile, err) // never start with VMs forgotten
		}
		for i := range doc.VMs {
			r := doc.VMs[i]
			if !vmIDRE.MatchString(r.ID) || s.recs[r.ID] != nil {
				return fmt.Errorf("%s: bad or duplicate id %q", vmsFile, r.ID)
			}
			if _, ok := s.hosts[r.Host]; !ok {
				// Kept: its disk is still on that host. Calls answer 409.
				log.Printf("vms: %s is on host %q, which is not in vm_hosts; its routes answer 409 until the host is back", r.ID, r.Host)
			}
			s.recs[r.ID] = &r
		}
	}
	if err := s.loadRuns(); err != nil {
		return err // never start with run history forgotten
	}
	b.vms = s
	log.Printf("vms: on, %d host(s), %d VM(s) from %s", len(s.hosts), len(s.recs), vmsFile)
	return nil
}

// saveLocked writes vms.json. Caller holds s.mu.
func (s *vmStore) saveLocked() error {
	if s.saveHook != nil {
		if err := s.saveHook(); err != nil {
			return err
		}
	}
	doc := vmsFileDoc{Version: 1, VMs: []vmRecord{}}
	for _, r := range s.recs {
		doc.VMs = append(doc.VMs, *r)
	}
	sort.Slice(doc.VMs, func(i, j int) bool { return doc.VMs[i].ID < doc.VMs[j].ID })
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	return writeFileDurable(filepath.Join(s.dir, vmsFile), raw)
}

// ---------------------------------------------------------------- routing

func (b *broker) handleVMs(w http.ResponseWriter, r *http.Request, rest string) {
	if b.vms == nil {
		// Same answer as any route the broker does not have.
		writeErr(w, 404, "route_not_found", "central booking does not route "+r.Method+" "+r.URL.Path)
		return
	}
	if !b.isOperator(r) {
		writeErr(w, 401, "unauthorized", "operator key required")
		return
	}
	if rest == "" {
		switch r.Method {
		case "GET":
			b.listVMs(w, r)
		case "POST":
			b.createVM(w, r)
		default:
			writeErr(w, 405, "method_not_allowed", "GET or POST")
		}
		return
	}
	id, action, _ := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
	if !vmIDRE.MatchString(id) {
		writeErr(w, 404, "vm_not_found", "no such VM")
		return
	}
	if gen, ok := strings.CutPrefix(action, "runs/"); ok && r.Method == "GET" && !strings.Contains(gen, "/") {
		b.getVMRun(w, r, id, gen)
		return
	}
	if strings.Contains(action, "/") {
		writeErr(w, 404, "vm_not_found", "no such VM")
		return
	}
	switch {
	case action == "" && r.Method == "GET":
		b.getVM(w, r, id)
	case action == "" && r.Method == "DELETE":
		b.deleteVM(w, r, id)
	case action == "authorize" && r.Method == "POST":
		b.authorizeVM(w, r, id)
	case action == "start" && r.Method == "POST":
		b.startVM(w, r, id)
	case action == "stop" && r.Method == "POST":
		b.stopVM(w, r, id)
	case action == "reboot" && r.Method == "POST":
		b.rebootVM(w, r, id)
	case action == "rebundle" && r.Method == "POST":
		b.rebundleVM(w, r, id)
	case action == "rewrap" && r.Method == "POST":
		b.rewrapVM(w, r, id)
	default:
		writeErr(w, 404, "route_not_found", "no such VM route")
	}
}

// readVMBody decodes a JSON body strictly. An empty body is {} when
// optional.
func readVMBody(w http.ResponseWriter, r *http.Request, v any, optional bool) bool {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, vmsBodyMax))
	if err != nil {
		writeErr(w, 413, "body_too_large", "body too large")
		return false
	}
	if optional && len(bytes.TrimSpace(raw)) == 0 {
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		writeErr(w, 400, "invalid_json", "body must be one JSON object with only the known fields")
		return false
	}
	return true
}

// ---------------------------------------------------------------- host calls

// vmCallErr is a host call that did not succeed.
type vmCallErr struct {
	status  int
	code    string
	msg     string
	unknown bool // the outcome on the host is unknown (timeout, connection)
}

func (e *vmCallErr) write(w http.ResponseWriter) { writeErr(w, e.status, e.code, e.msg) }

// call runs one subcommand and decodes its JSON line. Never puts stderr or
// the host's output in an error the client sees.
func (s *vmStore) call(ctx context.Context, h vmHostConfig, timeout time.Duration, stdin []byte, args ...string) (map[string]any, *vmCallErr) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, code, err := s.exec.Run(ctx, h, stdin, args...)
	if err != nil {
		log.Printf("vms: host %s: %s: %v", h.ID, args[0], err)
		return nil, &vmCallErr{502, "vm_host_unreachable", "the VM host did not answer; the outcome is unknown", true}
	}
	switch code {
	case 0:
	case vmExitStale:
		if c := vmRefusalCode(out); c != "" { // history_open, history_unknown
			return nil, &vmCallErr{409, c, "the host has no closed history for this run (" + c + ")", false}
		}
		return nil, &vmCallErr{409, "stale_authorization", "the host holds a newer generation or a later paid_through", false}
	case vmExitUnpaid:
		return nil, &vmCallErr{409, "not_paid", "the host has no paid_through after now for this VM", false}
	case vmExitConflict:
		if res, ok := vmCapacityRefusal(out); ok {
			msg := "the VM host has no room for this VM"
			if res != "" {
				msg += " (" + res + ")"
			}
			return nil, &vmCallErr{409, "no_vm_capacity", msg, false}
		}
		log.Printf("vms: host %s: %s: exit %d", h.ID, args[0], code)
		return nil, &vmCallErr{502, "vm_host_refused", fmt.Sprintf("the VM host refused %s (exit %d)", args[0], code), false}
	default:
		log.Printf("vms: host %s: %s: exit %d", h.ID, args[0], code)
		return nil, &vmCallErr{502, "vm_host_refused", fmt.Sprintf("the VM host refused %s (exit %d)", args[0], code), false}
	}
	return vmHostDoc(h, args[0], out)
}

// vmHostDoc decodes the JSON line of a host answer that exited 0.
func vmHostDoc(h vmHostConfig, verb string, out []byte) (map[string]any, *vmCallErr) {
	var doc map[string]any
	line := bytes.TrimSpace(out)
	if i := bytes.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	if err := json.Unmarshal(line, &doc); err != nil || doc == nil {
		log.Printf("vms: host %s: %s: answer is not one JSON object", h.ID, verb)
		return nil, &vmCallErr{502, "vm_host_bad_answer", "the VM host's answer is not one JSON object", true}
	}
	return doc, nil
}

// vmCapacityResources are the host ledger's resource names (room-kit/vm/vm_capacity.py
// RESOURCES). Only these reach the client, in the 409 message.
var vmCapacityResources = map[string]bool{
	"memory": true, "disk": true, "asid": true, "vcpu": true,
	"kit_unaccounted": true, "vm_unaccounted": true, "custom_guest_host": true,
}

// vmCapacityRefusal reads a host exit 5: ok when it is the ledger's
// host_capacity refusal, with its resource when that is a known name.
func vmCapacityRefusal(out []byte) (resource string, ok bool) {
	line := bytes.TrimSpace(out)
	if i := bytes.LastIndexByte(line, '\n'); i >= 0 {
		line = line[i+1:]
	}
	var doc struct {
		Error    string `json:"error"`
		Resource string `json:"resource"`
	}
	if json.Unmarshal(line, &doc) != nil || doc.Error != "host_capacity" {
		return "", false
	}
	if !vmCapacityResources[doc.Resource] {
		return "", true
	}
	return doc.Resource, true
}

// sshVMExecutor runs `ssh ... <target> <args...>`. The host's forced
// command takes SSH_ORIGINAL_COMMAND, the args joined by spaces, so every
// arg is a validated token without spaces or shell characters.
type sshVMExecutor struct{}

func (sshVMExecutor) Run(ctx context.Context, h vmHostConfig, stdin []byte, args ...string) ([]byte, int, error) {
	for _, a := range args {
		if !vmArgRE.MatchString(a) {
			return nil, 0, fmt.Errorf("refused arg %q", a)
		}
	}
	argv := []string{
		"-F", "/dev/null", // no user ssh config
		"-i", h.SSHKeyFile,
		"-o", "IdentitiesOnly=yes",
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile=" + h.KnownHostsFile,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=10",
		"-o", "ClearAllForwardings=yes",
		"-T",
		"--", h.SSHTarget,
	}
	argv = append(argv, args...)
	cmd := exec.CommandContext(ctx, "ssh", argv...)
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr limitedBuffer
	stdout.max, stderr.max = vmHostAnswerMax, 4<<10
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	// A host answer that arrived wins over a deadline that passed afterwards:
	// a known refusal (exit 3, 4) must roll back, not read as "unknown".
	if err == nil {
		return stdout.Bytes(), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) && ee.Exited() {
		if code := ee.ExitCode(); code != 255 { // 255: ssh itself failed
			return stdout.Bytes(), code, nil
		}
	}
	if ctx.Err() != nil {
		return nil, 0, ctx.Err()
	}
	if ee != nil {
		return nil, 0, fmt.Errorf("ssh exit %d: %s", ee.ExitCode(), strings.TrimSpace(stderr.String()))
	}
	return nil, 0, err
}

// vmArgRE: what may go on the remote command line.
var vmArgRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$|^--[a-z][a-z-]{0,31}$`)

// limitedBuffer keeps the first max bytes and drops the rest.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.Len(); room > 0 {
		if len(p) > room {
			l.Buffer.Write(p[:room])
		} else {
			l.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// ---------------------------------------------------------------- validation

// normalizeSSHKey checks a customer public key: one line, an allowed type,
// a blob whose own type matches, an optional plain comment. It answers the
// key rebuilt from its parts, so nothing else reaches the host.
func normalizeSSHKey(k string) (string, error) {
	k = strings.TrimSpace(k)
	if k == "" || len(k) > 8192 {
		return "", errors.New("ssh_public_key must be one key line up to 8 KiB")
	}
	for _, c := range k {
		if c < 0x20 || c > 0x7e {
			return "", errors.New("ssh_public_key must be one printable ASCII line")
		}
	}
	parts := strings.Fields(k)
	if len(parts) < 2 || len(parts) > 3 {
		return "", errors.New("ssh_public_key must be \"<type> <base64> [comment]\"")
	}
	typ, b64 := parts[0], parts[1]
	if !vmKeyTypes[typ] {
		return "", errors.New("ssh_public_key type must be ssh-ed25519, ecdsa-sha2-*, sk-*, or ssh-rsa")
	}
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(blob) < 4 {
		return "", errors.New("ssh_public_key blob is not base64")
	}
	n := binary.BigEndian.Uint32(blob[:4])
	if uint64(n) > uint64(len(blob)-4) || string(blob[4:4+n]) != typ {
		return "", errors.New("ssh_public_key blob does not match its type")
	}
	if typ == "ssh-ed25519" && len(blob) != 4+11+4+32 {
		return "", errors.New("ssh_public_key is not a valid ed25519 key")
	}
	if typ == "ssh-rsa" && len(blob) < 256 { // well under 2048 bits
		return "", errors.New("ssh_public_key RSA key is too short")
	}
	out := typ + " " + b64
	if len(parts) == 3 {
		if !vmKeyCommentRE.MatchString(parts[2]) {
			return "", errors.New("ssh_public_key comment may hold only letters, digits and @._+:=-")
		}
		out += " " + parts[2]
	}
	return out, nil
}

func newVMID() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return "vm-" + hex.EncodeToString(b[:])
}

// ---------------------------------------------------------------- views

func (s *vmStore) view(r *vmRecord) map[string]any {
	v := map[string]any{
		"id": r.ID, "account": r.Account, "host": r.Host, "ssh_port": r.SSHPort,
		"vcpus": r.VCPUs, "mem_gib": r.MemGiB, "disk_gib": r.DiskGiB,
		"generation": r.Generation, "authorized_generation": r.AuthorizedGeneration,
		"paid_through": r.PaidThrough, "desired_state": r.DesiredState,
		"created_at": r.CreatedAt, "stopped_at": r.StoppedAt,
	}
	if h, ok := s.hosts[r.Host]; ok {
		v["public_ip"] = h.PublicIP
	}
	if r.LastError != "" {
		v["last_error"] = r.LastError
	}
	// The create's Idempotency-Key, so the API can tell exactly which of its
	// creates a listed VM answers (polariscomputer #2345). It is the API's own
	// derived id, never a customer value.
	if r.RequestID != "" {
		v["request_id"] = r.RequestID
	}
	return v
}

func (b *broker) listVMs(w http.ResponseWriter, r *http.Request) {
	s := b.vms
	s.mu.Lock()
	out := []map[string]any{}
	used := map[string]bool{}
	for _, rec := range s.recs {
		out = append(out, s.view(rec))
		used[rec.Host] = true
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i]["id"].(string) < out[j]["id"].(string) })

	// One list per host with VMs, in parallel.
	type hostList struct {
		byName map[string]any
		err    string
	}
	lists := map[string]*hostList{}
	var wg sync.WaitGroup
	var lmu sync.Mutex
	for id := range used {
		h, ok := s.hosts[id]
		if !ok {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			hl := &hostList{byName: map[string]any{}}
			doc, cerr := s.call(r.Context(), h, 15*time.Second, nil, "list")
			if cerr != nil {
				hl.err = cerr.code
			} else if vms, ok := doc["vms"].([]any); ok {
				for _, x := range vms {
					if m, ok := x.(map[string]any); ok {
						if name, ok := m["name"].(string); ok {
							hl.byName[name] = m
						}
					}
				}
			}
			lmu.Lock()
			lists[h.ID] = hl
			lmu.Unlock()
		}()
	}
	wg.Wait()
	for _, v := range out {
		hl := lists[v["host"].(string)]
		switch {
		case hl == nil:
			v["host_status_error"] = "vm_host_not_configured"
		case hl.err != "":
			v["host_status_error"] = hl.err
		case hl.byName[v["id"].(string)] != nil:
			v["host_status"] = hl.byName[v["id"].(string)]
		default:
			v["host_status_error"] = "not_on_host"
		}
	}
	writeJSON(w, 200, map[string]any{"vms": out})
}

func (b *broker) getVM(w http.ResponseWriter, r *http.Request, id string) {
	s := b.vms
	s.reconcileRuns(r.Context(), id) // receipts and history still pending (B1, B2)
	s.mu.Lock()
	rec := s.recs[id]
	if rec == nil {
		s.mu.Unlock()
		writeErr(w, 404, "vm_not_found", "no such VM")
		return
	}
	v := s.view(rec)
	h, ok := s.hosts[rec.Host]
	s.mu.Unlock()
	if !ok {
		v["host_status_error"] = "vm_host_not_configured"
	} else if doc, cerr := s.call(r.Context(), h, 15*time.Second, nil, "status", id); cerr != nil {
		v["host_status_error"] = cerr.code
	} else {
		v["host_status"] = doc
		if s.reconcileStarting(id, doc) {
			s.mu.Lock()
			v2 := s.view(rec)
			s.mu.Unlock()
			v2["host_status"] = doc
			v = v2
		}
	}
	writeJSON(w, 200, v)
}

// reconcileStarting moves a VM whose start answer was lost from starting
// to running once the host's status says it runs in that generation.
//
// It moves it to stopped when the host is stopped (or only created) and
// its generation is another one or closed: that run never runs again. The
// generation stays consumed and stopped_at stays unset, so a Stop of it
// still asks the host for a receipt.
func (s *vmStore) reconcileStarting(id string, doc map[string]any) bool {
	gen, ok := doc["generation"].(float64)
	state, _ := doc["state"].(string)
	closed, _ := doc["closed"].(bool)
	if !ok {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := s.recs[id]
	if rec == nil || s.busy[id] || rec.DesiredState != vmStateStarting {
		return false
	}
	same := float64(rec.Generation) == gen
	switch {
	case state == vmStateRunning && same:
		rec.DesiredState, rec.LastError, rec.Ran = vmStateRunning, "", true
	case (state == vmStateStopped || state == "created") && (!same || closed):
		rec.DesiredState = vmStateStopped
	default:
		return false
	}
	if err := s.saveLocked(); err != nil {
		log.Printf("vms: %s not saved after reconciling %s to %s: %v", vmsFile, id, rec.DesiredState, err)
	}
	return true
}

// ---------------------------------------------------------------- create

func (b *broker) createVM(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account      string `json:"account"`
		VCPUs        int    `json:"vcpus"`
		MemGiB       int    `json:"mem_gib"`
		DiskGiB      int    `json:"disk_gib"`
		SSHPublicKey string `json:"ssh_public_key"`
		Host         string `json:"host"`
		RequestID    string `json:"request_id"`
	}
	if !readVMBody(w, r, &req, false) {
		return
	}
	// Optional idempotency key: the Idempotency-Key header (as the compat
	// create takes it, compat.go compatIdemLimit) and/or request_id. Both must
	// agree when both are sent.
	reqID := req.RequestID
	if h := r.Header.Get("Idempotency-Key"); h != "" {
		if reqID != "" && reqID != h {
			writeErr(w, 400, "invalid_request_id", "Idempotency-Key and request_id differ")
			return
		}
		reqID = h
	}
	if reqID != "" && !vmRequestIDRE.MatchString(reqID) {
		writeErr(w, 400, "invalid_request_id", "request id must be 1 to 128 of letters, digits and _.:-")
		return
	}
	if !vmAccountRE.MatchString(req.Account) {
		writeErr(w, 400, "invalid_account", "account must be 1 to 128 of letters, digits and _.:-")
		return
	}
	if req.VCPUs < 1 || req.VCPUs > vmMaxVCPUs || req.MemGiB < 1 || req.MemGiB > vmMaxMemGiB || req.DiskGiB < vmMinDiskGiB || req.DiskGiB > vmMaxDiskGiB {
		writeErr(w, 400, "invalid_size", fmt.Sprintf("need vcpus 1-%d, mem_gib 1-%d, disk_gib %d-%d", vmMaxVCPUs, vmMaxMemGiB, vmMinDiskGiB, vmMaxDiskGiB))
		return
	}
	key, err := normalizeSSHKey(req.SSHPublicKey)
	if err != nil {
		writeErr(w, 400, "invalid_ssh_public_key", err.Error())
		return
	}
	s := b.vms
	if req.Host != "" {
		if _, ok := s.hosts[req.Host]; !ok {
			writeErr(w, 400, "unknown_vm_host", "no such VM host")
			return
		}
	}

	// No unsealed VMs, ever (AB#999): refuse unless some candidate host is
	// sealed and has the SNP VM runtime. placeLocked skips the others.
	eligible := false
	for _, id := range s.order {
		if (req.Host == "" || id == req.Host) && s.hosts[id].takesVMs() {
			eligible = true
		}
	}
	if !eligible {
		writeErr(w, 409, "vm_runtime_not_sealed", "VM create refused: the host is not sealed or has no SEV-SNP VM runtime (AB#999)")
		return
	}

	reqHash := ""
	if reqID != "" {
		sum := sha256.Sum256([]byte(strings.Join([]string{req.Account, strconv.Itoa(req.VCPUs), strconv.Itoa(req.MemGiB),
			strconv.Itoa(req.DiskGiB), key, req.Host}, "\x00")))
		reqHash = hex.EncodeToString(sum[:])
	}

	s.mu.Lock()
	if reqID != "" {
		for _, old := range s.recs {
			if old.RequestID != reqID {
				continue
			}
			defer s.mu.Unlock()
			if old.RequestHash != reqHash {
				writeErr(w, 409, "idempotency_key_reused", "this request id was used for a different create")
				return
			}
			// busy is shared with start, stop, authorize, reboot and delete, so
			// only a VM still in creating means this create is in flight; any
			// other busy VM was already created and the replay returns it.
			if old.DesiredState == vmStateCreating && s.busy[old.ID] {
				writeErr(w, 409, "vm_busy", "the create for this request id is still in flight")
				return
			}
			writeJSON(w, 200, s.view(old)) // a replay: the same VM, no second host call, no second hold
			return
		}
	}
	h, port, ok := s.placeLocked(req.Host, req.VCPUs, req.MemGiB, req.DiskGiB)
	if !ok {
		s.mu.Unlock()
		writeErr(w, 409, "no_vm_capacity", "no VM host has the capacity and a free SSH port")
		return
	}
	id := s.newID()
	for s.recs[id] != nil || s.idUsedLocked(id) { // never an id a receipt or tombstone names (B4)
		id = s.newID()
	}
	rec := &vmRecord{ID: id, Account: req.Account, Host: h.ID, SSHPort: port, VCPUs: req.VCPUs, MemGiB: req.MemGiB, DiskGiB: req.DiskGiB,
		DesiredState: vmStateCreating, CreatedAt: s.now().Unix(), RequestID: reqID, RequestHash: reqHash}
	s.recs[id] = rec // holds the port and the capacity while the host works
	if err := s.saveLocked(); err != nil {
		delete(s.recs, id)
		s.mu.Unlock()
		log.Printf("vms: %s not saved: %v", vmsFile, err)
		writeErr(w, 500, "state_not_saved", "the VM could not be recorded; nothing was sent to the host")
		return
	}
	s.busy[id] = true
	s.mu.Unlock()

	doc, cerr := s.call(r.Context(), h, 3*time.Minute, []byte(key+"\n"), "create", id,
		"--vcpus", strconv.Itoa(req.VCPUs), "--mem-gib", strconv.Itoa(req.MemGiB),
		"--disk-gib", strconv.Itoa(req.DiskGiB), "--ssh-port", strconv.Itoa(port))

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, id)
	switch {
	case cerr != nil && !cerr.unknown:
		delete(s.recs, id) // the host refused: nothing there
		if err := s.saveLocked(); err != nil {
			log.Printf("vms: %s not saved after a refused create of %s: %v", vmsFile, id, err)
		}
		cerr.write(w)
		return
	case cerr != nil:
		// Kept as creating, so the port stays held; DELETE clears it.
		rec.LastError = "create: " + cerr.code
		_ = s.saveLocked()
		cerr.write(w)
		return
	}
	rec.DesiredState, rec.LastError = vmStateStopped, ""
	if err := s.saveLocked(); err != nil {
		log.Printf("vms: %s not saved after create of %s: %v", vmsFile, id, err)
		writeErr(w, 500, "state_not_saved", "the host created the VM but the broker could not record it")
		return
	}
	// The host's answer as GET gives it: a sealed VM's launch values and identity_document,
	// which the customer needs to recompute the measurement (spec r2 6.3).
	v := s.view(rec)
	v["host_status"] = doc
	writeJSON(w, 201, v)
}

// placeLocked picks a host with room and its lowest free SSH port. Every
// VM counts against its host, stopped or not: its disk is there and it
// may start again. Caller holds s.mu.
func (s *vmStore) placeLocked(want string, vcpus, mem, disk int) (vmHostConfig, int, bool) {
	for _, id := range s.order {
		if want != "" && id != want {
			continue
		}
		h := s.hosts[id]
		if !h.takesVMs() {
			continue
		}
		usedC, usedM, usedD := 0, 0, 0
		ports := map[int]bool{}
		for _, r := range s.recs {
			if r.Host == id {
				usedC, usedM, usedD = usedC+r.VCPUs, usedM+r.MemGiB, usedD+r.DiskGiB
				ports[r.SSHPort] = true
			}
		}
		if usedC+vcpus > h.MaxVCPUs || usedM+mem > h.MaxMemGiB || usedD+disk > h.MaxDiskGiB {
			continue
		}
		for p := h.PortMin; p <= h.PortMax; p++ {
			if !ports[p] {
				return h, p, true
			}
		}
	}
	return vmHostConfig{}, 0, false
}

// ---------------------------------------------------------------- operations

// begin takes the VM for one host call. On false it has answered.
func (s *vmStore) begin(w http.ResponseWriter, id string) (*vmRecord, vmHostConfig, bool) {
	rec := s.recs[id]
	if rec == nil {
		writeErr(w, 404, "vm_not_found", "no such VM")
		return nil, vmHostConfig{}, false
	}
	h, ok := s.hosts[rec.Host]
	if !ok {
		writeErr(w, 409, "vm_host_not_configured", "the VM's host is not in vm_hosts")
		return nil, vmHostConfig{}, false
	}
	if s.busy[id] {
		writeErr(w, 409, "vm_busy", "another operation on this VM is in flight")
		return nil, vmHostConfig{}, false
	}
	s.busy[id] = true
	return rec, h, true
}

func (b *broker) authorizeVM(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		PaidThrough *int64  `json:"paid_through"`
		Generation  *uint64 `json:"generation"`
	}
	if !readVMBody(w, r, &req, false) {
		return
	}
	s := b.vms
	now := s.now().Unix()
	if req.PaidThrough == nil || req.Generation == nil || *req.Generation < 1 {
		writeErr(w, 400, "invalid_authorization", "need paid_through (unix seconds) and generation >= 1")
		return
	}
	pt, gen := *req.PaidThrough, *req.Generation
	if pt <= now || pt > now+366*24*3600 {
		writeErr(w, 400, "invalid_paid_through", "paid_through must be unix seconds after now and within a year")
		return
	}
	s.mu.Lock()
	rec, h, ok := s.begin(w, id)
	if !ok {
		s.mu.Unlock()
		return
	}
	var refuse string
	code := "stale_authorization"
	switch {
	case rec.DesiredState == vmStateCreating:
		refuse = "the VM is not created yet"
	case s.receiptMissingLocked(rec) || s.openIntentLocked(id):
		code, refuse = "receipt_missing", "a close or authorize of this VM has no receipt yet; repeat the stop, or wait for the replay"
	case (rec.DesiredState == vmStateRunning || rec.DesiredState == vmStateStarting) && gen != rec.Generation:
		refuse = fmt.Sprintf("a running VM takes only its own generation %d", rec.Generation)
	case rec.DesiredState == vmStateStopped && rec.Generation > 0 && rec.StoppedAt == 0:
		// A stop whose answer was lost: the run may still be closing at the host.
		// Its receipt comes first, so the next run never makes it look stale.
		refuse = fmt.Sprintf("the stop of generation %d has no receipt yet; repeat that stop first", rec.Generation)
	case rec.DesiredState == vmStateStopped && gen != rec.Generation+1:
		// Stop ended the run's authorizations (#2290 rule 5); a start needs the next one.
		refuse = fmt.Sprintf("a stopped VM takes only generation %d", rec.Generation+1)
	case gen < rec.AuthorizedGeneration:
		refuse = "generation never goes down"
	case gen == rec.AuthorizedGeneration && pt < rec.PaidThrough:
		// Within one run only: a new run may be funded for a shorter window
		// than the settled run before it.
		refuse = "paid_through never goes down within a generation"
	}
	if refuse == "" {
		code, refuse = s.closedInJournalLocked(id, gen)
	}
	if refuse != "" {
		delete(s.busy, id)
		s.mu.Unlock()
		writeErr(w, 409, code, refuse)
		return
	}
	// Intent first for a generation the broker has not recorded yet: a lost
	// reply must never leave an open generation on the host that no line names.
	// A refresh of the tracked generation has no intent (cancelling it would
	// close a run that is live).
	fresh := false
	if gen > rec.AuthorizedGeneration {
		var err error
		if fresh, err = s.appendAuthIntentLocked(id, rec.Account, rec.Host, gen); err != nil {
			delete(s.busy, id)
			s.mu.Unlock()
			writeErr(w, 500, "state_not_saved", "the authorization could not be recorded; nothing was sent to the host")
			return
		}
	}
	s.mu.Unlock()

	_, cerr := s.call(r.Context(), h, time.Minute, nil, "authorize", id, strconv.FormatInt(pt, 10), strconv.FormatUint(gen, 10))

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, id)
	if cerr != nil {
		if cerr.unknown {
			rec.LastError = "authorize: " + cerr.code // the intent stays open: replay fences it
			_ = s.saveLocked()
		} else if err := s.resolveAuthLocked(id, gen, false, fresh); err != nil {
			log.Printf("vms: refused authorize of %s generation %d not resolved: %v", id, gen, err)
		}
		cerr.write(w)
		return
	}
	if err := s.resolveAuthLocked(id, gen, true, fresh); err != nil {
		writeErr(w, 500, "state_not_saved", "the host took the authorization but the broker could not record it; repeat it")
		return
	}
	rec.AuthorizedGeneration, rec.PaidThrough, rec.LastError = gen, pt, ""
	if err := s.saveLocked(); err != nil {
		log.Printf("vms: %s not saved after authorize of %s: %v", vmsFile, id, err)
		writeErr(w, 500, "state_not_saved", "the host took the authorization but the broker could not record it; repeat it")
		return
	}
	writeJSON(w, 200, s.view(rec))
}

// startVM starts a stopped VM in the next generation, or repeats a start
// whose host answer was lost (state starting, same generation).
func (b *broker) startVM(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Generation *uint64 `json:"generation"`
	}
	if !readVMBody(w, r, &req, true) {
		return
	}
	s := b.vms
	s.mu.Lock()
	rec, h, ok := s.begin(w, id)
	if !ok {
		s.mu.Unlock()
		return
	}
	gen := rec.Generation + 1
	if rec.DesiredState == vmStateStarting {
		gen = rec.Generation // a retry: host start is idempotent for this generation
	}
	var code, refuse string
	switch {
	case rec.DesiredState != vmStateStopped && rec.DesiredState != vmStateStarting:
		code, refuse = "vm_not_stopped", "only a stopped VM starts (state "+rec.DesiredState+")"
	case req.Generation != nil && *req.Generation != gen:
		code, refuse = "stale_generation", fmt.Sprintf("the generation to start is %d", gen)
	case s.receiptMissingLocked(rec) || s.openIntentLocked(id):
		code, refuse = "receipt_missing", "a close or authorize of this VM has no receipt yet; repeat the stop, or wait for the replay"
	case rec.AuthorizedGeneration != gen || rec.PaidThrough <= s.now().Unix():
		code, refuse = "not_authorized", fmt.Sprintf("authorize generation %d with a paid_through after now first", gen)
	}
	if refuse == "" {
		// Under the same lock as the start intent below: a generation the
		// journal closed never starts, whatever vms.json still says.
		code, refuse = s.closedInJournalLocked(id, gen)
	}
	if refuse != "" {
		delete(s.busy, id)
		s.mu.Unlock()
		writeErr(w, 409, code, refuse)
		return
	}
	// Intent first: a start whose answer is lost stays starting in the new
	// generation, and a repeated start finishes it.
	prev := *rec
	retry := rec.DesiredState == vmStateStarting
	if !retry {
		prev.LastError = ""
		rec.Generation, rec.DesiredState, rec.StoppedAt, rec.Ran = gen, vmStateStarting, 0, false
		if err := s.saveLocked(); err != nil {
			*rec = prev
			delete(s.busy, id)
			s.mu.Unlock()
			log.Printf("vms: %s not saved before start of %s: %v", vmsFile, id, err)
			writeErr(w, 500, "state_not_saved", "the start could not be recorded; nothing was sent to the host")
			return
		}
	}
	s.mu.Unlock()

	_, cerr := s.call(r.Context(), h, 2*time.Minute, nil, "start", id, "--generation", strconv.FormatUint(gen, 10))

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, id)
	if cerr != nil {
		switch {
		case !retry && !cerr.unknown:
			*rec = prev // the host refused the first attempt: stopped, the previous run's stopped_at and the authorization kept
		default:
			// Unknown outcome, or a refused retry: the first attempt may
			// have run, so the generation stays. GET reconciles from host
			// status, or a Stop of this generation settles it.
			rec.LastError = "start: " + cerr.code
		}
		if err := s.saveLocked(); err != nil {
			log.Printf("vms: %s not saved after a failed start of %s: %v", vmsFile, id, err)
		}
		if cerr.code == "stale_authorization" { // host exit 3: not its authorized generation
			cerr = &vmCallErr{409, "stale_generation", "the host's current generation is not this one", false}
		}
		cerr.write(w)
		return
	}
	rec.DesiredState, rec.LastError, rec.Ran = vmStateRunning, "", true
	if err := s.saveLocked(); err != nil {
		log.Printf("vms: %s not saved after start of %s: %v", vmsFile, id, err)
	}
	writeJSON(w, 200, s.view(rec))
}

// stopVM stops the run of the given generation. On a stopped VM, a Stop of
// generation+1 cancels that run before it started (cancelVMRun). A Stop for
// any other generation (a late billing outbox delivery) is refused without
// a host call; a repeated Stop of a stopped run answers its stored
// stopped_at.
func (b *broker) stopVM(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Generation *uint64 `json:"generation"`
	}
	if !readVMBody(w, r, &req, true) {
		return
	}
	if req.Generation == nil || *req.Generation < 1 {
		writeErr(w, 400, "generation_required", "the body must be {\"generation\": n}, the run to stop")
		return
	}
	gen := *req.Generation
	s := b.vms
	s.mu.Lock()
	rec, h, ok := s.begin(w, id)
	if !ok {
		s.mu.Unlock()
		return
	}
	if rec.DesiredState == vmStateStopped && gen == rec.Generation+1 {
		s.mu.Unlock()
		b.cancelVMRun(w, r, rec, h, gen)
		return
	}
	var code, refuse string
	switch {
	case rec.DesiredState == vmStateCreating:
		code, refuse = "vm_not_created", "the VM is not created yet"
	case gen != rec.Generation:
		code, refuse = "stale_generation", fmt.Sprintf("the current generation is %d", rec.Generation)
	}
	if refuse != "" {
		delete(s.busy, id)
		s.mu.Unlock()
		writeErr(w, 409, code, refuse)
		return
	}
	if rec.DesiredState == vmStateStopped && rec.StoppedAt != 0 {
		// The stored receipt, answered only once it is on disk: the save
		// after the host's stop may have failed.
		// A receipt a failed append left on disk is acknowledged only once the
		// journal is settled (fsynced) again.
		if err := s.settleLocked(vmRunsFile); err != nil {
			delete(s.busy, id)
			s.mu.Unlock()
			log.Printf("vms: %s not settled for the stop of %s: %v", vmRunsFile, id, err)
			writeErr(w, 500, "state_not_saved", "the receipt could not be made durable; repeat the stop")
			return
		}
		if _, have := s.receipts[vmRunKey{id, gen}]; !have {
			// Closed on record with no B1 receipt (a crash, or an older
			// broker): the host's close record makes it, if it agrees.
			stored := rec.StoppedAt
			if err := s.appendCloseIntentLocked(id, rec.Account, rec.Host, gen); err != nil {
				delete(s.busy, id)
				s.mu.Unlock()
				writeErr(w, 500, "state_not_saved", "the close could not be recorded; nothing was sent to the host")
				return
			}
			s.mu.Unlock()
			at, cerr := s.hostCancel(r.Context(), h, id, gen)
			s.mu.Lock()
			if cerr != nil {
				delete(s.busy, id)
				s.mu.Unlock()
				cerr.write(w)
				return
			}
			if at != stored {
				// A legacy time: the host's close is the receipt, marked disputed;
				// the old time stays in the record for audit (B5 answers 409).
				log.Printf("vms: %s generation %d: host close at %d, vms.json says %d; receipt written as disputed", id, gen, at, stored)
				s.finishClose(r.Context(), w, rec, gen, at, vmReceiptCancel, true, func(r *vmRecord) { r.LegacyStoppedAt, r.StoppedAt = stored, at }, false)
				return
			}
			s.finishClose(r.Context(), w, rec, gen, at, vmReceiptCancel, false, func(*vmRecord) {}, false)
			return
		}
		err := s.saveLocked()
		delete(s.busy, id)
		v := s.view(rec)
		s.mu.Unlock()
		if err != nil {
			log.Printf("vms: %s not saved for the stop receipt of %s: %v", vmsFile, id, err)
			writeErr(w, 500, "state_not_saved", "the host stopped the VM but the broker could not record stopped_at; repeat the stop")
			return
		}
		writeJSON(w, 200, v)
		return
	}
	// Close intent first (vm-runs.jsonl), then the stop intent in vms.json.
	held := s.closeRefusing[vmRunKey{id, gen}]
	if err := s.appendCloseIntentLocked(id, rec.Account, rec.Host, gen); err != nil {
		delete(s.busy, id)
		s.mu.Unlock()
		writeErr(w, 500, "state_not_saved", "the stop could not be recorded; nothing was sent to the host")
		return
	}
	// Intent first: once asked to stop, the run takes no more authorizations.
	prev := rec.DesiredState
	rec.DesiredState = vmStateStopped
	if err := s.saveLocked(); err != nil {
		rec.DesiredState = prev
		if held {
			s.closeRefusing[vmRunKey{id, gen}] = true // nothing was sent: the host's refusal still stands
		}
		delete(s.busy, id)
		s.mu.Unlock()
		log.Printf("vms: %s not saved before stop of %s: %v", vmsFile, id, err)
		writeErr(w, 500, "state_not_saved", "the stop could not be recorded; nothing was sent to the host")
		return
	}
	s.mu.Unlock()

	doc, cerr := s.call(r.Context(), h, 2*time.Minute, nil, "stop", id, "--generation", strconv.FormatUint(gen, 10))
	kind := vmReceiptStop
	if cerr != nil && cerr.code == "stale_authorization" {
		// A lost start (or one GET settled to stopped) that was never confirmed
		// running, and whose generation the host does not hold. The host's own
		// close record settles it (B0), never broker time. A run that ran keeps
		// the refusal: its real stop is the host's stop answer.
		s.mu.Lock()
		neverRan := (prev == vmStateStopped || prev == vmStateStarting) && !rec.Ran
		s.mu.Unlock()
		if neverRan {
			var at int64
			if at, cerr = s.hostCancel(r.Context(), h, id, gen); cerr == nil {
				doc, kind = map[string]any{"stopped_at": float64(at)}, vmReceiptCancel
			}
		}
	}

	s.mu.Lock()
	if cerr != nil {
		defer s.mu.Unlock()
		delete(s.busy, id)
		if cerr.unknown {
			rec.LastError = "stop: " + cerr.code // stays stopped in intent; repeat the stop
		} else {
			rec.DesiredState = prev // the host refused this generation's stop
			if err := s.refuseCloseLocked(id, gen); err != nil {
				// Held in memory, never cancelled by this broker; a repeated
				// stop gets the same refusal and records it.
				_ = s.saveLocked()
				writeErr(w, 500, "state_not_saved", "the host refused this stop but the broker could not record the refusal; repeat the stop")
				return
			}
		}
		_ = s.saveLocked()
		if cerr.code == "stale_authorization" {
			cerr = &vmCallErr{409, "stale_generation", "the host's current generation is not this one", false}
		}
		cerr.write(w)
		return
	}
	at, ok := vmUnixField(doc["stopped_at"])
	if !ok {
		defer s.mu.Unlock()
		delete(s.busy, id)
		rec.LastError = "stop: no stopped_at"
		_ = s.saveLocked()
		writeErr(w, 502, "vm_host_bad_answer", "the host's stop answer has no stopped_at")
		return
	}
	// B1: the receipt is durable before vms.json shows the stop and before the 200.
	s.finishClose(r.Context(), w, rec, gen, at, kind, false, func(r *vmRecord) { r.StoppedAt, r.LastError = at, "" }, false)
}

// cancelVMRun closes the next run of a stopped VM before it started (its
// authorization delivered, or its reply lost). The generation is consumed:
// a late start or authorize of it is refused since the next is gen+1. The
// host closes it and answers stopped_at; when the host refuses the stop
// (exit 3, it never got that authorization) the host's cancel closes the
// generation and its close record is used (B0), never broker time. A host
// that does not answer changes nothing and the cancel may be repeated.
// Caller holds the VM busy (begin), not s.mu.
func (b *broker) cancelVMRun(w http.ResponseWriter, r *http.Request, rec *vmRecord, h vmHostConfig, gen uint64) {
	s := b.vms
	id := rec.ID
	s.mu.Lock()
	if err := s.appendCloseIntentLocked(id, rec.Account, rec.Host, gen); err != nil {
		delete(s.busy, id)
		s.mu.Unlock()
		writeErr(w, 500, "state_not_saved", "the cancel could not be recorded; nothing was sent to the host")
		return
	}
	s.mu.Unlock()
	doc, cerr := s.call(r.Context(), h, 2*time.Minute, nil, "stop", id, "--generation", strconv.FormatUint(gen, 10))
	var at int64
	switch {
	case cerr != nil && cerr.code == "stale_authorization":
		at, cerr = s.hostCancel(r.Context(), h, id, gen)
	case cerr == nil:
		var ok bool
		if at, ok = vmUnixField(doc["stopped_at"]); !ok {
			cerr = &vmCallErr{502, "vm_host_bad_answer", "the host's stop answer has no stopped_at", false}
		}
	}
	s.mu.Lock()
	if cerr != nil {
		delete(s.busy, id)
		s.mu.Unlock()
		cerr.write(w)
		return
	}
	s.finishClose(r.Context(), w, rec, gen, at, vmReceiptCancel, false, func(r *vmRecord) {
		r.Generation, r.StoppedAt, r.LastError = gen, at, ""
	}, true)
}

// vmUnixField reads a time as unix seconds (a number) or RFC 3339.
func vmUnixField(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		if t > 0 && t < 1e11 {
			return int64(t), true
		}
	case string:
		if n, err := strconv.ParseInt(t, 10, 64); err == nil && n > 0 && n < 1e11 {
			return n, true
		}
		if ts, err := time.Parse(time.RFC3339, t); err == nil {
			return ts.Unix(), true
		}
	}
	return 0, false
}

func (b *broker) rebootVM(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Generation *uint64 `json:"generation"`
	}
	if !readVMBody(w, r, &req, true) {
		return
	}
	s := b.vms
	s.mu.Lock()
	rec, h, ok := s.begin(w, id)
	if !ok {
		s.mu.Unlock()
		return
	}
	var code, refuse string
	switch {
	case rec.DesiredState != vmStateRunning:
		code, refuse = "vm_not_running", "only a running VM reboots"
	case req.Generation != nil && *req.Generation != rec.Generation:
		code, refuse = "stale_generation", fmt.Sprintf("the current generation is %d", rec.Generation)
	}
	if refuse != "" {
		delete(s.busy, id)
		s.mu.Unlock()
		writeErr(w, 409, code, refuse)
		return
	}
	gen := rec.Generation
	s.mu.Unlock()

	_, cerr := s.call(r.Context(), h, 2*time.Minute, nil, "reboot", id, "--generation", strconv.FormatUint(gen, 10))

	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, id)
	if cerr != nil {
		if cerr.code == "stale_authorization" {
			cerr = &vmCallErr{409, "stale_generation", "the host's current generation is not this one", false}
		}
		cerr.write(w)
		return
	}
	writeJSON(w, 200, s.view(rec))
}

func (b *broker) deleteVM(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Confirm string `json:"confirm"`
	}
	if !readVMBody(w, r, &req, true) {
		return
	}
	if req.Confirm != id {
		writeErr(w, 400, "confirm_required", "the body must be {\"confirm\": \"<id>\"}: delete removes the disk")
		return
	}
	s := b.vms
	s.mu.Lock()
	_, h, ok := s.begin(w, id)
	if !ok {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	cerr := s.deleteSteps(r.Context(), id, h)
	s.mu.Lock()
	delete(s.busy, id)
	s.mu.Unlock()
	if cerr != nil {
		cerr.write(w)
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "deleted": true})
}

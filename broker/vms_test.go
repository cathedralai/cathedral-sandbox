package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeVMHost records host calls and answers them like vm-ctl.sh.
type fakeVMHost struct {
	mu     sync.Mutex
	calls  [][]string
	stdin  []string
	answer func(args []string) ([]byte, int, error)
}

func (f *fakeVMHost) Run(_ context.Context, h vmHostConfig, stdin []byte, args ...string) ([]byte, int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{h.ID}, args...))
	f.stdin = append(f.stdin, string(stdin))
	ans := f.answer
	f.mu.Unlock()
	if ans != nil {
		return ans(args)
	}
	switch args[0] {
	case "stop":
		return []byte(`{"ok":true,"stopped_at":1900000000}` + "\n"), 0, nil
	case "list":
		return []byte(`{"vms":[]}`), 0, nil
	}
	return []byte(`{"ok":true}` + "\n"), 0, nil
}

func (f *fakeVMHost) last() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return nil
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeVMHost) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func testED25519Key() string {
	var blob []byte
	put := func(b []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(b)))
		blob = append(blob, n[:]...)
		blob = append(blob, b...)
	}
	put([]byte("ssh-ed25519"))
	put(bytes.Repeat([]byte{7}, 32))
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " tester@example"
}

type vmTestBroker struct {
	b    *broker
	host *fakeVMHost
	cfg  string
	now  time.Time
}

func vmConfig(t *testing.T, enabled bool, stateDir string) config {
	t.Helper()
	dir := t.TempDir()
	key, kh := filepath.Join(dir, "id"), filepath.Join(dir, "known_hosts")
	for _, f := range []string{key, kh} {
		if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	host := func(id string, pmin, pmax, cpus int) vmHostConfig {
		return vmHostConfig{ID: id, SSHTarget: "vmctl@" + id + ".example", SSHKeyFile: key, KnownHostsFile: kh, PublicIP: "203.0.113.9",
			PortMin: pmin, PortMax: pmax, MaxVCPUs: cpus, MaxMemGiB: 32, MaxDiskGiB: 200}
	}
	return config{
		Listen: "127.0.0.1:0", StateDir: stateDir, OperatorKeySHA256: sha("operator-key"),
		Guests:     []guestConfig{{ID: "g1", KeySHA256: sha("key1")}},
		VMsEnabled: enabled,
		VMHosts:    []vmHostConfig{host("vmh-a", 22000, 22001, 4), host("vmh-b", 23000, 23009, 16)},
	}
}

func newVMTestBroker(t *testing.T, enabled bool) *vmTestBroker {
	t.Helper()
	c := vmConfig(t, enabled, t.TempDir())
	return loadVMTestBroker(t, writeConfig(t, c))
}

func loadVMTestBroker(t *testing.T, path string) *vmTestBroker {
	t.Helper()
	b, err := loadBroker(path)
	if err != nil {
		t.Fatal(err)
	}
	tb := &vmTestBroker{b: b, host: &fakeVMHost{}, cfg: path, now: time.Unix(1_800_000_000, 0)}
	if b.vms != nil {
		b.vms.exec = tb.host
		b.vms.now = func() time.Time { return tb.now }
	}
	return tb
}

func (tb *vmTestBroker) call(t *testing.T, key, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	switch v := body.(type) {
	case nil:
		rd = bytes.NewReader(nil)
	case string:
		rd = bytes.NewReader([]byte(v))
	default:
		raw, _ := json.Marshal(v)
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	rec := httptest.NewRecorder()
	tb.b.ServeHTTP(rec, req)
	var doc map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &doc)
	return rec.Code, doc
}

func vmErrCode(doc map[string]any) string {
	if e, ok := doc["error"].(map[string]any); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

func (tb *vmTestBroker) create(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	req := map[string]any{"account": "acct-1", "vcpus": 2, "mem_gib": 4, "disk_gib": 20, "ssh_public_key": testED25519Key()}
	for k, v := range body {
		req[k] = v
	}
	st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms", req)
	if st != 201 {
		t.Fatalf("create: %d %v", st, doc)
	}
	return doc
}

func TestVMsDisabledAnswer404(t *testing.T) {
	tb := newVMTestBroker(t, false)
	if tb.b.vms != nil {
		t.Fatal("vms on without vms_enabled")
	}
	for _, rt := range []struct{ method, path string }{
		{"GET", "/v1/broker/vms"}, {"POST", "/v1/broker/vms"}, {"GET", "/v1/broker/vms/vm-0123456789ab"},
		{"POST", "/v1/broker/vms/vm-0123456789ab/start"}, {"DELETE", "/v1/broker/vms/vm-0123456789ab"},
	} {
		for _, key := range []string{"operator-key", "key1", ""} {
			st, doc := tb.call(t, key, rt.method, rt.path, nil)
			if st != 404 || vmErrCode(doc) != "route_not_found" {
				t.Fatalf("%s %s key %q: %d %v", rt.method, rt.path, key, st, doc)
			}
		}
	}
	// Same answer a guest gets for a route the broker does not have.
	_, unknown := tb.call(t, "key1", "GET", "/v1/nothing-here", nil)
	if vmErrCode(unknown) != "route_not_found" {
		t.Fatalf("unknown route: %v", unknown)
	}
	if tb.host.count() != 0 {
		t.Fatal("host called while off")
	}
}

func TestVMsNeedOperatorKey(t *testing.T) {
	tb := newVMTestBroker(t, true)
	for _, key := range []string{"", "key1", "wrong"} {
		st, doc := tb.call(t, key, "GET", "/v1/broker/vms", nil)
		if st != 401 || vmErrCode(doc) != "unauthorized" {
			t.Fatalf("key %q: %d %v", key, st, doc)
		}
		if st, _ := tb.call(t, key, "POST", "/v1/broker/vms", map[string]any{"account": "a"}); st != 401 {
			t.Fatalf("key %q create: %d", key, st)
		}
	}
	// Same as /v1/broker/guests for a guest key.
	if st, _ := tb.call(t, "key1", "GET", "/v1/broker/guests", nil); st != 401 {
		t.Fatalf("guests: %d", st)
	}
}

func TestVMsConfigValidation(t *testing.T) {
	c := vmConfig(t, true, "")
	mustNotLoad(t, c, "vms_enabled needs state_dir")
	c = vmConfig(t, true, t.TempDir())
	c.VMHosts = nil
	mustNotLoad(t, c, "at least one vm_hosts")
	c = vmConfig(t, true, t.TempDir())
	c.VMHosts[1].ID = c.VMHosts[0].ID
	mustNotLoad(t, c, "duplicate id")
	c = vmConfig(t, true, t.TempDir())
	c.VMHosts[0].SSHTarget = "-oProxyCommand=x@h"
	mustNotLoad(t, c, "ssh_target")
	c = vmConfig(t, true, t.TempDir())
	c.VMHosts[0].PortMin = 80
	mustNotLoad(t, c, "port_min")
	c = vmConfig(t, true, t.TempDir())
	c.VMHosts[0].KnownHostsFile = "/nonexistent/known_hosts"
	mustNotLoad(t, c, "vm host vmh-a")
}

func TestVMsCreatePicksHostAndPortAndSurvivesReload(t *testing.T) {
	tb := newVMTestBroker(t, true)
	a := tb.create(t, nil)
	id := a["id"].(string)
	if !vmIDRE.MatchString(id) || a["host"] != "vmh-a" || a["ssh_port"] != float64(22000) || a["desired_state"] != "stopped" || a["public_ip"] != "203.0.113.9" {
		t.Fatalf("first VM: %v", a)
	}
	want := []string{"vmh-a", "create", id, "--vcpus", "2", "--mem-gib", "4", "--disk-gib", "20", "--ssh-port", "22000"}
	if got := tb.host.last(); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("create argv %v", got)
	}
	if tb.host.stdin[0] != testED25519Key()+"\n" {
		t.Fatalf("key on stdin: %q", tb.host.stdin[0])
	}
	b := tb.create(t, map[string]any{"vcpus": 2})
	if b["host"] != "vmh-a" || b["ssh_port"] != float64(22001) {
		t.Fatalf("second VM: %v", b)
	}
	// vmh-a is out of vCPUs (4) and ports: the next goes to vmh-b.
	c := tb.create(t, map[string]any{"vcpus": 1})
	if c["host"] != "vmh-b" || c["ssh_port"] != float64(23000) {
		t.Fatalf("third VM: %v", c)
	}
	if st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms", map[string]any{"account": "acct-1", "vcpus": 1, "mem_gib": 1, "disk_gib": 10, "ssh_public_key": testED25519Key(), "host": "vmh-a"}); st != 409 || vmErrCode(doc) != "no_vm_capacity" {
		t.Fatalf("full host: %d %v", st, doc)
	}

	// A restart reads vms.json back.
	tb2 := loadVMTestBroker(t, tb.cfg)
	st, list := tb2.call(t, "operator-key", "GET", "/v1/broker/vms", nil)
	if st != 200 || len(list["vms"].([]any)) != 3 {
		t.Fatalf("after reload: %d %v", st, list)
	}
	st, one := tb2.call(t, "operator-key", "GET", "/v1/broker/vms/"+id, nil)
	if st != 200 || one["account"] != "acct-1" || one["ssh_port"] != float64(22000) || one["host_status"] == nil {
		t.Fatalf("get after reload: %d %v", st, one)
	}
	if got := tb2.host.last(); got[1] != "status" || got[2] != id {
		t.Fatalf("status argv %v", got)
	}
	// The ports stay held after the restart.
	d := tb2.create(t, map[string]any{"vcpus": 1, "host": "vmh-b"})
	if d["ssh_port"] != float64(23001) {
		t.Fatalf("port after reload: %v", d)
	}
	info, err := os.Stat(filepath.Join(tb.b.cfg.StateDir, vmsFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("vms.json: %v %v", info, err)
	}
}

func TestVMsCreateRefusesBadInput(t *testing.T) {
	tb := newVMTestBroker(t, true)
	good := testED25519Key()
	parts := strings.Fields(good)
	for name, body := range map[string]map[string]any{
		"two keys":       {"ssh_public_key": good + "\n" + good},
		"options prefix": {"ssh_public_key": `command="sh" ` + good},
		"dsa":            {"ssh_public_key": "ssh-dss " + parts[1]},
		"type mismatch":  {"ssh_public_key": "ecdsa-sha2-nistp256 " + parts[1]},
		"not base64":     {"ssh_public_key": "ssh-ed25519 !!!!"},
		"bad comment":    {"ssh_public_key": parts[0] + " " + parts[1] + " $(reboot)"},
		"empty key":      {"ssh_public_key": ""},
		"vcpus":          {"vcpus": 65},
		"mem":            {"mem_gib": 0},
		"disk":           {"disk_gib": 4096},
		"over host caps": {"vcpus": 32},
		"bad account":    {"account": "a b"},
		"unknown host":   {"host": "nope"},
		"unknown field":  {"extra": 1},
	} {
		req := map[string]any{"account": "acct-1", "vcpus": 2, "mem_gib": 4, "disk_gib": 20, "ssh_public_key": good}
		for k, v := range body {
			req[k] = v
		}
		st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms", req)
		if st != 400 && st != 409 {
			t.Fatalf("%s: %d %v", name, st, doc)
		}
	}
	if tb.host.count() != 0 {
		t.Fatalf("host called %d times for refused creates", tb.host.count())
	}
}

func TestVMsAuthorizeAndStartGenerations(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	base := "/v1/broker/vms/" + id
	now := tb.now.Unix()
	auth := func(pt int64, gen int) (int, map[string]any) {
		return tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": pt, "generation": gen})
	}

	// Never started: start needs generation 1 authorized first.
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 409 || vmErrCode(doc) != "not_authorized" {
		t.Fatalf("start before authorize: %d %v", st, doc)
	}
	if st, doc := auth(now+300, 2); st != 409 || vmErrCode(doc) != "stale_authorization" {
		t.Fatalf("skipped generation: %d %v", st, doc)
	}
	if st, _ := auth(now-1, 1); st != 400 {
		t.Fatalf("past paid_through: %d", st)
	}
	if st, _ := auth((now+300)*1000, 1); st != 400 {
		t.Fatalf("milliseconds paid_through: %d", st)
	}
	if st, doc := auth(now+300, 1); st != 200 || doc["authorized_generation"] != float64(1) {
		t.Fatalf("authorize 1: %d %v", st, doc)
	}
	if got := tb.host.last(); strings.Join(got[1:], " ") != "authorize "+id+" "+strconv.FormatInt(now+300, 10)+" 1" {
		t.Fatalf("authorize argv %v", got)
	}
	if st, _ := auth(now+300, 1); st != 200 {
		t.Fatalf("replayed authorize not idempotent: %d", st)
	}
	if st, doc := auth(now+200, 1); st != 409 || vmErrCode(doc) != "stale_authorization" {
		t.Fatalf("lower paid_through: %d %v", st, doc)
	}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", map[string]any{"generation": 2}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("start wrong generation: %d %v", st, doc)
	}
	st, doc := tb.call(t, "operator-key", "POST", base+"/start", map[string]any{"generation": 1})
	if st != 200 || doc["generation"] != float64(1) || doc["desired_state"] != "running" {
		t.Fatalf("start: %d %v", st, doc)
	}
	// Running: renewals of generation 1 only.
	if st, _ := auth(now+600, 1); st != 200 {
		t.Fatalf("renew: %d", st)
	}
	if st, _ := auth(now+900, 2); st != 409 {
		t.Fatalf("next generation while running: %d", st)
	}
	if st, _ := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 409 {
		t.Fatalf("second start: %d", st)
	}
	if st, _ := tb.call(t, "operator-key", "POST", base+"/reboot", nil); st != 200 {
		t.Fatalf("reboot: %d", st)
	}

	// Stop ends generation 1: its authorizations are refused, and a start
	// needs generation 2.
	st, doc = tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1})
	if st != 200 || doc["stopped_at"] != float64(1900000000) || doc["desired_state"] != "stopped" {
		t.Fatalf("stop: %d %v", st, doc)
	}
	if st, _ := tb.call(t, "operator-key", "POST", base+"/reboot", nil); st != 409 {
		t.Fatalf("reboot while stopped: %d", st)
	}
	if st, doc := auth(now+1200, 1); st != 409 || vmErrCode(doc) != "stale_authorization" {
		t.Fatalf("old generation after stop: %d %v", st, doc)
	}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 409 || vmErrCode(doc) != "not_authorized" {
		t.Fatalf("start without generation 2: %d %v", st, doc)
	}
	if st, _ := auth(now+1200, 2); st != 200 {
		t.Fatalf("authorize 2: %d", st)
	}
	// The generation survives a restart.
	tb2 := loadVMTestBroker(t, tb.cfg)
	tb2.now = tb.now
	if st, _ := tb2.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/authorize", map[string]any{"paid_through": now + 1300, "generation": 1}); st != 409 {
		t.Fatalf("old generation after restart: %d", st)
	}
	if st, doc := tb2.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/start", nil); st != 200 || doc["generation"] != float64(2) {
		t.Fatalf("start 2 after restart: %d %v", st, doc)
	}
	// An authorization that has run out does not start a VM.
	tb2.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/stop", map[string]any{"generation": 2})
	tb2.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/authorize", map[string]any{"paid_through": now + 1400, "generation": 3})
	tb2.now = time.Unix(now+1500, 0)
	if st, doc := tb2.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/start", nil); st != 409 || vmErrCode(doc) != "not_authorized" {
		t.Fatalf("start past paid_through: %d %v", st, doc)
	}
}

func TestVMsHostRefusalsMapTo409(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	base := "/v1/broker/vms/" + id
	now := tb.now.Unix()
	tb.host.answer = func(args []string) ([]byte, int, error) {
		if args[0] == "authorize" {
			return []byte(`{"error":"stale"}`), vmExitStale, nil
		}
		return []byte(`{"error":"unpaid"}`), vmExitUnpaid, nil
	}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": now + 300, "generation": 1}); st != 409 || vmErrCode(doc) != "stale_authorization" {
		t.Fatalf("host stale: %d %v", st, doc)
	}
	tb.host.answer = nil
	tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": now + 300, "generation": 1})
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"unpaid"}`), vmExitUnpaid, nil }
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 409 || vmErrCode(doc) != "not_paid" {
		t.Fatalf("host unpaid: %d %v", st, doc)
	}
	// Refused start: still stopped in generation 0, the authorization still usable.
	tb.host.answer = nil
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 200 || doc["generation"] != float64(1) {
		t.Fatalf("start after refusal: %d %v", st, doc)
	}
}

func TestVMsExecutorErrorsAre502WithoutStderr(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	secret := "Permission denied (publickey) /etc/cathedral/secret-path"
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New(secret) }
	for _, rt := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/v1/broker/vms", map[string]any{"account": "acct-1", "vcpus": 1, "mem_gib": 1, "disk_gib": 10, "ssh_public_key": testED25519Key()}},
		{"POST", "/v1/broker/vms/" + id + "/authorize", map[string]any{"paid_through": tb.now.Unix() + 60, "generation": 1}},
		{"DELETE", "/v1/broker/vms/" + id, map[string]any{"confirm": id}},
	} {
		req := httptest.NewRequest(rt.method, rt.path, bytes.NewReader(vmBodyJSON(rt.body)))
		req.Header.Set("Authorization", "Bearer operator-key")
		rec := httptest.NewRecorder()
		tb.b.ServeHTTP(rec, req)
		if rec.Code != 502 || strings.Contains(rec.Body.String(), "secret") || strings.Contains(rec.Body.String(), "Permission") {
			t.Fatalf("%s %s: %d %s", rt.method, rt.path, rec.Code, rec.Body.String())
		}
	}
	// A non-zero exit with output on stdout: 502, output not passed on.
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"secret detail"}`), 1, nil }
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/v1/broker/vms/"+id+"/authorize", bytes.NewReader(vmBodyJSON(map[string]any{"paid_through": tb.now.Unix() + 60, "generation": 1})))
	req.Header.Set("Authorization", "Bearer operator-key")
	tb.b.ServeHTTP(rec, req)
	if rec.Code != 502 || strings.Contains(rec.Body.String(), "secret") {
		t.Fatalf("exit 1: %d %s", rec.Code, rec.Body.String())
	}
	// A failed delete keeps the VM; GET shows the host error code only.
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New(secret) }
	st, doc := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+id, nil)
	if st != 200 || doc["host_status_error"] != "vm_host_unreachable" {
		t.Fatalf("get with host down: %d %v", st, doc)
	}
	// A create whose answer was lost keeps its record (and port) as creating.
	st, list := tb.call(t, "operator-key", "GET", "/v1/broker/vms", nil)
	if st != 200 || len(list["vms"].([]any)) != 2 {
		t.Fatalf("list: %d %v", st, list)
	}
}

func TestVMsDeleteNeedsConfirm(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	other := tb.create(t, nil)["id"].(string)
	calls := tb.host.count()
	for _, body := range []any{nil, map[string]any{}, map[string]any{"confirm": other}, map[string]any{"confirm": strings.ToUpper(id)}} {
		if st, doc := tb.call(t, "operator-key", "DELETE", "/v1/broker/vms/"+id, body); st != 400 || vmErrCode(doc) != "confirm_required" {
			t.Fatalf("delete %v: %d %v", body, st, doc)
		}
	}
	if tb.host.count() != calls {
		t.Fatal("host called for an unconfirmed delete")
	}
	if st, _ := tb.call(t, "operator-key", "DELETE", "/v1/broker/vms/"+id, map[string]any{"confirm": id}); st != 200 {
		t.Fatalf("delete: %d", st)
	}
	if got := tb.host.last(); strings.Join(got[1:], " ") != "delete "+id+" --confirm "+id {
		t.Fatalf("delete argv %v", got)
	}
	if st, _ := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+id, nil); st != 404 {
		t.Fatalf("get after delete: %d", st)
	}
	// Gone after a restart too, and its port is free again.
	tb2 := loadVMTestBroker(t, tb.cfg)
	if st, _ := tb2.call(t, "operator-key", "GET", "/v1/broker/vms/"+id, nil); st != 404 {
		t.Fatalf("get after delete and restart: %d", st)
	}
	if again := tb2.create(t, nil); again["ssh_port"] != float64(22000) {
		t.Fatalf("port not freed: %v", again)
	}
}

func TestVMsSSHExecutorArgv(t *testing.T) {
	// A token that is not a plain word never reaches ssh.
	_, _, err := sshVMExecutor{}.Run(context.Background(), vmHostConfig{SSHTarget: "u@h"}, nil, "create", "x; reboot")
	if err == nil || !strings.Contains(err.Error(), "refused arg") {
		t.Fatalf("unsafe arg: %v", err)
	}
}

func vmBodyJSON(v any) []byte {
	if v == nil {
		return nil
	}
	raw, _ := json.Marshal(v)
	return raw
}

func TestVMsSSHExecutorRunsSSH(t *testing.T) {
	// A stand-in ssh on PATH: prints its argv and stdin, exits as told.
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ncat > \"$0.stdin\"\necho 'some stderr' >&2\necho '{\"ok\":true}'\nexit \"$(cat \"$0.code\")\"\n"
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	h := vmHostConfig{SSHTarget: "vmctl@vmh-a.example", SSHKeyFile: "/k/id", KnownHostsFile: "/k/known_hosts"}
	for _, tc := range []struct {
		code    string
		exit    int
		wantErr bool
	}{{"0", 0, false}, {"4", 4, false}, {"255", 0, true}} {
		_ = os.WriteFile(ssh+".code", []byte(tc.code), 0o600)
		out, exit, err := sshVMExecutor{}.Run(context.Background(), h, []byte("ssh-ed25519 AAAA\n"), "create", "vm-0123456789ab", "--vcpus", "2")
		if (err != nil) != tc.wantErr || exit != tc.exit {
			t.Fatalf("exit %s: got %d %v", tc.code, exit, err)
		}
		if !tc.wantErr && strings.TrimSpace(string(out)) != `{"ok":true}` {
			t.Fatalf("stdout %q", out)
		}
	}
	argv, _ := os.ReadFile(ssh + ".argv")
	got := strings.Split(strings.TrimSpace(string(argv)), "\n")
	tail := strings.Join(got[len(got)-6:], " ")
	if tail != "-- vmctl@vmh-a.example create vm-0123456789ab --vcpus 2" {
		t.Fatalf("argv tail %q", tail)
	}
	for _, want := range []string{"BatchMode=yes", "StrictHostKeyChecking=yes", "UserKnownHostsFile=/k/known_hosts", "/k/id"} {
		if !strings.Contains(string(argv), want) {
			t.Fatalf("argv lacks %s: %s", want, argv)
		}
	}
	if in, _ := os.ReadFile(ssh + ".stdin"); string(in) != "ssh-ed25519 AAAA\n" {
		t.Fatalf("stdin %q", in)
	}
	// A hung ssh is cut at the context deadline.
	_ = os.WriteFile(ssh, []byte("#!/bin/sh\nsleep 30\n"), 0o700)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, _, err := (sshVMExecutor{}).Run(ctx, h, nil, "list"); err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout: %v after %s", err, time.Since(start))
	}
}

// vmRunning makes a VM running in generation 1.
func vmRunning(t *testing.T, tb *vmTestBroker) (string, string) {
	t.Helper()
	id := tb.create(t, nil)["id"].(string)
	base := "/v1/broker/vms/" + id
	if st, doc := tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1}); st != 200 {
		t.Fatalf("authorize: %d %v", st, doc)
	}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 200 {
		t.Fatalf("start: %d %v", st, doc)
	}
	return id, base
}

func TestVMsStopIsScopedToGeneration(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id, base := vmRunning(t, tb)
	if got := tb.host.last(); strings.Join(got[1:], " ") != "start "+id+" --generation 1" {
		t.Fatalf("start argv %v", got)
	}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/reboot", map[string]any{"generation": 2}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("reboot wrong generation: %d %v", st, doc)
	}
	if st, _ := tb.call(t, "operator-key", "POST", base+"/reboot", map[string]any{"generation": 1}); st != 200 {
		t.Fatalf("reboot: %d", st)
	}
	if got := tb.host.last(); strings.Join(got[1:], " ") != "reboot "+id+" --generation 1" {
		t.Fatalf("reboot argv %v", got)
	}
	calls := tb.host.count()
	for _, body := range []any{nil, map[string]any{}, map[string]any{"generation": 0}} {
		if st, doc := tb.call(t, "operator-key", "POST", base+"/stop", body); st != 400 || vmErrCode(doc) != "generation_required" {
			t.Fatalf("stop %v: %d %v", body, st, doc)
		}
	}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 2}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("stop of a future generation: %d %v", st, doc)
	}
	if tb.host.count() != calls {
		t.Fatal("host called for a refused stop")
	}
	_, one := tb.call(t, "operator-key", "GET", base, nil)
	if one["desired_state"] != "running" {
		t.Fatalf("refused stop changed state: %v", one)
	}
	st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1})
	if st != 200 || doc["stopped_at"] != float64(1900000000) {
		t.Fatalf("stop: %d %v", st, doc)
	}
	if got := tb.host.last(); strings.Join(got[1:], " ") != "stop "+id+" --generation 1" {
		t.Fatalf("stop argv %v", got)
	}
	// A repeated Stop of the same run answers the stored receipt, no host call.
	calls = tb.host.count()
	st, doc = tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1})
	if st != 200 || doc["stopped_at"] != float64(1900000000) || tb.host.count() != calls {
		t.Fatalf("repeated stop: %d %v, host calls %d -> %d", st, doc, calls, tb.host.count())
	}
}

func TestVMsHostRefusesStopOfOtherGeneration(t *testing.T) {
	tb := newVMTestBroker(t, true)
	_, base := vmRunning(t, tb)
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"stale_generation"}`), vmExitStale, nil }
	if st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("host stale stop: %d %v", st, doc)
	}
	tb.host.answer = nil
	if _, one := tb.call(t, "operator-key", "GET", base, nil); one["desired_state"] != "running" {
		t.Fatalf("state after a host refusal: %v", one)
	}
}

func TestVMsLostStartStaysStartingAndRetries(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	base := "/v1/broker/vms/" + id
	tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1})
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New("connection reset") }
	if st, _ := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 502 {
		t.Fatalf("lost start: %d", st)
	}
	tb.host.answer = nil
	// Starting survives a restart; a retry with the same generation finishes it.
	tb2 := loadVMTestBroker(t, tb.cfg)
	tb2.now = tb.now
	_, one := tb2.call(t, "operator-key", "GET", base, nil)
	if one["desired_state"] != "starting" || one["generation"] != float64(1) {
		t.Fatalf("after lost start: %v", one)
	}
	if st, doc := tb2.call(t, "operator-key", "POST", base+"/start", map[string]any{"generation": 2}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("retry with next generation: %d %v", st, doc)
	}
	st, doc := tb2.call(t, "operator-key", "POST", base+"/start", map[string]any{"generation": 1})
	if st != 200 || doc["desired_state"] != "running" || doc["generation"] != float64(1) {
		t.Fatalf("retry start: %d %v", st, doc)
	}
	if got := tb2.host.last(); strings.Join(got[1:], " ") != "start "+id+" --generation 1" {
		t.Fatalf("retry argv %v", got)
	}
}

func TestVMsStartingCanStopOrReconcile(t *testing.T) {
	tb := newVMTestBroker(t, true)
	lost := func() string {
		id := tb.create(t, nil)["id"].(string)
		tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1})
		tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New("timeout") }
		tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/start", nil)
		tb.host.answer = nil
		return id
	}
	// Stop of a starting VM is allowed.
	a := lost()
	if st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+a+"/stop", map[string]any{"generation": 1}); st != 200 || doc["desired_state"] != "stopped" {
		t.Fatalf("stop starting: %d %v", st, doc)
	}
	// GET moves starting to running when the host runs that generation.
	b := lost()
	tb.host.answer = func(args []string) ([]byte, int, error) {
		return []byte(`{"name":"` + b + `","state":"running","generation":1}`), 0, nil
	}
	if st, doc := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+b, nil); st != 200 || doc["desired_state"] != "running" {
		t.Fatalf("reconcile: %d %v", st, doc)
	}
	// Not for another generation.
	c := lost()
	tb.host.answer = func(args []string) ([]byte, int, error) {
		return []byte(`{"name":"` + c + `","state":"running","generation":7}`), 0, nil
	}
	if _, doc := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+c, nil); doc["desired_state"] != "starting" {
		t.Fatalf("reconciled on another generation: %v", doc)
	}
	// A refused retry proves nothing about the first attempt: it stays
	// starting in its generation, with last_error.
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"unpaid"}`), vmExitUnpaid, nil }
	if st, _ := tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+c+"/start", nil); st != 409 {
		t.Fatalf("refused retry: %d", st)
	}
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New("down") }
	if _, doc := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+c, nil); doc["desired_state"] != "starting" || doc["generation"] != float64(1) || doc["last_error"] != "start: not_paid" {
		t.Fatalf("after refused retry: %v", doc)
	}
	// The host says it is stopped with that generation closed: stopped,
	// generation kept, and a Stop of it still asks the host for a receipt.
	tb.host.answer = func(args []string) ([]byte, int, error) {
		return []byte(`{"name":"` + c + `","state":"stopped","generation":1,"closed":true}`), 0, nil
	}
	if _, doc := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+c, nil); doc["desired_state"] != "stopped" || doc["generation"] != float64(1) {
		t.Fatalf("reconcile to stopped: %v", doc)
	}
	tb.host.answer = nil
	if st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+c+"/stop", map[string]any{"generation": 1}); st != 200 || doc["stopped_at"] != float64(1900000000) {
		t.Fatalf("stop after reconcile: %d %v", st, doc)
	}
	if st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+c+"/start", map[string]any{"generation": 1}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("start of the closed generation: %d %v", st, doc)
	}
	// Host stopped in the same generation, not closed: still unknown.
	d := lost()
	tb.host.answer = func(args []string) ([]byte, int, error) {
		return []byte(`{"name":"` + d + `","state":"stopped","generation":1}`), 0, nil
	}
	if _, doc := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+d, nil); doc["desired_state"] != "starting" {
		t.Fatalf("reconciled an open generation: %v", doc)
	}
	// A first attempt the host refuses rolls back to stopped in generation 0.
	e := tb.create(t, nil)["id"].(string)
	tb.host.answer = nil
	tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+e+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1})
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"unpaid"}`), vmExitUnpaid, nil }
	tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+e+"/start", nil)
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New("down") }
	if _, doc := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+e, nil); doc["desired_state"] != "stopped" || doc["generation"] != float64(0) {
		t.Fatalf("after refused first start: %v", doc)
	}
}

func TestVMsStopReceiptOnlyOnceSaved(t *testing.T) {
	tb := newVMTestBroker(t, true)
	_, base := vmRunning(t, tb)
	// A directory where the temp file goes makes every save fail.
	block := filepath.Join(tb.b.cfg.StateDir, vmsFile+".tmp")
	stop := func() (int, map[string]any) {
		return tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1})
	}
	if err := os.Mkdir(block, 0o700); err != nil {
		t.Fatal(err)
	}
	// The intent save fails first: nothing sent to the host.
	calls := tb.host.count()
	if st, doc := stop(); st != 500 || tb.host.count() != calls {
		t.Fatalf("stop with no saves: %d %v", st, doc)
	}
	// Intent saved, then the receipt save fails.
	os.Remove(block)
	tb.host.answer = func(args []string) ([]byte, int, error) {
		if args[0] == "stop" {
			if err := os.Mkdir(block, 0o700); err != nil {
				t.Error(err)
			}
			return []byte(`{"stopped_at":1900000000}`), 0, nil
		}
		return []byte(`{"ok":true}`), 0, nil
	}
	if st, doc := stop(); st != 500 || vmErrCode(doc) != "state_not_saved" {
		t.Fatalf("receipt not saved: %d %v", st, doc)
	}
	// The repeat answers the cached receipt only after it is on disk.
	if st, doc := stop(); st != 500 || vmErrCode(doc) != "state_not_saved" {
		t.Fatalf("repeat with saves failing: %d %v", st, doc)
	}
	os.Remove(block)
	if st, doc := stop(); st != 200 || doc["stopped_at"] != float64(1900000000) {
		t.Fatalf("repeat once saves work: %d %v", st, doc)
	}
	tb2 := loadVMTestBroker(t, tb.cfg)
	if _, doc := tb2.call(t, "operator-key", "GET", base, nil); doc["stopped_at"] != float64(1900000000) {
		t.Fatalf("receipt after restart: %v", doc)
	}
}

func TestVMsStopCancelsNextRunBeforeStart(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id, base := vmRunning(t, tb)
	tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1})
	tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 2})

	// A host that does not answer: 502, nothing changes, the cancel may be repeated.
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New("timeout") }
	if st, _ := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 2}); st != 502 {
		t.Fatalf("cancel with host down: %d", st)
	}
	tb.host.answer = nil
	if _, one := tb.call(t, "operator-key", "GET", base, nil); one["generation"] != float64(1) || one["stopped_at"] != float64(1900000000) {
		t.Fatalf("state after a lost cancel: %v", one)
	}
	// Stop of a generation two ahead is still refused.
	for _, g := range []int{3} {
		if st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": g}); st != 409 || vmErrCode(doc) != "stale_generation" {
			t.Fatalf("stop generation %d: %d %v", g, st, doc)
		}
	}
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"ok":true,"stopped_at":1800000123}`), 0, nil }
	st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 2})
	if st != 200 || doc["generation"] != float64(2) || doc["stopped_at"] != float64(1800000123) || doc["desired_state"] != "stopped" {
		t.Fatalf("cancel: %d %v", st, doc)
	}
	tb.host.answer = nil
	if got := tb.host.last(); strings.Join(got[1:], " ") != "stop "+id+" --generation 2" {
		t.Fatalf("cancel argv %v", got)
	}
	calls := tb.host.count()
	if st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 2}); st != 200 || doc["stopped_at"] != float64(1800000123) {
		t.Fatalf("repeated cancel: %d %v", st, doc)
	}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", map[string]any{"generation": 2}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("late start of the cancelled run: %d %v", st, doc)
	}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 600, "generation": 2}); st != 409 || vmErrCode(doc) != "stale_authorization" {
		t.Fatalf("late authorize of the cancelled run: %d %v", st, doc)
	}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("old run stop after cancel: %d %v", st, doc)
	}
	if tb.host.count() != calls {
		t.Fatal("host called after the cancel")
	}
	// The run after it starts normally.
	tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 600, "generation": 3})
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 200 || doc["generation"] != float64(3) {
		t.Fatalf("start after cancel: %d %v", st, doc)
	}
}

func TestVMsCancelWithLostAuthorizeReply(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	base := "/v1/broker/vms/" + id
	// The authorize reply was lost: the broker never recorded generation 1,
	// and the host never got it, so its stop answers exit 3.
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New("connection reset") }
	tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1})
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"stale_generation"}`), vmExitStale, nil }
	st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1})
	if st != 200 || doc["generation"] != float64(1) || doc["stopped_at"] != float64(tb.now.Unix()) || doc["desired_state"] != "stopped" {
		t.Fatalf("cancel with lost authorize: %d %v", st, doc)
	}
	tb.host.answer = nil
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", map[string]any{"generation": 1}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("late start: %d %v", st, doc)
	}
	// Closed across a restart too.
	tb2 := loadVMTestBroker(t, tb.cfg)
	tb2.now = tb.now
	if st, _ := tb2.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1}); st != 409 {
		t.Fatalf("authorize of the cancelled run after restart: %d", st)
	}
}

func TestVMsRefusedStartKeepsPreviousReceipt(t *testing.T) {
	tb := newVMTestBroker(t, true)
	_, base := vmRunning(t, tb)
	tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1})
	tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 2})
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"stale_generation"}`), vmExitStale, nil }
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("host exit 3 on start: %d %v", st, doc)
	}
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New("down") }
	_, doc := tb.call(t, "operator-key", "GET", base, nil)
	if doc["desired_state"] != "stopped" || doc["generation"] != float64(1) || doc["stopped_at"] != float64(1900000000) {
		t.Fatalf("after refused first start: %v", doc)
	}
	// The generation-1 receipt still answers without a host call.
	calls := tb.host.count()
	if st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1}); st != 200 || doc["stopped_at"] != float64(1900000000) || tb.host.count() != calls {
		t.Fatalf("receipt after refused start: %d %v", st, doc)
	}
}

// Cursor on #755: a lost start that GET settled to stopped because the host
// holds another generation must still get a stop receipt, not 409 forever.
func TestVMsSettledLostStartGetsAReceipt(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1})
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New("timeout") }
	tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/start", nil)
	// The host never got generation 1 (the authorize never reached it).
	tb.host.answer = func(args []string) ([]byte, int, error) {
		return []byte(`{"name":"` + id + `","state":"created","generation":0}`), 0, nil
	}
	if _, doc := tb.call(t, "operator-key", "GET", "/v1/broker/vms/"+id, nil); doc["desired_state"] != "stopped" {
		t.Fatalf("settle: %v", doc)
	}
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"stale_generation"}`), 3, nil }
	st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/stop", map[string]any{"generation": 1})
	if st != 200 || doc["stopped_at"] != float64(tb.now.Unix()) {
		t.Fatalf("stop of the settled run: %d %v", st, doc)
	}
	// Repeat: the stored receipt, no host call.
	tb.host.answer = func(a []string) ([]byte, int, error) { t.Fatalf("host called for a stored receipt: %v", a); return nil, 0, nil }
	if st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/stop", map[string]any{"generation": 1}); st != 200 || doc["stopped_at"] != float64(tb.now.Unix()) {
		t.Fatalf("repeat: %d %v", st, doc)
	}
	// A running run whose host refuses the stop as stale keeps the refusal.
	tb.host.answer = nil
	b := tb.create(t, nil)["id"].(string)
	tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+b+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1})
	if st, _ := tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+b+"/start", nil); st != 200 {
		t.Fatalf("start b: %d", st)
	}
	tb.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"stale_generation"}`), 3, nil }
	if st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+b+"/stop", map[string]any{"generation": 1}); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("running stale stop: %d %v", st, doc)
	}
}

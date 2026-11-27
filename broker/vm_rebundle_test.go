package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	testBundle2 = strings.Repeat("2b", 32)
	testOpID    = strings.Repeat("c3", 16)
)

func rebundleBody(gen, expect int) map[string]any {
	return map[string]any{"generation": gen, "expect_revision": expect, "op_id": testOpID, "to": testBundle2}
}

// vmStopped makes a VM that ran generation 1 and was stopped (the host closed it).
func vmStopped(t *testing.T, tb *vmTestBroker) (string, string) {
	t.Helper()
	id, base := vmRunning(t, tb)
	if st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1}); st != 200 {
		t.Fatalf("stop: %d %v", st, doc)
	}
	return id, base
}

func vmsFileBytes(t *testing.T, tb *vmTestBroker) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(tb.b.vms.dir, vmsFile))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVMsRebundleSendsTheFencedCallAndKeepsNoState(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string) // never ran: generation 0
	base := "/v1/broker/vms/" + id
	before := vmsFileBytes(t, tb)
	tb.host.answer = func(args []string) ([]byte, int, error) {
		return []byte(`{"name":"` + id + `","bundle":"` + testBundle2 + `","bundle_selection_revision":1}` + "\n"), 0, nil
	}
	st, doc := tb.call(t, "operator-key", "POST", base+"/rebundle", rebundleBody(0, 0))
	if st != 200 {
		t.Fatalf("rebundle: %d %v", st, doc)
	}
	if got := doc["rebundle"].(map[string]any)["bundle_selection_revision"]; got != float64(1) {
		t.Fatalf("rebundle answer %v", doc)
	}
	want := "rebundle " + id + " --generation 0 --expect-revision 0 --op-id " + testOpID + " --to " + testBundle2
	if got := tb.host.last(); strings.Join(got[1:], " ") != want {
		t.Fatalf("argv %v", got)
	}
	if in := tb.host.stdin[len(tb.host.stdin)-1]; in != "" {
		t.Fatalf("rebundle sent stdin %q", in)
	}
	if !bytes.Equal(vmsFileBytes(t, tb), before) {
		t.Fatal("rebundle changed vms.json")
	}
	// A stopped VM that ran: its closed generation.
	tb2 := newVMTestBroker(t, true)
	_, base2 := vmStopped(t, tb2)
	if st, doc := tb2.call(t, "operator-key", "POST", base2+"/rebundle", rebundleBody(1, 0)); st != 200 {
		t.Fatalf("rebundle after a run: %d %v", st, doc)
	}
}

func TestVMsRebundleRefusesBeforeTheHost(t *testing.T) {
	tb := newVMTestBroker(t, true)
	_, base := vmStopped(t, tb)
	calls := tb.host.count()
	bad := func(change map[string]any) map[string]any {
		body := rebundleBody(1, 0)
		for k, v := range change {
			if v == nil {
				delete(body, k)
			} else {
				body[k] = v
			}
		}
		return body
	}
	for _, tc := range []struct {
		body any
		st   int
		code string
	}{
		{nil, 400, "invalid_json"},
		{bad(map[string]any{"generation": nil}), 400, "invalid_generation"},
		{bad(map[string]any{"expect_revision": nil}), 400, "invalid_expect_revision"},
		{bad(map[string]any{"expect_revision": -1}), 400, "invalid_json"},
		{bad(map[string]any{"to": nil}), 400, "invalid_bundle"},
		{bad(map[string]any{"to": strings.ToUpper(testBundle2)}), 400, "invalid_bundle"},
		{bad(map[string]any{"to": testBundle2[:63]}), 400, "invalid_bundle"},
		{bad(map[string]any{"op_id": testOpID[:31]}), 400, "invalid_op_id"},
		{bad(map[string]any{"op_id": "x; reboot"}), 400, "invalid_op_id"},
		{bad(map[string]any{"from": testBundle2}), 400, "invalid_json"}, // spec r3: no from
		{bad(map[string]any{"generation": 2}), 409, "stale_generation"},
	} {
		if st, doc := tb.call(t, "operator-key", "POST", base+"/rebundle", tc.body); st != tc.st || vmErrCode(doc) != tc.code {
			t.Fatalf("%v: %d %v, want %d %s", tc.body, st, doc, tc.st, tc.code)
		}
	}
	// The next run authorized: the host holds it open, so the broker refuses first.
	if st, doc := tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 2}); st != 200 {
		t.Fatalf("authorize: %d %v", st, doc)
	}
	calls = tb.host.count()
	if st, doc := tb.call(t, "operator-key", "POST", base+"/rebundle", rebundleBody(1, 0)); st != 409 || vmErrCode(doc) != "stale_generation" {
		t.Fatalf("authorized next run: %d %v", st, doc)
	}
	// A running VM.
	tbr := newVMTestBroker(t, true)
	_, baser := vmRunning(t, tbr)
	callsr := tbr.host.count()
	if st, doc := tbr.call(t, "operator-key", "POST", baser+"/rebundle", rebundleBody(1, 0)); st != 409 || vmErrCode(doc) != "vm_not_stopped" {
		t.Fatalf("running: %d %v", st, doc)
	}
	if tb.host.count() != calls || tbr.host.count() != callsr {
		t.Fatal("the host was called for a refused rebundle")
	}
}

func TestVMsRebundleMapsHostRefusalsByExitAndToken(t *testing.T) {
	tb := newVMTestBroker(t, true)
	_, base := vmStopped(t, tb)
	for _, tc := range []struct {
		token, reason string
		exit, st      int
		code          string
	}{
		{"stale_selection", "revision_changed", 19, 409, "stale_selection"},
		{"stale_selection", "op_id_reused", 19, 409, "stale_selection"},
		{"bundle_incompatible", "no_verified_build", 20, 409, "bundle_incompatible"},
		{"bundle_incompatible", "base_root_differs", 20, 409, "bundle_incompatible"},
		{"stale_generation", "unit_active", 3, 409, "stale_generation"},
		// A token with another exit code than its contract, or one not in the table: not shown.
		{"stale_selection", "", 17, 502, "vm_host_refused"},
		{"stale_selection", "", 3, 502, "vm_host_refused"},
		{"bundle_incompatible", "", 1, 502, "vm_host_refused"},
		{"sev_platform_changed", "", 17, 502, "vm_host_refused"},
		{"launch_values", "", 1, 502, "vm_host_refused"},
		{"history_open", "", 3, 502, "vm_host_refused"},
	} {
		answer := []byte(`{"error":"` + tc.token + `","detail":"x","reason":"` + tc.reason + `"}` + "\n")
		exit := tc.exit
		tb.host.answer = func([]string) ([]byte, int, error) { return answer, exit, nil }
		st, doc := tb.call(t, "operator-key", "POST", base+"/rebundle", rebundleBody(1, 0))
		if st != tc.st || vmErrCode(doc) != tc.code {
			t.Fatalf("%s exit %d: %d %v, want %d %s", tc.token, tc.exit, st, doc, tc.st, tc.code)
		}
		msg, _ := doc["error"].(map[string]any)["message"].(string)
		if tc.reason != "" && tc.st == 409 && !strings.Contains(msg, "reason: "+tc.reason) {
			t.Fatalf("%s: the reason is not in %q", tc.token, msg)
		}
	}
	// A reason that is not a plain token is dropped, not echoed.
	tb.host.answer = func([]string) ([]byte, int, error) {
		return []byte(`{"error":"stale_selection","reason":"<b>x</b>"}`), 19, nil
	}
	if _, doc := tb.call(t, "operator-key", "POST", base+"/rebundle", rebundleBody(1, 0)); strings.Contains(doc["error"].(map[string]any)["message"].(string), "<b>") {
		t.Fatalf("raw reason echoed: %v", doc)
	}
	// A host that did not answer: outcome unknown, vms.json untouched; the caller repeats the op_id.
	before := vmsFileBytes(t, tb)
	tb.host.answer = func([]string) ([]byte, int, error) { return nil, 0, errors.New("timeout") }
	if st, doc := tb.call(t, "operator-key", "POST", base+"/rebundle", rebundleBody(1, 0)); st != 502 || vmErrCode(doc) != "vm_host_unreachable" {
		t.Fatalf("timeout: %d %v", st, doc)
	}
	if !bytes.Equal(vmsFileBytes(t, tb), before) {
		t.Fatal("a rebundle with an unknown outcome changed vms.json")
	}
}

// Start's gate refusals keep their answer: 17 and 18 (vm_gates.py) are 502 at start, and
// rebundle's 19 and 20 mean nothing there either. Only rebundle maps by exit code and token.
func TestVMsStartGateExitsStay502AfterRebundleMapping(t *testing.T) {
	for _, tc := range []struct {
		token string
		exit  int
	}{{"sev_platform_changed", 17}, {"sev_state_unavailable", 18}, {"stale_selection", 19}, {"bundle_incompatible", 20}} {
		tb := newVMTestBroker(t, true)
		id := tb.create(t, nil)["id"].(string)
		base := "/v1/broker/vms/" + id
		if st, doc := tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1}); st != 200 {
			t.Fatalf("authorize: %d %v", st, doc)
		}
		answer, exit := []byte(`{"error":"`+tc.token+`"}`), tc.exit
		tb.host.answer = func([]string) ([]byte, int, error) { return answer, exit, nil }
		if st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 502 || vmErrCode(doc) != "vm_host_refused" {
			t.Fatalf("start %s exit %d: %d %v", tc.token, tc.exit, st, doc)
		}
	}
}

func TestVMsRebundleArgsPassTheRealSSHExecutor(t *testing.T) {
	// A stand-in ssh on PATH: records its argv and stdin.
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ncat > \"$0.stdin\"\necho '{\"bundle_selection_revision\":1}'\n"
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	h := vmHostConfig{SSHTarget: "vmctl@vmh-a.example", SSHKeyFile: "/k/id", KnownHostsFile: "/k/known_hosts"}
	// A bundle id is 64 characters, vmArgRE's limit: it passes the same check as every argument.
	args := []string{"rebundle", "vm-0123456789ab", "--generation", "0", "--expect-revision", "0", "--op-id", testOpID, "--to", testBundle2}
	if _, exit, err := (sshVMExecutor{}).Run(context.Background(), h, nil, args...); err != nil || exit != 0 {
		t.Fatalf("rebundle args refused: %d %v", exit, err)
	}
	argv, _ := os.ReadFile(ssh + ".argv")
	got := strings.Split(strings.TrimSpace(string(argv)), "\n")
	if tail := strings.Join(got[len(got)-len(args)-2:], " "); tail != "-- vmctl@vmh-a.example "+strings.Join(args, " ") {
		t.Fatalf("argv tail %q", tail)
	}
	if _, _, err := (sshVMExecutor{}).Run(context.Background(), h, nil, "rebundle", "vm-0123456789ab", "--to", testBundle2+"0"); err == nil {
		t.Fatal("a 65-character argument passed")
	}
}

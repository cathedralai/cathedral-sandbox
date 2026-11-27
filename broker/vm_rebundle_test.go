package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var (
	testBundle1 = strings.Repeat("1a", 32)
	testBundle2 = strings.Repeat("2b", 32)
	testOpID    = strings.Repeat("c3", 16)
)

func testRewrapAnswer() map[string]any {
	b64 := func(n int, c byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{c}, n)) }
	return map[string]any{
		"schema": vmRewrapSchema, "algorithm": vmRewrapAlgorithm, "offer_sha256": strings.Repeat("5e", 32),
		"ephemeral_public_b64": b64(32, 1), "nonce_b64": b64(12, 2), "ciphertext_b64": b64(48, 3),
	}
}

func rebundleBody(gen, expect int) map[string]any {
	return map[string]any{"generation": gen, "from": testBundle1, "to": testBundle2, "expect_revision": expect, "op_id": testOpID}
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
	want := "rebundle " + id + " --generation 0 --from " + testBundle1 + " --to " + testBundle2 +
		" --expect-revision 0 --op-id " + testOpID
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
		{bad(map[string]any{"to": testBundle1}), 400, "invalid_bundle"},
		{bad(map[string]any{"to": strings.ToUpper(testBundle2)}), 400, "invalid_bundle"},
		{bad(map[string]any{"from": testBundle1[:63]}), 400, "invalid_bundle"},
		{bad(map[string]any{"op_id": testOpID[:31]}), 400, "invalid_op_id"},
		{bad(map[string]any{"op_id": "x; reboot"}), 400, "invalid_op_id"},
		{bad(map[string]any{"extra": 1}), 400, "invalid_json"},
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
	if st, doc := tb.call(t, "operator-key", "POST", base+"/rebundle", rebundleBody(1, 0)); st != 409 || vmErrCode(doc) != "generation_open" {
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

func TestVMsRebundleAndRewrapMapHostRefusalsByTokenAndExit(t *testing.T) {
	tb := newVMTestBroker(t, true)
	_, base := vmStopped(t, tb)
	tbw := newVMTestBroker(t, true)
	_, basew := vmRunning(t, tbw)
	rewrapBody := map[string]any{"generation": 1, "answer": testRewrapAnswer()}
	for _, tc := range []struct {
		route, token string
		exit, st     int
		code         string
	}{
		{"rebundle", "stale_selection", 17, 409, "stale_selection"},
		{"rebundle", "stale_generation", 3, 409, "stale_generation"},
		{"rebundle", "generation_open", 3, 409, "generation_open"},
		{"rebundle", "bundle_changed", 3, 409, "bundle_changed"},
		{"rebundle", "vm_not_stopped", 3, 409, "vm_not_stopped"},
		{"rebundle", "op_id_conflict", 2, 409, "op_id_conflict"},
		{"rebundle", "bundle_not_enabled", 1, 409, "bundle_not_enabled"},
		{"rebundle", "no_bundle", 1, 409, "no_bundle"},
		{"rebundle", "bundle_incompatible", 1, 409, "bundle_incompatible"},
		// A token with another exit code than its contract, or an unknown one: not shown.
		{"rebundle", "stale_selection", 3, 502, "vm_host_refused"},
		{"rebundle", "launch_values", 1, 502, "vm_host_refused"},
		{"rebundle", "history_open", 3, 502, "vm_host_refused"},
		{"rewrap", "invalid_rewrap_answer", 2, 400, "invalid_rewrap_answer"},
		{"rewrap", "stale_generation", 3, 409, "stale_generation"},
		{"rewrap", "generation_closed", 3, 409, "generation_closed"},
		{"rewrap", "no_rewrap_offer", 3, 409, "no_rewrap_offer"},
		{"rewrap", "rewrap_offer_changed", 3, 409, "rewrap_offer_changed"},
		{"rewrap", "mailbox_invalid", 1, 502, "vm_host_refused"},
		{"rewrap", "stale_selection", 17, 502, "vm_host_refused"},
	} {
		answer := []byte(`{"error":"` + tc.token + `","detail":"x"}` + "\n")
		exit := tc.exit
		fake := func([]string) ([]byte, int, error) { return answer, exit, nil }
		var st int
		var doc map[string]any
		if tc.route == "rebundle" {
			tb.host.answer = fake
			st, doc = tb.call(t, "operator-key", "POST", base+"/rebundle", rebundleBody(1, 0))
		} else {
			tbw.host.answer = fake
			st, doc = tbw.call(t, "operator-key", "POST", basew+"/rewrap", rewrapBody)
		}
		if st != tc.st || vmErrCode(doc) != tc.code {
			t.Fatalf("%s %s exit %d: %d %v, want %d %s", tc.route, tc.token, tc.exit, st, doc, tc.st, tc.code)
		}
	}
	// Exit 17 means stale_selection only on rebundle: on any other route it is not a known refusal.
	tbw.host.answer = func([]string) ([]byte, int, error) { return []byte(`{"error":"stale_selection"}`), 17, nil }
	if st, doc := tbw.call(t, "operator-key", "POST", basew+"/reboot", nil); st != 502 || vmErrCode(doc) != "vm_host_refused" {
		t.Fatalf("exit 17 on reboot: %d %v", st, doc)
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

func TestVMsRewrapSendsTheAnswerOnStdinOnly(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id, base := vmRunning(t, tb)
	tb.host.answer = func([]string) ([]byte, int, error) {
		return []byte(`{"name":"` + id + `","generation":1,"written":true}` + "\n"), 0, nil
	}
	// Spaces and newlines in the body are compacted away; the key order is the caller's.
	raw := `{"generation": 1, "answer": {"schema": "` + vmRewrapSchema + `", "algorithm": "` + vmRewrapAlgorithm + `",
	  "offer_sha256": "` + strings.Repeat("5e", 32) + `", "ephemeral_public_b64": "` + testRewrapAnswer()["ephemeral_public_b64"].(string) + `",
	  "nonce_b64": "` + testRewrapAnswer()["nonce_b64"].(string) + `", "ciphertext_b64": "` + testRewrapAnswer()["ciphertext_b64"].(string) + `"}}`
	st, doc := tb.call(t, "operator-key", "POST", base+"/rewrap", raw)
	if st != 200 || doc["rewrap"].(map[string]any)["written"] != true {
		t.Fatalf("rewrap: %d %v", st, doc)
	}
	if got := tb.host.last(); strings.Join(got[1:], " ") != "rewrap "+id+" --generation 1" {
		t.Fatalf("argv %v", got)
	}
	in := tb.host.stdin[len(tb.host.stdin)-1]
	var sent map[string]any
	if json.Unmarshal([]byte(in), &sent) != nil || len(sent) != 6 || strings.ContainsAny(in, " \n") {
		t.Fatalf("stdin %q", in)
	}
	for _, a := range tb.host.last() {
		if strings.Contains(a, "cathedral.vm") || strings.Contains(a, "{") {
			t.Fatalf("the answer reached argv: %v", tb.host.last())
		}
	}
	calls := tb.host.count()
	with := func(change map[string]any) map[string]any {
		a := testRewrapAnswer()
		for k, v := range change {
			if v == nil {
				delete(a, k)
			} else {
				a[k] = v
			}
		}
		return map[string]any{"generation": 1, "answer": a}
	}
	for _, tc := range []struct {
		body any
		st   int
		code string
	}{
		{map[string]any{"answer": testRewrapAnswer()}, 400, "invalid_generation"},
		{map[string]any{"generation": 1}, 400, "invalid_rewrap_answer"},
		{map[string]any{"generation": 1, "answer": "x"}, 400, "invalid_rewrap_answer"},
		{map[string]any{"generation": 1, "answer": []any{}}, 400, "invalid_rewrap_answer"},
		{with(map[string]any{"extra": "x"}), 400, "invalid_rewrap_answer"},
		{with(map[string]any{"nonce_b64": nil}), 400, "invalid_rewrap_answer"},
		{with(map[string]any{"schema": "cathedral.vm.rewrap-answer/v2"}), 400, "invalid_rewrap_answer"},
		{with(map[string]any{"algorithm": "none"}), 400, "invalid_rewrap_answer"},
		{with(map[string]any{"offer_sha256": strings.Repeat("5E", 32)}), 400, "invalid_rewrap_answer"},
		{with(map[string]any{"ciphertext_b64": base64.StdEncoding.EncodeToString(make([]byte, 47))}), 400, "invalid_rewrap_answer"},
		{with(map[string]any{"ephemeral_public_b64": strings.TrimRight(base64.StdEncoding.EncodeToString(make([]byte, 32)), "=")}), 400, "invalid_rewrap_answer"},
		{with(map[string]any{"nonce_b64": 12}), 400, "invalid_rewrap_answer"},
		{map[string]any{"generation": 2, "answer": testRewrapAnswer()}, 409, "stale_generation"},
	} {
		if st, doc := tb.call(t, "operator-key", "POST", base+"/rewrap", tc.body); st != tc.st || vmErrCode(doc) != tc.code {
			t.Fatalf("%v: %d %v, want %d %s", tc.body, st, doc, tc.st, tc.code)
		}
	}
	// A stopped VM has no guest waiting.
	tb.host.answer = nil
	if st, doc := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1}); st != 200 {
		t.Fatalf("stop: %d %v", st, doc)
	}
	calls = tb.host.count()
	if st, doc := tb.call(t, "operator-key", "POST", base+"/rewrap", map[string]any{"generation": 1, "answer": testRewrapAnswer()}); st != 409 || vmErrCode(doc) != "vm_not_running" {
		t.Fatalf("stopped: %d %v", st, doc)
	}
	if tb.host.count() != calls {
		t.Fatal("the host was called for a refused rewrap")
	}
}

func TestVMsRewrapAnswerOverTheRealSSHExecutor(t *testing.T) {
	// A stand-in ssh on PATH: records its argv and stdin, answers like vm-ctl.sh.
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ncat > \"$0.stdin\"\necho '{\"written\":true}'\n"
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	h := vmHostConfig{SSHTarget: "vmctl@vmh-a.example", SSHKeyFile: "/k/id", KnownHostsFile: "/k/known_hosts"}
	// The largest answer the host takes, byte for byte on stdin, none of it on the command line.
	compact, err := vmRewrapAnswer(json.RawMessage(mustJSON(testRewrapAnswer())))
	if err != nil {
		t.Fatal(err)
	}
	full := append(append([]byte{}, compact...), bytes.Repeat([]byte(" "), vmRewrapAnswerMax-len(compact))...)
	out, exit, err := sshVMExecutor{}.Run(context.Background(), h, full, "rewrap", "vm-0123456789ab", "--generation", "1")
	if err != nil || exit != 0 || strings.TrimSpace(string(out)) != `{"written":true}` {
		t.Fatalf("run: %q %d %v", out, exit, err)
	}
	argv, _ := os.ReadFile(ssh + ".argv")
	got := strings.Split(strings.TrimSpace(string(argv)), "\n")
	if tail := strings.Join(got[len(got)-6:], " "); tail != "-- vmctl@vmh-a.example rewrap vm-0123456789ab --generation 1" {
		t.Fatalf("argv tail %q", tail)
	}
	if bytes.Contains(argv, []byte("cathedral.vm")) || bytes.Contains(argv, compact[:20]) {
		t.Fatalf("the answer reached argv: %s", argv)
	}
	if in, _ := os.ReadFile(ssh + ".stdin"); !bytes.Equal(in, full) || len(in) != vmRewrapAnswerMax {
		t.Fatalf("stdin %d bytes", len(in))
	}
	// A bundle id (64 hex) and an op_id fit vmArgRE: rebundle passes the same check.
	if _, exit, err := (sshVMExecutor{}).Run(context.Background(), h, nil, "rebundle", "vm-0123456789ab", "--generation", "0",
		"--from", testBundle1, "--to", testBundle2, "--expect-revision", "0", "--op-id", testOpID); err != nil || exit != 0 {
		t.Fatalf("rebundle args refused: %d %v", exit, err)
	}
	// And the route end to end through the real executor: the compacted answer on stdin.
	tb := newVMTestBroker(t, true)
	_, base := vmRunning(t, tb)
	tb.b.vms.exec = sshVMExecutor{}
	if st, doc := tb.call(t, "operator-key", "POST", base+"/rewrap", map[string]any{"generation": 1, "answer": testRewrapAnswer()}); st != 200 {
		t.Fatalf("rewrap over ssh: %d %v", st, doc)
	}
	if in, _ := os.ReadFile(ssh + ".stdin"); !bytes.Equal(in, compact) {
		t.Fatalf("route stdin %q", in)
	}
}

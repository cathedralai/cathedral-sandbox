package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The answer vector the host's tests use (tests/fixtures/vm_mailbox_v1.json): the broker's
// canonical bytes must be the host's, byte for byte.
func rewrapVector(t *testing.T) (map[string]any, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "tests", "fixtures", "vm_mailbox_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vec struct {
		Answer struct {
			Document map[string]any `json:"document"`
			Body     string         `json:"body_utf8"`
		} `json:"answer"`
	}
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	return vec.Answer.Document, vec.Answer.Body
}

func TestVMsRewrapAnswerIsTheHostsCanonicalBytes(t *testing.T) {
	doc, body := rewrapVector(t)
	// Any key order and spacing in, the canonical body out.
	loose := `{ "ct": "` + doc["ct"].(string) + `", "schema": "` + vmRewrapSchema + `",
	  "nonce": "` + doc["nonce"].(string) + `", "offer_sha256": "` + doc["offer_sha256"].(string) + `",
	  "epk": "` + doc["epk"].(string) + `" }`
	got, err := vmRewrapAnswer(json.RawMessage(loose))
	if err != nil || string(got) != body {
		t.Fatalf("canonical: %v\n got %s\nwant %s", err, got, body)
	}
	with := func(change map[string]any) json.RawMessage {
		a := map[string]any{}
		for k, v := range doc {
			a[k] = v
		}
		for k, v := range change {
			if v == nil {
				delete(a, k)
			} else {
				a[k] = v
			}
		}
		return json.RawMessage(mustJSON(a))
	}
	for name, raw := range map[string]json.RawMessage{
		"empty":           nil,
		"a string":        json.RawMessage(`"x"`),
		"an array":        json.RawMessage(`[]`),
		"unknown field":   with(map[string]any{"algorithm": "x"}),
		"missing ct":      with(map[string]any{"ct": nil}),
		"another schema":  with(map[string]any{"schema": "cathedral.vm.rewrap-answer/v2"}),
		"uppercase hex":   with(map[string]any{"offer_sha256": strings.ToUpper(doc["offer_sha256"].(string))}),
		"47-byte ct":      with(map[string]any{"ct": base64.StdEncoding.EncodeToString(make([]byte, 47))}),
		"unpadded epk":    with(map[string]any{"epk": strings.TrimRight(doc["epk"].(string), "=")}),
		"number nonce":    with(map[string]any{"nonce": 12}),
		"two objects":     json.RawMessage(body + body),
		"13-byte nonce":   with(map[string]any{"nonce": base64.StdEncoding.EncodeToString(make([]byte, 13))}),
		"non-base64 epk":  with(map[string]any{"epk": strings.Repeat("!", 44)}),
		"short sha256":    with(map[string]any{"offer_sha256": "ab"}),
		"null schema":     with(map[string]any{"schema": json.RawMessage("null")}),
		"nested object":   with(map[string]any{"ct": map[string]any{}}),
		"escaped unicode": json.RawMessage(strings.Replace(body, `"schema"`, `"schéma"`, 1)),
	} {
		if _, err := vmRewrapAnswer(raw); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func TestVMsRewrapSendsTheAnswerOnStdinOnly(t *testing.T) {
	doc, body := rewrapVector(t)
	tb := newVMTestBroker(t, true)
	id, base := vmRunning(t, tb)
	tb.host.answer = func([]string) ([]byte, int, error) {
		return []byte(`{"name":"` + id + `","generation":1,"written":true}` + "\n"), 0, nil
	}
	st, out := tb.call(t, "operator-key", "POST", base+"/rewrap", map[string]any{"generation": 1, "answer": doc})
	if st != 200 || out["rewrap"].(map[string]any)["written"] != true {
		t.Fatalf("rewrap: %d %v", st, out)
	}
	if got := tb.host.last(); strings.Join(got[1:], " ") != "rewrap "+id+" --generation 1" {
		t.Fatalf("argv %v", got)
	}
	if in := tb.host.stdin[len(tb.host.stdin)-1]; in != body {
		t.Fatalf("stdin %q", in)
	}
	calls := tb.host.count()
	for _, tc := range []struct {
		body any
		st   int
		code string
	}{
		{map[string]any{"answer": doc}, 400, "invalid_generation"},
		{map[string]any{"generation": 0, "answer": doc}, 400, "invalid_generation"},
		{map[string]any{"generation": 1}, 400, "invalid_rewrap_answer"},
		{map[string]any{"generation": 1, "answer": "x"}, 400, "invalid_rewrap_answer"},
		{map[string]any{"generation": 1, "answer": doc, "extra": 1}, 400, "invalid_json"},
		{map[string]any{"generation": 2, "answer": doc}, 409, "stale_generation"},
	} {
		if st, out := tb.call(t, "operator-key", "POST", base+"/rewrap", tc.body); st != tc.st || vmErrCode(out) != tc.code {
			t.Fatalf("%v: %d %v, want %d %s", tc.body, st, out, tc.st, tc.code)
		}
	}
	// A stopped VM has no guest waiting.
	tb.host.answer = nil
	if st, out := tb.call(t, "operator-key", "POST", base+"/stop", map[string]any{"generation": 1}); st != 200 {
		t.Fatalf("stop: %d %v", st, out)
	}
	calls = tb.host.count()
	if st, out := tb.call(t, "operator-key", "POST", base+"/rewrap", map[string]any{"generation": 1, "answer": doc}); st != 409 || vmErrCode(out) != "vm_not_running" {
		t.Fatalf("stopped: %d %v", st, out)
	}
	if tb.host.count() != calls {
		t.Fatal("the host was called for a refused rewrap")
	}
}

func TestVMsRewrapMapsHostRefusalsByExitAndToken(t *testing.T) {
	doc, _ := rewrapVector(t)
	tb := newVMTestBroker(t, true)
	_, base := vmRunning(t, tb)
	for _, tc := range []struct {
		token    string
		exit, st int
		code     string
	}{
		{"invalid_rewrap_answer", 2, 400, "invalid_rewrap_answer"},
		{"stale_generation", 3, 409, "stale_generation"},
		{"generation_closed", 3, 409, "generation_closed"},
		{"no_rewrap_offer", 3, 409, "no_rewrap_offer"},
		{"rewrap_offer_changed", 3, 409, "rewrap_offer_changed"},
		{"mailbox_invalid", 3, 409, "mailbox_invalid"},
		{"mailbox_invalid", 1, 502, "vm_host_refused"},
		{"stale_selection", 19, 502, "vm_host_refused"}, // rebundle's, not this route's
		{"internal", 1, 502, "vm_host_refused"},
	} {
		answer, exit := []byte(`{"error":"`+tc.token+`"}`), tc.exit
		tb.host.answer = func([]string) ([]byte, int, error) { return answer, exit, nil }
		if st, out := tb.call(t, "operator-key", "POST", base+"/rewrap", map[string]any{"generation": 1, "answer": doc}); st != tc.st || vmErrCode(out) != tc.code {
			t.Fatalf("%s exit %d: %d %v, want %d %s", tc.token, tc.exit, st, out, tc.st, tc.code)
		}
	}
}

func TestVMsRewrapAnswerOverTheRealSSHExecutor(t *testing.T) {
	doc, body := rewrapVector(t)
	// A stand-in ssh on PATH: records its argv and stdin, answers like vm-ctl.sh.
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$0.argv\"\ncat > \"$0.stdin\"\necho '{\"written\":true}'\n"
	ssh := filepath.Join(dir, "ssh")
	if err := os.WriteFile(ssh, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	h := vmHostConfig{SSHTarget: "vmctl@vmh-a.example", SSHKeyFile: "/k/id", KnownHostsFile: "/k/known_hosts"}
	// A full-size envelope (the host's bound), byte for byte on stdin, none of it on the command line.
	full := append([]byte(body), bytes.Repeat([]byte(" "), vmRewrapAnswerMax-len(body))...)
	args := []string{"rewrap", "vm-0123456789ab", "--generation", "1"}
	out, exit, err := sshVMExecutor{}.Run(context.Background(), h, full, args...)
	if err != nil || exit != 0 || strings.TrimSpace(string(out)) != `{"written":true}` {
		t.Fatalf("run: %q %d %v", out, exit, err)
	}
	argv, _ := os.ReadFile(ssh + ".argv")
	got := strings.Split(strings.TrimSpace(string(argv)), "\n")
	if tail := strings.Join(got[len(got)-len(args)-2:], " "); tail != "-- vmctl@vmh-a.example "+strings.Join(args, " ") {
		t.Fatalf("argv tail %q", tail)
	}
	if bytes.Contains(argv, []byte("cathedral.vm")) || bytes.Contains(argv, []byte(doc["epk"].(string))) {
		t.Fatalf("the answer reached argv: %s", argv)
	}
	if in, _ := os.ReadFile(ssh + ".stdin"); !bytes.Equal(in, full) || len(in) != vmRewrapAnswerMax {
		t.Fatalf("stdin %d bytes", len(in))
	}
	// And the route end to end through the real executor: the canonical body on stdin.
	tb := newVMTestBroker(t, true)
	_, base := vmRunning(t, tb)
	tb.b.vms.exec = sshVMExecutor{}
	if st, out := tb.call(t, "operator-key", "POST", base+"/rewrap", map[string]any{"generation": 1, "answer": doc}); st != 200 {
		t.Fatalf("rewrap over ssh: %d %v", st, out)
	}
	if in, _ := os.ReadFile(ssh + ".stdin"); string(in) != body {
		t.Fatalf("route stdin %q", in)
	}
}

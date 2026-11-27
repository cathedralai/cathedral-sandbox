package main

import (
	"context"
	"strings"
	"testing"
)

// AB#999 VM spec r2 section 9: the host ledger refuses create and start with
// exit 5 and {"error":"host_capacity","resource":...}. The broker answers 409
// no_vm_capacity; every other exit 5 stays 502 vm_host_refused.

func hostCapacityAnswer(cmd, resource string) func([]string) ([]byte, int, error) {
	return func(args []string) ([]byte, int, error) {
		if args[0] == cmd {
			return []byte(`{"detail":"host text the client never sees","error":"host_capacity","resource":"` + resource + `"}` + "\n"), vmExitConflict, nil
		}
		return (&fakeVMHost{}).Run(context.Background(), vmHostConfig{}, nil, args...)
	}
}

func vmErrMessage(doc map[string]any) string {
	if e, ok := doc["error"].(map[string]any); ok {
		s, _ := e["message"].(string)
		return s
	}
	return ""
}

func TestVMsHostCapacityRefusedCreateIs409AndLeavesNoRecord(t *testing.T) {
	tb := newVMTestBroker(t, true)
	tb.host.answer = hostCapacityAnswer("create", "memory")
	req := map[string]any{"account": "acct-1", "vcpus": 2, "mem_gib": 4, "disk_gib": 20,
		"ssh_public_key": testED25519Key(), "host": "vmh-a", "request_id": "req-1"}
	st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms", req)
	if st != 409 || vmErrCode(doc) != "no_vm_capacity" {
		t.Fatalf("host_capacity create: %d %v", st, doc)
	}
	if msg := vmErrMessage(doc); !strings.Contains(msg, "(memory)") || strings.Contains(msg, "host text") {
		t.Fatalf("message: %q", msg)
	}
	if last := tb.host.last(); len(last) < 2 || last[1] != "create" {
		t.Fatalf("the host was not asked: %v", last)
	}
	// Nothing is kept: no record, the port is free again and the same request id may retry.
	if _, doc := tb.call(t, "operator-key", "GET", "/v1/broker/vms", nil); len(doc["vms"].([]any)) != 0 {
		t.Fatalf("a refused create left a record: %v", doc)
	}
	tb.host.answer = nil
	st, doc = tb.call(t, "operator-key", "POST", "/v1/broker/vms", req)
	if st != 201 || doc["ssh_port"] != float64(22000) {
		t.Fatalf("retry after the refusal: %d %v", st, doc)
	}
}

func TestVMsHostCapacityRefusedStartIs409AndStaysStopped(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	base := "/v1/broker/vms/" + id
	now := tb.now.Unix()
	if st, doc := tb.call(t, "operator-key", "POST", base+"/authorize", map[string]any{"paid_through": now + 300, "generation": 1}); st != 200 {
		t.Fatalf("authorize: %d %v", st, doc)
	}
	for _, res := range []string{"asid", "disk", "kit_unaccounted"} {
		tb.host.answer = hostCapacityAnswer("start", res)
		st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil)
		if st != 409 || vmErrCode(doc) != "no_vm_capacity" || !strings.Contains(vmErrMessage(doc), "("+res+")") {
			t.Fatalf("host_capacity start (%s): %d %v", res, st, doc)
		}
		// A refused first attempt goes back to stopped in the old generation; the authorization stays.
		_, doc = tb.call(t, "operator-key", "GET", base, nil)
		if doc["desired_state"] != vmStateStopped || doc["generation"] != float64(0) || doc["authorized_generation"] != float64(1) {
			t.Fatalf("after a refused start (%s): %v", res, doc)
		}
	}
	tb.host.answer = nil
	if st, doc := tb.call(t, "operator-key", "POST", base+"/start", nil); st != 200 || doc["generation"] != float64(1) {
		t.Fatalf("start once there is room: %d %v", st, doc)
	}
}

func TestVMsHostExit5OtherThanCapacityStays502(t *testing.T) {
	tb := newVMTestBroker(t, true)
	tb.host.answer = func(args []string) ([]byte, int, error) {
		return []byte(`{"detail":"VM exists","error":"exists"}` + "\n"), vmExitConflict, nil
	}
	st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms",
		map[string]any{"account": "acct-1", "vcpus": 2, "mem_gib": 4, "disk_gib": 20, "ssh_public_key": testED25519Key()})
	if st != 502 || vmErrCode(doc) != "vm_host_refused" || !strings.Contains(vmErrMessage(doc), "exit 5") {
		t.Fatalf("exit 5 exists: %d %v", st, doc)
	}
	tb.host.answer = nil
	id := tb.create(t, nil)["id"].(string)
	tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/authorize", map[string]any{"paid_through": tb.now.Unix() + 300, "generation": 1})
	tb.host.answer = func(args []string) ([]byte, int, error) {
		return []byte(`{"detail":"no VM named x","error":"not_found"}` + "\n"), vmExitConflict, nil
	}
	if st, doc := tb.call(t, "operator-key", "POST", "/v1/broker/vms/"+id+"/start", nil); st != 502 || vmErrCode(doc) != "vm_host_refused" {
		t.Fatalf("exit 5 not_found: %d %v", st, doc)
	}
}

func TestVMCapacityRefusalReadsOnlyTheLedgerCode(t *testing.T) {
	for _, tc := range []struct {
		out      string
		resource string
		ok       bool
	}{
		{`{"error":"host_capacity","resource":"memory"}`, "memory", true},
		{`{"error":"host_capacity","resource":"custom_guest_host","detail":"x"}` + "\n", "custom_guest_host", true},
		{"noise on an earlier line\n" + `{"error":"host_capacity","resource":"vcpu"}`, "vcpu", true},
		// A host_capacity refusal with a name the broker does not know is still a 409, without the name.
		{`{"error":"host_capacity","resource":"../../etc/passwd"}`, "", true},
		{`{"error":"host_capacity"}`, "", true},
		{`{"error":"exists","resource":"memory"}`, "", false},
		{`{"code":"host_capacity"}`, "", false},
		{`not json`, "", false},
		{``, "", false},
	} {
		res, ok := vmCapacityRefusal([]byte(tc.out))
		if res != tc.resource || ok != tc.ok {
			t.Fatalf("%q: got (%q, %v), want (%q, %v)", tc.out, res, ok, tc.resource, tc.ok)
		}
	}
}

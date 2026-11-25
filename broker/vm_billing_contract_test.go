package main

import (
	"testing"
	"time"
)

// Billing contract regressions for AB#992 against AB#991's operator interface.
// Only the existing fake host is used; no SSH, resources, or credit are involved.
func billingContractRunningVM(t *testing.T) (*vmTestBroker, string) {
	t.Helper()
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	path := "/v1/broker/vms/" + id
	for _, op := range []struct {
		name string
		body map[string]any
	}{
		{"authorize", map[string]any{"generation": 1, "paid_through": tb.now.Unix() + 300}},
		{"start", map[string]any{"generation": 1}},
	} {
		if st, doc := tb.call(t, "operator-key", "POST", path+"/"+op.name, op.body); st != 200 {
			t.Fatalf("setup %s: %d %v", op.name, st, doc)
		}
	}
	return tb, path
}

func TestVMBillingFreshRunCanUseShorterPaidWindow(t *testing.T) {
	tb, path := billingContractRunningVM(t)
	if st, doc := tb.call(t, "operator-key", "POST", path+"/stop", map[string]any{"generation": 1}); st != 200 {
		t.Fatalf("stop: %d %v", st, doc)
	}
	tb.now = tb.now.Add(10 * time.Second)
	// The previous run was settled. Remaining credit funds only 30 seconds
	// of this explicit new run, ending before the old, refunded deadline.
	st, doc := tb.call(t, "operator-key", "POST", path+"/authorize", map[string]any{
		"generation": 2, "paid_through": tb.now.Unix() + 30,
	})
	if st != 200 {
		t.Fatalf("fresh funded generation must accept its own deadline: %d %v", st, doc)
	}
}

func TestVMBillingDelayedStopMustNotStopNewRun(t *testing.T) {
	tb, path := billingContractRunningVM(t)
	oldStop := map[string]any{"generation": 1}
	if st, doc := tb.call(t, "operator-key", "POST", path+"/stop", oldStop); st != 200 {
		t.Fatalf("first stop: %d %v", st, doc)
	}
	tb.now = tb.now.Add(10 * time.Second)
	for _, op := range []struct {
		name string
		body map[string]any
	}{
		{"authorize", map[string]any{"generation": 2, "paid_through": tb.now.Unix() + 300}},
		{"start", map[string]any{"generation": 2}},
	} {
		if st, doc := tb.call(t, "operator-key", "POST", path+"/"+op.name, op.body); st != 200 {
			t.Fatalf("new run %s: %d %v", op.name, st, doc)
		}
	}
	before := tb.host.count()
	st, doc := tb.call(t, "operator-key", "POST", path+"/stop", oldStop)
	if tb.host.count() != before || doc["desired_state"] == "stopped" {
		t.Fatalf("delayed generation-1 Stop reached generation-2 host: status=%d body=%v last_call=%v", st, doc, tb.host.last())
	}
}

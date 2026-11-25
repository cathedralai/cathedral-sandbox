package main

import "testing"

// AB#992 can cancel after authorize is delivered but before start is sent.
func TestVMBillingStopCancelsFundedButNotStartedRun(t *testing.T) {
	tb := newVMTestBroker(t, true)
	id := tb.create(t, nil)["id"].(string)
	path := "/v1/broker/vms/" + id
	st, doc := tb.call(t, "operator-key", "POST", path+"/authorize", map[string]any{
		"generation": 1, "paid_through": tb.now.Unix() + 300,
	})
	if st != 200 {
		t.Fatalf("authorize: %d %v", st, doc)
	}
	// A user Stop or cancelled start closes this run. It must not be necessary
	// to start paid compute first just to obtain a Stop receipt.
	st, doc = tb.call(t, "operator-key", "POST", path+"/stop", map[string]any{"generation": 1})
	if st != 200 {
		t.Fatalf("cannot cancel authorized unstarted generation: %d %v", st, doc)
	}
	if doc["generation"] != float64(1) || doc["desired_state"] != "stopped" || doc["stopped_at"] == float64(0) {
		t.Fatalf("missing fenced terminal receipt: %v", doc)
	}
	before := tb.host.count()
	st, doc = tb.call(t, "operator-key", "POST", path+"/start", map[string]any{"generation": 1})
	if st == 200 || tb.host.count() != before {
		t.Fatalf("late Start revived cancelled run: %d %v", st, doc)
	}
}

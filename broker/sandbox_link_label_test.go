package main

import "testing"

// AB#389: the Cathedral API names the sandbox a create is for in the
// cathedral_sandbox_id label, and the hotel's guest signs it into the create
// receipt. The broker must hand the label to the hotel exactly as the guest
// sent it; only its own broker_guest and broker_batch labels are the broker's.
func TestCreateLabelsReachTheHotelAsTheGuestSentThem(t *testing.T) {
	tc := r6Chain(t, "", nil)
	const sandbox = "0f1e2d3c-4b5a-4968-8776-655443322110"
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "labels": map[string]any{
		"cathedral_sandbox_id": sandbox, "customer": "ditto", guestLabel: "someone-else", batchLabel: "mine"}})
	labels, _ := r6LastCreate(tc)["labels"].(map[string]any)
	if labels["cathedral_sandbox_id"] != sandbox || labels["customer"] != "ditto" {
		t.Fatalf("the guest's labels did not reach the hotel as sent: %v", labels)
	}
	if labels[guestLabel] != "g1" || labels[batchLabel] == "mine" || labels[batchLabel] == nil {
		t.Fatalf("broker_guest and broker_batch must be the broker's: %v", labels)
	}
}

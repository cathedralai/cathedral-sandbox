package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// refuseDind answers a Docker-in-Docker create on hotel id as a hotel API with
// CATHEDRAL_ALLOW_PRIVILEGED_DIND=0 does (cathedral/sandbox_guest.py), as every
// sealed hotel does once AB#576 ships.
func refuseDind(id string) func(string, *fakeHotel, http.Handler) http.Handler {
	return func(hotelID string, f *fakeHotel, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hotelID == id && r.URL.Path == "/v1/sandboxes" && r.Method == "POST" {
				raw, _ := io.ReadAll(r.Body)
				var body map[string]any
				_ = json.Unmarshal(raw, &body)
				image, _ := body["image"].(string)
				if strings.Contains(image, "docker:") && strings.Contains(image, "dind") {
					writeErr(w, 403, "privileged_dind_disabled", "DinD requires CATHEDRAL_ALLOW_PRIVILEGED_DIND=1")
					return
				}
				r.Body = io.NopCloser(strings.NewReader(string(raw)))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func TestDindRefusalIsTheGuestsErrorAndDoesNotRestTheHotel(t *testing.T) {
	tc := r6Chain(t, "", refuseDind("a"))
	status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "docker:28-dind", "hotels": []string{"a"}})
	if status != 403 || errCode(doc) != "privileged_dind_disabled" {
		t.Fatalf("DinD create on a hotel without privileged rooms: %d %v", status, doc)
	}
	h := tc.b.hotelByID("a")
	tc.b.mu.Lock()
	resting, failed := !h.backoffUntil.IsZero(), h.failed
	tc.b.mu.Unlock()
	if resting || failed != 0 {
		t.Fatalf("a DinD refusal rested the hotel (backoff %v, failed %d)", resting, failed)
	}
	// The next guest's plain create lands on the same hotel at once.
	if id := tc.room(t, "key2", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}}); !strings.HasPrefix(id, "a.") {
		t.Fatalf("plain create after a DinD refusal landed on %q", id)
	}
}

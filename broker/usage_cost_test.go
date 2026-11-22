package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// AB#870: a hotel prices /v1/usage with an illustrative rate card (about 8x list on
// 21 Nov 2026). A guest gets hours only, on the native and the compat route, and a
// marker saying where prices are. Unknown fields (a miner kit's own cost keys) never
// pass through; an error part stays an error; a non-JSON 200 becomes unavailable.
func TestGuestUsageCarriesHoursNotHotelPrices(t *testing.T) {
	tc := newChain(t)
	hotelDoc := `{"group_by":"label.job","currency":"USD","groups":{"agent-ide":{"sandbox_hours":2,"vcpu_hours":4,"gib_hours":8,"cost_usd":0.1592,"list_price_usd":1}},` +
		`"snapshot_gib_months":0.5,"snapshot_cost_usd":0.04,"total_cost_usd":0.1992,"pricing":{"gib_hour_usd":0.0149},"reference":{"daytona":0.116}}`
	answers := map[string]func(w http.ResponseWriter){
		"a": func(w http.ResponseWriter) { io.WriteString(w, hotelDoc) },
		"b": func(w http.ResponseWriter) { w.WriteHeader(500) },
		"c": func(w http.ResponseWriter) { io.WriteString(w, "not json") },
	}
	for id, answer := range answers {
		answer := answer
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/usage" {
				w.WriteHeader(404)
				return
			}
			if !strings.Contains(r.URL.RawQuery, "broker_guest") {
				t.Errorf("usage asked without the guest label: %s", r.URL.RawQuery)
			}
			answer(w)
		}))
		t.Cleanup(s.Close)
		tc.b.hotelByID(id).cfg.API = s.URL
	}
	for _, ua := range []string{"curl/8", "ctcli/0.6.1"} {
		req, _ := http.NewRequest("GET", tc.srv.URL+"/v1/usage", nil)
		req.Header.Set("Authorization", "Bearer key1")
		req.Header.Set("User-Agent", ua)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d %s", ua, resp.StatusCode, raw)
		}
		for _, leak := range []string{"cost_usd", "total_cost_usd", "snapshot_cost_usd", "list_price_usd", "pricing", "reference", "currency", "0.1592", "0.0149"} {
			if strings.Contains(string(raw), `"`+leak+`"`) || strings.Contains(string(raw), leak+",") || strings.Contains(string(raw), leak+"}") {
				t.Errorf("%s: guest usage carries %q: %s", ua, leak, raw)
			}
		}
		var doc struct {
			Hotels   map[string]map[string]any `json:"hotels"`
			Cost     string                    `json:"cost"`
			PriceDoc string                    `json:"price_doc"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v %s", ua, err, raw)
		}
		if doc.Cost != "not_priced_here" || doc.PriceDoc != "https://cathedral.computer/pricing/" {
			t.Errorf("%s: missing price marker: %s", ua, raw)
		}
		a := doc.Hotels["a"]
		g, _ := a["groups"].(map[string]any)["agent-ide"].(map[string]any)
		if g["sandbox_hours"] != 2.0 || g["vcpu_hours"] != 4.0 || g["gib_hours"] != 8.0 || a["snapshot_gib_months"] != 0.5 || a["group_by"] != "label.job" {
			t.Errorf("%s: hours lost: %v", ua, a)
		}
		if doc.Hotels["b"]["error"] != "unavailable" || doc.Hotels["c"]["error"] != "unavailable" {
			t.Errorf("%s: error parts: b=%v c=%v", ua, doc.Hotels["b"], doc.Hotels["c"])
		}
	}
}

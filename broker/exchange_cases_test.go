package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Exchange cases: real exchanges between the API and this broker, captured
// in the pair run of 21 Nov 2026 (API P2 1f8b0ab, broker 8d1b9a4). The API
// repository holds the same bytes and tests its side against them, so a
// change to the shape on either side fails a test in that repository. The
// two sides were reviewed apart and their first joint run found mismatches;
// these files are the contract they share.
//
//	testdata/exchange-meter-page-mixed.json
//	  sha256 40cb93fb4f5c1f80a2179fd81c470bae08ef8c7b5bce2f68f0438d98511c511a
//	  GET /v1/broker/usage-meter?after=28&limit=500, 18 readings
//	testdata/exchange-allowance-put-200.json
//	  sha256 e4f9c9693356da7ed711593fedce20a149d9ebdbb2bca5660a7fbc3cdf1dbf21
//	  PUT /v1/broker/guests/g-small/allowance and its 200 answer
//
// Change these files only together with the API repository's copies.
const (
	exchangeMeterPageFile    = "testdata/exchange-meter-page-mixed.json"
	exchangeMeterPageSHA256  = "40cb93fb4f5c1f80a2179fd81c470bae08ef8c7b5bce2f68f0438d98511c511a"
	exchangeAllowancePutFile = "testdata/exchange-allowance-put-200.json"
	exchangeAllowancePutSHA  = "e4f9c9693356da7ed711593fedce20a149d9ebdbb2bca5660a7fbc3cdf1dbf21"
)

// exchangeCase is one captured request and its answer.
type exchangeCase struct {
	Method       string          `json:"method"`
	Path         string          `json:"path"`
	RequestBody  json.RawMessage `json:"request_body"`
	Status       int             `json:"status"`
	ResponseBody json.RawMessage `json:"response_body"`
}

func loadExchangeCase(t *testing.T, path, wantSHA256 string) exchangeCase {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != wantSHA256 {
		t.Fatalf("%s has sha256 %x, want %s: the API repository holds the same bytes, so change both copies or neither", path, sum, wantSHA256)
	}
	var c exchangeCase
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return c
}

// jsonShape is the JSON type of each field of one JSON object: string,
// integer, number (not a whole number as written), boolean, null, array or
// object.
func jsonShape(t *testing.T, what string, raw []byte) map[string]string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatalf("%s is not one JSON object: %v: %s", what, err, raw)
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		switch x := v.(type) {
		case nil:
			out[k] = "null"
		case bool:
			out[k] = "boolean"
		case string:
			out[k] = "string"
		case json.Number:
			out[k] = "number"
			if _, err := x.Int64(); err == nil {
				out[k] = "integer"
			}
		case []any:
			out[k] = "array"
		case map[string]any:
			out[k] = "object"
		}
	}
	return out
}

// shapeDiff names every field whose presence or JSON type differs between
// the captured case and what the broker served.
func shapeDiff(captured, served map[string]string) []string {
	var out []string
	for k, ct := range captured {
		switch st, ok := served[k]; {
		case !ok:
			out = append(out, fmt.Sprintf("field %q (%s) is in the captured case but not served by the broker", k, ct))
		case st != ct:
			out = append(out, fmt.Sprintf("field %q is %s in the captured case but %s from the broker", k, ct, st))
		}
	}
	for k, st := range served {
		if _, ok := captured[k]; !ok {
			out = append(out, fmt.Sprintf("field %q (%s) is served by the broker but not in the captured case", k, st))
		}
	}
	sort.Strings(out)
	return out
}

func wantSameShape(t *testing.T, what string, captured, served map[string]string) {
	t.Helper()
	for _, d := range shapeDiff(captured, served) {
		t.Errorf("%s: %s", what, d)
	}
}

// readingKind is a reading's state and whether it is billable: an absent
// billable field means billable, false means not billable.
func readingKind(t *testing.T, raw []byte) (kind, schema string) {
	t.Helper()
	var r map[string]any
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("reading %s: %v", raw, err)
	}
	billable := "billable"
	if v, ok := r["billable"]; ok {
		billable = fmt.Sprintf("billable %v", v)
		if v == false {
			billable = "not billable"
		}
	}
	state, _ := r["state"].(string)
	schema, _ = r["schema"].(string)
	return state + " " + billable, schema
}

// The meter page the route serves has exactly the field names and JSON types
// of the captured page, for the page and for each kind of reading it holds:
// a billable running reading, and the running and ended readings of a failed
// create's room, which are not billable. Values that differ by run (ids,
// times, seqs) are not compared.
func TestExchangeMeterPageMatchesTheCapturedCase(t *testing.T) {
	c := loadExchangeCase(t, exchangeMeterPageFile, exchangeMeterPageSHA256)
	var captured struct {
		Readings []json.RawMessage `json:"readings"`
	}
	if err := json.Unmarshal(c.ResponseBody, &captured); err != nil {
		t.Fatal(err)
	}
	type kindCase struct {
		shape  map[string]string
		schema string
	}
	kinds := map[string]kindCase{}
	for _, r := range captured.Readings {
		kind, schema := readingKind(t, r)
		k := kindCase{jsonShape(t, "captured "+kind+" reading", r), schema}
		if prev, ok := kinds[kind]; ok && !reflect.DeepEqual(prev, k) {
			t.Fatalf("captured %s readings differ among themselves: %v and %v", kind, prev, k)
		}
		kinds[kind] = k
	}
	for _, kind := range []string{"running billable", "running not billable", "ended not billable"} {
		if _, ok := kinds[kind]; !ok {
			t.Fatalf("the captured page holds no %s reading; kinds %v", kind, kinds)
		}
	}

	tc := newChainState(t, t.TempDir())
	// A billable running room, as in TestUsageMeterBrokerHooksAndRoute.
	tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}, "resources": map[string]any{"vcpu": 1, "memory_gib": 4}})
	syncNow(tc, "b")
	// A failed create whose room the hotel started: the cleanup meters that
	// room not billable, running then ended, as in
	// TestUsageMeterOrphanCleanupMetersTheRoom.
	f := tc.hotels["c"]
	f.mu.Lock()
	f.createFail, f.createFailAfterStart = 500, true
	f.mu.Unlock()
	if status, doc := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}}); status == 202 {
		t.Fatalf("failed create: %d %v", status, doc)
	}
	mustFlush(t, tc.b.usageMeter)

	status, raw, err := rawCall(tc, "operator-key", "", c.Method, "/v1/broker/usage-meter?after=0&limit=500", nil)
	if err != nil || status != c.Status {
		t.Fatalf("meter route: %d %v %s, want %d", status, err, raw, c.Status)
	}
	wantSameShape(t, "page", jsonShape(t, "captured page", c.ResponseBody), jsonShape(t, "served page", raw))
	var served struct {
		Readings []json.RawMessage `json:"readings"`
	}
	if err := json.Unmarshal(raw, &served); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, r := range served.Readings {
		kind, schema := readingKind(t, r)
		want, ok := kinds[kind]
		if !ok {
			t.Errorf("the broker served a %s reading, a kind the captured page does not hold: %s", kind, r)
			continue
		}
		seen[kind]++
		wantSameShape(t, kind+" reading", want.shape, jsonShape(t, "served "+kind+" reading", r))
		if schema != want.schema {
			t.Errorf("%s reading: schema %q, the captured case has %q", kind, schema, want.schema)
		}
	}
	for kind := range kinds {
		if seen[kind] == 0 {
			t.Errorf("the broker served no %s reading; served %s", kind, raw)
		}
	}
}

// The captured allowance PUT body, sent unchanged to a guest metered in the
// config, is accepted, and the allowance the broker then reports matches it.
// The same body with one more field is refused 400 invalid_json, so the body
// cannot grow a field without a broker change.
func TestExchangeAllowancePutMatchesTheCapturedCase(t *testing.T) {
	c := loadExchangeCase(t, exchangeAllowancePutFile, exchangeAllowancePutSHA)
	guest, ok := strings.CutPrefix(c.Path, "/v1/broker/guests/")
	guest, ok2 := strings.CutSuffix(guest, "/allowance")
	if !ok || !ok2 || c.Method != "PUT" || c.Status != 200 {
		t.Fatalf("captured case %s %s %d is not a 200 allowance PUT", c.Method, c.Path, c.Status)
	}
	tc, _ := meteredChain(t, func(cfg *config) {
		g := guestConfig{ID: guest, KeySHA256: sha("key-" + guest)}
		g.Metered = true
		cfg.Guests = append(cfg.Guests, g)
	})

	var grown map[string]json.RawMessage
	if err := json.Unmarshal(c.RequestBody, &grown); err != nil {
		t.Fatal(err)
	}
	grown["reason"] = json.RawMessage(`"covered"`)
	status, raw, err := rawCall(tc, "operator-key", "", c.Method, c.Path, mustMarshal(grown))
	var refusal map[string]any
	_ = json.Unmarshal(raw, &refusal)
	if err != nil || status != 400 || errCode(refusal) != "invalid_json" {
		t.Fatalf("body with a sixth field: %d %v %s, want 400 invalid_json", status, err, raw)
	}
	if v := tc.getAllowance(t, guest); v["cap"] != 0.0 || v["issue"] != 0.0 || v["ledger_seen_at"] != nil {
		t.Fatalf("a refused body changed the guest: %v", v)
	}

	status, raw, err = rawCall(tc, "operator-key", "", c.Method, c.Path, c.RequestBody)
	if err != nil || status != c.Status {
		t.Fatalf("captured body %s: %d %v %s, want %d", c.RequestBody, status, err, raw, c.Status)
	}
	wantSameShape(t, "PUT answer", jsonShape(t, "captured answer", c.ResponseBody), jsonShape(t, "served answer", raw))
	var capturedAnswer, answer, sent map[string]any
	_ = json.Unmarshal(c.ResponseBody, &capturedAnswer)
	_ = json.Unmarshal(raw, &answer)
	_ = json.Unmarshal(c.RequestBody, &sent)
	for k, want := range capturedAnswer {
		if k == "ledger_seen_at" || k == "lease_seconds_left" {
			continue // the broker clock at the PUT
		}
		if answer[k] != want {
			t.Errorf("PUT answer %s = %v, the captured answer has %v", k, answer[k], want)
		}
	}
	view := tc.getAllowance(t, guest)
	for k, want := range sent {
		if view[k] != want {
			t.Errorf("reported allowance %s = %v, the body sent %v", k, view[k], want)
		}
	}
	if view["guest"] != guest || view["metered"] != true || view["lease_fresh"] != true {
		t.Errorf("reported allowance %v", view)
	}
}

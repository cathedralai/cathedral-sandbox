package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// alertClock is a test clock for the alerter.
type alertClock struct{ t time.Time }

func (c *alertClock) now() time.Time { return c.t }

// captureAlerts makes tc's alerter deliverable and returns a function that
// takes the alerts queued since the last call.
func captureAlerts(t *testing.T, tc *testChain, opsChat string) (func() []alertMsg, *alertClock) {
	t.Helper()
	clk := &alertClock{t: time.Now()}
	a := tc.b.alerts
	a.opsChat = opsChat
	a.now = clk.now
	a.post = func(context.Context, alertMsg) error { return nil }
	return func() []alertMsg {
		var out []alertMsg
		for {
			select {
			case m := <-a.queue:
				out = append(out, m)
			default:
				return out
			}
		}
	}, clk
}

func setHealthFail(tc *testChain, id string, fail bool) {
	f := tc.hotels[id]
	f.mu.Lock()
	f.healthFail = fail
	f.mu.Unlock()
}

// goDown makes hotel id miss health with no room call answering, so the
// next sync takes it down.
func alertGoDown(tc *testChain, id string) {
	setHealthFail(tc, id, true)
	setHotel(tc, id, func(h *hotel) { h.lastOK = time.Now().Add(-time.Minute) })
	tc.b.hotelByID(id).lastAnswer.Store(time.Now().Add(-time.Minute).UnixNano())
}

func TestFirstMissedHeartbeatAlertsTheMinerOperatorOnce(t *testing.T) {
	tc := newChain(t)
	take, clk := captureAlerts(t, tc, "-100200")
	setHotel(tc, "a", func(h *hotel) { h.cfg.AlertChatID = "4242" })

	syncNow(tc, "a") // health answers: no alert
	if got := take(); len(got) != 0 {
		t.Fatalf("alert while health answers: %v", got)
	}

	setHealthFail(tc, "a", true)
	syncNow(tc, "a") // first miss: the operator hears at once
	got := take()
	if len(got) != 1 || got[0].ChatID != "4242" || !strings.Contains(got[0].Text, "hotel a") || !strings.Contains(got[0].Text, "missed a heartbeat") {
		t.Fatalf("first miss: %+v", got)
	}

	syncNow(tc, "a") // same streak: no second alert
	if got := take(); len(got) != 0 {
		t.Fatalf("second miss in one streak alerted: %v", got)
	}

	// Health answers, then misses again inside the cooldown: no alert.
	setHealthFail(tc, "a", false)
	syncNow(tc, "a")
	setHealthFail(tc, "a", true)
	clk.t = clk.t.Add(alertCooldown - time.Second)
	syncNow(tc, "a")
	if got := take(); len(got) != 0 {
		t.Fatalf("a flap inside the cooldown alerted: %v", got)
	}
	clk.t = clk.t.Add(time.Hour)
	syncNow(tc, "a") // that streak stays quiet, even after the cooldown
	if got := take(); len(got) != 0 {
		t.Fatalf("a suppressed streak alerted later: %v", got)
	}

	// A new streak after the cooldown alerts again.
	setHealthFail(tc, "a", false)
	syncNow(tc, "a")
	setHealthFail(tc, "a", true)
	clk.t = clk.t.Add(alertCooldown)
	syncNow(tc, "a")
	if got := take(); len(got) != 1 || got[0].ChatID != "4242" {
		t.Fatalf("new streak after the cooldown: %+v", got)
	}
}

func TestHotelThatNeverAnsweredHealthSendsNoMissAlert(t *testing.T) {
	tc := newChain(t)
	take, _ := captureAlerts(t, tc, "-100200")
	setHotel(tc, "b", func(h *hotel) { h.cfg.AlertChatID = "4242" })
	setHealthFail(tc, "b", true)
	syncNow(tc, "b")
	syncNow(tc, "b")
	if got := take(); len(got) != 0 {
		t.Fatalf("alert for a hotel that never answered health: %v", got)
	}
}

func TestMissWithoutOperatorChatIsALogLineOnly(t *testing.T) {
	tc := newChain(t)
	take, _ := captureAlerts(t, tc, "-100200")
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	syncNow(tc, "a")
	setHealthFail(tc, "a", true)
	syncNow(tc, "a")
	if got := take(); len(got) != 0 {
		t.Fatalf("delivery without an operator chat: %v", got)
	}
	if !strings.Contains(buf.String(), "[OPERATOR-ALERT] Cathedral: hotel a missed a heartbeat") {
		t.Fatalf("no log line: %q", buf.String())
	}
}

func TestCustomerAffectingDropAlertsOpsOncePerEpisodeWithoutCustomerData(t *testing.T) {
	tc := newChain(t)
	take, clk := captureAlerts(t, tc, "-100200")
	syncNow(tc, "a")
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}, "labels": map[string]string{"customer_secret": "s3cret-label"}})

	alertGoDown(tc, "a")
	syncNow(tc, "a")
	var ops []alertMsg
	for _, m := range take() {
		if m.ChatID == "-100200" {
			ops = append(ops, m)
		}
	}
	if len(ops) != 1 || !strings.Contains(ops[0].Text, "hotel a is down with 1 customer rooms") {
		t.Fatalf("ops alerts: %+v", ops)
	}
	// No customer data: no broker or hotel room id, guest, label, image or key.
	hid := strings.TrimPrefix(id, "a.")
	for _, bad := range []string{id, hid, "g1", "key1", "s3cret-label", "customer_secret", "alpine", "hotel-key"} {
		if bad != "" && strings.Contains(ops[0].Text, bad) {
			t.Fatalf("ops alert carries %q: %q", bad, ops[0].Text)
		}
	}

	// Still down: no second ops alert, also after the cooldown.
	clk.t = clk.t.Add(time.Hour)
	syncNow(tc, "a")
	if got := take(); len(got) != 0 {
		t.Fatalf("second alert in one down episode: %v", got)
	}

	// Up, then down again after the cooldown: a new episode alerts again.
	setHealthFail(tc, "a", false)
	syncNow(tc, "a")
	alertGoDown(tc, "a")
	clk.t = clk.t.Add(alertCooldown)
	syncNow(tc, "a")
	if got := take(); len(got) != 1 || got[0].ChatID != "-100200" {
		t.Fatalf("new episode: %+v", got)
	}
}

func TestDropOfAnEmptyHotelDoesNotAlertOps(t *testing.T) {
	tc := newChain(t)
	take, _ := captureAlerts(t, tc, "-100200")
	syncNow(tc, "c")
	alertGoDown(tc, "c")
	syncNow(tc, "c")
	for _, m := range take() {
		if m.ChatID == "-100200" {
			t.Fatalf("ops alert for a hotel with no rooms: %v", m)
		}
	}
}

func TestAlertWebhookPostsChatAndTextAndNeverLogsTheURL(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		if strings.Contains(r.URL.Path, "fail") {
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	for _, path := range []string{"/botSECRET-TOKEN/sendMessage", "/botSECRET-TOKEN/fail"} {
		a, err := newAlerter(&alertsConfig{WebhookURLFile: write("url", srv.URL+path), OpsChatID: "-100200"})
		if err != nil {
			t.Fatal(err)
		}
		a.client = srv.Client() // trusts the test server's certificate
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { a.run(ctx); close(done) }()
		a.send("OPS-ALERT", "-100200", "hello")
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			n := len(bodies)
			mu.Unlock()
			if n > 0 || time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond) // let a failure be logged
		cancel()
		<-done
		mu.Lock()
		if len(bodies) != 1 || bodies[0]["chat_id"] != "-100200" || bodies[0]["text"] != "hello" {
			t.Fatalf("%s: bodies %v", path, bodies)
		}
		bodies = nil
		mu.Unlock()
	}
	if strings.Contains(buf.String(), "SECRET-TOKEN") || strings.Contains(buf.String(), srv.URL) {
		t.Fatalf("the webhook URL was logged: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "alert not delivered: status 500") {
		t.Fatalf("failure not logged: %q", buf.String())
	}

	// Plain http and a bad ops chat are refused at load.
	if _, err := newAlerter(&alertsConfig{WebhookURLFile: write("plain", "http://example.invalid/botX/sendMessage")}); err == nil || strings.Contains(err.Error(), "botX") {
		t.Fatalf("http webhook: %v", err)
	}
	if _, err := newAlerter(&alertsConfig{OpsChatID: "not a chat"}); err == nil {
		t.Fatalf("bad ops chat accepted")
	}
}

func TestAlertChatAtJoinAndPatch(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	joinMiner(t, tc, "m1", true, 4, map[string]any{"alert_chat_id": "777"})
	if got := tc.b.hotelByID("m1").alertChat(); got != "777" {
		t.Fatalf("alert chat after join: %q", got)
	}
	if _, doc := tc.call(t, "operator-key", "GET", "/v1/broker/hotels/m1", nil); doc["alert_chat_id"] != nil {
		t.Fatalf("hotel doc shows the alert chat: %v", doc)
	}
	if status, _ := tc.call(t, "operator-key", "POST", "/v1/broker/hotels", map[string]any{"id": "bad", "api": "https://x.invalid", "key": joinKey, "alert_chat_id": "x y"}); status != 400 {
		t.Fatalf("bad chat at join: %d", status)
	}
	if status, _ := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true, "alert_chat_id": "1"}); status != 403 {
		t.Fatalf("enroller PATCH of the alert chat: %d", status)
	}
	if status, _ := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"alert_chat_id": "x y"}); status != 400 {
		t.Fatalf("bad chat PATCH: %d", status)
	}
	if status, doc := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"alert_chat_id": "@cathedral_m1"}); status != 200 {
		t.Fatalf("PATCH: %d %v", status, doc)
	}
	tc.start(t) // the chat survives a restart (hotels.json)
	if got := tc.b.hotelByID("m1").alertChat(); got != "@cathedral_m1" {
		t.Fatalf("alert chat after restart: %q", got)
	}
}

func TestLateHealthWhileRoomCallsAnswerStillAlertsTheOperator(t *testing.T) {
	tc := newChain(t)
	take, _ := captureAlerts(t, tc, "-100200")
	setHotel(tc, "b", func(h *hotel) { h.cfg.AlertChatID = "4242" })
	syncNow(tc, "b")
	setHealthFail(tc, "b", true)
	setHotel(tc, "b", func(h *hotel) { h.lastOK = time.Now().Add(-time.Minute) }) // health late for a minute
	tc.b.hotelByID("b").lastAnswer.Store(time.Now().UnixNano())                   // room calls answer
	syncNow(tc, "b")
	var ok, late bool
	setHotel(tc, "b", func(h *hotel) { ok, late = h.ok, h.healthLate })
	got := take()
	if !ok || !late || len(got) != 1 || got[0].ChatID != "4242" {
		t.Fatalf("ok=%v late=%v alerts=%+v, want the hotel up, health late and one operator alert", ok, late, got)
	}
}

func TestAlertNamesTheMinerHotkeyAndNothingElse(t *testing.T) {
	h := &hotel{cfg: hotelConfig{ID: "m1", Name: "Miner one", MinerHotkey: minerHotkey, API: "https://10.0.0.1:8443", Labels: map[string]string{"x": "y"}}}
	if got, want := hotelAlertName(h), "hotel m1 (Miner one) miner "+minerHotkey; got != want {
		t.Fatalf("name %q, want %q", got, want)
	}
}

func TestConfigFileHotelRefusesAlertChatPatch(t *testing.T) {
	tc := newChain(t)
	if status, _ := tc.call(t, "operator-key", "PATCH", "/v1/broker/hotels/a", map[string]any{"alert_chat_id": "1"}); status != 409 {
		t.Fatalf("PATCH of a config file hotel's alert chat: %d", status)
	}
}

// TestFullQueueKeepsMissRetryable: a saturated alert queue must not consume
// the miss streak, so a later sync can still notify the operator (AB#330).
func TestFullQueueKeepsMissRetryable(t *testing.T) {
	tc := newChain(t)
	clk := &alertClock{t: time.Now()}
	a := tc.b.alerts
	a.now = clk.now
	a.post = func(context.Context, alertMsg) error { return nil }
	a.opsChat = "-100200"
	// Fill the queue so the next send drops.
	for i := 0; i < alertQueueSize; i++ {
		a.queue <- alertMsg{ChatID: "fill", Text: "x"}
	}
	setHotel(tc, "a", func(h *hotel) { h.cfg.AlertChatID = "4242" })
	syncNow(tc, "a")
	setHealthFail(tc, "a", true)
	syncNow(tc, "a")
	var missSent bool
	setHotel(tc, "a", func(h *hotel) { missSent = h.alerts.missSent })
	if missSent {
		t.Fatal("missSent set after a full-queue drop")
	}
	// Drain the filler so a retry can queue.
	for {
		select {
		case <-a.queue:
		default:
			goto drained
		}
	}
drained:
	syncNow(tc, "a") // hotel still unhealthy: retry must queue the operator alert
	var got []alertMsg
	for {
		select {
		case m := <-a.queue:
			got = append(got, m)
		default:
			goto done
		}
	}
done:
	if len(got) != 1 || got[0].ChatID != "4242" {
		t.Fatalf("retry after queue drain: %+v", got)
	}
	setHotel(tc, "a", func(h *hotel) { missSent = h.alerts.missSent })
	if !missSent {
		t.Fatal("missSent still false after a successful queue")
	}
}

// TestWebhookFailureRetriesThenDelivers: a failed first POST must still
// deliver once the webhook recovers, while the hotel stays down (AB#330).
func TestWebhookFailureRetriesThenDelivers(t *testing.T) {
	tc := newChain(t)
	var mu sync.Mutex
	var posts []alertMsg
	fail := true
	a := tc.b.alerts
	a.opsChat = "-100200"
	a.post = func(_ context.Context, m alertMsg) error {
		mu.Lock()
		defer mu.Unlock()
		if fail {
			fail = false
			return errors.New("status 503")
		}
		posts = append(posts, m)
		return nil
	}
	setHotel(tc, "a", func(h *hotel) { h.cfg.AlertChatID = "4242" })
	syncNow(tc, "a")
	id := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"a"}})
	_ = id
	alertGoDown(tc, "a")
	syncNow(tc, "a")
	// Drain queue into run with short deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { a.run(ctx); close(done) }()
	// Give run time to fail once, back off, and succeed.
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(posts)
		mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	var op, ops int
	for _, m := range posts {
		if m.ChatID == "4242" {
			op++
		}
		if m.ChatID == "-100200" {
			ops++
		}
	}
	if op != 1 || ops != 1 {
		t.Fatalf("want one operator and one ops delivery after recovery, got op=%d ops=%d posts=%+v", op, ops, posts)
	}
}

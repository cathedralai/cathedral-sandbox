package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// rebootingGuest is a miner guest that can reboot: each boot has its own
// self-issued TLS key and an attestation whose binding names it.
type rebootingGuest struct {
	*minerHotel
	url  string
	chip byte
	srv  *httptest.Server
	mu   sync.Mutex
	cert *tls.Certificate
}

func newRebootingGuest(t *testing.T, id string) *rebootingGuest {
	t.Helper()
	g := &rebootingGuest{minerHotel: &minerHotel{fakeHotel: &fakeHotel{t: t, snaps: map[string]map[string]any{}}}, chip: chipOf(id)}
	g.slots.Store(4)
	g.srv = httptest.NewUnstartedServer(g.minerHotel)
	// GetConfigForClient runs on every handshake; GetCertificate would not
	// (httptest fills Certificates, and a client dialing an IP sends no SNI).
	g.srv.TLS = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		g.mu.Lock()
		defer g.mu.Unlock()
		return &tls.Config{Certificates: []tls.Certificate{*g.cert}}, nil
	}}
	g.boot(t, attestOpts{})
	g.srv.StartTLS()
	t.Cleanup(g.srv.Close)
	g.url = g.srv.URL
	return g
}

// boot gives the guest a new TLS key and an attestation per o for that key,
// and drops every connection, as a real reboot does.
func (g *rebootingGuest) boot(t *testing.T, o attestOpts) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	o.chip = g.chip
	g.mu.Lock()
	g.cert = &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	g.mu.Unlock()
	g.setAttestation(testAttestationWithTLSPin(t, snpAttestation(t, o), leaf))
	if g.srv != nil {
		g.srv.CloseClientConnections()
	}
}

// joinWithRoom enrolls g as miner hotel id, admits it and starts one room.
func joinWithRoom(t *testing.T, tc *testChain, id string, g *rebootingGuest) (*hotel, string) {
	t.Helper()
	tc.hotels[id] = g.fakeHotel
	if status, doc := tc.call(t, "enroller-key", "POST", "/v1/broker/hotels", map[string]any{
		"id": id, "api": g.url, "health": g.url, "key": joinKey, "sealed": true, "miner_hotkey": minerHotkey,
	}); status != 201 {
		t.Fatalf("join: %d %v", status, doc)
	}
	syncNow(tc, id)
	admitNow(t, tc, id)
	optInMiner(t, tc, "g1")
	status, room := tc.call(t, "key1", "POST", "/v1/sandboxes", map[string]any{"image": "alpine:3.20", "hotels": []string{id}})
	if status != 201 && status != 202 {
		t.Fatalf("create on the miner hotel: %d %v", status, room)
	}
	return tc.b.hotelByID(id), room["id"].(string)
}

// goDown reboots g (its pinned calls now fail), runs one sync step so the
// broker marks the hotel down, and backdates the down time by ago.
func goDown(t *testing.T, tc *testChain, h *hotel, g *rebootingGuest, ago time.Duration) {
	t.Helper()
	g.boot(t, attestOpts{})
	// The last good answers age out of okWindow, as they would in real time.
	tc.b.mu.Lock()
	h.lastOK = h.lastOK.Add(-2 * okWindow)
	tc.b.mu.Unlock()
	h.lastAnswer.Store(time.Now().Add(-2 * okWindow).UnixNano())
	syncNow(tc, h.cfg.ID)
	tc.b.mu.Lock()
	defer tc.b.mu.Unlock()
	if h.ok || h.downSince.IsZero() {
		t.Fatalf("hotel %s still up after its guest rebooted", h.cfg.ID)
	}
	h.downSince = h.downSince.Add(-ago)
}

func TestOperatorForgetsTheRoomsOfADeadMinerHotel(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	h, roomID := joinWithRoom(t, tc, "m1", g)
	goDown(t, tc, h, g, 0)
	forget := "/v1/broker/hotels/m1?forget_rooms=true"
	if status, doc := tc.call(t, "enroller-key", "DELETE", "/v1/broker/hotels/m1", nil); status != 409 || errCode(doc) != "hotel_not_empty" {
		t.Fatalf("leave with rooms: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "enroller-key", "DELETE", forget, nil); status != 403 || errCode(doc) != "enroller_scope" {
		t.Fatalf("the enroll key forgot rooms: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", forget, nil); status != 409 || errCode(doc) != "forget_refused" {
		t.Fatalf("forget before drain: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("drain: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", forget, nil); status != 409 || errCode(doc) != "forget_refused" {
		t.Fatalf("forget before the hotel was down long enough: %d %v", status, doc)
	}
	// Give the room the client id a Cathedral client (the Polaris API) holds.
	const clientID = "0f0e0d0c-0b0a-4000-8000-000000000001"
	tc.b.mu.Lock()
	h.downSince = h.downSince.Add(-minerForgetDownFor)
	for _, rm := range h.rooms {
		rm.uuid = clientID
		tc.b.byUUID[clientID] = rm
	}
	tc.b.mu.Unlock()
	if status, doc := tc.call(t, "operator-key", "DELETE", forget, nil); status != 204 {
		t.Fatalf("operator forget of a dead miner hotel: %d %v", status, doc)
	}
	if status, doc := tc.call(t, "key1", "GET", "/v1/sandboxes/"+roomID, nil); status != 404 {
		t.Fatalf("forgotten room by broker id: %d %v", status, doc)
	}
	// compatRoom answers a tombstoned client id with state "deleted".
	tc.b.compat.mu.Lock()
	tomb, ok := tc.b.compat.tombs[clientID]
	tc.b.compat.mu.Unlock()
	if !ok || tomb.bid != roomID {
		t.Fatalf("forgotten room not tombstoned for its client: %v %+v", ok, tomb)
	}
	if tc.b.hotelByID("m1") != nil {
		t.Fatal("hotel still in the set after the forget")
	}
}

func TestRoomsOfALiveMinerHotelCannotBeForgotten(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	h, roomID := joinWithRoom(t, tc, "m1", g)
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("drain: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	ok := h.ok
	tc.b.mu.Unlock()
	if !ok {
		t.Fatal("test hotel is not up")
	}
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/m1?forget_rooms=true", nil); status != 409 || errCode(doc) != "forget_refused" {
		t.Fatalf("forget on a live hotel: %d %v", status, doc)
	}
	tc.b.mu.Lock()
	used := h.used()
	tc.b.mu.Unlock()
	if status, _ := tc.call(t, "key1", "GET", "/v1/sandboxes/"+roomID, nil); used != 1 || status != 200 {
		t.Fatalf("live room lost: rooms=%d get=%d", used, status)
	}
}

// readyToForget joins g as m1 with one room that has a client id, takes the
// guest down for longer than minerForgetDownFor, and drains the hotel.
func readyToForget(t *testing.T, tc *testChain, g *rebootingGuest) (*hotel, string, string) {
	t.Helper()
	h, roomID := joinWithRoom(t, tc, "m1", g)
	goDown(t, tc, h, g, minerForgetDownFor+time.Minute)
	if status, doc := tc.call(t, "enroller-key", "PATCH", "/v1/broker/hotels/m1", map[string]any{"drain": true}); status != 200 {
		t.Fatalf("drain: %d %v", status, doc)
	}
	const clientID = "0f0e0d0c-0b0a-4000-8000-000000000002"
	tc.b.mu.Lock()
	for _, rm := range h.rooms {
		rm.uuid = clientID
		tc.b.byUUID[clientID] = rm
	}
	tc.b.mu.Unlock()
	return h, roomID, clientID
}

// roomsIntact fails the test unless h still holds its room, its client id
// still finds it, and no tombstone was written.
func roomsIntact(t *testing.T, tc *testChain, h *hotel, clientID string) {
	t.Helper()
	tc.b.mu.Lock()
	used, mapped, leaving := h.used(), tc.b.byUUID[clientID] != nil, h.leaving
	tc.b.mu.Unlock()
	tc.b.compat.mu.Lock()
	_, tomb := tc.b.compat.tombs[clientID]
	tc.b.compat.mu.Unlock()
	if used != 1 || !mapped || tomb || leaving || tc.b.hotelByID("m1") != h {
		t.Fatalf("rooms not intact: rooms=%d mapped=%v tomb=%v leaving=%v hotel=%v", used, mapped, tomb, leaving, tc.b.hotelByID("m1") == h)
	}
}

func TestAFailedWriteDuringForgetKeepsEveryRoom(t *testing.T) {
	forget := "/v1/broker/hotels/m1?forget_rooms=true"
	for name, blocked := range map[string]string{"hotel list": runtimeHotelsFile + ".tmp", "tombstones": stateFile + ".tmp"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			tc := newChainState(t, dir)
			h, _, clientID := readyToForget(t, tc, newRebootingGuest(t, "m1"))
			if err := os.Mkdir(filepath.Join(dir, blocked), 0o700); err != nil {
				t.Fatal(err)
			}
			if status, doc := tc.call(t, "operator-key", "DELETE", forget, nil); status != 500 || errCode(doc) != "state_write_failed" {
				t.Fatalf("forget with a failed write: %d %v", status, doc)
			}
			roomsIntact(t, tc, h, clientID)
		})
	}
}

func TestForgetIsRefusedWhenTheOldGuestAnswersAgain(t *testing.T) {
	tc := newChainState(t, t.TempDir())
	g := newRebootingGuest(t, "m1")
	g.mu.Lock()
	old := g.cert
	g.mu.Unlock()
	h, _, clientID := readyToForget(t, tc, g)
	// The old guest comes back on its attested key before the next sync.
	g.mu.Lock()
	g.cert = old
	g.mu.Unlock()
	g.srv.CloseClientConnections()
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/m1?forget_rooms=true", nil); status != 409 || errCode(doc) != "forget_refused" {
		t.Fatalf("forget of a guest that answers: %d %v", status, doc)
	}
	roomsIntact(t, tc, h, clientID)
	tc.b.mu.Lock()
	down := time.Since(h.downSince)
	tc.b.mu.Unlock()
	if down > time.Minute {
		t.Fatalf("the down interval did not start again: %s", down)
	}
}

func TestForgottenRoomsStayDeletedAfterAnImmediateRestart(t *testing.T) {
	dir := t.TempDir()
	tc := newChainState(t, dir)
	_, _, clientID := readyToForget(t, tc, newRebootingGuest(t, "m1"))
	if status, doc := tc.call(t, "operator-key", "DELETE", "/v1/broker/hotels/m1?forget_rooms=true", nil); status != 204 {
		t.Fatalf("forget: %d %v", status, doc)
	}
	tc2 := newChainState(t, dir) // no save loop tick between the 204 and the restart
	tc2.b.compat.mu.Lock()
	_, tomb := tc2.b.compat.tombs[clientID]
	tc2.b.compat.mu.Unlock()
	if !tomb || tc2.b.hotelByID("m1") != nil {
		t.Fatalf("after restart: tombstone=%v hotel back=%v", tomb, tc2.b.hotelByID("m1") != nil)
	}
}

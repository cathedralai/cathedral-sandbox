package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const testWSKey = "dGhlIHNhbXBsZSBub25jZQ=="

// termWSHotel is the hotel end of a terminal socket: it checks nothing, records
// the handshake it got, answers 101 like cathedral/sandbox_server.py and then
// runs serve on the raw connection.
type termWSHotel struct {
	mu     sync.Mutex
	got    []http.Header
	paths  []string
	accept string // overrides the Sec-WebSocket-Accept answer when set
	serve  func(conn net.Conn, rd *bufio.Reader)
}

func (h *termWSHotel) handle(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.got = append(h.got, r.Header.Clone())
	h.paths = append(h.paths, r.URL.RequestURI())
	accept := h.accept
	h.mu.Unlock()
	if accept == "" {
		accept = wsAccept(r.Header.Get("Sec-WebSocket-Key"))
	}
	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	ticket := r.Header.Get("X-Cathedral-Access-Ticket")
	_, _ = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\nSec-WebSocket-Protocol: cathedral.ticket." + ticket + "\r\nX-Room-Terminal: pty\r\n\r\n")
	_ = brw.Flush()
	h.serve(conn, brw.Reader)
}

func (h *termWSHotel) headers() []http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]http.Header(nil), h.got...)
}

// echoBytes sends back every byte it reads.
func echoBytes(conn net.Conn, rd *bufio.Reader) { _, _ = io.Copy(conn, rd) }

// termWSChain is a chain whose hotel "b" is on the terminal allowlist and answers
// WebSocket handshakes with hotel, a room of key1 on b, and the broker served
// through its production handler (countingWriter included).
func termWSChain(t *testing.T, hotel *termWSHotel) (tc *testChain, room string, srv *httptest.Server) {
	t.Helper()
	tc = newChain(t)
	withTerminalHotels(t, tc, "b")
	tc.hotels["b"].upgrade = hotel.handle
	room = tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"b"}})
	srv = httptest.NewServer(tc.b.handler())
	t.Cleanup(srv.Close)
	return tc, room, srv
}

// termWSDial sends a raw handshake for path with extra headers (a "" value drops
// the default) and returns the connection, its reader and the response.
func termWSDial(t *testing.T, srv *httptest.Server, path string, extra map[string]string, after string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	hdr := map[string]string{
		"Authorization":             "Bearer key1",
		"Upgrade":                   "websocket",
		"Connection":                "keep-alive, Upgrade",
		"Sec-WebSocket-Key":         testWSKey,
		"Sec-WebSocket-Version":     "13",
		"X-Cathedral-Access-Ticket": "tkt-1",
	}
	for k, v := range extra {
		hdr[k] = v
	}
	var sb strings.Builder
	sb.WriteString("GET " + path + " HTTP/1.1\r\nHost: broker\r\n")
	for k, v := range hdr {
		if v != "" {
			sb.WriteString(k + ": " + v + "\r\n")
		}
	}
	sb.WriteString("\r\n" + after)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(sb.String())); err != nil {
		t.Fatal(err)
	}
	rd := bufio.NewReader(conn)
	resp, err := http.ReadResponse(rd, nil)
	if err != nil {
		t.Fatal(err)
	}
	return conn, rd, resp
}

func termReadN(t *testing.T, rd io.Reader, n int) string {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(rd, buf); err != nil {
		t.Fatalf("read %d bytes: %v", n, err)
	}
	return string(buf)
}

func termErrBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	return doc
}

// The handshake reaches the hotel with the ticket and the hotel key, the 101
// comes back with the hotel's accept and subprotocol, and bytes flow both ways
// unchanged, including bytes sent right behind the handshake.
func TestTerminalWSPassesThroughToTheHotel(t *testing.T) {
	hotel := &termWSHotel{serve: echoBytes}
	tc, room, srv := termWSChain(t, hotel)
	_, hid, _ := strings.Cut(room, ".")

	conn, rd, resp := termWSDial(t, srv, "/v1/sandboxes/"+room+"/terminals/t1/ws", nil, "early")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d %v, want 101", resp.StatusCode, termErrBody(t, resp))
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.Errorf("accept %q", got)
	}
	if got := resp.Header.Get("Sec-WebSocket-Protocol"); got != "cathedral.ticket.tkt-1" {
		t.Errorf("protocol %q", got)
	}
	if got := resp.Header.Get("X-Room-Terminal"); got != "pty" {
		t.Errorf("X-Room-Terminal %q", got)
	}
	if got := termReadN(t, rd, 5); got != "early" {
		t.Errorf("pipelined bytes: %q", got)
	}
	frame := "\x82\x85\x01\x02\x03\x04ijklm" // a masked binary frame, passed as bytes
	if _, err := conn.Write([]byte(frame)); err != nil {
		t.Fatal(err)
	}
	if got := termReadN(t, rd, len(frame)); got != frame {
		t.Errorf("echo %q, want %q", got, frame)
	}

	hs := hotel.headers()
	if len(hs) != 1 {
		t.Fatalf("hotel got %d handshakes", len(hs))
	}
	h := hs[0]
	if h.Get("Authorization") != "Bearer hotel-key" {
		t.Errorf("hotel Authorization %q, want the hotel key", h.Get("Authorization"))
	}
	if h.Get("X-Cathedral-Access-Ticket") != "tkt-1" || h.Get("Sec-WebSocket-Key") != testWSKey || h.Get("Sec-WebSocket-Version") != "13" {
		t.Errorf("hotel handshake headers %v", h)
	}
	if hotel.paths[0] != "/v1/sandboxes/"+hid+"/terminals/t1/ws" {
		t.Errorf("hotel path %q", hotel.paths[0])
	}
	if got := terminalCalls(tc, "b"); len(got) != 1 {
		t.Errorf("hotel b terminal calls %v", got)
	}
}

// The guest's broker key, cookies and extension offers never reach the hotel.
// A ticket in the subprotocol alone is enough.
func TestTerminalWSForwardsOnlyHandshakeHeaders(t *testing.T) {
	hotel := &termWSHotel{serve: echoBytes}
	_, room, srv := termWSChain(t, hotel)
	_, _, resp := termWSDial(t, srv, "/v1/sandboxes/"+room+"/terminals/t1/ws", map[string]string{
		"X-Cathedral-Access-Ticket": "",
		"Sec-WebSocket-Protocol":    "cathedral.ticket.tkt-2",
		"Cookie":                    "session=secret",
		"Sec-WebSocket-Extensions":  "permessage-deflate",
	}, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d %v", resp.StatusCode, termErrBody(t, resp))
	}
	h := hotel.headers()[0]
	for _, k := range []string{"Cookie", "Sec-WebSocket-Extensions"} {
		if h.Get(k) != "" {
			t.Errorf("hotel got %s: %q", k, h.Get(k))
		}
	}
	if strings.Contains(h.Get("Authorization"), "key1") {
		t.Errorf("hotel got the guest key: %q", h.Get("Authorization"))
	}
	if h.Get("Sec-WebSocket-Protocol") != "cathedral.ticket.tkt-2" {
		t.Errorf("hotel protocol %q", h.Get("Sec-WebSocket-Protocol"))
	}
}

// When the hotel ends the session (the shell exits) the guest reads EOF after
// the last bytes; when the guest hangs up the hotel reads EOF.
func TestTerminalWSCloseReachesTheOtherSide(t *testing.T) {
	hotelEOF := make(chan error, 1)
	hotel := &termWSHotel{serve: func(conn net.Conn, rd *bufio.Reader) {
		line, err := rd.ReadString('\n')
		if err != nil {
			hotelEOF <- err
			return
		}
		if line == "exit\n" {
			_, _ = conn.Write([]byte("bye"))
			return // closes the hotel socket
		}
		_, err = rd.ReadByte()
		hotelEOF <- err
	}}
	_, room, srv := termWSChain(t, hotel)

	conn, rd, resp := termWSDial(t, srv, "/v1/sandboxes/"+room+"/terminals/t1/ws", nil, "exit\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got, err := io.ReadAll(rd); err != nil || string(got) != "bye" {
		t.Errorf("guest read %q %v, want bye then EOF", got, err)
	}
	conn.Close()

	conn, _, resp = termWSDial(t, srv, "/v1/sandboxes/"+room+"/terminals/t1/ws", nil, "hello\n")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	conn.Close()
	select {
	case err := <-hotelEOF:
		if err != io.EOF {
			t.Errorf("hotel read %v, want EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hotel did not see the guest hang up")
	}
}

// A socket with no bytes either way is closed after the idle limit.
func TestTerminalWSIdleCloses(t *testing.T) {
	hotel := &termWSHotel{serve: echoBytes}
	tc, room, srv := termWSChain(t, hotel)
	tc.b.terminalWSIdle = 200 * time.Millisecond
	_, rd, resp := termWSDial(t, srv, "/v1/sandboxes/"+room+"/terminals/t1/ws", nil, "")
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d", resp.StatusCode)
	}
	start := time.Now()
	if _, err := rd.ReadByte(); err != io.EOF {
		t.Errorf("read %v, want EOF from the idle close", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("idle close took %s", d)
	}
}

// A hotel refusal (bad or spent ticket) comes back with its status and code,
// with the hotel's room id rewritten to the guest's.
func TestTerminalWSRelaysTheHotelRefusal(t *testing.T) {
	hotel := &termWSHotel{serve: echoBytes}
	tc, room, srv := termWSChain(t, hotel)
	_, hid, _ := strings.Cut(room, ".")
	tc.hotels["b"].upgrade = func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 401, map[string]any{"sandbox_id": hid, "error": map[string]string{"code": "access_ticket_invalid", "message": "ticket already used"}})
	}
	_, _, resp := termWSDial(t, srv, "/v1/sandboxes/"+room+"/terminals/t1/ws", nil, "")
	doc := termErrBody(t, resp)
	if resp.StatusCode != 401 || errCode(doc) != "access_ticket_invalid" {
		t.Fatalf("got %d %v, want 401 access_ticket_invalid", resp.StatusCode, doc)
	}
	if doc["sandbox_id"] != room {
		t.Errorf("sandbox_id %v, want the guest id %s", doc["sandbox_id"], room)
	}
}

// A hotel 101 with the wrong accept is not handed to the guest.
func TestTerminalWSRefusesABadHotelHandshake(t *testing.T) {
	hotel := &termWSHotel{serve: echoBytes, accept: "wrong"}
	_, room, srv := termWSChain(t, hotel)
	_, _, resp := termWSDial(t, srv, "/v1/sandboxes/"+room+"/terminals/t1/ws", nil, "")
	if doc := termErrBody(t, resp); resp.StatusCode != 502 || errCode(doc) != "hotel_bad_handshake" {
		t.Errorf("got %d %v, want 502 hotel_bad_handshake", resp.StatusCode, doc)
	}
}

// Requests that could never open are refused before the hotel sees them, so
// no ticket is spent: no key, wrong version, a query ticket, no ticket,
// another guest's room, an unlisted hotel.
func TestTerminalWSRefusesBeforeTheHotel(t *testing.T) {
	hotel := &termWSHotel{serve: echoBytes}
	tc, room, srv := termWSChain(t, hotel)
	unlisted := tc.room(t, "key1", map[string]any{"image": "alpine:3.20", "hotels": []string{"c"}})
	tc.hotels["c"].upgrade = hotel.handle
	path := "/v1/sandboxes/" + room + "/terminals/t1/ws"
	for _, c := range []struct {
		name   string
		path   string
		extra  map[string]string
		status int
		code   string
	}{
		{"no key", path, map[string]string{"Sec-WebSocket-Key": ""}, 400, "invalid_websocket"},
		{"version 8", path, map[string]string{"Sec-WebSocket-Version": "8"}, 400, "invalid_websocket"},
		{"query ticket", path + "?ticket=tkt-1", nil, 401, "ticket_query_forbidden"},
		{"no ticket", path, map[string]string{"X-Cathedral-Access-Ticket": ""}, 401, "access_ticket_invalid"},
		{"other guest", path, map[string]string{"Authorization": "Bearer key2"}, 404, "sandbox_not_found"},
		{"unlisted hotel", "/v1/sandboxes/" + unlisted + "/terminals/t1/ws", nil, 403, "terminals_disabled"},
	} {
		_, _, resp := termWSDial(t, srv, c.path, c.extra, "")
		if doc := termErrBody(t, resp); resp.StatusCode != c.status || errCode(doc) != c.code {
			t.Errorf("%s: %d %v, want %d %s", c.name, resp.StatusCode, doc, c.status, c.code)
		}
	}
	if n := len(hotel.headers()); n != 0 {
		t.Errorf("hotel got %d handshakes, want 0", n)
	}
}

// A hotel that does not answer is a 502, like other room routes.
func TestTerminalWSHotelDown(t *testing.T) {
	hotel := &termWSHotel{serve: echoBytes}
	tc, room, srv := termWSChain(t, hotel)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + ln.Addr().String()
	ln.Close()
	tc.b.hotelByID("b").cfg.API = dead
	_, _, resp := termWSDial(t, srv, "/v1/sandboxes/"+room+"/terminals/t1/ws", nil, "")
	if doc := termErrBody(t, resp); resp.StatusCode != 502 || errCode(doc) != "hotel_unreachable" {
		t.Errorf("got %d %v, want 502 hotel_unreachable", resp.StatusCode, doc)
	}
}

// The client-compat path answers through a writer that cannot hand over the
// connection: it gets 501 and the hotel sees nothing.
func TestTerminalWSNotOnTheCompatPath(t *testing.T) {
	hotel := &termWSHotel{serve: echoBytes}
	tc, room, _ := termWSChain(t, hotel)
	_, hid, _ := strings.Cut(room, ".")
	h := tc.b.hotelByID("b")
	c := &capture{hdr: http.Header{}, status: 200}
	r := httptest.NewRequest("GET", "/v1/sandboxes/"+room+"/terminals/t1/ws", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Key", testWSKey)
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("X-Cathedral-Access-Ticket", "tkt-1")
	tc.b.proxyTerminalWS(c, r, h, hid, room, "terminals/t1/ws")
	if c.status != 501 {
		t.Errorf("compat status %d, want 501", c.status)
	}
	if n := len(hotel.headers()); n != 0 {
		t.Errorf("hotel got %d handshakes, want 0", n)
	}
}

func TestTerminalWSTail(t *testing.T) {
	for tail, want := range map[string]bool{
		"terminals/t1/ws":    true,
		"terminals//ws":      false,
		"terminals/t1":       false,
		"terminals/t1/ws/x":  false,
		"desktop/ws":         false,
		"terminals/t1/input": false,
	} {
		if got := terminalWSTail(tail); got != want {
			t.Errorf("%q: %v, want %v", tail, got, want)
		}
	}
}

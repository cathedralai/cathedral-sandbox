package main

// Room terminal WebSocket pass-through (AB#405 step 2).
//
// A guest opens GET /v1/sandboxes/<id>/terminals/<tid>/ws with a WebSocket
// handshake and a terminal ticket. After the same gates as every room route
// (terminal allowlist, ownership), the broker opens the same handshake to the
// room's hotel and, on the hotel's 101, hands raw bytes both ways. Frames are
// not parsed or changed: the hotel speaks WebSocket with the guest directly.
// The hotel checks and consumes the ticket; the broker only refuses requests
// that could never work, before any hotel call, so a ticket is not spent on a
// socket the broker cannot hand over.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // RFC 6455 accept key, not a security digest
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	// terminalWSHandshakeTimeout bounds the hotel's answer to the handshake.
	terminalWSHandshakeTimeout = 30 * time.Second
	// terminalWSErrorBodyMax caps a hotel's refusal relayed to the guest.
	terminalWSErrorBodyMax = 64 << 10
)

// defaultTerminalWSIdle closes a terminal socket with no bytes in either
// direction for this long. The hotel closes an idle socket after 600 s itself;
// this is longer, so it only frees sockets whose other end vanished without a
// FIN. broker.terminalWSIdle overrides it (tests).
const defaultTerminalWSIdle = 15 * time.Minute

// isWebSocketUpgrade reports whether r asks for a WebSocket on HTTP/1.1.
func isWebSocketUpgrade(r *http.Request) bool {
	if r.Method != "GET" || r.ProtoMajor != 1 || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	for _, v := range r.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "upgrade") {
				return true
			}
		}
	}
	return false
}

// terminalWSTail reports whether a room tail is terminals/<tid>/ws.
func terminalWSTail(tail string) bool {
	parts := strings.Split(tail, "/")
	return len(parts) == 3 && parts[0] == "terminals" && parts[1] != "" && parts[2] == "ws"
}

// wsAccept is the Sec-WebSocket-Accept value for a client key (RFC 6455 4.2.2).
func wsAccept(key string) string {
	sum := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // RFC 6455
	return base64.StdEncoding.EncodeToString(sum[:])
}

// hasTerminalTicket reports whether the handshake carries a terminal ticket
// where the hotel reads one: the X-Cathedral-Access-Ticket header or a
// cathedral.ticket.* subprotocol.
func hasTerminalTicket(r *http.Request) bool {
	if strings.TrimSpace(r.Header.Get("X-Cathedral-Access-Ticket")) != "" {
		return true
	}
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			if t, ok := strings.CutPrefix(strings.TrimSpace(p), "cathedral.ticket."); ok && t != "" {
				return true
			}
		}
	}
	return false
}

// canHijack reports whether w, or a writer it wraps, can hand over its
// connection. The client-compat path answers through a capture writer that
// cannot.
func canHijack(w http.ResponseWriter) bool {
	for {
		if _, ok := w.(http.Hijacker); ok {
			return true
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return false
		}
		w = u.Unwrap()
	}
}

// wsTransport is a one-off transport for one terminal socket: the hotel's TLS
// settings, no keep-alive and no per-host cap, so a long socket does not hold
// one of the hotel's exec connections.
func (h *hotel) wsTransport() *http.Transport {
	var tr *http.Transport
	if base, ok := h.client.Transport.(*http.Transport); ok {
		tr = base.Clone()
	} else {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	}
	tr.MaxConnsPerHost, tr.MaxIdleConnsPerHost, tr.DisableKeepAlives = 0, 0, true
	return tr
}

// proxyTerminalWS passes a room terminal WebSocket to the room's hotel. The
// caller has run the terminal allowlist and ownership checks. hid is the
// hotel's room id, bid the guest-facing id, tail terminals/<tid>/ws.
func (b *broker) proxyTerminalWS(w http.ResponseWriter, r *http.Request, h *hotel, hid, bid, tail string) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" || r.Header.Get("Sec-WebSocket-Version") != "13" {
		writeErr(w, 400, "invalid_websocket", "a WebSocket handshake needs Sec-WebSocket-Key and Sec-WebSocket-Version: 13")
		return
	}
	if r.URL.Query().Has("ticket") {
		writeErr(w, 401, "ticket_query_forbidden", "pass the ticket in X-Cathedral-Access-Ticket or a cathedral.ticket.* subprotocol (query string disabled)")
		return
	}
	if !hasTerminalTicket(r) {
		writeErr(w, 401, "access_ticket_invalid", "X-Cathedral-Access-Ticket header (or cathedral.ticket.* subprotocol) required")
		return
	}
	if !canHijack(w) {
		writeErr(w, 501, "websocket_unsupported", "the terminal WebSocket is served on the native API only")
		return
	}
	// The same guards as doHeaders: a miner hotel's key goes only over its
	// attested HTTPS. terminalsRefused already keeps miner hotels out.
	if h.cfg.MinerHotkey != "" && (h.tlsPinErr != nil || !strings.HasPrefix(h.cfg.API, "https://")) {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tr := h.wsTransport()
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, "GET", h.cfg.API+"/v1/sandboxes/"+url.PathEscape(hid)+"/"+tail, nil)
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	// Only what the hotel needs: never the guest's broker key or cookies.
	req.Header.Set("Authorization", "Bearer "+h.key)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	for _, k := range []string{"Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol", "X-Cathedral-Access-Ticket"} {
		if v := r.Header.Values(k); len(v) > 0 {
			req.Header[k] = v
		}
	}
	// The timer can cancel only the handshake: after a 101 the caller owns the
	// connection and a cancel no longer reaches it.
	timer := time.AfterFunc(terminalWSHandshakeTimeout, cancel)
	resp, err := client.Do(req)
	timer.Stop()
	if err != nil {
		writeErr(w, 502, "hotel_unreachable", "hotel "+h.cfg.ID+" did not answer")
		return
	}
	if resp.StatusCode < 500 {
		h.lastAnswer.Store(time.Now().UnixNano())
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		relayHotelRefusal(w, resp, hid, bid)
		return
	}
	upstream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok || resp.Header.Get("Sec-WebSocket-Accept") != wsAccept(key) {
		// The hotel has consumed the ticket by now; the guest mints a new one.
		resp.Body.Close()
		writeErr(w, 502, "hotel_bad_handshake", "hotel "+h.cfg.ID+" answered the WebSocket handshake wrongly")
		return
	}
	defer upstream.Close()

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		// canHijack said yes, so this is a broken guest connection.
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{})
	if err := writeSwitching(brw.Writer, resp.Header); err != nil {
		return
	}
	idle := b.terminalWSIdle
	if idle <= 0 {
		idle = defaultTerminalWSIdle
	}
	pumpWebSocket(conn, brw.Reader, upstream, idle)
}

// relayHotelRefusal answers the guest with the hotel's refusal of the
// handshake (a bad or spent ticket, a gone terminal), like other room routes.
func relayHotelRefusal(w http.ResponseWriter, resp *http.Response, hid, bid string) {
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, terminalWSErrorBodyMax))
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
		if strings.HasPrefix(ct, "application/json") {
			out = bytes.ReplaceAll(out, []byte(`"`+hid+`"`), []byte(`"`+bid+`"`))
		}
	}
	if v := resp.Header.Get("Retry-After"); v != "" {
		w.Header().Set("Retry-After", v)
	}
	copyRoomHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(out)
}

// writeSwitching writes the 101 to the guest with the hotel's accept and
// subprotocol, plus its X-Room-* headers.
func writeSwitching(bw *bufio.Writer, hdr http.Header) error {
	var sb strings.Builder
	sb.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n")
	fmt.Fprintf(&sb, "Sec-WebSocket-Accept: %s\r\n", hdr.Get("Sec-WebSocket-Accept"))
	if p := hdr.Get("Sec-WebSocket-Protocol"); p != "" {
		fmt.Fprintf(&sb, "Sec-WebSocket-Protocol: %s\r\n", p)
	}
	room := http.Header{}
	copyRoomHeaders(room, hdr)
	for k, vs := range room {
		for _, v := range vs {
			// A header value with a line break would split the response.
			if !strings.ContainsAny(v, "\r\n") {
				fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
			}
		}
	}
	sb.WriteString("\r\n")
	if _, err := bw.WriteString(sb.String()); err != nil {
		return err
	}
	return bw.Flush()
}

// pumpWebSocket copies raw bytes both ways until either side ends or no byte
// moves in either direction for idle, then closes both. fromGuest
// reads the guest connection through the hijack's buffer, so bytes the guest
// sent right after its handshake are kept.
func pumpWebSocket(guest net.Conn, fromGuest io.Reader, hotel io.ReadWriteCloser, idle time.Duration) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = guest.Close()
			_ = hotel.Close()
		})
	}
	timer := time.AfterFunc(idle, closeBoth)
	defer timer.Stop()
	pipe := func(dst io.Writer, src io.Reader) {
		defer closeBoth()
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				timer.Reset(idle)
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				// EOF, a reset and the idle close all end the session the same way.
				return
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); pipe(hotel, fromGuest) }()
	go func() { defer wg.Done(); pipe(guest, hotel) }()
	wg.Wait()
}

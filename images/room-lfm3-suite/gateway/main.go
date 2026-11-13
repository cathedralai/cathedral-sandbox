// lfm3-gateway: the Polaris runtime chat contract inside an LFM3 room (AB#539).
//
//	GET  /health, /healthz         200 once llama-server is up, 503 while it loads
//	POST /v1/chat/completions      OpenAI chat body; the last user message is one
//	                               turn of the room's conversation
//
// Each turn runs `lfm3-agent --events --turn UUID -` and turns its chat events
// (AB#542) into what Polaris agents speak: OpenAI chat.completion.chunk frames
// over SSE, hermes.tool.progress events, data: [DONE]. lfm3-agent keeps the
// model loop, the conversation and the redaction, so the console (liquid
// --events) and this gateway show the same safe fields.
//
// It listens on loopback only. A sealed room runs with network none, so the
// clients are processes in the room and execs through the authenticated,
// receipted exec path.
//
// Environment:
//
//	LFM3_GATEWAY_ADDR          listen address (default 127.0.0.1:8642); must be loopback
//	LFM3_GATEWAY_TOKEN         if set, POST needs "Authorization: Bearer <token>"
//	LFM3_GATEWAY_AGENT         the agent (default lfm3-agent on PATH)
//	LFM3_GATEWAY_TURN_TIMEOUT  seconds per turn (default 900)
//	MODEL_BASE_URL             llama-server's OpenAI base; /health is next to /v1
//	MODEL                      the model name in replies
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	maxBody = 1 << 20
	// The answer line may be 262144 bytes (AB#542 section 5.1).
	maxLine   = 262144 + 1024
	killGrace = 5 * time.Second
)

var turnIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type config struct {
	addr        string
	token       string
	agent       string
	healthURL   string
	model       string
	turnTimeout time.Duration
	keepalive   time.Duration
}

func configFromEnv() (config, error) {
	c := config{
		addr:        envOr("LFM3_GATEWAY_ADDR", "127.0.0.1:8642"),
		token:       os.Getenv("LFM3_GATEWAY_TOKEN"),
		agent:       envOr("LFM3_GATEWAY_AGENT", "lfm3-agent"),
		model:       envOr("MODEL", "lfm3"),
		turnTimeout: 900 * time.Second,
		keepalive:   15 * time.Second,
	}
	if v := os.Getenv("LFM3_GATEWAY_TURN_TIMEOUT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			return c, fmt.Errorf("LFM3_GATEWAY_TURN_TIMEOUT must be a positive number of seconds")
		}
		c.turnTimeout = time.Duration(n) * time.Second
	}
	base := strings.TrimRight(envOr("MODEL_BASE_URL", "http://127.0.0.1:8080/v1"), "/")
	c.healthURL = strings.TrimSuffix(base, "/v1") + "/health"
	if err := checkLoopback(c.addr); err != nil {
		return c, err
	}
	return c, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// checkLoopback refuses any address a process outside the room could reach.
func checkLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("LFM3_GATEWAY_ADDR %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("LFM3_GATEWAY_ADDR %q is not a loopback address", addr)
	}
	return nil
}

type gateway struct {
	cfg    config
	busy   chan struct{}
	health *http.Client
}

func newGateway(cfg config) *gateway {
	return &gateway{cfg: cfg, busy: make(chan struct{}, 1), health: &http.Client{Timeout: 3 * time.Second}}
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/health", "/healthz":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET.")
			return
		}
		g.serveHealth(w, r)
	case "/v1/chat/completions":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST.")
			return
		}
		g.serveChat(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "Not found.")
	}
}

func (g *gateway) serveHealth(w http.ResponseWriter, r *http.Request) {
	status, code := "live", http.StatusOK
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, g.cfg.healthURL, nil)
	if err == nil {
		var resp *http.Response
		resp, err = g.health.Do(req)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				err = errors.New(resp.Status)
			}
		}
	}
	if err != nil {
		status, code = "warming", http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]any{"ok": code == http.StatusOK, "status": status, "runtime": "lfm3", "model": g.cfg.model})
}

func (g *gateway) authorized(r *http.Request) bool {
	if g.cfg.token == "" {
		return true
	}
	want := "Bearer " + g.cfg.token
	got := r.Header.Get("Authorization")
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// chatRequest is the part of an OpenAI chat body the gateway reads.
type chatRequest struct {
	Messages []struct {
		Role    string          `json:"role"`
		Content json.RawMessage `json:"content"`
	} `json:"messages"`
	Stream bool `json:"stream"`
}

var errNotText = errors.New("only text messages are supported")

// lastUserMessage returns the text of the last user message. The room keeps
// the conversation itself, as it does for the console, so earlier messages
// in the body are not sent again.
func lastUserMessage(req *chatRequest) (string, error) {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		m := req.Messages[i]
		if m.Role != "user" {
			continue
		}
		var text string
		if err := json.Unmarshal(m.Content, &text); err == nil {
			return strings.TrimSpace(text), nil
		}
		var parts []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}
		if err := json.Unmarshal(m.Content, &parts); err != nil {
			return "", errNotText
		}
		var b strings.Builder
		for _, p := range parts {
			if p.Type != "text" {
				return "", errNotText
			}
			b.WriteString(p.Text)
		}
		return strings.TrimSpace(b.String()), nil
	}
	return "", nil
}

func (g *gateway) serveChat(w http.ResponseWriter, r *http.Request) {
	if !g.authorized(r) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "Invalid or missing gateway token.")
		return
	}
	var req chatRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "The body must be a JSON chat request.")
		return
	}
	message, err := lastUserMessage(&req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "Only text messages are supported.")
		return
	}
	if message == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "No user message.")
		return
	}
	// One turn at a time: the room has one conversation. lfm3-agent also
	// locks it, so a console turn and a gateway turn queue rather than mix.
	select {
	case g.busy <- struct{}{}:
		defer func() { <-g.busy }()
	default:
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "busy", "Another turn is still running.")
		return
	}

	turnID := strings.ToLower(r.Header.Get("X-Turn-Id"))
	if !turnIDPattern.MatchString(turnID) {
		turnID = newUUID()
	}
	ctx, cancel := context.WithTimeout(r.Context(), g.cfg.turnTimeout)
	defer cancel()
	t, err := startTurn(ctx, g.cfg.agent, turnID, message)
	if err != nil {
		log.Printf("turn %s: start: %v", turnID, err)
		writeError(w, http.StatusInternalServerError, "internal", internalError.Message)
		return
	}
	defer t.close()

	id := "chatcmpl-" + turnID
	created := time.Now().Unix()
	w.Header().Set("X-Turn-Id", turnID)
	if req.Stream {
		g.stream(w, t, id, created)
	} else {
		g.complete(w, t, id, created)
	}
}

func (g *gateway) stream(w http.ResponseWriter, t *turn, id string, created int64) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	out := newSSE(w, flush, id, created, g.cfg.model)
	// A comment line at a fixed beat while the agent is quiet: it can wait on
	// a console turn's lock, on the model loading, or on a tool, and a client
	// or proxy with a read timeout would otherwise drop the stream.
	beat := time.NewTicker(g.cfg.keepalive)
	defer beat.Stop()
	events := t.events()
	for {
		var r result
		select {
		case <-beat.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flush()
			continue
		case r = <-events:
		}
		if r.err != nil {
			log.Printf("turn %s: %v", t.id, r.err)
			out.fail(internalError)
			return
		}
		a, te, werr := out.handle(r.ev)
		if werr != nil {
			// The client went away; close() stops the agent.
			log.Printf("turn %s: write: %v", t.id, werr)
			return
		}
		if a != nil || te != nil {
			return
		}
	}
}

func (g *gateway) complete(w http.ResponseWriter, t *turn, id string, created int64) {
	for r := range t.events() {
		if r.err != nil {
			log.Printf("turn %s: %v", t.id, r.err)
			writeTurnError(w, internalError)
			return
		}
		ev := r.ev
		switch ev.Type {
		case "answer":
			writeJSON(w, http.StatusOK, map[string]any{
				"id":      id,
				"object":  "chat.completion",
				"created": created,
				"model":   g.cfg.model,
				"choices": []any{map[string]any{
					"index":         0,
					"message":       map[string]any{"role": "assistant", "content": ev.Text},
					"finish_reason": finishReason(ev.StopReason),
				}},
				"cathedral": map[string]any{"stop_reason": ev.StopReason, "rounds": ev.Rounds, "tool_calls": ev.ToolCalls},
			})
			return
		case "error":
			writeTurnError(w, &turnError{Code: ev.Code, Message: ev.Message, Retryable: ev.Retryable})
			return
		}
	}
	writeTurnError(w, internalError)
}

func writeTurnError(w http.ResponseWriter, te *turnError) {
	status := http.StatusInternalServerError
	switch te.Code {
	case "bad_request", "context_too_long", "not_chat_model":
		status = http.StatusBadRequest
	case "model_unavailable":
		status = http.StatusServiceUnavailable
	case "model_failed":
		status = http.StatusBadGateway
	}
	writeJSON(w, status, map[string]any{"error": te})
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// turn is one running lfm3-agent --events.
type turn struct {
	id     string
	cmd    *exec.Cmd
	lines  *bufio.Scanner
	parser parser
	stderr *capped
	done   chan struct{}

	// terminal is set once the answer or error line was read; the agent
	// then exits by itself.
	terminal atomic.Bool

	mu     sync.Mutex
	reaped bool
}

func startTurn(ctx context.Context, agent, turnID, message string) (*turn, error) {
	// "-": the message comes on stdin, so text that starts with "-" is not
	// read as an option.
	cmd := exec.Command(agent, "--events", "--turn", turnID, "-")
	cmd.Stdin = strings.NewReader(message)
	cmd.Env = childEnv()
	// In events mode lfm3-agent writes at most one fatal line here; it goes to
	// the gateway log, never to the client.
	stderr := &capped{max: 512}
	cmd.Stderr = stderr
	// Its own process group, so a stopped turn also stops the command a tool
	// round is running.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	t := &turn{
		id:     turnID,
		cmd:    cmd,
		lines:  sc,
		parser: parser{turnID: turnID},
		stderr: stderr,
		done:   make(chan struct{}),
	}
	go func() {
		select {
		case <-ctx.Done():
			// The client went away or the turn ran out of time.
			t.signal(syscall.SIGTERM)
		case <-t.done:
		}
	}()
	return t, nil
}

// signal reaches the agent's whole process group, until it is reaped.
func (t *turn) signal(sig syscall.Signal) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.reaped {
		syscall.Kill(-t.cmd.Process.Pid, sig)
	}
}

type result struct {
	ev  *event
	err error
}

// events reads the agent's lines until the terminal line or a failure, which
// is always the last result.
func (t *turn) events() <-chan result {
	ch := make(chan result)
	go func() {
		defer close(ch)
		for {
			ev, err := t.next()
			if err == nil && t.parser.done {
				t.terminal.Store(true)
			}
			select {
			case ch <- result{ev, err}:
			case <-t.done:
				return
			}
			if err != nil || t.terminal.Load() {
				return
			}
		}
	}()
	return ch
}

func (t *turn) next() (*event, error) {
	for t.lines.Scan() {
		line := t.lines.Bytes()
		if len(line) == 0 {
			continue
		}
		return t.parser.parse(line)
	}
	if err := t.lines.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("the agent ended without a terminal line")
}

// close waits for the agent to exit. After a terminal line it exits by
// itself; otherwise it is stopped, and killed if it does not stop in time.
func (t *turn) close() {
	if !t.terminal.Load() {
		t.signal(syscall.SIGTERM)
	}
	waited := make(chan error, 1)
	go func() {
		err := t.cmd.Wait()
		t.mu.Lock()
		t.reaped = true
		t.mu.Unlock()
		waited <- err
	}()
	var err error
	select {
	case err = <-waited:
	case <-time.After(killGrace):
		t.signal(syscall.SIGKILL)
		err = <-waited
	}
	close(t.done)
	if err != nil || t.stderr.Len() > 0 {
		log.Printf("turn %s: agent exit: %v %s", t.id, err, strings.TrimSpace(t.stderr.String()))
	}
}

// capped keeps the first max bytes written to it.
type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// childEnv is the gateway's environment without its token: the agent's tools
// run commands the model chose and need nothing of the gateway's.
func childEnv() []string {
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LFM3_GATEWAY_") || strings.HasPrefix(kv, "LFM3_AGENT_NAME=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "LFM3_AGENT_NAME=lfm3-gateway")
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("lfm3-gateway: ")
	cfg, err := configFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s, model %s", ln.Addr(), cfg.model)
	srv := &http.Server{
		Handler:           newGateway(cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Fatal(srv.Serve(ln))
}

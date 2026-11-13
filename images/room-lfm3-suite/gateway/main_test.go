package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The turn id of every fixture in ../test/chat-events.
const fixtureTurn = "0b8f3c9e-5d1a-4f6e-9a7b-2c4d6e8f0a1b"

var fixtureDir = filepath.Join("..", "test", "chat-events")

// fakeAgent writes a stand-in for lfm3-agent that records its arguments and
// stdin, then runs body (a shell snippet).
func fakeAgent(t *testing.T, body string) (agent, argsFile, stdinFile string) {
	t.Helper()
	dir := t.TempDir()
	agent = filepath.Join(dir, "lfm3-agent")
	argsFile = filepath.Join(dir, "args")
	stdinFile = filepath.Join(dir, "stdin")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\ncat > %q\nenv > %q\n%s\n", argsFile, stdinFile, filepath.Join(dir, "env"), body)
	if err := os.WriteFile(agent, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return agent, argsFile, stdinFile
}

func fixtureAgent(t *testing.T, name string) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(fixtureDir, name+".stdout"))
	if err != nil {
		t.Fatal(err)
	}
	exit := 0
	if lastType(t, path) == "error" {
		exit = 1
	}
	agent, _, _ := fakeAgent(t, fmt.Sprintf("cat %q\nexit %d", path, exit))
	return agent
}

func lastType(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var ev event
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatal(err)
	}
	return ev.Type
}

func testGateway(t *testing.T, agent string, mutate ...func(*config)) *httptest.Server {
	t.Helper()
	cfg := config{addr: "127.0.0.1:0", agent: agent, model: "lfm3-vl-2b", healthURL: "http://127.0.0.1:1/health", turnTimeout: 30 * time.Second, keepalive: time.Hour}
	for _, m := range mutate {
		m(&cfg)
	}
	srv := httptest.NewServer(newGateway(cfg))
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Turn-Id", fixtureTurn)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

const streamBody = `{"model":"lfm3","stream":true,"messages":[{"role":"user","content":"what is in the room"}]}`

// polarisEvent is one event as agent_os/hermes_chat.py hermes_chat_events
// (hermes-next) yields it.
type polarisEvent struct {
	Kind    string
	Content string
	ID      string
	Name    string
	Finish  string
	Message string
	Args    map[string]any
}

// polarisEvents reads an SSE body with the rules of hermes_chat_events: frames
// split on blank lines, "event:" and "data:" fields, [DONE] completes only
// after a finish_reason, event: error or an error field fails the turn, and a
// stream that ends before [DONE] is an error.
func polarisEvents(t *testing.T, body string) []polarisEvent {
	t.Helper()
	var out []polarisEvent
	var finish string
	evName, data := "message", []string{}
	frames := [][2]string{}
	sc := bufio.NewScanner(strings.NewReader(body))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if len(data) > 0 {
				frames = append(frames, [2]string{evName, strings.Join(data, "\n")})
			}
			evName, data = "message", nil
		case strings.HasPrefix(line, "event:"):
			evName = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "data:"):
			data = append(data, strings.TrimLeft(line[5:], " "))
		case strings.HasPrefix(line, ":"):
		default:
			t.Fatalf("unexpected SSE line %q", line)
		}
	}
	if len(data) > 0 {
		frames = append(frames, [2]string{evName, strings.Join(data, "\n")})
	}
	for i, f := range frames {
		name, raw := f[0], f[1]
		if raw == "[DONE]" && name != "error" {
			if i != len(frames)-1 {
				t.Fatalf("frames after [DONE]")
			}
			if finish == "" {
				return append(out, polarisEvent{Kind: "error", Message: "no completion status"})
			}
			return append(out, polarisEvent{Kind: "done", Finish: finish})
		}
		var d map[string]any
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			t.Fatalf("frame %q: %v", raw, err)
		}
		if d["error"] != nil || name == "error" {
			e, _ := d["error"].(map[string]any)
			msg, _ := e["message"].(string)
			if i != len(frames)-1 {
				t.Fatalf("frames after the error")
			}
			return append(out, polarisEvent{Kind: "error", Message: msg})
		}
		if name == "hermes.tool.progress" {
			ev := polarisEvent{ID: d["toolCallId"].(string), Name: d["tool"].(string)}
			if d["output"] != "" {
				t.Fatalf("tool output forwarded: %v", d["output"])
			}
			switch d["status"] {
			case "completed":
				ev.Kind = "tool-result"
			case "error", "failed":
				ev.Kind, ev.Message = "tool-error", d["message"].(string)
			default:
				ev.Kind = "tool-start"
				ev.Args, _ = d["arguments"].(map[string]any)
			}
			out = append(out, ev)
			continue
		}
		if d["object"] != "chat.completion.chunk" {
			t.Fatalf("not a chunk: %v", d)
		}
		for _, c := range d["choices"].([]any) {
			choice := c.(map[string]any)
			delta, ok := choice["delta"].(map[string]any)
			if !ok {
				t.Fatalf("choice without delta: %v", choice)
			}
			if s, ok := delta["content"].(string); ok && s != "" {
				out = append(out, polarisEvent{Kind: "token", Content: s})
			}
			if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
				finish = fr
			}
		}
	}
	return append(out, polarisEvent{Kind: "error", Message: "ended before completion"})
}

func tokens(evs []polarisEvent) string {
	var b strings.Builder
	for _, e := range evs {
		if e.Kind == "token" {
			b.WriteString(e.Content)
		}
	}
	return b.String()
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEveryFixtureStreamsInThePolarisFormat(t *testing.T) {
	cases := map[string]struct {
		text   string
		finish string
		err    string
		tools  []string
	}{
		"plain":          {text: "Hello from the room.", finish: "stop"},
		"unicode":        {text: "café naïve \U0001F600 done", finish: "stop"},
		"length":         {text: "This reply was cut", finish: "length"},
		"steps":          {text: "Enough looking.", finish: "stop", tools: []string{"tool-start:call_1:run", "tool-result:call_1:run"}},
		"tool-round":     {text: "Let me look.\n\nIt says hello.", finish: "stop", tools: []string{"tool-start:call_1:run", "tool-result:call_1:run"}},
		"markup":         {text: "Checking. \n\nDone.", finish: "stop", tools: []string{"tool-start:call_text_0:run", "tool-result:call_text_0:run"}},
		"redaction":      {text: "Finished.", finish: "stop", tools: []string{"tool-start:call_1:run", "tool-result:call_1:run"}},
		"loop":           {finish: "stop"},
		"model-down":     {err: "The model server is not ready."},
		"not-chat-model": {err: "This model does not chat."},
	}
	matches, _ := filepath.Glob(filepath.Join(fixtureDir, "*.stdout"))
	if len(matches) != len(cases) {
		t.Fatalf("%d fixtures, %d cases: add the new fixture here", len(matches), len(cases))
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			srv := testGateway(t, fixtureAgent(t, name))
			resp := post(t, srv, streamBody, nil)
			if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
				t.Fatalf("status %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
			}
			if resp.Header.Get("X-Turn-Id") != fixtureTurn {
				t.Fatalf("X-Turn-Id %q", resp.Header.Get("X-Turn-Id"))
			}
			body := readAll(t, resp.Body)
			evs := polarisEvents(t, body)
			last := evs[len(evs)-1]
			if want.err != "" {
				if last.Kind != "error" || last.Message != want.err || strings.Contains(body, "[DONE]") {
					t.Fatalf("want error %q, got %+v\n%s", want.err, last, body)
				}
				return
			}
			if last.Kind != "done" || last.Finish != want.finish {
				t.Fatalf("want done %q, got %+v\n%s", want.finish, last, body)
			}
			if !strings.HasSuffix(body, "data: [DONE]\n\n") {
				t.Fatalf("[DONE] is not last:\n%s", body)
			}
			got := tokens(evs)
			if name == "loop" {
				// Streamed repeats cannot be taken back; the answer is in them.
				if !strings.HasPrefix(got, "I will say this over and over.") {
					t.Fatalf("loop text %q", got)
				}
				if !strings.Contains(body, `"stop_reason":"loop"`) {
					t.Fatalf("loop stop reason missing:\n%s", body)
				}
			} else if got != want.text {
				t.Fatalf("text %q, want %q", got, want.text)
			}
			var tools []string
			for _, e := range evs {
				if strings.HasPrefix(e.Kind, "tool-") {
					tools = append(tools, e.Kind+":"+e.ID+":"+e.Name)
				}
			}
			if strings.Join(tools, " ") != strings.Join(want.tools, " ") {
				t.Fatalf("tools %v, want %v", tools, want.tools)
			}
			for _, bad := range []string{"<tool_call", "<function=", "<|", "<think"} {
				if strings.Contains(body, bad) {
					t.Fatalf("markup %q in the stream", bad)
				}
			}
		})
	}
}

func TestToolSummaryIsTheOnlyArgumentAndSecretsStayOut(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixtureDir, "redaction.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Planted []string `json:"planted"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil || len(fixture.Planted) == 0 {
		t.Fatalf("planted values: %v", err)
	}
	srv := testGateway(t, fixtureAgent(t, "redaction"))
	body := readAll(t, post(t, srv, streamBody, nil).Body)
	for _, secret := range fixture.Planted {
		if strings.Contains(body, secret) {
			t.Fatalf("planted secret %q in the stream", secret)
		}
	}
	for _, e := range polarisEvents(t, body) {
		if e.Kind == "tool-start" {
			if len(e.Args) != 1 || !strings.Contains(e.Args["summary"].(string), "[redacted]") {
				t.Fatalf("arguments %v", e.Args)
			}
		}
	}
}

func TestFailedToolsAreToolErrorsWithFixedText(t *testing.T) {
	lines := []string{
		`{"type":"start","model":"m","tools":true}`,
		`{"type":"thinking","round":1,"phase":"working"}`,
		`{"type":"tool_call","round":1,"call_id":"a","name":"run","summary":"false","redacted":false}`,
		`{"type":"tool_result","round":1,"call_id":"a","status":"timeout","exit_code":null,"duration_ms":60000,"output_bytes":0,"output_cut":false}`,
		`{"type":"thinking","round":2,"phase":"working"}`,
		`{"type":"answer","text":"It timed out.","stop_reason":"stop","rounds":2,"tool_calls":1}`,
	}
	srv := testGateway(t, scriptedAgent(t, lines, 0))
	evs := polarisEvents(t, readAll(t, post(t, srv, streamBody, nil).Body))
	if evs[1].Kind != "tool-error" || evs[1].Message != "The command timed out." || evs[1].ID != "a" || evs[1].Name != "run" {
		t.Fatalf("%+v", evs)
	}
	// Nothing streamed in the final round: the answer text is sent whole.
	if tokens(evs) != "It timed out." || evs[len(evs)-1].Kind != "done" {
		t.Fatalf("%+v", evs)
	}
}

func TestAnswerLongerThanTheDeltasSendsTheRest(t *testing.T) {
	lines := []string{
		`{"type":"start","model":"m","tools":true}`,
		`{"type":"thinking","round":1,"phase":"working"}`,
		`{"type":"delta","round":1,"text":"Hello"}`,
		`{"type":"answer","text":"Hello there.","stop_reason":"stop","rounds":1,"tool_calls":0}`,
	}
	srv := testGateway(t, scriptedAgent(t, lines, 0))
	evs := polarisEvents(t, readAll(t, post(t, srv, streamBody, nil).Body))
	if tokens(evs) != "Hello there." {
		t.Fatalf("%q", tokens(evs))
	}
}

// scriptedAgent prints lines with the envelope filled in.
func scriptedAgent(t *testing.T, lines []string, exit int) string {
	t.Helper()
	var b strings.Builder
	for i, l := range lines {
		fmt.Fprintf(&b, `{"version":1,"turn_id":"%s","seq":%d,%s`+"\n", fixtureTurn, i+1, strings.TrimPrefix(l, "{"))
	}
	path := filepath.Join(t.TempDir(), "events")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	agent, _, _ := fakeAgent(t, fmt.Sprintf("cat %q\nexit %d", path, exit))
	return agent
}

func TestBrokenAgentOutputEndsInAnInternalError(t *testing.T) {
	cases := map[string]string{
		"no terminal line": fmt.Sprintf(`printf '%%s\n' '{"version":1,"turn_id":"%s","seq":1,"type":"start","model":"m","tools":true}'; exit 1`, fixtureTurn),
		"not json":         "echo 'lfm3-agent: oops'",
		"seq gap":          fmt.Sprintf(`printf '%%s\n' '{"version":1,"turn_id":"%s","seq":2,"type":"start"}'`, fixtureTurn),
		"other turn":       `printf '%s\n' '{"version":1,"turn_id":"00000000-0000-0000-0000-000000000000","seq":1,"type":"start"}'`,
		"no output":        "exit 3",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			agent, _, _ := fakeAgent(t, body)
			srv := testGateway(t, agent)
			out := readAll(t, post(t, srv, streamBody, nil).Body)
			evs := polarisEvents(t, out)
			if last := evs[len(evs)-1]; last.Kind != "error" || last.Message != "The agent failed." || strings.Contains(out, "[DONE]") {
				t.Fatalf("%+v\n%s", last, out)
			}
			if !strings.Contains(out, "event: error\n") {
				t.Fatalf("no error event:\n%s", out)
			}
		})
	}
}

func TestMessageGoesOnStdinWithTheTurnID(t *testing.T) {
	agent, argsFile, stdinFile := fakeAgent(t, "exit 1")
	srv := testGateway(t, agent)
	body := `{"stream":true,"messages":[{"role":"system","content":"x"},{"role":"user","content":"old"},{"role":"assistant","content":"y"},{"role":"user","content":[{"type":"text","text":"--new "},{"type":"text","text":"hi"}]}]}`
	readAll(t, post(t, srv, body, map[string]string{"X-Turn-Id": strings.ToUpper(fixtureTurn)}).Body)
	args, _ := os.ReadFile(argsFile)
	if string(args) != "--events\n--turn\n"+fixtureTurn+"\n-\n" {
		t.Fatalf("args %q", args)
	}
	stdin, _ := os.ReadFile(stdinFile)
	if string(stdin) != "--new hi" {
		t.Fatalf("stdin %q", stdin)
	}
}

func TestTurnIDIsMadeWhenTheHeaderIsNotAUUID(t *testing.T) {
	agent, argsFile, _ := fakeAgent(t, "exit 1")
	srv := testGateway(t, agent)
	resp := post(t, srv, streamBody, map[string]string{"X-Turn-Id": "../../etc"})
	readAll(t, resp.Body)
	id := resp.Header.Get("X-Turn-Id")
	if !turnIDPattern.MatchString(id) || id == fixtureTurn {
		t.Fatalf("turn id %q", id)
	}
	args, _ := os.ReadFile(argsFile)
	if !strings.Contains(string(args), id) {
		t.Fatalf("args %q", args)
	}
}

func TestChildEnvDropsTheGatewayToken(t *testing.T) {
	t.Setenv("LFM3_GATEWAY_TOKEN", "gateway-token-value")
	agent, argsFile, _ := fakeAgent(t, "exit 1")
	srv := testGateway(t, agent)
	readAll(t, post(t, srv, streamBody, nil).Body)
	env, _ := os.ReadFile(filepath.Join(filepath.Dir(argsFile), "env"))
	if strings.Contains(string(env), "gateway-token-value") || !strings.Contains(string(env), "LFM3_AGENT_NAME=lfm3-gateway") {
		t.Fatalf("env:\n%s", env)
	}
}

func TestNonStreamingReturnsTheAuthoritativeAnswer(t *testing.T) {
	srv := testGateway(t, fixtureAgent(t, "loop"))
	resp := post(t, srv, strings.Replace(streamBody, `"stream":true`, `"stream":false`, 1), nil)
	var got struct {
		Object  string `json:"object"`
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Cathedral map[string]any `json:"cathedral"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil || resp.StatusCode != 200 {
		t.Fatalf("%d %v", resp.StatusCode, err)
	}
	if got.Object != "chat.completion" || got.Choices[0].Message.Content != "I will say this over and over." ||
		got.Choices[0].FinishReason != "stop" || got.Cathedral["stop_reason"] != "loop" {
		t.Fatalf("%+v", got)
	}
}

func TestNonStreamingErrorsUseHTTPStatus(t *testing.T) {
	for name, status := range map[string]int{"model-down": 503, "not-chat-model": 400} {
		srv := testGateway(t, fixtureAgent(t, name))
		resp := post(t, srv, `{"messages":[{"role":"user","content":"hi"}]}`, nil)
		var got struct {
			Error turnError `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&got)
		if resp.StatusCode != status || got.Error.Message == "" {
			t.Fatalf("%s: %d %+v", name, resp.StatusCode, got)
		}
	}
}

func TestBadRequests(t *testing.T) {
	agent, argsFile, _ := fakeAgent(t, "exit 1")
	srv := testGateway(t, agent)
	for name, body := range map[string]string{
		"not json":   `{`,
		"no user":    `{"messages":[{"role":"system","content":"x"}]}`,
		"blank":      `{"messages":[{"role":"user","content":"   "}]}`,
		"image part": `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:,"}}]}]}`,
		"too big":    `{"messages":[{"role":"user","content":"` + strings.Repeat("a", maxBody) + `"}]}`,
	} {
		if resp := post(t, srv, body, nil); resp.StatusCode != 400 {
			t.Fatalf("%s: %d", name, resp.StatusCode)
		}
	}
	if _, err := os.Stat(argsFile); err == nil {
		t.Fatal("the agent ran for a bad request")
	}
	resp, _ := http.Get(srv.URL + "/v1/chat/completions")
	if resp.StatusCode != 405 {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
	resp, _ = http.Get(srv.URL + "/v1/models")
	if resp.StatusCode != 404 {
		t.Fatalf("unknown path: %d", resp.StatusCode)
	}
}

func TestTokenIsRequiredWhenSet(t *testing.T) {
	srv := testGateway(t, fixtureAgent(t, "plain"), func(c *config) { c.token = "s3cret-token" })
	for _, h := range []string{"", "Bearer wrong", "s3cret-token", "Bearer s3cret-tokenX", "bearer s3cret-token"} {
		if resp := post(t, srv, streamBody, map[string]string{"Authorization": h}); resp.StatusCode != 401 {
			t.Fatalf("%q: %d", h, resp.StatusCode)
		}
	}
	if resp := post(t, srv, streamBody, map[string]string{"Authorization": "Bearer s3cret-token"}); resp.StatusCode != 200 {
		t.Fatalf("good token: %d", resp.StatusCode)
	}
}

func TestOneTurnAtATime(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	agent, _, _ := fakeAgent(t, fmt.Sprintf("touch %q\nsleep 30", started))
	srv := testGateway(t, agent)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(streamBody))
		if resp, err := http.DefaultClient.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	waitFor(t, func() bool { _, err := os.Stat(started); return err == nil })
	resp := post(t, srv, streamBody, nil)
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("second turn: %d", resp.StatusCode)
	}
}

func TestClientGoneStopsTheAgentAndItsTools(t *testing.T) {
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "pid")
	// The agent's child stands for a tool command the model is running.
	agent, _, _ := fakeAgent(t, fmt.Sprintf("sleep 60 &\necho $! > %q\nwait", pidFile))
	srv := testGateway(t, agent)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/v1/chat/completions", strings.NewReader(streamBody))
		if resp, err := http.DefaultClient.Do(req); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	var pid int
	waitFor(t, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		_, err = fmt.Sscanf(string(b), "%d", &pid)
		return err == nil
	})
	cancel()
	<-done
	waitFor(t, func() bool { return syscall.Kill(pid, 0) != nil })
	// The slot is free again.
	waitFor(t, func() bool { return len(srvBusy(srv)) == 0 })
}

func srvBusy(srv *httptest.Server) chan struct{} {
	return srv.Config.Handler.(*gateway).busy
}

func TestTurnTimeoutStopsTheAgent(t *testing.T) {
	agent, _, _ := fakeAgent(t, fmt.Sprintf(`printf '%%s\n' '{"version":1,"turn_id":"%s","seq":1,"type":"start","model":"m","tools":true}'; sleep 60`, fixtureTurn))
	srv := testGateway(t, agent, func(c *config) { c.turnTimeout = time.Second })
	start := time.Now()
	out := readAll(t, post(t, srv, streamBody, nil).Body)
	if time.Since(start) > 10*time.Second {
		t.Fatalf("took %s", time.Since(start))
	}
	evs := polarisEvents(t, out)
	if last := evs[len(evs)-1]; last.Kind != "error" {
		t.Fatalf("%+v", last)
	}
}

func TestHealthFollowsTheModelServer(t *testing.T) {
	up := true
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			w.WriteHeader(404)
			return
		}
		if !up {
			w.WriteHeader(503)
			return
		}
		io.WriteString(w, `{"status":"ok"}`)
	}))
	defer model.Close()
	t.Setenv("MODEL_BASE_URL", model.URL+"/v1")
	t.Setenv("MODEL", "lfm3-omni-2b")
	t.Setenv("LFM3_GATEWAY_ADDR", "")
	cfg, err := configFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.healthURL != model.URL+"/health" || cfg.addr != "127.0.0.1:8642" {
		t.Fatalf("%+v", cfg)
	}
	srv := httptest.NewServer(newGateway(cfg))
	defer srv.Close()
	for _, tc := range []struct {
		up     bool
		status int
		state  string
	}{{true, 200, "live"}, {false, 503, "warming"}} {
		up = tc.up
		for _, path := range []string{"/health", "/healthz"} {
			resp, err := http.Get(srv.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			var got map[string]any
			json.NewDecoder(resp.Body).Decode(&got)
			resp.Body.Close()
			if resp.StatusCode != tc.status || got["status"] != tc.state || got["model"] != "lfm3-omni-2b" {
				t.Fatalf("%s up=%v: %d %v", path, tc.up, resp.StatusCode, got)
			}
		}
	}
	model.Close()
	resp, _ := http.Get(srv.URL + "/health")
	if resp.StatusCode != 503 {
		t.Fatalf("model server gone: %d", resp.StatusCode)
	}
}

func TestOnlyLoopbackAddresses(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:8642": true, "[::1]:8642": true, "localhost:8642": true, "127.0.0.2:1": true,
		"0.0.0.0:8642": false, ":8642": false, "10.0.0.5:8642": false, "[::]:8642": false, "example.com:80": false, "8642": false,
	} {
		if err := checkLoopback(addr); (err == nil) != ok {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	t.Setenv("LFM3_GATEWAY_ADDR", "0.0.0.0:8642")
	if _, err := configFromEnv(); err == nil {
		t.Fatal("a wildcard address was accepted")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestKeepaliveWhileTheAgentIsQuiet(t *testing.T) {
	lines := fmt.Sprintf(`printf '%%s\n' '{"version":1,"turn_id":"%[1]s","seq":1,"type":"start","model":"m","tools":true}'
sleep 1
printf '%%s\n' '{"version":1,"turn_id":"%[1]s","seq":2,"type":"answer","text":"ok","stop_reason":"stop","rounds":1,"tool_calls":0}'`, fixtureTurn)
	agent, _, _ := fakeAgent(t, lines)
	srv := testGateway(t, agent, func(c *config) { c.keepalive = 100 * time.Millisecond })
	body := readAll(t, post(t, srv, streamBody, nil).Body)
	if !strings.Contains(body, ": keepalive\n\n") {
		t.Fatalf("no keepalive:\n%s", body)
	}
	if evs := polarisEvents(t, body); tokens(evs) != "ok" || evs[len(evs)-1].Kind != "done" {
		t.Fatalf("%+v", evs)
	}
}

func TestWhitespaceOnlyStreamGetsTheAnswerText(t *testing.T) {
	lines := []string{
		`{"type":"start","model":"m","tools":true}`,
		`{"type":"thinking","round":1,"phase":"working"}`,
		`{"type":"delta","round":1,"text":"\n "}`,
		`{"type":"answer","text":"(the model gave no answer)","stop_reason":"stop","rounds":1,"tool_calls":0}`,
	}
	srv := testGateway(t, scriptedAgent(t, lines, 0))
	evs := polarisEvents(t, readAll(t, post(t, srv, streamBody, nil).Body))
	if strings.TrimSpace(tokens(evs)) != "(the model gave no answer)" {
		t.Fatalf("%q", tokens(evs))
	}
}

func TestMain(m *testing.M) {
	// Turn failures are logged on purpose in many tests; keep the output short.
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

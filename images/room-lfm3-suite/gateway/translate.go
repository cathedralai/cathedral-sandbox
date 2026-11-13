package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// event is one line of lfm3-agent --events (the AB#542 chat events, version 1).
// Only the fields the gateway reads are here; redaction already happened in
// lfm3-agent, so nothing the gateway forwards can carry a secret value.
type event struct {
	Version    int    `json:"version"`
	TurnID     string `json:"turn_id"`
	Seq        int    `json:"seq"`
	Type       string `json:"type"`
	Round      int    `json:"round"`
	Text       string `json:"text"`
	CallID     string `json:"call_id"`
	Name       string `json:"name"`
	Summary    string `json:"summary"`
	Status     string `json:"status"`
	StopReason string `json:"stop_reason"`
	Rounds     int    `json:"rounds"`
	ToolCalls  int    `json:"tool_calls"`
	Code       string `json:"code"`
	Message    string `json:"message"`
	Retryable  bool   `json:"retryable"`
}

// turnError is a terminal failure in the shape of the chat events error line.
type turnError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

func (e *turnError) Error() string { return e.Code + ": " + e.Message }

// internalError is what a turn ends with when lfm3-agent breaks the contract
// (no terminal line, a line that does not parse, a gap in seq). The text is
// lfm3-agent's own for the code.
var internalError = &turnError{Code: "internal", Message: "The agent failed."}

// answer is the terminal answer line, kept for the reply.
type answer struct {
	Text       string
	StopReason string
	Rounds     int
	ToolCalls  int
}

// parser checks the envelope of each line and remembers the turn's state.
type parser struct {
	turnID string
	seq    int
	done   bool
}

func (p *parser) parse(line []byte) (*event, error) {
	if p.done {
		return nil, errors.New("line after the terminal line")
	}
	var ev event
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil, fmt.Errorf("line %d: %w", p.seq+1, err)
	}
	if ev.Version != 1 {
		return nil, fmt.Errorf("line %d: version %d", p.seq+1, ev.Version)
	}
	if ev.TurnID != p.turnID {
		return nil, fmt.Errorf("line %d: turn id %q", p.seq+1, ev.TurnID)
	}
	if ev.Seq != p.seq+1 {
		return nil, fmt.Errorf("seq %d after %d", ev.Seq, p.seq)
	}
	p.seq = ev.Seq
	if ev.Type == "answer" || ev.Type == "error" {
		p.done = true
	}
	return &ev, nil
}

// finishReason maps the room's stop reasons onto OpenAI's. loop and steps
// both mean the model stopped with an answer; the original reason travels in
// the cathedral field of the last chunk.
func finishReason(stop string) string {
	if stop == "length" {
		return "length"
	}
	return "stop"
}

// toolMessage is fixed text per tool status, never the tool's output.
func toolMessage(status string) string {
	switch status {
	case "timeout":
		return "The command timed out."
	case "refused":
		return "The command was refused."
	default:
		return "The command failed."
	}
}

// sse writes the Polaris runtime format: OpenAI chat.completion.chunk frames,
// hermes.tool.progress events, data: [DONE] after the finish chunk, and
// event: error for a failed turn (no [DONE]), as agent_os/hermes_chat.py
// reads it.
type sse struct {
	w       io.Writer
	flush   func()
	id      string
	created int64
	model   string

	// round is the round of the latest thinking line; roundText is what was
	// streamed as content in it, so the answer can be reconciled at the end.
	round     int
	roundText strings.Builder
	streamed  bool
	tools     map[string]string
}

func newSSE(w io.Writer, flush func(), id string, created int64, model string) *sse {
	if flush == nil {
		flush = func() {}
	}
	return &sse{w: w, flush: flush, id: id, created: created, model: model, tools: map[string]string{}}
}

func (s *sse) frame(name string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if name != "" {
		if _, err := fmt.Fprintf(s.w, "event: %s\n", name); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(s.w, "data: %s\n\n", data); err != nil {
		return err
	}
	s.flush()
	return nil
}

func (s *sse) chunk(delta map[string]any, finish any, extra map[string]any) error {
	body := map[string]any{
		"id":      s.id,
		"object":  "chat.completion.chunk",
		"created": s.created,
		"model":   s.model,
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
	}
	for k, v := range extra {
		body[k] = v
	}
	return s.frame("", body)
}

func (s *sse) content(text string) error {
	if text == "" {
		return nil
	}
	out := text
	// A later round's text starts on a new paragraph, so a tool round's
	// narration and the answer do not run together in one message.
	if s.streamed && s.roundText.Len() == 0 {
		out = "\n\n" + text
	}
	s.streamed = true
	s.roundText.WriteString(text)
	return s.chunk(map[string]any{"content": out}, nil, nil)
}

func (s *sse) toolProgress(callID, name, status, message string, args map[string]any) error {
	if args == nil {
		args = map[string]any{}
	}
	return s.frame("hermes.tool.progress", map[string]any{
		"toolCallId": callID,
		"tool":       name,
		"status":     status,
		"arguments":  args,
		"output":     "",
		"message":    message,
	})
}

// handle writes the frames for one event. It returns the answer or the error
// when the event is terminal.
func (s *sse) handle(ev *event) (*answer, *turnError, error) {
	switch ev.Type {
	case "start":
		return nil, nil, s.chunk(map[string]any{"role": "assistant"}, nil, nil)
	case "thinking":
		if ev.Round != s.round {
			s.round = ev.Round
			s.roundText.Reset()
		}
		// A comment keeps idle proxies from closing the stream while the model
		// reads the prompt; SSE parsers skip it.
		if _, err := io.WriteString(s.w, ": thinking\n\n"); err != nil {
			return nil, nil, err
		}
		s.flush()
		return nil, nil, nil
	case "delta":
		return nil, nil, s.content(ev.Text)
	case "tool_call":
		s.tools[ev.CallID] = ev.Name
		return nil, nil, s.toolProgress(ev.CallID, ev.Name, "running", "", map[string]any{"summary": ev.Summary})
	case "tool_result":
		name := s.tools[ev.CallID]
		if name == "" {
			name = "other"
		}
		if ev.Status == "ok" {
			return nil, nil, s.toolProgress(ev.CallID, name, "completed", "", nil)
		}
		return nil, nil, s.toolProgress(ev.CallID, name, "error", toolMessage(ev.Status), nil)
	case "answer":
		a := &answer{Text: ev.Text, StopReason: ev.StopReason, Rounds: ev.Rounds, ToolCalls: ev.ToolCalls}
		return a, nil, s.finish(a)
	case "error":
		te := &turnError{Code: ev.Code, Message: ev.Message, Retryable: ev.Retryable}
		return nil, te, s.fail(te)
	default:
		// Unknown types are skipped: a newer lfm3-agent may add some.
		return nil, nil, nil
	}
}

// finish reconciles the streamed text with the authoritative answer text where
// it can (the answer extends what was streamed, or nothing was streamed in the
// final round), then ends the stream. Text already streamed cannot be taken
// back: a client that needs answer.text exactly asks with stream false.
func (s *sse) finish(a *answer) error {
	streamed := s.roundText.String()
	switch {
	case strings.TrimSpace(streamed) == "":
		// Nothing, or only white space, was streamed in the final round.
		if err := s.content(a.Text); err != nil {
			return err
		}
	case len(a.Text) > len(streamed) && strings.HasPrefix(a.Text, streamed):
		rest := a.Text[len(streamed):]
		s.roundText.WriteString(rest)
		if err := s.chunk(map[string]any{"content": rest}, nil, nil); err != nil {
			return err
		}
	}
	extra := map[string]any{"cathedral": map[string]any{
		"stop_reason": a.StopReason,
		"rounds":      a.Rounds,
		"tool_calls":  a.ToolCalls,
	}}
	if err := s.chunk(map[string]any{}, finishReason(a.StopReason), extra); err != nil {
		return err
	}
	if _, err := io.WriteString(s.w, "data: [DONE]\n\n"); err != nil {
		return err
	}
	s.flush()
	return nil
}

func (s *sse) fail(te *turnError) error {
	return s.frame("error", map[string]any{"error": te})
}

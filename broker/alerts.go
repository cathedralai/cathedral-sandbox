// Alerts (AB#330).
//
// The miner operator hears about the first missed heartbeat of their hotel:
// the first /room/health call that fails after the hotel has answered health
// at least once. One alert per miss streak; the streak ends at the next good
// health answer. Cathedral ops hear about a customer-affecting drop: a hotel
// that was up goes down while it holds rooms or creates. One alert per down
// episode. Both audiences also have a per-hotel cooldown, so a hotel that
// flaps does not send an alert every few seconds.
//
// Delivery is a JSON POST {"chat_id", "text"} to the URL in
// alerts.webhook_url_file (a Telegram sendMessage URL with the bot token,
// https only; the URL is never logged). The miner operator's chat is the
// hotel's alert_chat_id; ops is alerts.ops_chat_id. Without a URL or a chat
// id the alert is a log line only. Every alert is a log line.
//
// An alert carries no customer data: hotel id, name, miner hotkey, how long
// health has been missing and a room count. No guest, room id, label, image
// or key.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

type alertsConfig struct {
	// WebhookURLFile holds the https URL alerts are POSTed to. It is a file
	// because a Telegram URL carries the bot token.
	WebhookURLFile string `json:"webhook_url_file,omitempty"`
	OpsChatID      string `json:"ops_chat_id,omitempty"`
}

// alertCooldown is the least time between two alerts of one audience about
// one hotel.
const alertCooldown = 10 * time.Minute

const alertQueueSize = 64

// A Telegram chat id: a number (groups are negative) or a public @channel.
var alertChatRE = regexp.MustCompile(`^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$`)

func validAlertChat(s string) bool { return s == "" || alertChatRE.MatchString(s) }

type alertMsg struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

// alertJob is one queued delivery. onSuccess runs after a successful POST;
// onGiveUp after alertPostMaxAttempts failures. Both may be nil. They are
// called from the alerter goroutine, not under broker.mu.
type alertJob struct {
	msg       alertMsg
	onSuccess func()
	onGiveUp  func()
}

type alerter struct {
	opsChat string
	// post sends one alert. nil: log lines only. Tests replace it.
	post   func(ctx context.Context, m alertMsg) error
	queue  chan alertJob
	now    func() time.Time
	client *http.Client // the webhook client; tests swap it
}

// hotelAlerts is the alert state of one hotel. Guarded by broker.mu.
type hotelAlerts struct {
	missSent     bool      // operator alert delivered for the current miss streak
	missInflight bool      // operator alert queued or POST in progress
	missEpoch    uint64    // changes when the miss streak ends
	operatorLast time.Time // last operator alert delivery
	dropSent     bool      // ops alert delivered for the current down episode
	dropInflight bool      // ops alert queued or POST in progress
	dropEpoch    uint64    // changes when the down episode ends
	opsLast      time.Time // last ops alert delivery
}

func newAlerter(c *alertsConfig) (*alerter, error) {
	a := &alerter{queue: make(chan alertJob, alertQueueSize), now: time.Now}
	if c == nil {
		return a, nil
	}
	if !validAlertChat(c.OpsChatID) {
		return nil, errors.New("config: alerts.ops_chat_id must be a Telegram chat id (digits) or @channel")
	}
	a.opsChat = c.OpsChatID
	if c.WebhookURLFile == "" {
		return a, nil
	}
	raw, err := os.ReadFile(c.WebhookURLFile)
	if err != nil {
		return nil, fmt.Errorf("config: alerts.webhook_url_file: %w", errors.Unwrap(err))
	}
	target := strings.TrimSpace(string(raw))
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		// The URL holds a token: the error names the file, not the URL.
		return nil, errors.New("config: alerts.webhook_url_file must hold one https URL")
	}
	a.client = &http.Client{Timeout: 10 * time.Second}
	a.post = func(ctx context.Context, m alertMsg) error {
		body, _ := json.Marshal(m)
		req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(body))
		if err != nil {
			return errors.New("bad request")
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := a.client.Do(req)
		if err != nil {
			// A *url.Error prints the URL, and the URL holds the token.
			var ue *url.Error
			if errors.As(err, &ue) {
				if ue.Timeout() {
					return errors.New("timeout")
				}
				return errors.New("transport error")
			}
			return errors.New("transport error")
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("status %d", resp.StatusCode)
		}
		return nil
	}
	return a, nil
}

// alertPostBackoff is the base wait before retrying a failed webhook POST.
var alertPostBackoff = time.Second

// alertPostMaxAttempts bounds POST retries before onGiveUp (tests may lower it).
var alertPostMaxAttempts = 8

// run sends queued alerts one at a time until ctx ends. A failed POST is
// retried with bounded backoff so a transient Telegram 429/503 still delivers
// once the webhook recovers (AB#330). After alertPostMaxAttempts failures the
// job is dropped and onGiveUp runs so a later sync can enqueue again.
func (a *alerter) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-a.queue:
			if a.post == nil {
				continue
			}
			delivered := false
			for attempt := 0; attempt < alertPostMaxAttempts; attempt++ {
				sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
				err := a.post(sctx, job.msg)
				cancel()
				if err == nil {
					delivered = true
					break
				}
				log.Printf("alert not delivered: %v", err)
				if attempt+1 >= alertPostMaxAttempts {
					break
				}
				wait := alertPostBackoff << attempt
				if wait > 30*time.Second {
					wait = 30 * time.Second
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(wait):
				}
			}
			if delivered {
				if job.onSuccess != nil {
					job.onSuccess()
				}
			} else if job.onGiveUp != nil {
				job.onGiveUp()
			}
		}
	}
}

// send logs the alert and queues it for delivery. It never blocks: a full
// queue drops the delivery (the log line stays) and returns false so the
// caller can leave the alert unmarked and retry on a later sync (AB#330).
// onSuccess and onGiveUp are invoked from run(), not under broker.mu.
// Safe under broker.mu.
func (a *alerter) send(tag, chat, text string, onSuccess, onGiveUp func()) bool {
	log.Printf("[%s] %s", tag, text)
	if a == nil || chat == "" || a.post == nil {
		// Log-only: no webhook or chat. alertHealth marks the streak consumed;
		// onSuccess must not run here (send may be called under broker.mu).
		return true
	}
	select {
	case a.queue <- alertJob{msg: alertMsg{ChatID: chat, Text: text}, onSuccess: onSuccess, onGiveUp: onGiveUp}:
		return true
	default:
		log.Printf("alert queue full: %s alert not delivered", tag)
		return false
	}
}

// alertChat is the miner operator's chat; PATCH may change it at any time.
func (h *hotel) alertChat() string {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.AlertChatID
}

func hotelAlertName(h *hotel) string {
	s := "hotel " + h.cfg.ID
	if h.cfg.Name != "" && h.cfg.Name != h.cfg.ID {
		s += " (" + h.cfg.Name + ")"
	}
	if h.cfg.MinerHotkey != "" {
		s += " miner " + h.cfg.MinerHotkey
	}
	return s
}

// customerLoad counts the guest rooms and creates a drop of h affects:
// creates queued and in flight (not in h.rooms yet) plus listed guest rooms
// that are not on their way out. Caller holds b.mu.
func customerLoad(h *hotel) int {
	n := h.queued + h.creating
	for _, rm := range h.rooms {
		if rm.guest != "" && rm.state != stDeleting && rm.state != stFailed {
			n++
		}
	}
	return n
}

// alertHealth runs after syncHotel has stored the new health state. herr:
// this sync's health call failed; hadHealth: the hotel had answered health
// before this sync. Caller holds b.mu.
func (b *broker) alertHealth(h *hotel, herr error, hadHealth bool) {
	a := b.alerts
	if a == nil {
		return
	}
	now := a.now()
	st := &h.alerts
	if herr == nil {
		st.missEpoch++
		st.missSent = false
		st.missInflight = false
	} else if hadHealth && !st.missSent && !st.missInflight {
		if st.operatorLast.IsZero() || now.Sub(st.operatorLast) >= alertCooldown {
			chat := h.alertChat()
			text := fmt.Sprintf("Cathedral: %s missed a heartbeat (no /room/health answer for %s). Check the machine.",
				hotelAlertName(h), now.Sub(h.lastOK).Round(time.Second))
			epoch := st.missEpoch
			onOK := func() {
				b.mu.Lock()
				if st.missEpoch == epoch && st.missInflight {
					st.missSent = true
					st.missInflight = false
					st.operatorLast = a.now()
				}
				b.mu.Unlock()
			}
			onFail := func() {
				b.mu.Lock()
				if st.missEpoch == epoch {
					st.missInflight = false
				}
				b.mu.Unlock()
			}
			if a.send("OPERATOR-ALERT", chat, text, onOK, onFail) {
				if chat == "" || a.post == nil {
					st.missSent = true
					st.operatorLast = now
				} else {
					st.missInflight = true
				}
			}
		} else {
			st.missSent = true // cooldown: one attempt per streak
		}
	}
	if h.ok {
		st.dropEpoch++
		st.dropSent = false
		st.dropInflight = false
		return
	}
	if !st.dropSent && !st.dropInflight {
		load := customerLoad(h)
		if load <= 0 || (!st.opsLast.IsZero() && now.Sub(st.opsLast) < alertCooldown) {
			st.dropSent = true // no ops audience, or cooldown for this episode
			return
		}
		text := fmt.Sprintf("Cathedral: %s is down with %d customer rooms or creates on it.", hotelAlertName(h), load)
		epoch := st.dropEpoch
		onOK := func() {
			b.mu.Lock()
			if st.dropEpoch == epoch && st.dropInflight {
				st.dropSent = true
				st.dropInflight = false
				st.opsLast = a.now()
			}
			b.mu.Unlock()
		}
		onFail := func() {
			b.mu.Lock()
			if st.dropEpoch == epoch {
				st.dropInflight = false
			}
			b.mu.Unlock()
		}
		if a.send("OPS-ALERT", a.opsChat, text, onOK, onFail) {
			if a.opsChat == "" || a.post == nil {
				st.dropSent = true
				st.opsLast = now
			} else {
				st.dropInflight = true
			}
		}
	}
}

// Planned maintenance: a signed drain notice for a miner hotel (AB#328).
//
// A miner announces maintenance ahead of time with a notice signed by its
// SN94 hotkey. The control plane (which holds the miner enrollment key and
// checks the sr25519 signature at intake) forwards it here:
//
//	PATCH /v1/broker/hotels/<id>  {"drain": true, "drain_notice": {...}}
//
// The broker checks the notice's shape and that it names this hotel and its
// miner hotkey, stamps received_at with its own clock, drains the hotel at
// once (no new rooms; live rooms keep working), keeps the notice in the hotel
// record, and appends it to state_dir/drain-notices.jsonl. That log outlives
// the hotel, so the record survives the hotel leaving.
//
// The broker does not verify the sr25519 signature (no sr25519 in this
// module). It adds no authority either: the enrollment key could already
// drain. The validator verifies the signature and decides whether the notice
// came early enough to excuse the outage (cathedral-validator
// cathedral_thin/independent_runtime/maintenance.py). received_at is the
// trusted clock for that rule; the miner's own issued_at is not.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const (
	drainNoticeSchema = "cathedral_drain_notice_v1"
	drainNoticeLog    = "drain-notices.jsonl"
)

var noticeIDRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type drainNoticeSignature struct {
	Algorithm   string `json:"algorithm"`
	ValueBase64 string `json:"value_base64"`
}

// drainNotice is the miner-signed document. Times are unix seconds; the
// maintenance window is [drain_at, until).
type drainNotice struct {
	Schema    string               `json:"schema"`
	Network   string               `json:"network"`
	Netuid    int                  `json:"netuid"`
	Hotkey    string               `json:"hotkey"`
	HotelID   string               `json:"hotel_id"`
	DrainAt   int64                `json:"drain_at"`
	Until     int64                `json:"until"`
	IssuedAt  int64                `json:"issued_at"`
	NoticeID  string               `json:"notice_id"`
	Signature drainNoticeSignature `json:"signature"`
}

// drainNoticeRecord is the notice as the broker accepted it.
type drainNoticeRecord struct {
	Notice     drainNotice `json:"notice"`
	ReceivedAt int64       `json:"received_at"` // broker clock, unix seconds
}

// parseDrainNotice decodes a notice strictly: unknown fields are refused, so
// the record keeps every signed field and the validator can recompute the id.
func parseDrainNotice(raw json.RawMessage) (drainNotice, error) {
	var n drainNotice
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&n); err != nil {
		return n, fmt.Errorf("drain_notice is not a notice object: %v", err)
	}
	return n, nil
}

// checkDrainNotice checks a notice against the hotel it is sent for.
func checkDrainNotice(n drainNotice, h *hotel, now time.Time) error {
	sig, err := base64.StdEncoding.DecodeString(n.Signature.ValueBase64)
	switch {
	case n.Schema != drainNoticeSchema:
		return fmt.Errorf("drain_notice schema must be %s", drainNoticeSchema)
	case n.Network == "" || len(n.Network) > 32 || n.Netuid < 0:
		return fmt.Errorf("drain_notice needs a network and a netuid")
	case !ss58RE.MatchString(n.Hotkey) || n.Hotkey != h.cfg.MinerHotkey:
		return fmt.Errorf("drain_notice hotkey is not this hotel's miner hotkey")
	case n.HotelID != h.cfg.ID:
		return fmt.Errorf("drain_notice names another hotel")
	case n.IssuedAt <= 0 || n.DrainAt <= 0 || n.Until <= n.DrainAt:
		return fmt.Errorf("drain_notice needs issued_at, drain_at and an until after drain_at (unix seconds)")
	case n.Until <= now.Unix():
		return fmt.Errorf("drain_notice window has already ended")
	case !noticeIDRE.MatchString(n.NoticeID):
		return fmt.Errorf("drain_notice notice_id must be sha256:<64 hex>")
	case n.Signature.Algorithm != "sr25519" || err != nil || len(sig) != 64:
		return fmt.Errorf("drain_notice signature must be sr25519 with 64 bytes of base64")
	}
	return nil
}

func (h *hotel) drainNotice() *drainNoticeRecord {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.cfg.DrainNotice
}

// appendDrainNotice adds one accepted notice to the append-only log.
func (b *broker) appendDrainNotice(rec drainNoticeRecord) error {
	if b.cfg.StateDir == "" {
		return nil
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(b.cfg.StateDir, drainNoticeLog), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

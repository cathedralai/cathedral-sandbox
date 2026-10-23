package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// rememberGuestRoom records a hotel-local room id for a guest. The hotel
// chain is one list per boot; this set is how the broker later returns only
// that guest's receipts. Caller holds b.mu. Empty guest, hotel, or room id
// is ignored, so an unlabeled room stays visible only to an ops key.
func (b *broker) rememberGuestRoom(guest, hotel, hid string) {
	if guest == "" || hotel == "" || hid == "" {
		return
	}
	if b.guestRooms == nil {
		b.guestRooms = map[string]map[string]map[string]struct{}{}
	}
	byHotel := b.guestRooms[guest]
	if byHotel == nil {
		byHotel = map[string]map[string]struct{}{}
		b.guestRooms[guest] = byHotel
	}
	ids := byHotel[hotel]
	if ids == nil {
		ids = map[string]struct{}{}
		byHotel[hotel] = ids
	}
	ids[hid] = struct{}{}
	b.markDirty()
}

// guestRoomIDs is the hotel-local room ids this guest has owned on hotel,
// including rooms already released from the live list.
func (b *broker) guestRoomIDs(guest, hotel string) map[string]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]bool{}
	if byHotel := b.guestRooms[guest]; byHotel != nil {
		for id := range byHotel[hotel] {
			out[id] = true
		}
	}
	if h := b.hotelByID(hotel); h != nil {
		for id, rm := range h.rooms {
			if rm.guest == guest && id != "" {
				out[id] = true
			}
		}
	}
	return out
}

// filterHotelReceipts keeps receipts whose statement.sandbox_id is in owned.
// Each kept receipt is copied byte for byte, so its signature still matches.
// Receipts with no sandbox id are dropped: a failed create can still name an
// image. previous_receipt_sha256 is left as the hotel signed it, even when it
// points at a receipt this response left out.
func filterHotelReceipts(body []byte, owned map[string]bool) ([]byte, error) {
	return filterHotelReceiptsFor(body, owned, "")
}

// filterHotelReceiptsFor is filterHotelReceipts that also keeps the guest's
// own bulk deletes. A bulk delete is signed with no sandbox id; the broker
// appends its broker_guest label last, and the hotel applies the last value
// of a repeated label, so the last broker_guest label names the guest.
func filterHotelReceiptsFor(body []byte, owned map[string]bool, guest string) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	raw, ok := doc["receipts"]
	if !ok {
		return nil, fmt.Errorf("receipt chain has no receipts field")
	}
	var receipts []json.RawMessage
	if err := json.Unmarshal(raw, &receipts); err != nil {
		return nil, err
	}
	kept := make([]json.RawMessage, 0, len(receipts))
	for _, rec := range receipts {
		id, keep, err := receiptSandboxID(rec)
		if err != nil {
			return nil, err
		}
		if (keep && owned[id]) || (guest != "" && bulkDeleteGuest(rec) == guest) {
			kept = append(kept, rec)
		}
	}
	encoded, err := marshalRaw(kept)
	if err != nil {
		return nil, err
	}
	doc["receipts"] = encoded
	count, err := marshalRaw(len(kept))
	if err != nil {
		return nil, err
	}
	doc["count"] = count
	// The head stays the hotel's real head, but this is a subset: the flag
	// tells verify_receipts.py to check each receipt, not a gap-free chain.
	doc["filtered"] = json.RawMessage("true")
	return marshalRaw(doc)
}

func receiptSandboxID(raw json.RawMessage) (string, bool, error) {
	var rec struct {
		Statement struct {
			SandboxID *string `json:"sandbox_id"`
		} `json:"statement"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return "", false, err
	}
	if rec.Statement.SandboxID == nil || *rec.Statement.SandboxID == "" {
		return "", false, nil
	}
	return *rec.Statement.SandboxID, true, nil
}

func marshalRaw(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// bulkDeleteGuest returns the guest a bulk_delete receipt belongs to: the
// last broker_guest label in its signed target, or "".
func bulkDeleteGuest(raw json.RawMessage) string {
	var rec struct {
		Statement struct {
			Action string `json:"action"`
			Target string `json:"target"`
		} `json:"statement"`
	}
	if json.Unmarshal(raw, &rec) != nil || rec.Statement.Action != "bulk_delete" {
		return ""
	}
	_, rawURL, _ := strings.Cut(rec.Statement.Target, " ")
	_, query, ok := strings.Cut(rawURL, "?")
	if !ok {
		return ""
	}
	vals, err := url.ParseQuery(query)
	if err != nil {
		return ""
	}
	guest := ""
	for _, l := range vals["label"] {
		if k, v, ok := strings.Cut(l, "="); ok && k == guestLabel {
			guest = v
		}
	}
	return guest
}

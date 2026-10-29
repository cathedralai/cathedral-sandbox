// Capacity plane, slice 1: guest placement policy and the capacity catalog.
//
// A guest policy names hotels by selector instead of by a fixed id list:
//
//	"policy": {
//	  "prefer": [{"class": "sealed"}],
//	  "allow":  [{"class": "unsealed"}],
//	  "deny":   [{"hotel": "nc-sealed"}]
//	}
//
// A selector is {"class": "sealed"|"unsealed"}, {"hotel": "<id>"} or
// {"label": {"k": "v"}} (every pair must match). Deny wins over prefer and
// allow. A create with no hotel choice goes to the preferred hotels while one
// of them has a free room, else to the allowed hotels. A hotel that joins at
// runtime is matched by class and label with no policy edit.
//
// When a guest has a policy, the policy replaces its "hotels" list and its
// "default_sealed" flag. Miner hotels are denied unless the guest policy
// explicitly selects the miner=true label; broad sealed selectors do not opt in.
//
// A hotel can be reserved for one guest (hotel field "reserved_for", in the
// config or by PATCH /v1/broker/hotels/<id>). Every other guest treats it as
// denied and does not see it in the catalog; its owner reaches it through its
// own policy or hotel list as before. PATCH "reserved_for": null releases it
// to the pool: from then on every policy matches it by class and label.
//
// GET /v1/broker/capacity lists the capacity the caller can reach: every
// hotel for the operator key, the hotels the guest's policy reaches (with
// the tier) for a guest key. Free rooms come from admissibleFree, the same
// count the placer uses, so a hotel listed with free rooms takes a create.
package main

import (
	"fmt"
	"net/http"
	"sort"
	"time"
)

const (
	classSealed   = "sealed"
	classUnsealed = "unsealed"
	tierPrefer    = "prefer"
	tierAllow     = "allow"
)

type selector struct {
	Class string            `json:"class,omitempty"`
	Hotel string            `json:"hotel,omitempty"`
	Label map[string]string `json:"label,omitempty"`
}

type guestPolicy struct {
	Prefer []selector `json:"prefer"`
	Allow  []selector `json:"allow"`
	Deny   []selector `json:"deny"`
}

// hotelClass is "sealed" for a hotel with the sealed label (a sealed hotel
// always has it, see newHotel), else "unsealed". It is the same rule as the
// "prefer" fallback class.
func hotelClass(h *hotel) string {
	if h.labels()["sealed"] == "true" {
		return classSealed
	}
	return classUnsealed
}

func (s selector) matches(h *hotel) bool {
	switch {
	case s.Class != "":
		return hotelClass(h) == s.Class
	case s.Hotel != "":
		return h.cfg.ID == s.Hotel
	case len(s.Label) > 0:
		labels := h.labels()
		for k, v := range s.Label {
			if labels[k] != v {
				return false
			}
		}
		return true
	}
	return false
}

func anyMatch(list []selector, h *hotel) bool {
	for _, s := range list {
		if s.matches(h) {
			return true
		}
	}
	return false
}

// tier is "prefer", "allow" or "" (the policy does not reach h). Deny wins.
func (p *guestPolicy) tier(h *hotel) string {
	// Miner hotels require an explicit miner selector. A broad sealed class
	// or an absent policy must never opt an existing customer guest in.
	if h.cfg.MinerHotkey != "" && !p.minerOptIn(h) {
		return ""
	}
	switch {
	case anyMatch(p.Deny, h):
		return ""
	case anyMatch(p.Prefer, h):
		return tierPrefer
	case anyMatch(p.Allow, h):
		return tierAllow
	}
	return ""
}

func (p *guestPolicy) minerOptIn(h *hotel) bool {
	if p == nil {
		return false
	}
	for _, list := range [][]selector{p.Prefer, p.Allow} {
		for _, s := range list {
			if s.Label["miner"] == "true" && s.matches(h) {
				return true
			}
		}
	}
	return false
}

func validSelectors(field string, list []selector) error {
	for i, s := range list {
		n := 0
		if s.Class != "" {
			n++
			if s.Class != classSealed && s.Class != classUnsealed {
				return fmt.Errorf("policy.%s[%d].class must be \"sealed\" or \"unsealed\"", field, i)
			}
		}
		if s.Hotel != "" {
			n++
		}
		if len(s.Label) > 0 {
			n++
		}
		if n != 1 {
			return fmt.Errorf("policy.%s[%d] must have exactly one of class, hotel or label", field, i)
		}
	}
	return nil
}

// validate checks the selectors. A hotel id need not exist yet: a deny on a
// hotel that joins later must hold from its first minute.
func (p *guestPolicy) validate() error {
	if len(p.Prefer)+len(p.Allow) == 0 {
		return fmt.Errorf("policy must have at least one prefer or allow selector")
	}
	for _, f := range []struct {
		name string
		list []selector
	}{{"prefer", p.Prefer}, {"allow", p.Allow}, {"deny", p.Deny}} {
		if err := validSelectors(f.name, f.list); err != nil {
			return err
		}
	}
	return nil
}

// admissibleFree is the number of rooms a create may get on h now: 0 when h
// is down, draining, resting after a failure or not admitted (a joined sealed
// hotel without a fresh attestation pass, admission.go), else freeFor. pick and the
// capacity catalog both use it, so the catalog never lists a hotel with free
// rooms that the placer would refuse. Caller holds b.mu.
func (b *broker) admissibleFree(h *hotel, now time.Time) int {
	if !h.ok || h.leaving || h.drain() || now.Before(h.backoffUntil) || !b.admitted(h, now) {
		return 0
	}
	if f := b.freeFor(h); f > 0 {
		return f
	}
	return 0
}

// capacityEntry is one hotel in the catalog.
type capacityEntry struct {
	h *hotel
	// source is where the capacity comes from: "broker" for a hotel of the
	// config file, "join" for a hotel that joined at runtime (an SN94 miner
	// machine, or an operator hotel added without a restart). The catalog
	// and the placer read entries, not the source.
	source string
}

// capacityEntries lists the capacity sources. The seam for a later "join"
// source is here. Caller holds b.mu.
func (b *broker) capacityEntries() []capacityEntry {
	var out []capacityEntry
	for _, h := range b.hotelList() {
		src := "broker"
		if h.runtime {
			src = "join"
		}
		out = append(out, capacityEntry{h: h, source: src})
	}
	return out
}

func (b *broker) capacityDoc(e capacityEntry, now time.Time) map[string]any {
	h := e.h
	labels := h.labels()
	if labels == nil {
		labels = map[string]string{}
	}
	var reserved any
	if r := h.reservedFor(); r != "" {
		reserved = r
	}
	return map[string]any{
		"id": h.cfg.ID, "class": hotelClass(h), "labels": labels, "up": h.ok, "drain": h.drain(),
		"free_rooms": b.admissibleFree(h, now), "source": e.source, "down_since": downSince(h),
		"reserved_for": reserved, "slots": h.slots, "admission": b.admissionDoc(h, now),
	}
}

// classTotals is one class line of the catalog: hotels, how many take rooms
// now (up, admitted, not draining), and the rooms they have.
type classTotals struct {
	Hotels    int `json:"hotels"`
	Joined    int `json:"joined"`
	Up        int `json:"up"`
	Placeable int `json:"placeable"` // free_rooms > 0 is not needed: up, admitted, not draining or resting
	Pending   int `json:"pending_admission"`
	Draining  int `json:"draining"`
	Slots     int `json:"slots"`
	FreeRooms int `json:"free_rooms"`
}

// addTotals adds h to the class totals. Caller holds b.mu.
func (b *broker) addTotals(t map[string]*classTotals, e capacityEntry, now time.Time) {
	h := e.h
	c := t[hotelClass(h)]
	c.Hotels++
	if e.source == "join" {
		c.Joined++
	}
	if h.ok {
		c.Up++
	}
	switch {
	case h.drain():
		c.Draining++
	case h.ok && !b.admitted(h, now):
		c.Pending++
	case h.ok && !now.Before(h.backoffUntil):
		c.Placeable++
	}
	c.Slots += h.slots
	c.FreeRooms += b.admissibleFree(h, now)
}

var tierRank = map[string]int{tierPrefer: 0, tierAllow: 1, "hotels": 2}

// handleCapacity serves GET /v1/broker/capacity. g is nil for operator and
// miner enroller views. The enroller sees only miner hotels.
func (b *broker) handleCapacity(w http.ResponseWriter, g *guestState, minerOnly bool) {
	b.mu.Lock()
	now := time.Now()
	out := []map[string]any{}
	var guest map[string]any
	totals := map[string]*classTotals{classSealed: {}, classUnsealed: {}}
	for _, e := range b.capacityEntries() {
		if minerOnly && e.h.cfg.MinerHotkey == "" {
			continue
		}
		if g == nil {
			out = append(out, b.capacityDoc(e, now))
			b.addTotals(totals, e, now)
			continue
		}
		t := g.tierOf(e.h)
		if t == "" {
			continue
		}
		b.addTotals(totals, e, now)
		d := b.capacityDoc(e, now)
		d["tier"] = t
		out = append(out, d)
	}
	if g != nil {
		guest = map[string]any{"id": g.cfg.ID, "max_rooms": g.limits.maxRooms(), "active_rooms": b.activeRooms(g), "policy": g.limits.Policy != nil}
	}
	b.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool {
		ti, _ := out[i]["tier"].(string)
		tj, _ := out[j]["tier"].(string)
		if tierRank[ti] != tierRank[tj] {
			return tierRank[ti] < tierRank[tj]
		}
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	doc := map[string]any{"hotels": out, "classes": totals}
	if guest != nil {
		doc["guest"] = guest
	} else {
		sealedAdmission := b.cfg.SealedAdmission
		if sealedAdmission == "" {
			sealedAdmission = "on"
		}
		// Scoped joins verify the observed guest key against SNP REPORT_DATA,
		// and every subsequent miner call pins that key on both clients.
		doc["admission_policy"] = map[string]any{
			"sealed_admission":    sealedAdmission,
			"amd_verifier":        b.cfg.AMDVerifier != nil,
			"sealed_measurements": append([]string{}, b.cfg.SealedMeasurements...),
			"miner_hotkey_caps":   b.cfg.MinerHotkeyCaps,
			"miner_max_hotels":    b.cfg.MinerMaxHotels,
			"miner_tls_pin":       true,
		}
	}
	writeJSON(w, 200, doc)
}

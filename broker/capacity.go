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
// "default_sealed" flag. A guest with no policy behaves as before.
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
// is down, draining or resting after a failure, else freeFor. pick and the
// capacity catalog both use it, so the catalog never lists a hotel with free
// rooms that the placer would refuse. Caller holds b.mu.
func (b *broker) admissibleFree(h *hotel, now time.Time) int {
	if !h.ok || h.drain() || now.Before(h.backoffUntil) {
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
	// source is where the capacity comes from. Today only "broker": the
	// hotels of the config file and of runtime joins. A later miner SNP
	// plane adds its own source here (a "join" source); the catalog and the
	// placer read entries, not the source.
	source string
}

// capacityEntries lists the capacity sources. The seam for a later "join"
// source is here. Caller holds b.mu.
func (b *broker) capacityEntries() []capacityEntry {
	var out []capacityEntry
	for _, h := range b.hotelList() {
		out = append(out, capacityEntry{h: h, source: "broker"})
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
		"reserved_for": reserved,
	}
}

var tierRank = map[string]int{tierPrefer: 0, tierAllow: 1, "hotels": 2}

// handleCapacity serves GET /v1/broker/capacity. g is nil for the operator.
func (b *broker) handleCapacity(w http.ResponseWriter, g *guestState) {
	b.mu.Lock()
	now := time.Now()
	out := []map[string]any{}
	var guest map[string]any
	for _, e := range b.capacityEntries() {
		if g == nil {
			out = append(out, b.capacityDoc(e, now))
			continue
		}
		t := g.tierOf(e.h)
		if t == "" {
			continue
		}
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
	doc := map[string]any{"hotels": out}
	if guest != nil {
		doc["guest"] = guest
	}
	writeJSON(w, 200, doc)
}

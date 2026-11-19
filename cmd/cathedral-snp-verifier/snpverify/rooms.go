package snpverify

import (
	"fmt"
	"sort"
)

// Per-room numbering, serial rooms and pre-made (pool) rooms: room_numbering(),
// check_room_chain(), check_serial_room() and _check_pool_rooms() in
// verify_receipts.py. Integers that do not fit int64 fail here; Python would read them.

// ListDoc is the part of a receipts document the room checks read: a per-room
// list answer names its room_head and count. A plain list has none.
type ListDoc struct {
	Count       any
	HasCount    bool
	RoomHead    any
	HasRoomHead bool
}

type roomGroup struct {
	binding, room string
	rcs           []Receipt
}

// roomGroups is room_groups(): receipts by (binding, room id), in first-seen order.
func roomGroups(receipts []Receipt) []*roomGroup {
	var out []*roomGroup
	index := map[[2]string]*roomGroup{}
	for _, rc := range receipts {
		room, _ := rc.Statement["sandbox_id"].(string)
		if room == "" {
			continue
		}
		b, _ := rc.Statement["binding_sha256"].(string)
		key := [2]string{b, room}
		g := index[key]
		if g == nil {
			g = &roomGroup{binding: b, room: room}
			index[key] = g
			out = append(out, g)
		}
		g.rcs = append(g.rcs, rc)
	}
	return out
}

func hasNumbering(st map[string]any) bool {
	return hasKey(st, "room_sequence") || hasKey(st, "room_previous_receipt_sha256")
}

func hasCompleteNumbering(st map[string]any) bool {
	return hasKey(st, "room_sequence") && hasKey(st, "room_previous_receipt_sha256")
}

func roomSequenceOf(rc Receipt) int64 { n, _ := intOf(rc.Statement["room_sequence"]); return n }

func seqOfReceipt(rc Receipt) int64 { n, _ := sequenceOf(rc.Statement); return n }

// checkRoomChain is check_room_chain(): one room's numbered receipts run 1 to n with
// no gap and no repeat, each linked to the one before. It returns them in room order.
func checkRoomChain(room string, rcs []Receipt) ([]Receipt, error) {
	for _, rc := range rcs {
		st := rc.Statement
		where := fmt.Sprintf("room %s: receipt %d", room, seqOfReceipt(rc))
		if _, ok := intOf(st["room_sequence"]); !ok {
			return nil, fail(CodeRoomNumbering, "%s: room_sequence is not an integer", where)
		}
		if prev := st["room_previous_receipt_sha256"]; prev != nil {
			if s, ok := prev.(string); !ok || !isHex64Lower(s) {
				return nil, fail(CodeRoomNumbering, "%s: room_previous_receipt_sha256 is neither null nor 64 lower-case hex", where)
			}
		}
	}
	ordered := append([]Receipt(nil), rcs...)
	sort.SliceStable(ordered, func(i, j int) bool { return roomSequenceOf(ordered[i]) < roomSequenceOf(ordered[j]) })
	for i := range ordered {
		n := roomSequenceOf(ordered[i])
		if i > 0 && n == roomSequenceOf(ordered[i-1]) {
			return nil, fail(CodeRoomNumbering, "room %s: room_sequence %d appears more than once", room, n)
		}
	}
	if first := roomSequenceOf(ordered[0]); first != 1 {
		return nil, fail(CodeRoomNumbering, "room %s: room_sequence does not start at 1 (first is %d)", room, first)
	}
	for i := 1; i < len(ordered); i++ {
		if before, after := roomSequenceOf(ordered[i-1]), roomSequenceOf(ordered[i]); after != before+1 {
			return nil, fail(CodeRoomNumbering, "room %s: room_sequence jumps from %d to %d: a receipt is missing", room, before, after)
		}
	}
	for i, rc := range ordered {
		prev := rc.Statement["room_previous_receipt_sha256"]
		if i == 0 {
			if prev != nil {
				return nil, fail(CodeRoomNumbering, "room %s: room receipt 1 must have a null room_previous_receipt_sha256", room)
			}
		} else if s, _ := prev.(string); s != ordered[i-1].ReceiptSHA256 {
			return nil, fail(CodeRoomNumbering, "room %s: room receipt %d does not link to room receipt %d", room, i+1, i)
		}
	}
	return ordered, nil
}

// checkSerialRoom is check_serial_room(): its one create is receipt 1, and no
// receipt is for a lost answer (502).
func checkSerialRoom(room string, ordered []Receipt) error {
	for _, rc := range ordered {
		if rc.Statement["serial"] == true && roomSequenceOf(rc) != 1 {
			return fail(CodeRoomNumbering, "room %s: receipt %d: a serial create must be receipt 1 of its room", room, seqOfReceipt(rc))
		}
	}
	for _, rc := range ordered {
		st := rc.Statement
		where := fmt.Sprintf("room %s: receipt %d", room, seqOfReceipt(rc))
		if st["serial"] != true && actionOf(st) == "create" {
			return fail(CodeRoomNumbering, "%s: a second create in a serial room", where)
		}
		if n, ok := intOf(st["status"]); ok && n == 502 {
			return fail(CodeRoomNumbering, "%s: a lost answer (status 502) in a serial room", where)
		}
	}
	return nil
}

// checkRoomNumbering is room_numbering(). A room whose receipts all carry the
// numbering fields is checked in full; a room with some of them gets no claim (a
// warning in Python, nothing here); a room with none is left as it was. It returns
// the number of rooms that were checked in full.
func checkRoomNumbering(receipts []Receipt, list *ListDoc) (int, error) {
	groups := roomGroups(receipts)
	checked := 0
	for _, g := range groups {
		room, rcs := g.room, g.rcs
		serialSeen := false
		for _, rc := range rcs {
			st := rc.Statement
			where := fmt.Sprintf("room %s: receipt %d", room, seqOfReceipt(rc))
			if serial, present := st["serial"]; present {
				b, isBool := serial.(bool)
				if !isBool {
					return 0, fail(CodeRoomNumbering, "%s: serial is not a boolean", where)
				}
				if b {
					if actionOf(st) != "create" || !succeeded(st) {
						return 0, fail(CodeRoomNumbering, "%s: serial is set on a receipt that is not a successful create", where)
					}
					serialSeen = true
				}
			}
			if actionOf(st) == "room_end" {
				if reason, ok := st["reason"].(string); !ok || reason == "" {
					return 0, fail(CodeRoomNumbering, "%s: room_end has no reason", where)
				}
			}
		}
		anyNumbered, allComplete := false, true
		for _, rc := range rcs {
			anyNumbered = anyNumbered || hasNumbering(rc.Statement)
			allComplete = allComplete && hasCompleteNumbering(rc.Statement)
		}
		if serialSeen && !allComplete {
			for _, rc := range rcs {
				if rc.Statement["serial"] == true {
					return 0, fail(CodeRoomNumbering, "room %s: receipt %d: a serial create needs numbered receipts", room, seqOfReceipt(rc))
				}
			}
		}
		if !anyNumbered || !allComplete {
			continue
		}
		ordered, err := checkRoomChain(room, rcs)
		if err != nil {
			return 0, err
		}
		if serialSeen {
			if err := checkSerialRoom(room, ordered); err != nil {
				return 0, err
			}
		}
		checked++
	}
	return checked, checkListDocument(groups, list)
}

// checkListDocument is the tail of room_numbering(): a per-room list answer's count
// and room_head must agree with the receipts it holds.
func checkListDocument(groups []*roomGroup, list *ListDoc) error {
	if list == nil {
		return nil
	}
	count, hasCount := int64(0), false
	if list.HasCount {
		n, ok := intOf(list.Count)
		if !ok {
			return fail(CodeListDocument, "the list's count is not an integer")
		}
		count, hasCount = n, true
	}
	if !list.HasRoomHead {
		return nil
	}
	if len(groups) > 1 {
		return fail(CodeListDocument, "the list names a room_head but holds receipts of %d rooms", len(groups))
	}
	if len(groups) == 0 {
		if list.RoomHead != nil {
			return fail(CodeListDocument, "an empty room list names a nonempty room_head")
		}
		if hasCount && count != 0 {
			return fail(CodeListDocument, "an empty room list names a nonzero count")
		}
		return nil
	}
	rcs := groups[0].rcs
	numbered := true
	for _, rc := range rcs {
		numbered = numbered && hasCompleteNumbering(rc.Statement)
	}
	key := func(rc Receipt) int64 {
		if numbered {
			return roomSequenceOf(rc)
		}
		return seqOfReceipt(rc)
	}
	last := rcs[0]
	for _, rc := range rcs[1:] {
		if key(rc) > key(last) {
			last = rc
		}
	}
	if head, _ := list.RoomHead.(string); head != last.ReceiptSHA256 {
		return fail(CodeListDocument, "room %s: the last receipt is not the room_head the list names", groups[0].room)
	}
	if hasCount && count != int64(len(rcs)) {
		return fail(CodeListDocument, "room %s: the list names %d receipts but holds %d", groups[0].room, count, len(rcs))
	}
	return nil
}

// checkPoolRooms is _check_pool_rooms(): receipt 1 of a pre-made room is a pool
// create and receipt 2 is the claim made from it. It returns room -> the link the
// claim names, for the rooms that are claimed.
func checkPoolRooms(receipts []Receipt) (map[string]string, int, error) {
	links := map[string]string{}
	pools := 0
	for _, g := range roomGroups(receipts) {
		room, rcs := g.room, g.rcs
		var poolCreates, claims []Receipt
		for _, rc := range rcs {
			st := rc.Statement
			where := fmt.Sprintf("room %s: receipt %d", room, seqOfReceipt(rc))
			if pool, present := st["pool"]; present {
				b, isBool := pool.(bool)
				if !isBool {
					return nil, 0, fail(CodePoolRoom, "%s: pool is not a boolean", where)
				}
				if b {
					if actionOf(st) != "create" || !succeeded(st) {
						return nil, 0, fail(CodePoolRoom, "%s: pool is set on a receipt that is not a successful create", where)
					}
					if st["serial"] == true {
						return nil, 0, fail(CodePoolRoom, "%s: a pool create cannot also be serial", where)
					}
					if hasKey(st, "cathedral_sandbox_id") {
						return nil, 0, fail(CodePoolRoom, "%s: a pool create names a sandbox link", where)
					}
					poolCreates = append(poolCreates, rc)
				}
			}
		}
		for _, rc := range rcs {
			if actionOf(rc.Statement) == "claim" {
				claims = append(claims, rc)
				if len(poolCreates) == 0 {
					return nil, 0, fail(CodePoolRoom, "room %s: receipt %d: a claim in a room that was not made as a pool room", room, seqOfReceipt(rc))
				}
			}
		}
		if len(poolCreates) == 0 {
			continue
		}
		if len(poolCreates) != 1 {
			return nil, 0, fail(CodePoolRoom, "room %s: a pool room has one create", room)
		}
		pools++
		create := poolCreates[0]
		var ordered []Receipt
		if len(claims) > 0 {
			for _, rc := range rcs {
				if !hasCompleteNumbering(rc.Statement) {
					return nil, 0, fail(CodePoolRoom, "room %s: receipt %d: a claim needs numbered receipts: cannot show nothing sits between create and claim", room, seqOfReceipt(claims[0]))
				}
			}
			var err error
			if ordered, err = checkRoomChain(room, rcs); err != nil {
				return nil, 0, err
			}
		} else {
			ordered = append([]Receipt(nil), rcs...)
			sort.SliceStable(ordered, func(i, j int) bool { return seqOfReceipt(ordered[i]) < seqOfReceipt(ordered[j]) })
		}
		if ordered[0].ReceiptSHA256 != create.ReceiptSHA256 {
			return nil, 0, fail(CodePoolRoom, "room %s: a pool create must be receipt 1 of its room", room)
		}
		if len(claims) > 0 {
			for _, rc := range claims {
				if len(ordered) < 2 || ordered[1].ReceiptSHA256 != rc.ReceiptSHA256 {
					return nil, 0, fail(CodePoolRoom, "room %s: receipt %d: a claim must be receipt 2 of a pool room", room, seqOfReceipt(rc))
				}
			}
			st := ordered[1].Statement
			where := fmt.Sprintf("room %s: receipt %d", room, seqOfReceipt(ordered[1]))
			if target, _ := st["target"].(string); target != "POST /v1/sandboxes/"+room+"/claim" {
				return nil, 0, fail(CodePoolRoom, "%s: the claim's target is not POST /v1/sandboxes/%s/claim", where, room)
			}
			if from, _ := st["pooled_from"].(string); from != create.ReceiptSHA256 {
				return nil, 0, fail(CodePoolRoom, "%s: pooled_from is not the pool create's receipt hash", where)
			}
			if succeeded(st) {
				link, ok := st["cathedral_sandbox_id"].(string)
				if !ok || !isLowerUUID(link) {
					return nil, 0, fail(CodePoolRoom, "%s: cathedral_sandbox_id is not a lower-case UUID", where)
				}
				if n, ok := intOf(st["lifetime_seconds"]); !ok || n <= 0 {
					return nil, 0, fail(CodePoolRoom, "%s: lifetime_seconds is not a positive integer", where)
				}
				links[room] = link
			}
		} else if len(ordered) > 1 {
			// A room deleted before any claim is retired. Anything else at receipt 2 is a
			// request that reached the room with no claim.
			if second := ordered[1].Statement; actionOf(second) != "delete" {
				return nil, 0, fail(CodePoolRoom, "room %s: receipt %d: receipt 2 of a pool room is not a claim", room, seqOfReceipt(ordered[1]))
			}
		}
	}
	return links, pools, nil
}

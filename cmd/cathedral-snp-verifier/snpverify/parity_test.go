package snpverify

import (
	"strconv"
	"strings"
	"testing"
)

// Each case here is an input room-kit/verify_receipts.py rejects. The Go checker
// must reject it too; the test names the Python check it mirrors.

func TestRepeatedSequenceIsRefused(t *testing.T) { // verify_receipts: "sequence appears more than once"
	s := newSynth(t, nil)
	rcs := s.chain(t, map[string]any{}, map[string]any{})
	wantFail(t, s, append(rcs, rcs[1]), CodeReceiptSequenceRepeat)
}

func TestReceiptSchemaIsChecked(t *testing.T) { // verify_receipts: "not a cathedral_sealed_hotel_receipt_v1 statement"
	s := newSynth(t, nil)
	for name, schema := range map[string]any{
		"absent":      nil,
		"hotel level": "cathedral_hotel_receipt_v1",
		"other":       "x",
		"not string":  num("1"),
	} {
		t.Run(name, func(t *testing.T) {
			wantFail(t, s, s.chain(t, map[string]any{"schema": schema}), CodeReceiptSchema)
		})
	}
}

func TestStartCommandRule(t *testing.T) { // check_start_commands
	s := newSynth(t, nil)
	cmd := []any{"python", "-m", "http.server"}
	sum, err := sha256Canonical(cmd)
	if err != nil {
		t.Fatal(err)
	}
	create := func(extra map[string]any) []Receipt {
		extra["action"] = "create"
		return s.chain(t, extra)
	}
	t.Run("matching hash", func(t *testing.T) {
		wantPass(t, s, create(map[string]any{"start_command": cmd, "start_command_sha256": sum}))
	})
	t.Run("null command, no hash", func(t *testing.T) {
		wantPass(t, s, create(map[string]any{"start_command": explicitNull{}}))
	})
	t.Run("null command, null hash", func(t *testing.T) {
		wantPass(t, s, create(map[string]any{"start_command": explicitNull{}, "start_command_sha256": explicitNull{}}))
	})
	bad := map[string]map[string]any{
		"wrong hash":         {"start_command": cmd, "start_command_sha256": strings.Repeat("0", 64)},
		"missing hash":       {"start_command": cmd},
		"null hash":          {"start_command": cmd, "start_command_sha256": explicitNull{}},
		"hash for null cmd":  {"start_command": explicitNull{}, "start_command_sha256": sum},
		"command not a list": {"start_command": "sleep", "start_command_sha256": sum},
		"non-string part":    {"start_command": []any{"a", num("1")}, "start_command_sha256": sum},
		"empty list, no sum": {"start_command": []any{}},
	}
	for name, extra := range bad {
		t.Run(name, func(t *testing.T) {
			wantFail(t, s, create(extra), CodeStartCommand)
		})
	}
}

func TestAttestationShapeRule(t *testing.T) { // check_attestation_shape
	att := loadAtt(t, "attestation-proof.json")
	good := att.ReportB64
	mutate := map[string]func(*Attestation){
		"report with a newline":    func(a *Attestation) { a.ReportB64 = good[:100] + "\n" + good[100:] },
		"report with a space":      func(a *Attestation) { a.ReportB64 = good[:100] + " " + good[100:] },
		"report with a stray byte": func(a *Attestation) { a.ReportB64 = good[:100] + "!" + good[100:] },
		"report url alphabet":      func(a *Attestation) { a.ReportB64 = strings.NewReplacer("+", "-", "/", "_").Replace(good) },
		"report empty":             func(a *Attestation) { a.ReportB64 = "" },
		"receipt key short": func(a *Attestation) {
			a.Binding = cloneBinding(a.Binding)
			a.Binding["receipt_key_ed25519_b64"] = "AAAA"
		},
		"receipt key with newline": func(a *Attestation) {
			k := a.Binding["receipt_key_ed25519_b64"].(string)
			a.Binding = cloneBinding(a.Binding)
			a.Binding["receipt_key_ed25519_b64"] = k[:4] + "\n" + k[4:]
		},
		"receipt key not a string": func(a *Attestation) {
			a.Binding = cloneBinding(a.Binding)
			a.Binding["receipt_key_ed25519_b64"] = num("1")
		},
		"policy not a string": func(a *Attestation) {
			a.Binding = cloneBinding(a.Binding)
			a.Binding["policy"] = num("1")
		},
	}
	for name, mut := range mutate {
		t.Run(name, func(t *testing.T) {
			a := att
			mut(&a)
			_, err := VerifyAttestation(a, goodOpts(t))
			recordAttestation(t, a, err)
			if err == nil {
				t.Fatal("expected a failure")
			}
			if _, err := VerifyReceipts(a, nil, ""); err == nil && strings.Contains(name, "receipt key") {
				t.Fatal("VerifyReceipts accepted the key")
			}
		})
	}
}

func cloneBinding(b map[string]any) map[string]any {
	out := make(map[string]any, len(b))
	for k, v := range b {
		out[k] = v
	}
	return out
}

// wantFail runs the non-AMD checks in VerifyAll order and wants the given code.
func wantFail(t *testing.T, s *synth, rcs []Receipt, code string) {
	t.Helper()
	err := runChecks(s.att, rcs, "")
	recordCase(t, s.att, rcs, "", nil, err)
	wantCode(t, err, code)
}

func wantPass(t *testing.T, s *synth, rcs []Receipt) {
	t.Helper()
	err := runChecks(s.att, rcs, "")
	recordCase(t, s.att, rcs, "", nil, err)
	if err != nil {
		t.Fatalf("expected a pass: %v", err)
	}
}

const (
	testImage   = "sha256:0000000000000000000000000000000000000000000000000000000000000001"
	testArchive = "0000000000000000000000000000000000000000000000000000000000000002"
	testLink    = "123e4567-e89b-12d3-a456-426614174000"
)

// snapshotChain is: 1 create of room src, 2 snapshot of src, 3 fork of it into room dst.
// tweak edits the extras of receipt i before it is signed; prev is the hash before it.
var firstHash string

func snapshotChain(t *testing.T, s *synth, tweak func(i int, ex map[string]any, prev string)) []Receipt {
	content, err := snapshotContentSHA256(testImage, testArchive)
	if err != nil {
		t.Fatal(err)
	}
	return s.chainFn(t, 3, func(i int, prev string) map[string]any {
		var ex map[string]any
		switch i {
		case 1:
			ex = map[string]any{"action": "create", "sandbox_id": "src", "status": num("200")}
		case 2:
			firstHash = prev // receipt 1's hash, for cases that name a receipt that is not a snapshot
			ex = map[string]any{"action": "snapshot", "sandbox_id": "src", "status": num("200"), "snapshot_id": "snap1",
				"snapshot_image_id": testImage, "snapshot_work_archive_sha256": testArchive,
				"snapshot_size_bytes": num("10"), "snapshot_content_sha256": content}
		case 3:
			ex = map[string]any{"action": "create", "sandbox_id": "dst", "status": num("200"), "snapshot_id": "snap1",
				"snapshot_content_sha256": content, "snapshot_receipt_sha256": prev, "snapshot_source_sandbox_id": "src"}
		}
		if tweak != nil {
			tweak(i, ex, prev)
		}
		return ex
	})
}

func TestSnapshotRules(t *testing.T) { // check_snapshot_shapes, check_snapshot_edges
	s := newSynth(t, nil)
	wantPass(t, s, snapshotChain(t, s, nil))
	other, _ := snapshotContentSHA256(testImage, strings.Repeat("a", 64))
	cases := []struct {
		name  string
		code  string
		tweak func(i int, ex map[string]any, prev string)
	}{
		{"snapshot with some members", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				delete(ex, "snapshot_size_bytes")
			}
		}},
		{"failed snapshot carries members", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["status"] = num("500")
			}
		}},
		{"image id without the sha256 prefix", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["snapshot_image_id"] = strings.TrimPrefix(testImage, "sha256:")
			}
		}},
		{"upper-case archive hash", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["snapshot_work_archive_sha256"] = strings.Repeat("A", 64)
			}
		}},
		{"negative size", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["snapshot_size_bytes"] = num("-1")
			}
		}},
		{"float size", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["snapshot_size_bytes"] = num("1.0")
			}
		}},
		{"empty snapshot id", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["snapshot_id"] = ""
			}
		}},
		{"snapshot without sandbox_id", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				delete(ex, "sandbox_id")
			}
		}},
		{"content hash does not recompute", CodeSnapshotEdge, func(i int, ex map[string]any, _ string) {
			if i == 2 || i == 3 {
				ex["snapshot_content_sha256"] = other
			}
		}},
		{"fork with some members", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 3 {
				delete(ex, "snapshot_source_sandbox_id")
			}
		}},
		{"failed fork carries members", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 3 {
				ex["status"] = num("500")
			}
		}},
		{"fork names a receipt that is not a snapshot", CodeSnapshotEdge, func(i int, ex map[string]any, _ string) {
			if i == 3 {
				ex["snapshot_receipt_sha256"] = firstHash
			}
		}},
		{"fork names another snapshot id", CodeSnapshotEdge, func(i int, ex map[string]any, _ string) {
			if i == 3 {
				ex["snapshot_id"] = "snap2"
			}
		}},
		{"fork names another content hash", CodeSnapshotEdge, func(i int, ex map[string]any, _ string) {
			if i == 3 {
				ex["snapshot_content_sha256"] = other
			}
		}},
		{"fork names another source room", CodeSnapshotEdge, func(i int, ex map[string]any, _ string) {
			if i == 3 {
				ex["snapshot_source_sandbox_id"] = "elsewhere"
			}
		}},
		{"snapshot_delete with a room", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 3 {
				for k := range ex {
					delete(ex, k)
				}
				ex["action"], ex["sandbox_id"], ex["snapshot_id"], ex["status"] = "snapshot_delete", "src", "snap1", num("200")
			}
		}},
		{"snapshot_delete without sandbox_id", CodeSnapshotMalformed, func(i int, ex map[string]any, _ string) {
			if i == 3 {
				for k := range ex {
					delete(ex, k)
				}
				ex["action"], ex["snapshot_id"], ex["status"] = "snapshot_delete", "snap1", num("200")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { wantFail(t, s, snapshotChain(t, s, tc.tweak), tc.code) })
	}
	t.Run("repeat of a snapshot disagrees", func(t *testing.T) {
		content, _ := snapshotContentSHA256(testImage, strings.Repeat("a", 64))
		rcs := s.chainFn(t, 3, func(i int, prev string) map[string]any {
			a := map[string]any{"action": "snapshot", "sandbox_id": "src", "status": num("200"), "snapshot_id": "snap1",
				"snapshot_image_id": testImage, "snapshot_work_archive_sha256": testArchive, "snapshot_size_bytes": num("10")}
			if i == 1 {
				a["snapshot_content_sha256"], _ = snapshotContentSHA256(testImage, testArchive)
			} else {
				a["snapshot_work_archive_sha256"], a["snapshot_content_sha256"] = strings.Repeat("a", 64), content
			}
			return a
		})
		wantFail(t, s, rcs[:2], CodeSnapshotEdge)
	})
	t.Run("fork after the snapshot was deleted", func(t *testing.T) {
		content, _ := snapshotContentSHA256(testImage, testArchive)
		rcs := s.chainFn(t, 3, func(i int, prev string) map[string]any {
			switch i {
			case 1:
				return map[string]any{"action": "snapshot", "sandbox_id": "src", "status": num("200"), "snapshot_id": "snap1",
					"snapshot_image_id": testImage, "snapshot_work_archive_sha256": testArchive,
					"snapshot_size_bytes": num("10"), "snapshot_content_sha256": content}
			case 2:
				return map[string]any{"action": "snapshot_delete", "sandbox_id": explicitNull{}, "snapshot_id": "snap1", "status": num("200")}
			}
			return map[string]any{"action": "create", "sandbox_id": "dst", "status": num("200"), "snapshot_id": "snap1",
				"snapshot_content_sha256": content, "snapshot_receipt_sha256": strings.Repeat("0", 64), "snapshot_source_sandbox_id": "src"}
		})
		wantFail(t, s, rcs, CodeSnapshotEdge)
	})
}

// roomChain is n receipts of one room, numbered 1 to n with real links. edit changes the
// extras of receipt i before it is signed; prev is the hash of the receipt before it.
func roomChain(t *testing.T, s *synth, n int, edit func(i int, ex map[string]any)) []Receipt {
	return s.chainFn(t, n, func(i int, prev string) map[string]any {
		ex := map[string]any{"sandbox_id": "r1", "status": num("200"), "room_sequence": num(strconv.Itoa(i))}
		if i == 1 {
			ex["action"] = "create"
			ex["room_previous_receipt_sha256"] = explicitNull{}
		} else {
			ex["room_previous_receipt_sha256"] = prev
		}
		if edit != nil {
			edit(i, ex)
		}
		return ex
	})
}

func TestRoomNumberingRules(t *testing.T) { // room_numbering, check_room_chain, check_serial_room
	s := newSynth(t, nil)
	wantPass(t, s, roomChain(t, s, 3, nil))
	set := func(i int, k string, v any) func(int, map[string]any) {
		return func(at int, ex map[string]any) {
			if at == i {
				ex[k] = v
			}
		}
	}
	serialCreate := func(at int, ex map[string]any) {
		if at == 1 {
			ex["serial"] = true
		}
	}
	cases := []struct {
		name string
		edit func(int, map[string]any)
	}{
		{"gap in room_sequence", set(3, "room_sequence", num("4"))},
		{"repeated room_sequence", set(3, "room_sequence", num("2"))},
		{"does not start at 1", func(at int, ex map[string]any) { ex["room_sequence"] = num(strconv.Itoa(at + 1)) }},
		{"room_sequence not an integer", set(2, "room_sequence", "2")},
		{"room_sequence float", set(2, "room_sequence", num("2.0"))},
		{"bad link", set(3, "room_previous_receipt_sha256", strings.Repeat("0", 64))},
		{"first receipt links to something", set(1, "room_previous_receipt_sha256", strings.Repeat("0", 64))},
		{"link is not hex", set(2, "room_previous_receipt_sha256", "xyz")},
		{"link is a number", set(2, "room_previous_receipt_sha256", num("1"))},
		{"serial not a boolean", set(1, "serial", "yes")},
		{"serial on a failed create", func(at int, ex map[string]any) {
			if at == 1 {
				ex["serial"], ex["status"] = true, num("500")
			}
		}},
		{"serial on an exec", set(2, "serial", true)},
		{"serial create without numbering", func(at int, ex map[string]any) {
			if at == 1 {
				ex["serial"] = true
			}
			if at == 2 {
				delete(ex, "room_sequence")
			}
		}},
		{"second create in a serial room", func(at int, ex map[string]any) { serialCreate(at, ex); set(2, "action", "create")(at, ex) }},
		{"lost answer in a serial room", func(at int, ex map[string]any) { serialCreate(at, ex); set(3, "status", num("502"))(at, ex) }},
		{"room_end without a reason", set(3, "action", "room_end")},
		{"room_end with an empty reason", func(at int, ex map[string]any) { set(3, "action", "room_end")(at, ex); set(3, "reason", "")(at, ex) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { wantFail(t, s, roomChain(t, s, 3, tc.edit), CodeRoomNumbering) })
	}
	t.Run("serial room passes when well formed", func(t *testing.T) {
		wantPass(t, s, roomChain(t, s, 3, serialCreate))
	})
	t.Run("a partly numbered room is left alone", func(t *testing.T) {
		wantPass(t, s, roomChain(t, s, 3, func(at int, ex map[string]any) {
			if at == 3 {
				delete(ex, "room_sequence")
			}
		}))
	})
}

func TestRoomListDocument(t *testing.T) { // room_numbering: the list's count and room_head
	s := newSynth(t, nil)
	rcs := roomChain(t, s, 3, nil)
	head := rcs[2].ReceiptSHA256
	list := func(count any, hasCount bool, roomHead any, hasHead bool) *ListDoc {
		return &ListDoc{Count: count, HasCount: hasCount, RoomHead: roomHead, HasRoomHead: hasHead}
	}
	good := list(num("3"), true, head, true)
	err := runChecksList(s.att, rcs, "", good)
	recordCase(t, s.att, rcs, "", good, err)
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]*ListDoc{
		"room_head is not the last receipt": list(num("3"), true, rcs[1].ReceiptSHA256, true),
		"room_head is a number":             list(num("3"), true, num("1"), true),
		"count is wrong":                    list(num("2"), true, head, true),
		"count is a string":                 list("3", true, head, true),
		"count is a float":                  list(num("3.0"), true, head, true),
		"count is a boolean":                list(true, true, head, true),
	}
	for name, doc := range bad {
		t.Run(name, func(t *testing.T) {
			err := runChecksList(s.att, rcs, "", doc)
			recordCase(t, s.att, rcs, "", doc, err)
			wantCode(t, err, CodeListDocument)
		})
	}
	t.Run("empty list with a room_head", func(t *testing.T) {
		doc := list(nil, false, head, true)
		err := runChecksList(s.att, nil, "", doc)
		recordCase(t, s.att, nil, "", doc, err)
		wantCode(t, err, CodeListDocument)
	})
	t.Run("empty list with a count", func(t *testing.T) {
		doc := list(num("1"), true, nil, true)
		err := runChecksList(s.att, nil, "", doc)
		recordCase(t, s.att, nil, "", doc, err)
		wantCode(t, err, CodeListDocument)
	})
	t.Run("room_head over two rooms", func(t *testing.T) {
		two := s.chainFn(t, 2, func(i int, prev string) map[string]any {
			return map[string]any{"sandbox_id": "r" + strconv.Itoa(i)}
		})
		doc := list(nil, false, head, true)
		err := runChecksList(s.att, two, "", doc)
		recordCase(t, s.att, two, "", doc, err)
		wantCode(t, err, CodeListDocument)
	})
	t.Run("document fields come from the file", func(t *testing.T) {
		_, _, doc, err := ParseReceiptsDocument([]byte(`{"count":3,"room_head":"abc","receipts":[]}`))
		if err != nil || doc == nil || !doc.HasCount || !doc.HasRoomHead {
			t.Fatalf("%v %+v", err, doc)
		}
		if _, _, doc, _ = ParseReceiptsDocument([]byte(`[]`)); doc != nil {
			t.Fatal("a plain list has no list document")
		}
	})
}

// poolChain is a pool create (receipt 1) and its claim (receipt 2), numbered.
func poolChain(t *testing.T, s *synth, edit func(i int, ex map[string]any, prev string)) []Receipt {
	return s.chainFn(t, 2, func(i int, prev string) map[string]any {
		ex := map[string]any{"sandbox_id": "p1", "status": num("200"), "room_sequence": num(strconv.Itoa(i))}
		if i == 1 {
			ex["action"], ex["pool"] = "create", true
			ex["room_previous_receipt_sha256"] = explicitNull{}
		} else {
			ex["action"], ex["room_previous_receipt_sha256"] = "claim", prev
			ex["target"], ex["pooled_from"] = "POST /v1/sandboxes/p1/claim", prev
			ex["cathedral_sandbox_id"], ex["lifetime_seconds"] = testLink, num("60")
		}
		if edit != nil {
			edit(i, ex, prev)
		}
		return ex
	})
}

func TestPoolRoomRules(t *testing.T) { // _check_pool_rooms
	s := newSynth(t, nil)
	wantPass(t, s, poolChain(t, s, nil))
	links, pools, err := checkPoolRooms(poolChain(t, s, nil))
	if err != nil || pools != 1 || links["p1"] != testLink {
		t.Fatalf("%v %d %v", err, pools, links)
	}
	cases := []struct {
		name string
		edit func(int, map[string]any, string)
	}{
		{"pool not a boolean", func(i int, ex map[string]any, _ string) {
			if i == 1 {
				ex["pool"] = "true"
			}
		}},
		{"pool on an exec", func(i int, ex map[string]any, _ string) {
			if i == 1 {
				ex["action"] = "exec"
			}
		}},
		{"pool create that failed", func(i int, ex map[string]any, _ string) {
			if i == 1 {
				ex["status"] = num("500")
			}
		}},
		{"pool create that is serial", func(i int, ex map[string]any, _ string) {
			if i == 1 {
				ex["serial"] = true
			}
		}},
		{"pool create with a link", func(i int, ex map[string]any, _ string) {
			if i == 1 {
				ex["cathedral_sandbox_id"] = testLink
			}
		}},
		{"claim with the wrong target", func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["target"] = "POST /v1/sandboxes/other/claim"
			}
		}},
		{"claim with the wrong pooled_from", func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["pooled_from"] = strings.Repeat("0", 64)
			}
		}},
		{"claim with a bad link", func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["cathedral_sandbox_id"] = strings.ToUpper(testLink)
			}
		}},
		{"claim with lifetime 0", func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["lifetime_seconds"] = num("0")
			}
		}},
		{"claim with a float lifetime", func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["lifetime_seconds"] = num("60.0")
			}
		}},
		{"claim in a room that is not a pool room", func(i int, ex map[string]any, _ string) {
			if i == 1 {
				delete(ex, "pool")
			}
		}},
		{"claim without numbering", func(i int, ex map[string]any, _ string) {
			if i == 2 {
				delete(ex, "room_sequence")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { wantFail(t, s, poolChain(t, s, tc.edit), CodePoolRoom) })
	}
	t.Run("receipt 2 is neither claim nor delete", func(t *testing.T) {
		rcs := poolChain(t, s, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["action"] = "exec"
			}
		})
		wantFail(t, s, rcs, CodePoolRoom)
	})
	t.Run("a retired pool room passes", func(t *testing.T) {
		wantPass(t, s, poolChain(t, s, func(i int, ex map[string]any, _ string) {
			if i == 2 {
				ex["action"] = "delete"
				delete(ex, "target")
			}
		}))
	})
	t.Run("claim is receipt 3", func(t *testing.T) {
		rcs := s.chainFn(t, 3, func(i int, prev string) map[string]any {
			ex := map[string]any{"sandbox_id": "p1", "status": num("200"), "room_sequence": num(strconv.Itoa(i)),
				"room_previous_receipt_sha256": prev}
			switch i {
			case 1:
				ex["action"], ex["pool"], ex["room_previous_receipt_sha256"] = "create", true, explicitNull{}
			case 3:
				ex["action"], ex["target"], ex["pooled_from"] = "claim", "POST /v1/sandboxes/p1/claim", prev
				ex["cathedral_sandbox_id"], ex["lifetime_seconds"] = testLink, num("60")
			}
			return ex
		})
		wantFail(t, s, rcs, CodePoolRoom)
	})
	t.Run("two pool creates", func(t *testing.T) {
		rcs := s.chainFn(t, 2, func(i int, prev string) map[string]any {
			return map[string]any{"action": "create", "pool": true, "sandbox_id": "p1", "status": num("200")}
		})
		wantFail(t, s, rcs, CodePoolRoom)
	})
}

func TestPolicyTimelineTypes(t *testing.T) { // policy_timeline
	s := newSynth(t, nil)
	policy := map[string]any{"mode": "allowlist", "allow": []any{"example.com"}}
	withPolicy := func(p map[string]any, mut func(map[string]any)) []Receipt {
		ex := map[string]any{"sandbox_id": "r1", "action": "create", "status": num("200"), "issued_at": num("5"),
			"network_policy": p, "network_policy_sha256": policyHash(t, p)}
		if mut != nil {
			mut(ex)
		}
		return s.chain(t, ex)
	}
	wantPass(t, s, withPolicy(policy, nil))
	bad := map[string]func(map[string]any){
		"status null":    func(ex map[string]any) { ex["status"] = explicitNull{} },
		"status missing": func(ex map[string]any) { ex["status"] = nil },
		"issued_at null": func(ex map[string]any) { ex["issued_at"] = nil },
	}
	for name, mut := range bad {
		t.Run(name, func(t *testing.T) { wantFail(t, s, withPolicy(policy, mut), CodeNetworkPolicyMismatch) })
	}
	for name, p := range map[string]map[string]any{
		"mode not a string": {"mode": num("1"), "allow": []any{}},
		"allow not a list":  {"mode": "allowlist", "allow": "example.com"},
		"allow null":        {"mode": "allowlist", "allow": nil},
		"no mode":           {"allow": []any{}},
		"no allow":          {"mode": "allowlist"},
	} {
		t.Run(name, func(t *testing.T) { wantFail(t, s, withPolicy(p, nil), CodeNetworkPolicyMismatch) })
	}
	t.Run("delete with a null status after a policy", func(t *testing.T) {
		rcs := s.chain(t, withPolicy(policy, nil)[0].Statement, map[string]any{"sandbox_id": "r1", "action": "delete",
			"issued_at": num("6"), "status": explicitNull{}})
		wantFail(t, s, rcs, CodeNetworkPolicyMismatch)
	})
}

func TestGuestIngressRule(t *testing.T) { // verify_guest_ingress
	for name, ingress := range map[string]any{
		"not an object": "x",
		"wrong schema":  map[string]any{"schema": "other", "tls_spki_sha256": strings.Repeat("a", 64)},
		"no key":        map[string]any{"schema": "cathedral_guest_ingress_v1"},
		"upper-case":    map[string]any{"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": strings.Repeat("A", 64)},
		"short":         map[string]any{"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": "ab"},
	} {
		t.Run(name, func(t *testing.T) {
			s := newSynth(t, func(b map[string]any) { b["guest_ingress"] = ingress })
			wantFail(t, s, nil, CodeGuestTLSMalformed)
		})
	}
	good := newSynth(t, func(b map[string]any) {
		b["guest_ingress"] = map[string]any{"schema": "cathedral_guest_ingress_v1", "tls_spki_sha256": strings.Repeat("a", 64)}
	})
	t.Run("good", func(t *testing.T) { wantPass(t, good, nil) })
}

package snpverify

import (
	"sort"
	"strings"
)

// Snapshots and forks (AB#604): check_snapshot_shapes() and check_snapshot_edges()
// in verify_receipts.py. A snapshot receipt names the snapshot and the two parts of
// its content hash; a fork's create receipt names the snapshot receipt it was made
// from. Integers that do not fit int64 fail here; Python would read them.

var snapshotMembers = []string{"snapshot_id", "snapshot_image_id", "snapshot_work_archive_sha256",
	"snapshot_size_bytes", "snapshot_content_sha256"}
var forkMembers = []string{"snapshot_id", "snapshot_content_sha256", "snapshot_receipt_sha256",
	"snapshot_source_sandbox_id"}

// succeeded is _succeeded(): an integer status from 200 to 299.
func succeeded(st map[string]any) bool {
	n, ok := intOf(st["status"])
	return ok && n >= 200 && n < 300
}

func intOf(v any) (int64, bool) {
	if !isInt64(v) {
		return 0, false
	}
	n, err := v.(interface{ Int64() (int64, error) }).Int64()
	return n, err == nil
}

func actionOf(st map[string]any) string {
	a, _ := st["action"].(string)
	return a
}

func presentMembers(st map[string]any, names []string) int {
	n := 0
	for _, m := range names {
		if _, ok := st[m]; ok {
			n++
		}
	}
	return n
}

func checkSnapshotMember(st map[string]any, name, where string) error {
	value := st[name]
	s, isStr := value.(string)
	switch name {
	case "snapshot_id", "snapshot_source_sandbox_id":
		if !isStr {
			return fail(CodeSnapshotMalformed, "%s: %s is not a string", where, name)
		}
		if s == "" {
			return fail(CodeSnapshotMalformed, "%s: %s is empty", where, name)
		}
	case "snapshot_image_id":
		if !isStr || !strings.HasPrefix(s, "sha256:") || !isHex64Lower(strings.TrimPrefix(s, "sha256:")) {
			return fail(CodeSnapshotMalformed, "%s: snapshot_image_id is not sha256: and 64 lower-case hex", where)
		}
	case "snapshot_size_bytes":
		if n, ok := intOf(value); !ok || n < 0 {
			return fail(CodeSnapshotMalformed, "%s: snapshot_size_bytes is not an integer of 0 or more", where)
		}
	default:
		if !isStr || !isHex64Lower(s) {
			return fail(CodeSnapshotMalformed, "%s: %s is not 64 lower-case hex", where, name)
		}
	}
	return nil
}

// checkSnapshotShapes is check_snapshot_shapes(): the snapshot members of one
// statement by action, presence first, then form.
func checkSnapshotShapes(st map[string]any, where string) error {
	ok := succeeded(st)
	_, hasSandbox := st["sandbox_id"]
	_, isStr := st["sandbox_id"].(string)
	switch actionOf(st) {
	case "snapshot":
		present := presentMembers(st, snapshotMembers)
		if ok && present > 0 {
			if present != len(snapshotMembers) {
				return fail(CodeSnapshotMalformed, "%s: a snapshot receipt has some of its five snapshot members and not all", where)
			}
			if !hasSandbox {
				return fail(CodeSnapshotMalformed, "%s: a snapshot receipt has no sandbox_id string", where)
			}
		}
		if !ok && present > 0 {
			return fail(CodeSnapshotMalformed, "%s: a snapshot receipt that did not succeed carries snapshot members", where)
		}
		if ok && present > 0 {
			for _, m := range snapshotMembers {
				if err := checkSnapshotMember(st, m, where); err != nil {
					return err
				}
			}
			if !isStr {
				return fail(CodeSnapshotMalformed, "%s: a snapshot receipt has no sandbox_id string", where)
			}
		}
	case "create":
		present := presentMembers(st, forkMembers)
		if present > 0 && ok {
			if present != len(forkMembers) {
				return fail(CodeSnapshotMalformed, "%s: a create has some of its four snapshot fork members and not all", where)
			}
			if !hasSandbox {
				return fail(CodeSnapshotMalformed, "%s: a fork's create has no sandbox_id string", where)
			}
		}
		if present > 0 {
			if !ok {
				return fail(CodeSnapshotMalformed, "%s: a create that did not succeed carries snapshot fork members", where)
			}
			for _, m := range forkMembers {
				if err := checkSnapshotMember(st, m, where); err != nil {
					return err
				}
			}
			if !isStr {
				return fail(CodeSnapshotMalformed, "%s: a fork's create has no sandbox_id string", where)
			}
		}
	case "snapshot_delete":
		if !hasSandbox {
			return fail(CodeSnapshotMalformed, "%s: a snapshot_delete has no sandbox_id member: it must be null, not left out", where)
		}
		if _, has := st["snapshot_id"]; !has {
			return fail(CodeSnapshotMalformed, "%s: snapshot_id is not a string", where)
		}
		if st["sandbox_id"] != nil {
			return fail(CodeSnapshotMalformed, "%s: a snapshot_delete has a sandbox_id: it must be null", where)
		}
		if err := checkSnapshotMember(st, "snapshot_id", where); err != nil {
			return err
		}
		if _, has := st["snapshot_source_sandbox_id"]; has {
			return checkSnapshotMember(st, "snapshot_source_sandbox_id", where)
		}
	}
	return nil
}

func snapshotContentSHA256(imageID, workArchiveSHA256 string) (string, error) {
	return sha256Canonical(map[string]any{"schema": "cathedral_snapshot_content_v1", "image_id": imageID,
		"work_archive_sha256": workArchiveSHA256})
}

type snapshotKey struct{ binding, snapshot string }

// checkSnapshotEdges is check_snapshot_edges(), on receipts whose shapes, hashes,
// signatures and sequences are already checked. Everything is scoped by binding and
// ordered by the signed sequence, never by place in the list.
func checkSnapshotEdges(receipts []Receipt) error {
	byHash := map[string]int{}
	for i, rc := range receipts {
		byHash[rc.ReceiptSHA256] = i
	}
	order := make([]int, len(receipts))
	for i := range order {
		order[i] = i
	}
	bindingOf := func(i int) string { b, _ := receipts[i].Statement["binding_sha256"].(string); return b }
	seqOf := func(i int) int64 { n, _ := sequenceOf(receipts[i].Statement); return n }
	sort.SliceStable(order, func(a, b int) bool {
		if ba, bb := bindingOf(order[a]), bindingOf(order[b]); ba != bb {
			return ba < bb
		}
		return seqOf(order[a]) < seqOf(order[b])
	})
	var snapshots, forks []int
	firstDelete := map[snapshotKey]int{}
	seen := false
	for _, i := range order {
		st := receipts[i].Statement
		action := actionOf(st)
		if action == "snapshot" || action == "snapshot_delete" {
			seen = true
		}
		_, hasID := st["snapshot_id"]
		_, hasReceipt := st["snapshot_receipt_sha256"]
		switch {
		case action == "snapshot" && succeeded(st) && hasID:
			snapshots = append(snapshots, i)
		case action == "snapshot_delete" && succeeded(st):
			id, _ := st["snapshot_id"].(string)
			key := snapshotKey{bindingOf(i), id}
			if _, dup := firstDelete[key]; !dup {
				firstDelete[key] = i
			}
		case action == "create" && hasReceipt:
			forks = append(forks, i)
		}
	}
	if !seen && len(forks) == 0 {
		return nil
	}
	str := func(i int, k string) string { s, _ := receipts[i].Statement[k].(string); return s }
	for _, i := range snapshots {
		want, err := snapshotContentSHA256(str(i, "snapshot_image_id"), str(i, "snapshot_work_archive_sha256"))
		if err != nil || str(i, "snapshot_content_sha256") != want {
			return fail(CodeSnapshotEdge, "receipt %d: snapshot_content_sha256 does not recompute from snapshot_image_id and snapshot_work_archive_sha256", seqOf(i))
		}
	}
	firstOf := map[snapshotKey]int{}
	for _, i := range snapshots {
		key := snapshotKey{bindingOf(i), str(i, "snapshot_id")}
		if _, ok := firstOf[key]; !ok {
			firstOf[key] = i
		}
	}
	for _, i := range snapshots {
		first := firstOf[snapshotKey{bindingOf(i), str(i, "snapshot_id")}]
		if first == i {
			continue
		}
		if str(first, "snapshot_content_sha256") != str(i, "snapshot_content_sha256") {
			return fail(CodeSnapshotEdge, "snapshot %s: receipt %d and receipt %d disagree on snapshot_content_sha256", str(i, "snapshot_id"), seqOf(first), seqOf(i))
		}
		if receipts[first].Statement["sandbox_id"] != receipts[i].Statement["sandbox_id"] {
			return fail(CodeSnapshotEdge, "snapshot %s: receipt %d and receipt %d disagree on the source room", str(i, "snapshot_id"), seqOf(first), seqOf(i))
		}
	}
	for _, i := range forks {
		where := func(format string) error { return fail(CodeSnapshotEdge, "receipt %d: "+format, seqOf(i)) }
		if t, found := byHash[str(i, "snapshot_receipt_sha256")]; found {
			tst := receipts[t].Statement
			switch {
			case bindingOf(t) != bindingOf(i):
				return where("snapshot_receipt_sha256 names a receipt under another binding")
			case actionOf(tst) != "snapshot" || !succeeded(tst):
				return where("the fork names a receipt that is not a successful snapshot receipt")
			case !hasKey(tst, "snapshot_id"):
				return where("the fork names a snapshot receipt that states no snapshot")
			case str(t, "snapshot_id") != str(i, "snapshot_id"):
				return where("the fork names a snapshot receipt with another snapshot_id")
			case str(t, "snapshot_content_sha256") != str(i, "snapshot_content_sha256"):
				return where("the fork names a snapshot receipt with another snapshot_content_sha256")
			case tst["sandbox_id"] != receipts[i].Statement["snapshot_source_sandbox_id"]:
				return where("the fork names a snapshot receipt of another room than snapshot_source_sandbox_id")
			case seqOf(t) >= seqOf(i):
				return where("the fork names a snapshot receipt that does not come before it")
			case firstOf[snapshotKey{bindingOf(t), str(t, "snapshot_id")}] != t:
				return where("the fork names a snapshot receipt that is not the first to sign that snapshot")
			}
		}
		if gone, ok := firstDelete[snapshotKey{bindingOf(i), str(i, "snapshot_id")}]; ok && seqOf(gone) <= seqOf(i) {
			return where("the fork is of a snapshot that an earlier receipt deleted")
		}
	}
	return nil
}

func hasKey(st map[string]any, k string) bool { _, ok := st[k]; return ok }

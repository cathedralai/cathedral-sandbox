package vmdisk

import (
	"strings"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

const diskSize = 64 * MiB

func TestIntentRoundTripAndBinding(t *testing.T) {
	id := testIdentity(t, "vm-0123456789ab")
	other := testIdentity(t, "vm-ba9876543210")
	rec, err := EncodeIntent(id, diskSize)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(rec[:]), "CVMINT01") {
		t.Fatal("magic")
	}
	if got := ParseIntent(rec[:], id, diskSize); got != IntentValid {
		t.Fatalf("own intent reads %s", got)
	}
	if got := ParseIntent(rec[:], other, diskSize); got != IntentForeign {
		t.Fatalf("another identity reads %s", got)
	}
	if got := ParseIntent(rec[:], id, diskSize+MiB); got != IntentForeign {
		t.Fatalf("another disk size reads %s", got)
	}
	if got := ParseIntent(make([]byte, RecordBytes), id, diskSize); got != IntentNone {
		t.Fatalf("zero reads %s", got)
	}
}

func TestIntentRefusesEveryFlippedByteAndATornWrite(t *testing.T) {
	id := testIdentity(t, "vm-0123456789ab")
	rec, _ := EncodeIntent(id, diskSize)
	for i := 0; i < RecordBytes; i++ {
		bad := rec
		bad[i] ^= 0x01
		if ParseIntent(bad[:], id, diskSize) != IntentNone {
			t.Fatalf("byte %d flipped still reads as an intent", i)
		}
	}
	// A cut inside F2: a prefix of the record over zero.
	for _, n := range []int{8, 12, 100, 200} {
		var torn [RecordBytes]byte
		copy(torn[:n], rec[:n])
		if ParseIntent(torn[:], id, diskSize) != IntentNone {
			t.Fatalf("a %d-byte prefix reads as an intent", n)
		}
	}
	if ParseIntent(rec[:100], id, diskSize) != IntentNone {
		t.Fatal("a short buffer reads as an intent")
	}
}

func TestIntentRefusesAnotherBody(t *testing.T) {
	id := testIdentity(t, "vm-0123456789ab")
	body := func(o vmidentity.Object) [RecordBytes]byte {
		raw, err := vmidentity.Canonical(o)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := frame(intentMagic, raw)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	good := vmidentity.Object{"schema": IntentSchema, "vm_id": id.VMID, "identity_sha256": id.SHA256Hex(), "disk_bytes": int64(diskSize)}
	if rec := body(good); ParseIntent(rec[:], id, diskSize) != IntentValid {
		t.Fatal("control")
	}
	for name, mutate := range map[string]func(vmidentity.Object){
		"schema":      func(o vmidentity.Object) { o["schema"] = "cathedral.vm.format-intent/v2" },
		"extra field": func(o vmidentity.Object) { o["x"] = "y" },
		"no size":     func(o vmidentity.Object) { delete(o, "disk_bytes") },
		"size string": func(o vmidentity.Object) { o["disk_bytes"] = "67108864" },
		"bad vm_id":   func(o vmidentity.Object) { o["vm_id"] = "vm-XYZ" },
		"meta magic":  nil,
	} {
		o := vmidentity.Object{}
		for k, v := range good {
			o[k] = v
		}
		var rec [RecordBytes]byte
		if mutate == nil {
			raw, _ := vmidentity.Canonical(o)
			rec, _ = frame(metaMagic, raw)
		} else {
			mutate(o)
			rec = body(o)
		}
		if ParseIntent(rec[:], id, diskSize) != IntentNone {
			t.Errorf("%s: read as an intent", name)
		}
	}
}

func readyMeta(id vmidentity.Identity, seq int64) Meta {
	var m [48]byte
	m[0] = 0xaa
	return Meta{Seq: seq, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize, State: StateReady,
		Slots: map[int]string{0: MeasurementRole(m), 1: RoleRecovery}}
}

func TestMetaRoundTripAndTableRules(t *testing.T) {
	id := testIdentity(t, "vm-0123456789ab")
	m := readyMeta(id, 2)
	rec, err := EncodeMeta(m)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ParseMeta(rec[:])
	if !ok || got.Seq != 2 || got.DiskBytes != diskSize || got.State != StateReady || len(got.Slots) != 2 || got.Slots[1] != RoleRecovery || !got.Names(id) {
		t.Fatalf("round trip %+v", got)
	}
	init := Meta{Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize, State: StateInitializing, Slots: map[int]string{4: m.Slots[0]}}
	if _, err := EncodeMeta(init); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]Meta{
		"initializing with recovery": {Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize, State: StateInitializing, Slots: m.Slots},
		"ready without recovery":     {Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize, State: StateReady, Slots: init.Slots},
		"two recovery slots":         {Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize, State: StateReady, Slots: map[int]string{0: m.Slots[0], 1: RoleRecovery, 2: RoleRecovery}},
		"seq 0":                      {Seq: 0, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize, State: StateReady, Slots: m.Slots},
		"slot 32":                    {Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize, State: StateReady, Slots: map[int]string{32: m.Slots[0], 1: RoleRecovery}},
		"short measurement":          {Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize, State: StateReady, Slots: map[int]string{0: "m:aa", 1: RoleRecovery}},
		"other state":                {Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize, State: "open", Slots: m.Slots},
		"no disk size":               {Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), State: StateReady, Slots: m.Slots},
		"disk under the minimum":     {Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: MinDiskBytes - MiB, State: StateReady, Slots: m.Slots},
		"disk not whole MiB":         {Seq: 1, VMID: id.VMID, IdentitySHA256: id.SHA256Hex(), DiskBytes: diskSize + 512, State: StateReady, Slots: m.Slots},
	} {
		if _, err := EncodeMeta(bad); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	// A slot key that is not canonical decimal never parses.
	metaRecord := func(o vmidentity.Object) []byte {
		raw, err := vmidentity.Canonical(o)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := frame(metaMagic, raw)
		if err != nil {
			t.Fatal(err)
		}
		return rec[:]
	}
	fields := func(slots vmidentity.Object) vmidentity.Object {
		return vmidentity.Object{"schema": MetaSchema, "seq": int64(1), "vm_id": id.VMID, "identity_sha256": id.SHA256Hex(),
			"disk_bytes": int64(diskSize), "state": StateReady, "slots": slots}
	}
	good := vmidentity.Object{"0": m.Slots[0], "1": RoleRecovery}
	if _, ok := ParseMeta(metaRecord(fields(good))); !ok {
		t.Fatal("the hand-built control record does not parse")
	}
	if _, ok := ParseMeta(metaRecord(fields(vmidentity.Object{"00": m.Slots[0], "1": RoleRecovery}))); ok {
		t.Fatal("slot key 00 parsed")
	}
	// The #798 field set, without disk_bytes, is not a valid copy (#805).
	old := fields(good)
	delete(old, "disk_bytes")
	if _, ok := ParseMeta(metaRecord(old)); ok {
		t.Fatal("a meta without disk_bytes parsed")
	}
	for i := 0; i < RecordBytes; i += 7 {
		flipped := rec
		flipped[i] ^= 0x80
		if _, ok := ParseMeta(flipped[:]); ok {
			t.Fatalf("byte %d flipped still parses", i)
		}
	}
}

func TestChooseMetaWriteOrder(t *testing.T) {
	id := testIdentity(t, "vm-0123456789ab")
	enc := func(seq int64) []byte {
		rec, err := EncodeMeta(readyMeta(id, seq))
		if err != nil {
			t.Fatal(err)
		}
		return rec[:]
	}
	zero := make([]byte, RecordBytes)
	torn := append(append([]byte{}, enc(3)[:100]...), zero[100:]...)
	for name, c := range map[string]struct {
		c0, c1 []byte
		valid  bool
		copy   int
		seq    int64
	}{
		"first write":        {enc(1), zero, true, 0, 1},
		"second write":       {enc(1), enc(2), true, 1, 2},
		"third write":        {enc(3), enc(2), true, 0, 3},
		"torn third write":   {torn, enc(2), true, 1, 2},
		"torn first write":   {torn, zero, false, 0, 0},
		"equal, same bytes":  {enc(2), enc(2), true, 0, 2},
		"neither":            {zero, zero, false, 0, 0},
		"older copy 1 loses": {enc(5), enc(4), true, 0, 5},
	} {
		cur := ChooseMeta(c.c0, c.c1)
		if cur.Valid != c.valid || (c.valid && (cur.Copy != c.copy || cur.Meta.Seq != c.seq)) {
			t.Errorf("%s: %+v", name, cur)
		}
		if c.valid && cur.NextCopy() != 1-c.copy {
			t.Errorf("%s: next copy %d", name, cur.NextCopy())
		}
	}
	a := readyMeta(id, 2)
	b := readyMeta(id, 2)
	b.Slots = map[int]string{5: a.Slots[0], 6: RoleRecovery}
	ra, _ := EncodeMeta(a)
	rb, _ := EncodeMeta(b)
	if ChooseMeta(ra[:], rb[:]).Valid {
		t.Fatal("two different copies with one seq were trusted")
	}
}

func TestLayout(t *testing.T) {
	l, err := NewLayout(diskSize)
	if err != nil {
		t.Fatal(err)
	}
	if l.LUKSBytes != diskSize-MiB || l.IntentOffset != diskSize-MiB || l.VolumeBytes() != diskSize-MiB-16*MiB || l.FSBytes() != diskSize-MiB-32*MiB {
		t.Fatalf("%+v", l)
	}
	for _, bad := range []int64{0, MinDiskBytes - MiB, diskSize + 4096, MaxDiskBytes + MiB} {
		if _, err := NewLayout(bad); err == nil {
			t.Errorf("%d accepted", bad)
		}
	}
}

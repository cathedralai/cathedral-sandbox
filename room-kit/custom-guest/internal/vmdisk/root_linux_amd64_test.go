package vmdisk

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

// T3 (spec r3 13.1): init states on loop files.

func (h *harness) cryptsetupOn(d *disk, secrets [][]byte, args ...string) {
	h.t.Helper()
	d.attach().Close()
	defer d.detach()
	for i := range args {
		if args[i] == "DEV" {
			args[i] = d.loop
		}
	}
	r, err := h.tool.run(context.Background(), "test", slow, secrets, args...)
	if err != nil || r.Exit != 0 {
		h.t.Fatalf("cryptsetup %v: exit %d %s %v", args[0], r.Exit, r.Stderr, err)
	}
}

// writeMetaWith writes one meta copy through a volume opened with pass.
func (h *harness) writeMetaWith(d *disk, pass []byte, copyIndex int, m Meta) {
	h.t.Helper()
	f := d.attach()
	f.Close()
	defer func() { h.powerOff(); d.detach() }()
	ctl, err := openDM()
	if err != nil {
		h.t.Fatal(err)
	}
	defer ctl.close()
	st, _ := os.Stat(d.loop)
	luksDev, err := ctl.createLinear(h.names.LUKS, false, st.Sys().(*syscall.Stat_t).Rdev, 0, uint64((testDisk-IntentAreaBytes)/sectorBytes))
	if err != nil {
		h.t.Fatal(err)
	}
	luks, _ := openMapped(luksDev, syscall.O_RDONLY)
	cs := cryptsetup{tool: h.tool, dev: luks.Name()}
	luks.Close()
	if err := cs.open(context.Background(), pass, -1, h.names.Crypt, false); err != nil {
		h.t.Fatal(err)
	}
	dev, _, _ := ctl.devStatus(h.names.Crypt)
	vol, err := openMapped(dev, syscall.O_RDWR|syscall.O_DIRECT)
	if err != nil {
		h.t.Fatal(err)
	}
	defer vol.Close()
	rec, err := EncodeMeta(m)
	if err != nil {
		h.t.Fatal(err)
	}
	if err := writeDirect(vol, MetaOffsets()[copyIndex], rec[:]); err != nil {
		h.t.Fatal(err)
	}
}

func TestRootNewThenOpen(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	out := h.mustReady(d, id, k, StateNew)
	if out.Meta.State != StateReady || out.Meta.Seq != 3 {
		t.Fatalf("first boot meta %+v", out.Meta)
	}
	rep := h.checkReady(d, id, k)
	// F4 wrote copy 0 (seq 1), 4.5 copy 1 (seq 2), then copy 0 again (seq 3).
	if rep.meta.Copy != 0 || rep.copies[1].Seq != 2 {
		t.Fatalf("ready is copy %d, copy 1 seq %d; want copy 0 over copy 1 seq 2", rep.meta.Copy, rep.copies[1].Seq)
	}
	before := d.sha()
	out = h.mustReady(d, id, k, StateOpen)
	if out.Meta.Seq != 3 || d.sha() != before {
		t.Fatal("a second boot of a ready disk wrote it")
	}
}

func TestRootLocked(t *testing.T) {
	h := rootHarness(t)
	id := testID(t, "vm-0123456789ab")
	d := h.newDisk(testDisk)
	h.mustReady(d, id, newKey(1), StateNew)
	h.mustRefuse(d, id, newKey(2), StateLocked)
}

func TestRootNullCipherIsTampered(t *testing.T) {
	for _, target := range []string{"segment", "keyslot"} {
		t.Run(target, func(t *testing.T) {
			h := rootHarness(t)
			id, k := testID(t, "vm-0123456789ab"), newKey(1)
			d := h.newDisk(testDisk)
			h.mustReady(d, id, k, StateNew)
			edit := exec.Command("python3", "../../../../scripts/sealed_data_proof.py", "edit-header", d.path, "--target", target)
			if out, err := edit.CombinedOutput(); err != nil {
				t.Fatalf("edit-header: %v %s", err, out)
			}
			h.mustRefuse(d, id, k, StateTampered)
		})
	}
}

func TestRootZeroedHeaderOverDataIsBroken(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	h.mustReady(d, id, k, StateNew)
	d.writeAt(0, make([]byte, 16*MiB))
	h.mustRefuse(d, id, k, StateBroken)
}

func TestRootMetaOfAnotherIdentityIsBroken(t *testing.T) {
	h := rootHarness(t)
	k := newKey(1)
	d := h.newDisk(testDisk)
	h.mustReady(d, testID(t, "vm-0123456789ab"), k, StateNew)
	h.mustRefuse(d, testID(t, "vm-ba9876543210"), k, StateBroken)
}

// Slot numbers mean nothing: after a re-wrap to another bundle and a prune
// of slot 0, the disk opens with the new bundle's key.
func TestRootOpensWithSlotZeroRemoved(t *testing.T) {
	h := rootHarness(t)
	id, k1, k2 := testID(t, "vm-0123456789ab"), newKey(1), newKey(2)
	d := h.newDisk(testDisk)
	h.mustReady(d, id, k1, StateNew)
	rep := h.inspect(d, k1)
	r := rep.fs[2*MiB : 2*MiB+32]
	h.cryptsetupOn(d, [][]byte{r, k2.pass}, "luksAddKey", "--batch-mode", "--pbkdf", "pbkdf2",
		"--pbkdf-force-iterations", "1000", "--key-file", secretPath(0), "--keyfile-size", "32",
		"--new-keyfile-size", "32", "DEV", secretPath(1))
	// The re-wrap cut before its meta write: the next boot adds the slot (step 5).
	out := h.mustReady(d, id, k2, StateOpen)
	if out.Meta.Seq != 4 || len(out.Meta.Slots) != 3 {
		t.Fatalf("step 5 did not add the slot: %+v", out.Meta)
	}
	var m1 int
	for slot, role := range out.Meta.Slots {
		if role == MeasurementRole(k1.meas) {
			m1 = slot
		}
	}
	if m1 != 0 {
		t.Fatalf("the first measurement slot is %d, want 0", m1)
	}
	// Prune slot 0 and rewrite the meta without it.
	h.cryptsetupOn(d, nil, "luksKillSlot", "--batch-mode", "DEV", "0")
	pruned := out.Meta
	pruned.Seq++
	pruned.Slots = copySlots(out.Meta.Slots)
	delete(pruned.Slots, 0)
	h.writeMetaWith(d, k2.pass, 1-rep.meta.NextCopy(), pruned)
	out = h.mustReady(d, id, k2, StateOpen)
	if _, ok := out.Meta.Slots[0]; ok || out.Meta.Seq != pruned.Seq {
		t.Fatalf("pruned meta not read: %+v", out.Meta)
	}
	h.mustRefuse(d, id, k1, StateLocked)
}

// One unreadable meta copy after ready (P2 1): both copies are ready, so
// the boot opens with the same table, runs no first-boot step, the first
// boot's R still opens the recovery slot, and the lost copy is ready again.
func TestRootOneBadMetaCopyStaysReady(t *testing.T) {
	for copyIndex := range MetaOffsets() {
		t.Run(fmt.Sprintf("copy %d", copyIndex), func(t *testing.T) {
			h := rootHarness(t)
			id, k := testID(t, "vm-0123456789ab"), newKey(1)
			d := h.newDisk(testDisk)
			h.mustReady(d, id, k, StateNew)
			rep := h.checkReady(d, id, k)
			r := append([]byte(nil), rep.fs[2*MiB:2*MiB+32]...)
			// One 4 KiB sector of ciphertext: the copy decrypts to noise.
			d.writeAt(LUKSDataOffset+MetaOffsets()[copyIndex], bytes.Repeat([]byte{0xa5}, RecordBytes))
			if h.inspect(d, k).valid[copyIndex] {
				t.Fatal("the overwritten copy still parses")
			}
			out, err, lines := h.boot(d, id, k)
			log := strings.Join(lines, "\n")
			if err != nil || !out.Ready || out.State != StateOpen || out.Meta.State != StateReady ||
				!reflect.DeepEqual(out.Meta.Slots, rep.meta.Meta.Slots) || strings.Contains(log, "vm-disk: 4.1") {
				t.Fatalf("state %s ready %v meta %+v err %v\n%s", out.State, out.Ready, out.Meta, err, log)
			}
			after := h.checkReady(d, id, k)
			for slot, role := range after.meta.Meta.Slots {
				if role == RoleRecovery && !h.opensSlot(d, r, slot) {
					t.Fatal("the first boot's R no longer opens the recovery slot")
				}
			}
		})
	}
}

// A LUKS2 header whose two copies fail their checksums keeps its magics:
// broken, with or without this VM's intent (P2 3). Read as "no header",
// the intent would resume and format over the volume.
func TestRootUnreadableHeaderIsBroken(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	h.mustReady(d, id, k, StateNew)
	// One byte of each JSON area (F3's 16 KiB header: copies at 0 and 16 KiB).
	for _, off := range []int64{4096 + 1, 16<<10 + 4096 + 1} {
		d.writeAt(off, []byte{'X'})
	}
	h.mustRefuse(d, id, k, StateBroken)
	rec, err := EncodeIntent(id, testDisk)
	if err != nil {
		t.Fatal(err)
	}
	d.writeAt(testDisk-IntentAreaBytes, rec[:])
	h.mustRefuse(d, id, k, StateBroken)
}

func TestRootIntentCases(t *testing.T) {
	idA, idB, k1, k2 := testID(t, "vm-0123456789ab"), testID(t, "vm-ba9876543210"), newKey(1), newKey(2)
	intentOff := int64(testDisk - IntentAreaBytes)
	intentFor := func(id vmidentity.Identity, size int64) []byte {
		rec, err := EncodeIntent(id, size)
		if err != nil {
			t.Fatal(err)
		}
		return rec[:]
	}
	garbage := bytes.Repeat([]byte{0xa5}, 4096)

	t.Run("garbage intent and a nonzero byte is broken", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		d.writeAt(intentOff, garbage)
		d.writeAt(20*MiB, []byte{1})
		h.mustRefuse(d, idA, k1, StateBroken)
	})
	t.Run("garbage intent on a blank disk is new and zeroed", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		d.writeAt(intentOff, garbage)
		d.writeAt(intentOff+512*1024, garbage)
		h.mustReady(d, idA, k1, StateNew)
		h.checkReady(d, idA, k1)
	})
	t.Run("an intent of another identity is ignored", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		d.writeAt(intentOff, intentFor(idB, testDisk))
		d.writeAt(20*MiB, []byte{1})
		h.mustRefuse(d, idA, k1, StateBroken) // not resume: the intent is not this VM's
	})
	t.Run("an intent of another disk size is ignored", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.mustReady(d, idA, k1, StateNew)
		d.writeAt(intentOff, intentFor(idA, testDisk+MiB))
		h.mustRefuse(d, idA, k2, StateLocked)
	})
	t.Run("an intent on an open disk is zeroed and the volume untouched", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.mustReady(d, idA, k1, StateNew)
		volume := d.readAt(0, int(intentOff))
		d.writeAt(intentOff, intentFor(idA, testDisk))
		out := h.mustReady(d, idA, k1, StateOpen)
		if out.Meta.Seq != 3 || !bytes.Equal(d.readAt(0, int(intentOff)), volume) {
			t.Fatal("the volume changed")
		}
		if !bytes.Equal(d.intentArea(), make([]byte, IntentAreaBytes)) {
			t.Fatal("the intent was not zeroed")
		}
	})
	t.Run("an intent on a ready disk of another bundle is broken", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.mustReady(d, idA, k1, StateNew)
		d.writeAt(intentOff, intentFor(idA, testDisk))
		h.mustRefuse(d, idA, k2, StateBroken)
	})
	t.Run("an intent on a fresh header of another key is broken", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.cryptsetupOn(d, [][]byte{k2.pass}, "luksFormat", "--type", "luks2", "--batch-mode", "--cipher", cipher,
			"--key-size", "512", "--sector-size", "4096", "--offset", "32768", "--pbkdf", "pbkdf2",
			"--pbkdf-force-iterations", "1000", "--hash", "sha256", "--key-file", secretPath(0), "--keyfile-size", "32", "DEV")
		d.writeAt(intentOff, intentFor(idA, testDisk))
		h.mustRefuse(d, idA, k1, StateBroken)
	})
	t.Run("an intent on a header with no keyslot resumes", func(t *testing.T) {
		h := rootHarness(t)
		d := h.newDisk(testDisk)
		h.cryptsetupOn(d, [][]byte{k2.pass}, "luksFormat", "--type", "luks2", "--batch-mode", "--cipher", cipher,
			"--key-size", "512", "--sector-size", "4096", "--offset", "32768", "--pbkdf", "pbkdf2",
			"--pbkdf-force-iterations", "1000", "--hash", "sha256", "--key-file", secretPath(0), "--keyfile-size", "32", "DEV")
		h.cryptsetupOn(d, nil, "luksErase", "--batch-mode", "DEV")
		h.mustRefuse(d, idA, k1, StateTampered) // no intent: a header with no keyslot fails the rules
		d.writeAt(intentOff, intentFor(idA, testDisk))
		h.mustReady(d, idA, k1, StateResume)
		h.checkReady(d, idA, k1)
	})
}

func TestRootExistingMappingRefusesTheBoot(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	before := d.sha()
	// A mapping left with one of this boot's names refuses the boot before any read.
	f := d.attach()
	ctl, err := openDM()
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(d.loop)
	if _, err := ctl.createLinear(h.names.FS, true, st.Sys().(*syscall.Stat_t).Rdev, 0, 8); err != nil {
		t.Fatal(err)
	}
	ctl.close()
	_, err = Run(context.Background(), Config{Disk: f, DiskBytes: testDisk, Identity: id, Passphrase: k.pass,
		Measurement: k.meas, Cryptsetup: h.tool, Names: h.names, Setup: fakeSetup{},
		Log: func(string) {}})
	f.Close()
	h.powerOff()
	d.detach()
	if err == nil {
		t.Fatal("a boot ran over an existing mapping")
	}
	if d.sha() != before {
		t.Fatal("the refused boot wrote the disk")
	}
	// The wrong size is refused before any mapping.
	f = d.attach()
	_, err = Run(context.Background(), Config{Disk: f, DiskBytes: testDisk + MiB, Identity: id, Passphrase: k.pass,
		Measurement: k.meas, Cryptsetup: h.tool, Names: h.names, Setup: fakeSetup{},
		Log: func(string) {}})
	f.Close()
	h.powerOff()
	d.detach()
	if err == nil || d.sha() != before {
		t.Fatal("a disk of another size than the boot's was used")
	}
}

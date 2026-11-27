package vmdisk

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"reflect"
	"syscall"
)

type run struct {
	ctx      context.Context
	cfg      Config
	layout   Layout
	dm       *dm
	diskDev  uint64
	luksDev  uint64
	cs       cryptsetup
	header   Header // the classifier's header probe
	cryptDev uint64
	crypt    *os.File
	fs       *os.File
}

func (r *run) log(format string, args ...any) { r.cfg.Log(fmt.Sprintf(format, args...)) }

// Run is spec r3 7.2 steps 3 and 4 and the disk part of step 5. It maps the
// LUKS device read-only, classifies it, and only then, for new, resume and
// open, maps it read-write and writes. A locked, tampered or broken disk is
// closed with every byte unchanged and returned with a nil error: the
// caller writes its status and powers off. Any error means power off.
func Run(ctx context.Context, cfg Config) (Outcome, error) {
	if err := cfg.check(); err != nil {
		return Outcome{}, err
	}
	layout, err := NewLayout(cfg.DiskBytes)
	if err != nil {
		return Outcome{}, err
	}
	r := &run{ctx: ctx, cfg: cfg, layout: layout}
	if r.diskDev, err = blockDevice(cfg.Disk, cfg.DiskBytes, true); err != nil {
		return Outcome{}, fmt.Errorf("root disk: %w", err)
	}
	if err := setDirect(cfg.Disk); err != nil {
		return Outcome{}, fmt.Errorf("root disk: %w", err)
	}
	if r.dm, err = openDM(); err != nil {
		return Outcome{}, err
	}
	defer r.dm.close()
	for _, name := range cfg.Names.all() {
		if ok, err := r.dm.exists(name); err != nil || ok {
			return Outcome{}, fmt.Errorf("mapping %s already exists or is unreadable", name)
		}
	}
	ready := false
	defer func() {
		if !ready {
			r.teardown()
		}
	}()
	if r.luksDev, err = r.dm.createLinear(cfg.Names.LUKS, true, r.diskDev, 0, layout.LUKSSectors()); err != nil {
		return Outcome{}, err
	}
	luks, err := openMapped(r.luksDev, syscall.O_RDONLY)
	if err != nil {
		return Outcome{}, err
	}
	r.cs = cryptsetup{tool: cfg.Cryptsetup, dev: luks.Name()}
	luks.Close()

	res, err := Classify(&linuxFacts{r: r}, cfg.Identity)
	if err != nil {
		return Outcome{}, fmt.Errorf("classify: %w", err)
	}
	r.log("vm-disk: %s (%s; intent %s)", res.State, res.Why, res.Intent)
	out := Outcome{State: res.State, Why: res.Why, Slot: res.Slot}
	var meta Meta
	switch res.State {
	case StateLocked, StateTampered, StateBroken:
		return out, nil
	case StateNew:
		meta, err = r.fromF2()
	case StateResume:
		meta, err = r.fromF3()
	case StateOpen:
		meta, err = r.open(res)
	default:
		err = errors.New("unclassified disk")
	}
	if err != nil {
		return out, err
	}
	if err := r.mapFS(); err != nil {
		return out, err
	}
	// The caller needs only the file system area; the volume descriptor
	// would keep the crypt mapping busy.
	r.crypt.Close()
	r.crypt = nil
	out.Ready, out.Meta, out.FSArea = true, meta, r.fs
	ready = true
	return out, nil
}

// teardown closes this boot's descriptors and mappings, last first.
func (r *run) teardown() {
	if r.fs != nil {
		r.fs.Close()
	}
	if r.crypt != nil {
		r.crypt.Close()
	}
	r.dm.remove(r.cfg.Names.FS)
	for _, name := range []string{r.cfg.Names.Crypt, r.cfg.Names.Probe} {
		if ok, _ := r.dm.exists(name); ok && r.cs.close(r.ctx, name) != nil {
			r.dm.remove(name)
		}
	}
	r.dm.remove(r.cfg.Names.LUKS)
}

// linuxFacts are the classifier's probes on the read-only LUKS mapping.
type linuxFacts struct{ r *run }

func (f *linuxFacts) Intent() (IntentStatus, error) {
	rec, err := readDirect(f.r.cfg.Disk, f.r.layout.IntentOffset, RecordBytes)
	if err != nil {
		return IntentNone, fmt.Errorf("intent area: %w", err)
	}
	return ParseIntent(rec, f.r.cfg.Identity, f.r.cfg.DiskBytes), nil
}

func (f *linuxFacts) Header() (HeaderKind, Header, error) {
	res, err := f.r.cs.dump(f.r.ctx)
	if err != nil {
		return 0, Header{}, err
	}
	if res.Exit == 0 {
		f.r.header = ParseHeader(res.Stdout)
		clear(res.Stdout)
		return LUKS2, f.r.header, nil
	}
	head, err := readDirect(f.r.cfg.Disk, 0, 4096)
	if err != nil {
		return 0, Header{}, fmt.Errorf("LUKS device: %w", err)
	}
	if string(head[:6]) == "LUKS\xba\xbe" && binary.BigEndian.Uint16(head[6:8]) == 1 {
		return LUKS1, Header{}, nil
	}
	return NoLUKS2, Header{}, nil
}

func (f *linuxFacts) Opens(slots []int) (int, bool, error) {
	if slots == nil {
		ok, err := f.r.cs.opens(f.r.ctx, f.r.cfg.Passphrase, -1)
		return -1, ok, err
	}
	for _, slot := range slots {
		ok, err := f.r.cs.opens(f.r.ctx, f.r.cfg.Passphrase, slot)
		if err != nil || ok {
			return slot, ok, err
		}
	}
	return -1, false, nil
}

// Meta reads both copies through a read-only mapping. With a header that
// fails the rules, a mapping that does not come up or has another size
// holds no meta this boot trusts; with our header it is an error.
func (f *linuxFacts) Meta(slot int) (Current, error) {
	r := f.r
	names := r.cfg.Names
	if err := r.cs.open(r.ctx, r.cfg.Passphrase, slot, names.Probe, true); err != nil {
		if !r.header.RulesOK {
			return Current{}, nil
		}
		return Current{}, err
	}
	defer func() {
		if r.cs.close(r.ctx, names.Probe) != nil {
			r.dm.remove(names.Probe)
		}
	}()
	dev, _, err := r.dm.devStatus(names.Probe)
	if err != nil {
		return Current{}, err
	}
	vol, err := openMapped(dev, syscall.O_RDONLY|syscall.O_DIRECT)
	if err != nil {
		return Current{}, err
	}
	defer vol.Close()
	if _, err := blockDevice(vol, r.layout.VolumeBytes(), false); err != nil {
		if !r.header.RulesOK {
			return Current{}, nil
		}
		return Current{}, err
	}
	return readMeta(vol)
}

func (f *linuxFacts) Blank() (bool, error) {
	ok, why := allZero(f.r.cfg.Disk, f.r.layout.LUKSBytes)
	if !ok {
		f.r.log("vm-disk: not blank: %s", why)
	}
	return ok, nil
}

func readMeta(vol *os.File) (Current, error) {
	offsets := MetaOffsets()
	c0, err := readDirect(vol, offsets[0], RecordBytes)
	if err != nil {
		return Current{}, err
	}
	c1, err := readDirect(vol, offsets[1], RecordBytes)
	if err != nil {
		return Current{}, err
	}
	return ChooseMeta(c0, c1), nil
}

// writeRecord is one O_DIRECT record write, flushed and read back. The
// vmcuttest build can tear it (tornWrite) and stop there.
func (r *run) writeRecord(point string, f *os.File, off int64, rec []byte) error {
	write, torn := rec, false
	if CutHook {
		old, err := readDirect(f, off, len(rec))
		if err != nil {
			return err
		}
		write, torn = tornWrite(point, old, rec)
	}
	if err := writeDirect(f, off, write); err != nil {
		return fmt.Errorf("%s write: %w", point, err)
	}
	if torn {
		cutAfter(point + "-torn")
	}
	return nil
}

func (r *run) writeMeta(point string, copyIndex int, m Meta) error {
	rec, err := EncodeMeta(m)
	if err != nil {
		return err
	}
	return r.writeRecord(point, r.crypt, MetaOffsets()[copyIndex], rec[:])
}

// zeroIntent zeroes the whole intent area and reads it back as zero.
func (r *run) zeroIntent(point string) error {
	return r.writeRecord(point, r.cfg.Disk, r.layout.IntentOffset, make([]byte, IntentAreaBytes))
}

// writable reloads the LUKS mapping read-write: the first write of a boot.
func (r *run) writable() error {
	table := linearTarget(0, r.layout.LUKSSectors(), r.diskDev, 0)
	if err := r.dm.load(r.cfg.Names.LUKS, false, table); err != nil {
		return err
	}
	if _, ro, err := r.dm.devStatus(r.cfg.Names.LUKS); err != nil || ro {
		return errors.New("the LUKS mapping did not become writable")
	}
	return nil
}

// openVolume maps the volume read-write with one slot and checks the
// active table before anything is written through it.
func (r *run) openVolume(slot int) error {
	if err := r.cs.open(r.ctx, r.cfg.Passphrase, slot, r.cfg.Names.Crypt, false); err != nil {
		return err
	}
	dev, ro, err := r.dm.devStatus(r.cfg.Names.Crypt)
	if err != nil || ro {
		return errors.New("the volume did not map read-write")
	}
	targets, err := r.dm.table(r.cfg.Names.Crypt)
	if err != nil {
		return err
	}
	defer func() {
		for i := range targets {
			targets[i].Clear()
		}
	}()
	if len(targets) != 1 {
		return errors.New("the opened volume is not one crypt target")
	}
	t := targets[0]
	if err := CheckCryptTable(t.Type, t.Start, t.Length, t.Params, deviceString(r.luksDev), r.layout.LUKSSectors()); err != nil {
		return err
	}
	vol, err := openMapped(dev, syscall.O_RDWR|syscall.O_DIRECT)
	if err != nil {
		return err
	}
	if _, err := blockDevice(vol, r.layout.VolumeBytes(), true); err != nil {
		vol.Close()
		return err
	}
	r.crypt, r.cryptDev = vol, dev
	return nil
}

func (r *run) mapFS() error {
	dev, err := r.dm.createLinear(r.cfg.Names.FS, false, r.cryptDev, MetaAreaBytes/sectorBytes, uint64(r.layout.FSBytes()/sectorBytes))
	if err != nil {
		return err
	}
	fs, err := openMapped(dev, syscall.O_RDWR)
	if err != nil {
		return err
	}
	if _, err := blockDevice(fs, r.layout.FSBytes(), true); err != nil {
		fs.Close()
		return err
	}
	r.fs = fs
	return nil
}

// fromF2 is a first boot of a blank disk: F1 (the zero read) is done.
func (r *run) fromF2() (Meta, error) {
	cutAfter("f1")
	if err := r.writable(); err != nil {
		return Meta{}, err
	}
	rec, err := EncodeIntent(r.cfg.Identity, r.cfg.DiskBytes)
	if err != nil {
		return Meta{}, err
	}
	if err := r.writeRecord("f2", r.cfg.Disk, r.layout.IntentOffset, rec[:]); err != nil {
		return Meta{}, err
	}
	r.log("vm-disk: F2 intent written")
	cutAfter("f2")
	return r.format()
}

func (r *run) fromF3() (Meta, error) {
	if err := r.writable(); err != nil {
		return Meta{}, err
	}
	return r.format()
}

// format is F3 to F5, then first-boot step 4.
func (r *run) format() (Meta, error) {
	if err := r.cs.format(r.ctx, r.cfg.Passphrase); err != nil {
		return Meta{}, err
	}
	r.log("vm-disk: F3 luksFormat done")
	cutAfter("f3-format")
	h, err := r.cs.header(r.ctx)
	if err != nil {
		return Meta{}, err
	}
	if !h.RulesOK || len(h.Keyslots) != 1 {
		return Meta{}, errors.New("the new header fails the VM header rules")
	}
	slot := h.Keyslots[0]
	if err := r.openVolume(slot); err != nil {
		return Meta{}, err
	}
	r.log("vm-disk: F3 volume open, header rules hold")
	cutAfter("f3-open")
	cur := Current{Copy: 0, Valid: true, Meta: Meta{Seq: 1, VMID: r.cfg.Identity.VMID,
		IdentitySHA256: r.cfg.Identity.SHA256Hex(), State: StateInitializing,
		Slots: map[int]string{slot: MeasurementRole(r.cfg.Measurement)}}}
	if err := r.writeMeta("f4", 0, cur.Meta); err != nil {
		return Meta{}, err
	}
	r.log("vm-disk: F4 meta copy 0 written: committed")
	cutAfter("f4")
	if err := r.zeroIntent("f5"); err != nil {
		return Meta{}, err
	}
	r.log("vm-disk: F5 intent zeroed")
	cutAfter("f5")
	return r.firstBoot(cur)
}

// open is a committed volume: intent cleanup, then step 4 or step 5.
func (r *run) open(res Result) (Meta, error) {
	area, err := readDirect(r.cfg.Disk, r.layout.IntentOffset, IntentAreaBytes)
	if err != nil {
		return Meta{}, err
	}
	nonzero := !bytes.Equal(area, make([]byte, IntentAreaBytes))
	if err := r.writable(); err != nil {
		return Meta{}, err
	}
	if nonzero {
		// Before any other write (spec r3 7.2 "Intent cleanup").
		if err := r.zeroIntent("open-intent"); err != nil {
			return Meta{}, err
		}
		r.log("vm-disk: a nonzero intent area on a committed disk was zeroed")
	}
	if err := r.openVolume(res.Slot); err != nil {
		return Meta{}, err
	}
	cur, err := readMeta(r.crypt)
	if err != nil {
		return Meta{}, err
	}
	if !cur.Valid || cur.Copy != res.Meta.Copy || !reflect.DeepEqual(cur.Meta, res.Meta.Meta) {
		return Meta{}, errors.New("the meta changed between the read-only probe and the open")
	}
	role, listed := cur.Meta.Slots[res.Slot]
	if cur.Meta.State == StateInitializing {
		if !listed {
			return Meta{}, errors.New("this key opened a slot the initializing table does not hold")
		}
		return r.firstBoot(cur)
	}
	if role == RoleRecovery {
		return Meta{}, errors.New("this boot's key opened the recovery slot")
	}
	if !listed {
		// A cut between a re-wrap slot add and its meta write (spec r3 7.2 step 5).
		next := cur.Meta
		next.Seq++
		next.Slots = copySlots(cur.Meta.Slots)
		next.Slots[res.Slot] = MeasurementRole(r.cfg.Measurement)
		if err := r.writeMeta("table", cur.NextCopy(), next); err != nil {
			return Meta{}, err
		}
		r.log("vm-disk: slot %d added to the meta table", res.Slot)
		cutAfter("table")
		return next, nil
	}
	return cur.Meta, nil
}

func copySlots(in map[int]string) map[int]string {
	out := make(map[int]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// firstBoot is spec r3 7.2 step 4 from meta initializing. A repeat after a
// cut at any point loses nothing: nothing customer-owned exists yet.
func (r *run) firstBoot(cur Current) (Meta, error) {
	// 4.1: remove every keyslot not in the table (left by a cut attempt).
	h, err := r.cs.header(r.ctx)
	if err != nil {
		return Meta{}, err
	}
	if !h.RulesOK {
		return Meta{}, errors.New("the header fails the VM header rules")
	}
	for _, slot := range h.Keyslots {
		if _, listed := cur.Meta.Slots[slot]; !listed {
			if err := r.cs.killSlot(r.ctx, slot); err != nil {
				return Meta{}, err
			}
			r.log("vm-disk: 4.1 removed stray slot %d", slot)
		}
	}
	if h, err = r.cs.header(r.ctx); err != nil {
		return Meta{}, err
	}
	if !h.RulesOK || !sameSlots(h.Keyslots, cur.Meta.Slots) {
		return Meta{}, errors.New("the keyslots differ from the meta table after 4.1")
	}
	r.log("vm-disk: 4.1 keyslots match the table")
	cutAfter("4.1")

	// 4.2 and 4.3: the file system (Setup), with the recovery key R.
	if err := r.mapFS(); err != nil {
		return Meta{}, err
	}
	cut := func(point string) error { r.log("vm-disk: %s", point); cutAfter(point); return nil }
	key, err := r.cfg.Setup.FirstBoot(r.ctx, r.fs, cut)
	defer clear(key[:])
	if err != nil {
		return Meta{}, fmt.Errorf("first boot setup: %w", err)
	}
	if key == [32]byte{} {
		return Meta{}, errors.New("recovery key is zero")
	}
	recovery := key[:]
	r.fs.Close()
	r.fs = nil
	if err := r.dm.remove(r.cfg.Names.FS); err != nil {
		return Meta{}, err
	}

	// 4.4: add R as a keyslot.
	before := h.Keyslots
	if err := r.cs.addKey(r.ctx, r.cfg.Passphrase, recovery); err != nil {
		return Meta{}, err
	}
	if h, err = r.cs.header(r.ctx); err != nil {
		return Meta{}, err
	}
	added := newSlots(before, h.Keyslots)
	if !h.RulesOK || len(added) != 1 || len(h.Keyslots) != len(before)+1 {
		return Meta{}, errors.New("the recovery slot add did not add exactly one slot")
	}
	if ok, err := r.cs.opens(r.ctx, recovery, added[0]); err != nil || !ok {
		return Meta{}, errors.New("the recovery key does not open its slot")
	}
	r.log("vm-disk: 4.4 recovery slot %d added", added[0])
	cutAfter("4.4")

	// 4.5: meta ready with both slots. Last.
	next := cur.Meta
	next.Seq++
	next.State = StateReady
	next.Slots = copySlots(cur.Meta.Slots)
	next.Slots[added[0]] = RoleRecovery
	if err := r.writeMeta("4.5", cur.NextCopy(), next); err != nil {
		return Meta{}, err
	}
	r.log("vm-disk: 4.5 meta ready")
	cutAfter("4.5")
	return next, nil
}

func sameSlots(slots []int, table map[int]string) bool {
	if len(slots) != len(table) {
		return false
	}
	for _, s := range slots {
		if _, ok := table[s]; !ok {
			return false
		}
	}
	return true
}

func newSlots(before, after []int) []int {
	had := map[int]bool{}
	for _, s := range before {
		had[s] = true
	}
	var out []int
	for _, s := range after {
		if !had[s] {
			out = append(out, s)
		}
	}
	return out
}

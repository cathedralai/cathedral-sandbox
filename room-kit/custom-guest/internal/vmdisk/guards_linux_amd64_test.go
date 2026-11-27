package vmdisk

import (
	"context"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cathedralai/cathedral-sandbox/custom-guest/internal/vmidentity"
)

// Root tests for the init's checks on its own tools and on crafted metas:
// a cryptsetup that exits 0 but did something else, a setup that returns
// no key, a read-only disk, and slot tables a key must not boot from. Each
// is a guard in disk_linux_amd64.go that only a wrong tool or a forged meta
// reaches. After each refusal a boot with the real tool still ends ready.

// lyingTool is a root-owned sh wrapper around the real cryptsetup. The
// init runs it as it runs the pinned binary (by descriptor, secrets on
// fds 4 and 5), so a lie that needs a secret twice copies it to a file in
// the test's temporary directory first.
func (h *harness) lyingTool(lie string) Tool {
	h.t.Helper()
	keys := filepath.Join(h.dir, "lie-"+randomHex(4))
	script := `#!/bin/sh
real='` + h.tool.Path + `'
keys='` + keys + `'
lie='` + lie + `'
case "$1:$lie" in
luksFormat:format-512)
	first=1
	for a in "$@"; do
		if [ "$first" = 1 ]; then set --; first=0; fi
		if [ "$a" = 4096 ]; then a=512; fi
		set -- "$@" "$a"
	done
	;;
luksKillSlot:kill-noop)
	exit 0
	;;
luksAddKey:add-two|luksAddKey:add-wrong)
	mkdir -m 700 "$keys" || exit 9
	cat /proc/self/fd/4 > "$keys/old" && cat /proc/self/fd/5 > "$keys/new" || exit 9
	new="$keys/new"
	if [ "$lie" = add-wrong ]; then new="$keys/old"; fi
	first=1
	for a in "$@"; do
		if [ "$first" = 1 ]; then set --; first=0; fi
		case "$a" in
		/proc/self/fd/4) a="$keys/old" ;;
		/proc/self/fd/5) a="$new" ;;
		esac
		set -- "$@" "$a"
	done
	if [ "$lie" = add-two ]; then "$real" "$@" || { rm -rf "$keys"; exit 1; }; fi
	"$real" "$@"
	status=$?
	rm -rf "$keys"
	exit $status
	;;
esac
exec "$real" "$@"
`
	path := filepath.Join(h.dir, "cryptsetup-"+lie)
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		h.t.Fatal(err)
	}
	os.Chmod(path, 0755)
	return Tool{Path: path, SHA256: sha256.Sum256([]byte(script)), Name: "cryptsetup"}
}

// mustFail boots with tool and setup and requires an error that names why.
func (h *harness) mustFail(d *disk, id vmidentity.Identity, k key, tool Tool, setup Setup, why string) {
	h.t.Helper()
	out, err, lines := h.bootWith(d, id, k, tool, setup)
	if err == nil || out.Ready || !strings.Contains(err.Error(), why) {
		h.t.Fatalf("want an error with %q, got state %s ready %v err %v\n%s", why, out.State, out.Ready, err, strings.Join(lines, "\n"))
	}
}

func TestRootToolThatFormatsOtherSectorsIsCaught(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	h.mustFail(d, id, k, h.lyingTool("format-512"), fakeSetup{}, "the new header fails the VM header rules")
	// The intent stands and the slot is this key's: the real tool resumes.
	h.mustReady(d, id, k, StateResume)
	h.checkReady(d, id, k)
}

func TestRootToolThatAddsTwoSlotsIsCaught(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	h.mustFail(d, id, k, h.lyingTool("add-two"), fakeSetup{}, "did not add exactly one slot")
	// Both strays are removed at 4.1 of the next boot.
	h.mustReady(d, id, k, StateOpen)
	h.checkReady(d, id, k)
}

func TestRootToolThatAddsAnotherKeyIsCaught(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	h.mustFail(d, id, k, h.lyingTool("add-wrong"), fakeSetup{}, "the recovery key does not open its slot")
	h.mustReady(d, id, k, StateOpen)
	h.checkReady(d, id, k)
}

func TestRootToolThatKeepsAStraySlotIsCaught(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	h.mustFail(d, id, k, h.lyingTool("add-two"), fakeSetup{}, "did not add exactly one slot")
	h.mustFail(d, id, k, h.lyingTool("kill-noop"), fakeSetup{}, "the keyslots differ from the meta table after 4.1")
	h.mustReady(d, id, k, StateOpen)
	h.checkReady(d, id, k)
}

type zeroKeySetup struct{ fakeSetup }

func (z zeroKeySetup) FirstBoot(ctx context.Context, fs *os.File, cut func(string) error) ([32]byte, error) {
	_, err := z.fakeSetup.FirstBoot(ctx, fs, cut)
	return [32]byte{}, err
}

func TestRootZeroRecoveryKeyIsRefused(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	h.mustFail(d, id, k, h.tool, zeroKeySetup{}, "recovery key is zero")
	h.mustReady(d, id, k, StateOpen)
	h.checkReady(d, id, k)
}

func TestRootReadOnlyDiskIsRefused(t *testing.T) {
	h := rootHarness(t)
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	d := h.newDisk(testDisk)
	before := d.sha()
	f := d.attach()
	if out, err := exec.Command("blockdev", "--setro", d.loop).CombinedOutput(); err != nil {
		t.Fatalf("blockdev: %v %s", err, out)
	}
	_, err := Run(context.Background(), Config{Disk: f, DiskBytes: testDisk, Identity: id, Passphrase: k.pass,
		Measurement: k.meas, Cryptsetup: h.tool, Names: h.names, Setup: fakeSetup{}, Log: func(string) {}})
	exec.Command("blockdev", "--setrw", d.loop).Run()
	f.Close()
	h.powerOff()
	d.detach()
	if err == nil || !strings.Contains(err.Error(), "read-only") || d.sha() != before {
		t.Fatalf("a read-only disk: %v", err)
	}
}

// A ready disk whose table is rewritten (through the key, as only a holder
// of it can) so that this key's slot is listed as something it must not be.
func TestRootCraftedTablesAreRefused(t *testing.T) {
	id, k := testID(t, "vm-0123456789ab"), newKey(1)
	for name, c := range map[string]struct {
		table func(m, rec int) map[int]string
		state string
		why   string
	}{
		"initializing, the opening slot unlisted": {
			table: func(m, rec int) map[int]string { return map[int]string{7: MeasurementRole(k.meas)} },
			state: StateInitializing, why: "a slot the initializing table does not hold"},
		"ready, the opening slot listed as recovery": {
			table: func(m, rec int) map[int]string { return map[int]string{m: RoleRecovery, rec: MeasurementRole(k.meas)} },
			state: StateReady, why: "opened the recovery slot"},
	} {
		t.Run(name, func(t *testing.T) {
			h := rootHarness(t)
			d := h.newDisk(testDisk)
			h.mustReady(d, id, k, StateNew)
			rep := h.inspect(d, k)
			m, rec := -1, -1
			for slot, role := range rep.meta.Meta.Slots {
				if role == RoleRecovery {
					rec = slot
				} else {
					m = slot
				}
			}
			crafted := rep.meta.Meta
			crafted.Seq++
			crafted.State = c.state
			crafted.Slots = c.table(m, rec)
			h.writeMetaWith(d, k.pass, rep.meta.NextCopy(), crafted)
			before := d.sha()
			h.mustFail(d, id, k, h.tool, fakeSetup{}, c.why)
			if d.sha() != before {
				t.Fatal("the refused boot wrote the disk")
			}
		})
	}
}

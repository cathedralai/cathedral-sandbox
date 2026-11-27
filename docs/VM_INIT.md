# VM init: identity, chip key, root disk states and format resume

`cmd/cathedral-vm-init` is `/init` of the sealed VM initrd (AB#999, VM1b part 2;
spec r3 section 7.2, errata 27 Nov 14:44Z). It is a separate PID1 from the
dedicated init in the same Go module (`room-kit/custom-guest`). The initrd that
carries it is built by `room-kit/vm/build-vm-initrd.py` (PR C).

Any failure powers off. Nothing runs the customer's root before the disk's
encrypted meta says `ready`.

## Boot order

| Step | What | Code |
|------|------|------|
| 0 | Load the boot modules listed in `usr/lib/cathedral/vm-modules.list`, after checking the kernel release equals `vm-closure.json`'s | `platform_linux_amd64.go` |
| 0 | Fresh `/proc`, `/sys`, `/dev`; `/dev/sev-guest` root-only | `bootstate.PrepareKernelViews` (read-only import) |
| 1 | fw_cfg: exactly `opt/cathedral/vm-identity.json` and `opt/cathedral/link`. The identity's sha256 must be the one `/proc/cmdline` names (`cathedral.vm=`, the exact v1 cmdline), and a fresh report's HOST_DATA must be `sha256("cathedral-vm-v1\0" \|\| sha256(identity))`. No disk is opened before this | `internal/vmidentity`, `snp.CheckLocal` |
| 2 | `SNP_GET_DERIVED_KEY`: VCEK root, field select `0x9` (POLICY, MEASUREMENT), VMPL 0; then HKDF-SHA256, salt `cathedral-vm-root-v1`, info `luks2-passphrase\0 \|\| u64le(0x9) \|\| HOST_DATA`. `key_id` uses info `key-id\0` | `internal/vmkey` |
| 2 | Pinned cryptsetup (`usr/lib/cathedral/cryptsetup`, sha256 from `vm-closure.json`) at 2.8.1 or later | `vmdisk.CheckCryptsetupVersion` |
| 3, 4 | The three virtio disks by serial (`cathedral-root`, `cathedral-base`, `cathedral-mailbox`, exactly three), each opened only if its device number equals sysfs's and it is not a link. Classify and, where allowed, format or open the root disk | `internal/vmdisk` |
| 5 | Root setup, then the mailbox status record (state, `key_id`, a report with zero REPORT_DATA), then `switch_root` | `Root` and `Mailbox` seams (vmroot, vmmailbox: PR C) |

A disk that may not boot (`locked`, `tampered`, `broken`) gets its status record
and the VM powers off. The re-wrap of a `locked` disk (7.5) is VM6 and not in
this init yet.

## Root disk layout

`root.raw` of S bytes:

- LUKS device: `[0, S - 1 MiB)`, dm-linear from offset 0, so the LUKS2 header stays at offset 0.
- Intent area: the last 1 MiB, outside the LUKS device. Zero except during a first-boot format.
- Inside the LUKS volume (data offset 16 MiB): the meta area (first 16 MiB, copies at 0 and 8 MiB) and the file system area from 16 MiB, dm-linear.

Records (intent `CVMINT01`, meta `CVMMETA1`): 8-byte magic, 4-byte big-endian
length, canonical JSON (D 8.1), sha256 of every byte before it, zero padding to
4 KiB. Every record write is `O_DIRECT`, flushed and read back.

The LUKS device is mapped read-only while the disk is classified, so cryptsetup
cannot repair or rewrite a header the init then refuses. Only `new`, `resume`
and `open` reload it read-write.

Header snapshot: before the classifier, the init copies the header and keyslot
area (the 16 MiB before the volume) into a memfd. Every header read of the boot
(`luksDump`, each `--test-passphrase`, the probe and volume opens) passes that
copy as `--header`, so each sees the header the rules were checked on, not one
the host swapped on the disk in between. The header writes (`luksFormat`,
`luksKillSlot`, `luksAddKey`) go to the disk, and the init copies the header
again after each before it reads it.

A key test (`open --test-passphrase`) reads only exit 2 (no key available with
this passphrase) as "does not open". Any other nonzero exit is an error and
powers off, so a tool failure never classifies a disk as `locked`.

The mailbox disk is opened `O_RDWR|O_DIRECT`, as `internal/vmmailbox` (PR C)
requires, so a poll reads what the host wrote and not a cached page.

## States

Order of the probes: intent, header, (blank), opens, meta.

| State | When | Then |
|-------|------|------|
| `open` | header rules hold, a slot opens with this key, a meta copy is valid, names this `vm_id` and `identity_sha256`, and records this boot's `disk_bytes` | a nonzero intent area is zeroed first; `initializing` repeats step 4; a slot missing from the table is added (7.5 step 5) |
| `resume` | not committed, this VM's valid intent, and no LUKS2 header, a LUKS2 header with no keyslot, or a slot this key opens with no valid meta | format from F3 |
| `new` | no valid intent, not LUKS, every byte of the LUKS device zero | format from F1 |
| `locked` | no valid intent, header rules hold, no slot opens | status, power off; never written |
| `tampered` | no valid intent, a LUKS2 header that fails the rules | status, power off; never written |
| `broken` | anything else: LUKS1; a LUKS magic (primary, or a LUKS2 secondary at any offset LUKS2 allows) that cryptsetup cannot read, with or without an intent; not blank and not LUKS with no intent; a valid intent with a keyslot this key cannot open; meta of another identity; meta of another disk size, smaller or larger (#805); a slot opens with no meta and no intent; a valid meta behind a header that fails the rules | status, power off; never written |

The host's `vm_state` shows `resume` as `new`.

Disk size (#805): the layout is derived from root.raw's size (the LUKS device
ends and the intent area starts 1 MiB before the end), so a committed volume
opens only at the size its meta records. Smaller, the last MiB the open would
zero as the intent area is live ciphertext; larger, the old intent area and any
tail join the volume under a file system that never had them. Both are `broken`
and nothing is written. Growing a root disk needs its own step that rewrites
`disk_bytes`; none exists yet.

The last `broken` row is stricter than r3's text (D4 on PR #798): a header that
fails the rules, a slot this key opens and a valid meta would read as `resume`,
which would re-format a volume holding a valid meta. The same holds for a LUKS
magic cryptsetup cannot read: read as "no header", a valid intent would resume
and format over the volume. Its cost: a power cut inside F3's own header write
(cryptsetup writes the header without its checksum, then the JSON, then the
checksum) leaves a disk `broken` instead of `resume`. F3 runs before any
customer data exists, so that cost is a new VM, never lost data.

Header rules (sealed-data.sh:84-104 without the slot-0 test): one crypt segment
`aes-xts-plain64`, 4 KiB sectors, offset 16 MiB, size dynamic, no integrity or
flags; 1 to 32 keyslots, each luks2, 512-bit, no null cipher; no requirements
other than an empty mandatory list. Slot numbers mean nothing: the meta table
names each slot's role (`m:<measurement>` or `recovery`). After open, the
kernel's crypt table must be the same cipher, sector size and device.

## First boot

- F1 (`new` only): the zero read of the LUKS device.
- F2: write the intent and read it back.
- F3: `luksFormat` (aes-xts-plain64, 512-bit key, 4 KiB sectors, data offset 16 MiB) with the M key; open; check the header rules.
- F4: meta copy 0, `seq` 1, `initializing`, the M slot only, and `disk_bytes` (root.raw's size now). The commit point. Every later meta write copies `disk_bytes`.
- F5: zero the intent area and read it back as zero.
- 4.1: remove every keyslot the table does not list.
- 4.2, 4.3: root setup on the file system area; it returns the recovery key R.
- 4.4: add R as a keyslot; exactly one slot is new and R opens it.
- 4.5: meta `ready` with both slots, to the other copy (the commit), then again
  with `seq + 1` over the `initializing` copy. Last. With one copy ready and the
  other still `initializing`, one unreadable sector of the ready copy would
  bring back `initializing`, and that boot's 4.1 would remove the recovery slot.
  A boot of a ready disk whose other copy is not ready (a cut between the two
  writes, or a copy lost since) writes it ready the same way.

## Tests

| Suite | Where | What |
|-------|-------|------|
| Key vectors | `tests/test_vm_root_key_vectors.py`, `internal/vmkey` | the Go passphrase and `key_id` equal `sealed_data_key.py`'s HKDF (imported read-only) on two fake chip keys and both identities |
| Identity | `internal/vmidentity` | `vm_measure_v1.json` vectors; cmdline and canonical JSON refusals |
| Boot | `cmd/cathedral-vm-init` (fake platform) | wrong identity, cmdline, HOST_DATA, REPORT_DATA or link power off with no key or disk call; status before switch_root; the key is cleared before the root starts |
| Hook | `cmd/cathedral-vm-init` | the init built as the initrd builds it has no `vmcuttest` or `CATHEDRAL_VMCUT` bytes; the tagged build has both |
| Classifier | `internal/vmdisk` | every branch, with the exact probe sequence |
| T3 | `.github/workflows/vm-init.yml`, root | init states on loop files with the kernel device-mapper and cryptsetup; refused disks keep their sha256 |
| T5 | `.github/workflows/vm-init.yml`, root, `-tags vmcuttest` | a SIGKILL at every F step and step-4 point (both 4.5 writes and the ready-boot repair), inside luksFormat and luksAddKey, and twice, then a clean boot: ready, one M slot, one recovery slot, both meta copies ready, zero intent |

Run as a user (any linux/amd64 host; `go test -c` elsewhere):

    cd room-kit/custom-guest
    go test ./cmd/cathedral-vm-init ./internal/vmidentity ./internal/vmkey ./internal/vmdisk

Root suites (throwaway VM or CI only; they create loop devices and DM mappings
named `cvmt<random>-*` and remove them):

    go test -c -o /tmp/vmdisk.test ./internal/vmdisk
    go test -c -tags vmcuttest -o /tmp/vmdisk-cut.test ./internal/vmdisk
    cd internal/vmdisk
    sudo VMDISK_ROOT_TESTS=1 /tmp/vmdisk.test -test.run '^TestRoot'
    sudo VMDISK_ROOT_TESTS=1 /tmp/vmdisk-cut.test -test.run '^TestCut'

`VMDISK_CRYPTSETUP` picks the cryptsetup binary (default `/usr/sbin/cryptsetup`).

## The cut hook

`internal/vmdisk/cut_vmcuttest.go` is compiled only with `-tags vmcuttest`.
`CATHEDRAL_VMCUT=<point>` kills the init after that point, `<point>-torn`
writes only the first `CATHEDRAL_VMCUT_BYTES` (default 64) of a record and
dies, `<point>-kill` kills a running cryptsetup after `CATHEDRAL_VMCUT_DELAY_MS`.
The initrd build refuses any executable that contains `vmcuttest`.

## Open items

- Wiring: vmroot and vmmailbox (PR C) replace the `unwired` seams in one commit after C merges. Until then this build refuses at the link check and touches no disk.
- Keyslot write order: the in-helper kills (14 runs, 0 to 100 ms) all recovered, on the runner's cryptsetup 2.7.0 only. Unproven for the pinned 2.8.4 until C's tools build runs T5.
- Re-wrap of a `locked` disk (7.5): VM6.
- `slots prune`: a follow-up.

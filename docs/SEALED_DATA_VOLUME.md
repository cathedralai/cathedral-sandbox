# Sealed data volume: persistent workspaces the host cannot read

Status: phase 1 in this change. Not on any live hotel. A live hotel gets it
only through a roll in a window Toby approves.

## The problem

A sealed hotel is one AMD SEV-SNP guest. SEV-SNP encrypts guest memory. The
guest's disks are files on the host.

What the code did before this change (every sealed build since 9594d48):

- The guest has one disk, the scratch disk. At every boot `guest-boot.sh`
  opens it with dm-crypt (plain, AES-XTS-512) and a random key from the
  guest's `/dev/urandom`. The key lives only in guest memory.
- Docker, the room file systems, `/work` and workspaces live on the scratch.
- So the host already sees only ciphertext. But nothing survives a restart:
  at the next boot the old key is gone and the scratch is formatted again.
  Persistent workspaces lasted until the next guest restart or roll.

This comes from the code and the proof below; no live hotel's host disk was
inspected. By the code, the security table line "the machine does not
encrypt stored data" is wrong for the scratch disk. The true gap was that
encrypted data could not persist.

## What this change does

1. A second disk, `$SEALED_DIR/data.raw` (sparse, `SEALED_DATA_GIB`), virtio
   serial `sealed-data`. Only a build with `SEALED_DATA_GIB` > 0 and
   `SEALED_ROOM_WORKSPACES=1` uses it. The switch is in the measured
   `room.env` (`ROOM_WORKSPACES_SOURCE=/srv/sealed-data/workspaces`) and in
   `manifest.json` (`data_volume`).
2. At every boot, before the room kit install, `sealed-data.sh` makes the
   key with `sealed_data_key.py` and opens the disk as LUKS2. The first boot
   formats it (LUKS2, then xfs). It mounts it at `/srv/sealed-data` with
   `nosuid,nodev,noexec`.
3. `room-data.sh` binds `/srv/sealed-data/workspaces` at
   `$ROOM_DATA_DIR/workspaces`. The API, its mount check, the owner layout
   and `meta.json` are unchanged; they now sit on the data volume.
4. Everything else stays on the scratch disk with its per-boot key. Only the
   data that must persist is under the long-lived key.

## Threat model

Protects the confidentiality of workspace data against anyone who reads the
host's disk: the host operator, a host backup or snapshot, the provider's
storage layer, a disk that leaves the machine. They get the LUKS2 header and
ciphertext.

The host can also write the disk, and the LUKS2 header lives on it, so the
host can edit the header. The header carries the key slot (the volume key
encrypted under the derived passphrase, which the host cannot read without the
key), the segment cipher and sector size, and a cathedral token (the build's
launch identity and a `key_id` label, not the key). None of these reveal the
data, but a host could edit the cipher to a null cipher (Trail of Bits,
2025-10-30) to make the guest write in clear. So the guest does not trust the
header: after open, `verify_header()` proves the mapping is our
`aes-xts-plain64` / 4096-byte-sector / 512-bit layout (device-mapper table and
header JSON), refuses a key slot or segment with a null cipher, refuses to
format a decrypted device that already holds a file system, and requires
cryptsetup 2.8.1 or newer. On any mismatch the volume is closed and left
untouched (status `tampered`). A sparse `data.raw` still reveals which blocks
were written (we issue no discards, so it does not leak the free map, but the
backing file's allocation does), which is metadata, not content.

Trusted: the AMD secure processor and its firmware, the measured guest build
(OVMF, kernel, initrd, command line), cryptsetup and dm-crypt in that build,
and the people who publish a build.

Not protected (see "Still not covered"): availability, integrity and
freshness of the data (the host can corrupt or roll back ciphertext blocks;
XTS has no authentication), and what the host can do through the hotel API.

## Key source

`sealed_data_key.py` runs inside the guest with the system python3 only.

1. `MSG_KEY_REQ` through the `SNP_GET_DERIVED_KEY` ioctl on `/dev/sev-guest`:
   - root key: VCEK (`root_key_select` 0). The key is unique to the chip.
     Another machine cannot make it.
   - `guest_field_select` = `0x9`: GUEST_POLICY and MEASUREMENT. Another
     build (any change to OVMF, kernel, initrd, command line or vCPU count),
     a debug policy, or a debug build (`cathedral.debug=1` is on the measured
     command line) gets another key.
   - VMPL 0, GUEST_SVN 0, TCB_VERSION 0.
2. HOST_DATA from the guest's own report (configfs-tsm, the same path as
   `room_receipts.py`). The chip signs the report, so the host cannot change
   HOST_DATA after launch.
3. Passphrase = HKDF-SHA256(salt `cathedral-sealed-data-v1`, IKM = the chip
   key, info = `luks2-passphrase\0` || field select (8 bytes LE) || HOST_DATA),
   32 bytes. `key_id` uses info `key-id\0` || the same, 8 bytes, hex.

Why these fields and not others:

| Field | In the key | Why |
|---|---|---|
| Chip (VCEK root) | Yes | A copied disk is useless on another machine |
| MEASUREMENT | Yes | Only this exact build opens the volume |
| GUEST_POLICY | Yes | A debug or migratable policy gets another key |
| HOST_DATA | Yes, by HKDF in the guest | No field select bit exists. On a dedicated machine HOST_DATA names the owner: a relaunch naming another owner gets another key. On a shared machine it is the manifest digest |
| FAMILY_ID, IMAGE_ID | No | They come from the ID block. The host signs the ID block with an ID key of its own choice, and no field select bit covers the ID key (bits 0 to 6: policy, image ID, family ID, measurement, SVN, TCB, launch mitigation vector). A host could launch its own image with our IDs and get the same key |
| GUEST_SVN | No | Also from the ID block; we launch without one |
| TCB_VERSION | No | A host firmware update would change the key and strand the volume. The cost: a key made under an old TCB stays valid after the update |

LUKS2 settings: `aes-xts-plain64`, 512-bit key, 4 KiB sectors, one key slot,
PBKDF2 with 1,000 iterations. The passphrase is a uniform 256-bit key, so a
slow KDF adds nothing. We issue no discards, so the mapping does not pass the
free-block map to the host; the sparse backing file still shows which blocks
were ever written, which is metadata, not content. At boot the guest verifies
the header against this layout before it trusts the device (see the threat
model).

The key goes to stdout only. `sealed-data.sh` keeps it in a 0600 file on
`/run` (tmpfs, so guest memory) while cryptsetup runs, then removes it. No
log, status file or receipt holds it.

## Boot states

`sealed-data.sh` writes `/run/sealed-data.status`. Health shows it as
`workspaces_storage`; the serial log shows `[sealed-data]` lines.

| State | Meaning | Workspaces this boot |
|---|---|---|
| `new` | A blank disk (every byte zero): formatted now | Data volume |
| `open` | Opened with this build's key, header verified | Data volume |
| `locked` | A LUKS2 volume no key slot of which opens with this key (another build, chip or HOST_DATA). Left untouched | Scratch (gone at next boot) |
| `tampered` | The header is not our layout (null cipher, wrong sector, extra segment). Closed, left untouched | Scratch |
| `broken` | The disk holds data that is not a LUKS2 volume (not all zero, for example damaged LUKS2 signatures or a zeroed header over a payload), a disk that could not be read to its end, a LUKS header cryptsetup cannot read, an existing volume whose token does not say `fs: xfs` (closed, never formatted, whatever `blkid` says), or xfs does not mount. Left untouched | Scratch |
| `absent` | No data disk attached | Scratch |
| `nokey` | The secure processor gave no key | Scratch |
| `error` | A step failed, or cryptsetup is older than 2.8.1 (serial log); the boot goes on | Scratch |

Rules:

- The guest formats only on positive evidence of a blank disk: every byte of
  the device reads as zero, as a fresh sparse `data.raw` does. A zero header is
  not enough: a disk whose first 16 MiB were zeroed can still hold a payload
  that a header backup would restore. Anything else that is not LUKS (for
  example damaged LUKS2 signatures, or a zeroed header over a payload), and a
  disk that cannot be read to its end, is `broken` and left untouched. A disk
  with data stops the read at its first nonzero byte; only a blank disk is
  read whole, once, at its first boot. It runs mkfs only in the same boot that
  proved the disk blank, ran luksFormat and opened the new volume. A volume
  from an earlier boot whose token does not say `fs: xfs` is `broken`: it is
  closed and nothing is written, because the token sits in the host-held LUKS
  header and a lost token must not turn into a format of customer data.
- Recovery after a first boot that stopped between luksFormat and the token
  (power loss, mkfs failure): the next boot reports `broken`. Such a volume never
  served a room, so an operator stops the guest, removes `data.raw` and boots
  again. A person decides; the guest never does.
- A locked or broken volume does not stop the hotel. Rooms without a
  workspace work; a create that names an old workspace answers 404
  `workspace_not_found`.
- To start empty: stop the guest and remove `data.raw`.

## Miner hotels

Workspace owners are a hash of the API key the API sees. On a miner hotel
that is the guest-internal key, made at every boot. With the data volume
open, `guest-boot.sh` makes it once and keeps it at
`/srv/sealed-data/hotel/internal-api-key` (0600), so owners stay the same
after a restart. Without the volume it is made per boot, as before.

## Upgrade path

A roll changes the measurement, so the new build cannot open the old volume.

### Phase 1 (this change): explicit choice at every roll

`install.sh --sealed` reads the launch identity (measurement, policy and
HOST_DATA) from `data.raw`'s own LUKS token and compares it with the launch
identity the new build would run with. It gets the new build's HOST_DATA from
`launch-guest.sh` itself, so the two never disagree. When the identities match,
the new build opens the volume and the roll proceeds. When they differ, it
stops unless the operator has written a one-line choice to
`$SEALED_DIR/data-on-new-build` (consumed by the run that uses it, so it never
silently applies to a later roll):

- `reset`: `data.raw` becomes `data.raw.prev` and the new build starts an empty
  volume. It refuses to overwrite an existing `data.raw.prev` unless
  `SEALED_DATA_OVERWRITE_PREV=1`, so an earlier owner's volume is never lost.
  Until the new build's measurement checks, an EXIT trap puts the owner's
  volume back on every failure path (a measurement mismatch, a guest that never
  attests, any error), not only a mismatch. On success `data.raw.prev` stays
  for the operator to remove once the new build is vouched for.
- `keep`: `data.raw` stays. The new build boots `locked` and keeps workspaces
  on the scratch. Rolling back to the old build opens it again.

So in phase 1, workspaces outlive restarts of the same build (host reboot,
guest crash, unit restart, `SEALED_SKIP_BUILD=1` reinstall), not a roll.
That is better than before (nothing outlived a restart) and a roll can no
longer drop or strand data without the operator saying so.

### Phase 2 (proposal, not built): attested rekey before a roll

LUKS2 holds up to 32 key slots, so one volume can carry a slot for the old
build and one for the next. Only a guest of the next build on this chip can
make the next key, so that guest must take part:

1. Build M2. A release key signs `{hotel, from: M1, to: M2}`. Its public key
   is pinned in the measured `room.env` (`SEALED_DATA_SUCCESSOR_SIGNERS`), in
   the same way as `SEALED_HOTEL_KEY_INSTALL_SIGNERS`.
2. The host starts M2 as a short rekey guest: the same vCPU count (the
   measurement needs it) and the same HOST_DATA as its real boot, little
   memory, no network card, a small mailbox disk. An fw_cfg flag selects rekey mode; in that mode the guest never
   starts the hotel.
3. M2 makes an X25519 key and a report with REPORT_DATA = sha256 of its
   offer, and writes the offer to the mailbox.
4. The operator posts the offer and the approval to M1
   (`POST /room/data/successor`). M1 checks: a pinned signer signed the
   approval; it names M1's own measurement as `from` and the report's as
   `to`; the report chains to a pinned AMD ARK; CHIP_ID equals M1's;
   policy equals M1's; REPORT_DATA covers the offer. M1 then seals the LUKS
   volume key to M2's X25519 key (the hotel-key install envelope:
   X25519, HKDF-SHA256, AES-256-GCM).
5. M2 opens it, makes K(M2), and writes AES-GCM(HKDF(K(M2)), volume key) to
   the mailbox. Only an M2 guest on this chip can open that wrap, so the host
   may keep it. M2 stops.
6. The roll boots M2 with the wrap in fw_cfg. M2 finds no slot for its key,
   opens the wrap, and adds its slot (`cryptsetup luksAddKey
   --volume-key-file`). After a soak the M1 slot is removed.

Trust: whoever holds the release key can approve a build that reads the data.
That is the trust a release already needs, and the volume key never leaves an
SNP guest on that chip. Decision needed: who holds the signer (custody).

Rejected:

- A key bound to FAMILY_ID and IMAGE_ID: not safe (the host signs the ID
  block; see the table above).
- An escrow key off the machine: a standing ability to open any copy of the
  disk.
- Customer export and import of workspaces: product work; a later phase for
  customers who want their own copies.

## Still not covered

- **Integrity and freshness (tracked separately, see AB#396).** XTS has no
  authentication. `verify_header()` checks the LUKS2 header layout, but not the
  data blocks: the host can corrupt sectors (the guest reads garbage) or put
  back an older copy of the whole disk, and the guest does not notice.
  dm-integrity or AEAD would catch corruption, not an old copy; a generation
  counter is needed for rollback.
- **Availability.** The host can delete `data.raw`. There is no backup and
  no replica.
- **The hotel API.** On a config hotel the host holds the hotel key and can
  read and write room files through the API with no receipt
  (`sealed/README.md`). Encryption at rest does not change that. A miner
  hotel (the key arrives over attested TLS) does.
- **Firmware updates.** The key does not mix in TCB_VERSION. Not yet tested
  across a real host firmware update.
- **Unclean stop.** `systemctl stop` sends SIGTERM to QEMU, which is a power
  cut for the guest. XFS replays its log; writes from the last ~30 s that a
  room did not fsync can be lost. A graceful ACPI shutdown is a follow-up.
- **A guest compromise.** Root in the guest (for example a gVisor escape)
  can read the open volume and the key, as it can read all room data today.
- **Owner keys.** Owners are a hash of the hotel API key. Rotating a config
  hotel's key hides its workspaces (true on unsealed hotels too).
- **Size.** Fixed when `data.raw` is made; no grow. No byte quota per
  workspace (as before).
- **First boot time.** The first boot reads the whole blank disk before it
  formats it, before the room API starts, so the time grows with
  `SEALED_DATA_GIB`. `install.sh --sealed` waits 15 min for the first
  attestation. The read rate inside an SNP guest is not measured yet: measure
  it on the canary before a large disk.
- **The `poolroom` uid.** It is stable across restarts of one build. Phase 2
  must pin it, because a new build could give it another uid.
- **Miner hotel path.** Unit-tested only; the proof below is a config hotel.

## Rollout (Toby)

1. Review and merge. Nothing changes on a hotel until it is rebuilt.
2. Canary, one hotel, in an approved window: set `SEALED_DATA_GIB` (the disk
   check counts it), rebuild, roll. The first roll needs no
   `SEALED_DATA_ON_NEW_BUILD`: there is no `data.raw` yet. Check health
   `workspaces_storage.state` is `new`; restart the guest; check `open` and
   that a workspace file is still there.
3. Copy for customers: workspaces on sealed hotels last until the next
   re-seal (phase 1), not forever.

## Proof on an SNP host (c48)

Run 3, 7 Nov 2026 07:19 to 07:24 UTC, the `room-kit/` tree of cc842db.
A non-production guest `diskproof` (4 vCPU, 8 GiB, a 40 GiB scratch, a
4 GiB data disk) built with this kit's `build-guest.sh` and started with
this kit's `launch-guest.sh` as a transient unit, on its own tap `sdc0`,
with a random test hotel key. Never joined to a broker. The driver scripts
(`proof.sh`, `run2.sh`) are in the pull request's proof comment.

Setup (once): the base root file system with `mmdebstrap` from the Ubuntu
`.deb` unpacked under `/root/snptest/disk-crypt/tools` (nothing installed on
the host), the pinned API tarball (`make-dist.sh 20d81fb`, sha256 equals
`versions.lock`), `sev-snp-measure==0.0.12` in a venv.

```
build-guest.sh sd/sealed.env           # build 1
build-guest.sh sd/sealed-build2.env    # build 2: SEALED_ROOM_MAX_SLOTS 21, another measured room.env
build 1 fa3c9bd3bc421e40e1c1fafe48da3c290e24af87359f48db783be12a5fe773209c9fb8a10f3e036833480fed1868d728
build 2 ca8b23df2206df3c2f1df577de8580b5c01b566831076f36c1f71d05a34a04eb61a2ce49199d9b02503f601b84289e75
host-net.sh up sd/sealed.env
systemd-run --unit=diskproof-guest ... launch-guest.sh sd/sealed.env
```

**Boot A, build 1: a blank data disk.** The report's measurement equals the build.

```
[sealed-data] no volume on the data disk: making one (key_id b347e4ae2df1d798)
[sealed-data] new: LUKS2 volume mounted at /srv/sealed-data (4211081216 bytes)
measurement fa3c9bd3...d728   expected fa3c9bd3...d728
workspaces_storage {"key_id": "b347e4ae2df1d798", "persistent": true, "state": "new", ...}
```

A room (`alpine:3.20`, workspace `proof`) writes a marker file and 20,000
marker lines to `/workspace`, and a copy of them to its own root file system
(on the scratch disk), then `sync`:

```
POST /v1/workspaces {"name":"proof"}                                  201
POST /v1/sandboxes {"image":"alpine:3.20","workspace":"proof"}       running
exec: printf MARK > /workspace/marker.txt; 20000 lines > /workspace/bulk.txt; cp to /root/scratch-copy.txt; sync
-rw-r--r-- 1 root root 968890 /root/scratch-copy.txt
-rw-r--r-- 1 root root 968890 /workspace/bulk.txt
-rw-r--r-- 1 root root     38 /workspace/marker.txt
CATHEDRAL-DISK-PROOF-f71e2bab1964fdc7
```

**The host side, after 45 s and a stop of the guest:**

```
grep -a -c -F CATHEDRAL-DISK-PROOF-f71e2bab1964fdc7 sd/data.raw      0   (4.0G apparent, 82M on disk)
grep -a -c -F CATHEDRAL-DISK-PROOF-f71e2bab1964fdc7 sd/scratch.raw   0   (40G apparent, 74M on disk)
head -c 6 sd/data.raw                                                L U K S 272 276
blkid -p sd/data.raw                                                 TYPE=crypto_LUKS VERSION=2 LABEL=cathedral-sealed-data
written 4 KiB sectors after the LUKS2 header: 16408 sampled, entropy 8.0000 bits/byte
```

`cryptsetup luksDump sd/data.raw` (run 1, the same format): data segment
`aes-xts-plain64`, sector 4096, offset 16 MiB; one key slot, 512-bit key,
PBKDF2 sha256; token 0 `cathedral-sealed-data`. Nothing else is readable.

**Boot B, build 1 again: the restart.** A new boot id, the same key:

```
[sealed-data] open: LUKS2 volume mounted at /srv/sealed-data (4211081216 bytes)
workspaces_storage {"key_id": "b347e4ae2df1d798", "persistent": true, "state": "open", ...}
GET /v1/workspaces                          proof
a new room on workspace proof: cat /workspace/marker.txt    CATHEDRAL-DISK-PROOF-f71e2bab1964fdc7
grep -c line /workspace/bulk.txt            20000
```

**Boot C, build 2 with build 1's HOST_DATA:** another measurement only. A
proof-only copy of `launch-guest.sh` sets HOST_DATA to build 1's value.

```
[sealed-data] locked: a LUKS2 volume is on the data disk but no key slot opens with this build's key (cryptsetup exit 2); left untouched
measurement ca8b23df...9e75   host_data 8013c175...9d39 (as boot A)
workspaces_storage {"key_id": "d8a2826072e119cd", "persistent": false, "state": "locked", ...}
GET /v1/workspaces                          (none)
sha256 of data.raw before C 9554e17714bbbcca, after C 9554e17714bbbcca
```

In run 1 the same create answered `404 workspace_not_found`.

**Boot D, build 1 again:** `open`, key_id `b347e4ae2df1d798`, the marker and
20,000 lines are back. The locked boot did not touch the volume.

**Run 1 (06:18 to 07:05 UTC, the same key code before two shell fixes):**
build 1 with another HOST_DATA (a dedicated-owner key in fw_cfg, the same
measurement) also booted `locked` with another key_id (`e1103419bcefb151`
against `e76c631a4b7a462c`). So HOST_DATA and the measurement each change
the key.

**Teardown:** the unit stopped after each boot, `host-net.sh down`, tap
`sdc0` gone, no `sealed-hotel:diskproof` rule left, no proof QEMU left. The
four other guests on c48 were not touched.

Not shown on hardware: the miner hotel path, the `install-sealed.sh` roll
guard (both unit-tested), and a host firmware update.

### Review round 1 (header verification and the roll-guard rework)

The fixes from the first independent review (header verification against a
null-cipher edit, the cryptsetup 2.8.1 floor, the `blkid` guard, the one-time
reset choice with the EXIT-trap restore, launch-identity ownership, the
`persistent` field, the miner-key fsync) are covered by
`tests/test_room_kit_sealed_data.py`. They were not re-run on c48: the next c48
window fell inside the 15:00 to 17:00 UTC escape rehearsal on 7 Nov, which is
off limits. The planned hardware check is a `cipher_null` header edit on a
throwaway `data.raw`, confirming `verify_header()` reports `tampered` and does
not mkfs or mount; it runs after 17:15 UTC or in the next free window.

# Sealed VM guest: root setup, mailbox and in-guest tools (AB#999, VM1b part 1)

Spec: VM runtime spec r3 (7.2 steps 4.2 to 5, 7.5, 6.4, 5) and its errata of 27 Nov. This is the
guest half that sits beside the disk package (VM1b part 2, `internal/vmdisk`) and the
init command (`cmd/cathedral-vm-init`). Everything here lives in the `room-kit/custom-guest` Go
module and `room-kit/vm`.

## Packages

| Path | What |
|---|---|
| `internal/vmmailbox` | The 1 MiB mailbox: records, depth-1 pre-scan, strict parse, status and offer writers, answer poll, envelope open. Pure Go. |
| `internal/vmroot` | Steps 4.2, 4.3 and 5 of 7.2: verity base copy, resize, user, host key, cloud-init off, recovery record, runtime binds, network file, `switch_root`. |
| `internal/vmrecovery` | The recovery key record and the line `recovery show` prints. |
| `internal/vmattest` | REPORT_DATA and the answer of the in-guest attest tool. |
| `cmd/cathedral-vm-attest` | Packed as `/run/cathedral/bin/cathedral-attest`. |
| `cmd/cathedral-vm` | `sudo cathedral-vm recovery show`. `slots prune` is a follow-up. |
| `room-kit/vm/build-vm-initrd.py` | The VM initrd recipe and its checks. |
| `scripts/build_vm_initrd_tools.py` | The static C tools build. |

## Mailbox (7.5)

The host side is `room-kit/vm/vm_mailbox.py` (sandbox PR 794) and its fixture
`tests/fixtures/vm_mailbox_v1.json`. This package must match it byte for byte: a 45 byte header
(`CVMMBX1\0`, kind, length u32 big-endian, sha256 of the body), canonical flat JSON bodies, the
slot offsets 0, 64 KiB and 128 KiB. Rules that matter:

- Every mailbox byte is untrusted, the guest's own earlier writes included. A reader checks the
  header, then a bounded pre-scan that refuses any `[` or `{` after the opening brace, then a strict
  parse of exactly the schema's keys. Any failure of any kind reads as an empty slot.
- The guest writes status and offer, each as one write of the whole slot and a flush. It never
  writes the answer slot. `ZeroOffer` reads the slot back as zero.
- `AnswerFor(offer_sha256)` ignores an answer for another offer. An answer over 4096 bytes is refused.

## Re-wrap envelope

`tests/fixtures/vm_rewrap_envelope_v1.json` is made by `scripts/make_vm_rewrap_envelope_vectors.py`
(`--check` fails if the file differs). It is the contract for `verify_vm.py rewrap`.

- `shared = X25519(customer ephemeral private, VM offer public)`
- `key = HKDF-SHA256(ikm=shared, salt=AAD, info="cathedral.vm-rewrap.v1" || epk || vm_pub, 32)`
- `ct = AES-256-GCM(key, nonce, R, AAD)`; R is 32 bytes, `ct` is 48 with its tag
- `AAD = offer_sha256` as 64 lowercase hex ASCII bytes (it is also the HKDF salt)

The offer's REPORT_DATA is `sha512("cathedral-vm-rewrap/v1\0" || pubkey || nonce)`
(`vmmailbox.RewrapReportData`).

## Attest (6.4)

`cathedral-attest CHALLENGE_HEX` hashes the ssh-ed25519 wire blob of
`/etc/ssh/ssh_host_ed25519_key.pub`, the blob `verify_vm.py` reads from the SSH handshake:

    REPORT_DATA = sha512("cathedral-vm-report/v1\0" || challenge[32] || sha256(host_key_blob))

stdout is one JSON object with `report_b64`. The Go result equals `verify_vm.report_data` on
`tests/fixtures/vm_attest_report_data_v1.json`, made by `scripts/make_vm_attest_vectors.py`. It is
not the dedicated guest's path or domain.

## Recovery (7.5)

First boot writes `/var/lib/cathedral-vm/recovery.key` (root only, canonical JSON with `vm_id`,
`identity_sha256` and the 32 byte key). `sudo cathedral-vm recovery show` prints one JSON line:

    {"chip_id":"<128 hex>","identity_sha256":"<64 hex>","recovery_key":"<base64>","schema":"cathedral.vm.recovery/v1","vm_id":"vm-..."}

The VM2 pin builder has no constants block for this output on main yet. If it expects another
shape, change `vmrecovery.Show` and its test together.

## Root setup (`vmroot`)

`FirstBoot` runs 7.2 steps 4.2 and 4.3 on the file-system-area file the disk package gives it, and
returns the recovery record for step 4.4 (the keyslot). Order, each followed by a cut point:

1. `CopyBase`: pinned `veritysetup open` of the base disk, read every data block through the mapping
   into the fs area from offset 0, flush, close the mapping. A flipped block fails the read (EIO).
   There is no `--panic-on-corruption`: the init powers off on the error.
2. `Mount` at `/newroot` (nodev), then `resize2fs` online.
3. `PrepareTree`: user `cathedral` (uid and gid 1000, passwd, group, shadow, gshadow, key in
   `authorized_keys`, `sudoers.d` with NOPASSWD as the old cloud-init config had), an Ed25519 SSH host key
   (the base's own host keys are removed first), an sshd drop-in with that one `HostKey` and key-only
   login, and `/etc/cloud/cloud-init.disabled`. `sync`.
4. `WriteRecovery`. `sync`.

A cut leaves a partial tree and the next boot copies the base again, so every file is created
exclusively (a rerun in place fails). The tree is the same after a rerun at any cut point.

`Finish` is step 5 after the disk package has written the meta: the module tree bound read-only at
`/usr/lib/modules/<release>`, a fresh tmpfs on `/run` (nosuid, nodev, noexec, as systemd keeps it),
the network file at `/run/systemd/network/10-uplink.network` from the link (never `/etc`), the tools
bound read-only at `/run/cathedral/bin/<name>`, and cloud-init off again. `SwitchRoot(ready)` calls
`ready` first and moves nothing unless it returns nil.

All file access in the new root goes through `os.Root`, so a link in the base cannot send a write out
of the root. The pinned-helper exec and `switch_root` are copies, with a comment naming the original
(`bootstate/verity_linux_amd64.go:66-107`, `runtime_linux_amd64.go:177-233`); one consolidation PR
merges them after PRs A, B and C land.

## VM initrd recipe

`room-kit/vm/build-vm-initrd.py` builds the VM initrd from the same source as the dedicated one, in VM
mode fixed per artifact. It reuses `custom_guest_initrd.py` read-only.

- Contents: `/init` and two more Go mains (built twice, identical, with an empty `-tags`), four static
  C tools, the kernel module tree under `usr/lib/modules/<release>/` (each file pinned), and two
  generated files for the init: `usr/lib/cathedral/vm-closure.json` and `usr/lib/cathedral/vm-modules.list`
  (boot modules in load order from `modules.dep`, dependencies first; built-in modules need no file).
  `build-bundle.sh` takes the archive through its existing `VM_BUNDLE_INITRD` hook.
- The check refuses an extra file, a dynamic or non-ELF executable, a missing or changed module, a wrong
  digest, a file with another mode, and any executable that contains the `vmcuttest` build tag.
- `vm_initrd_closure.json` is `unpinned` in this PR: its digests cannot exist before the tools build and
  the kernel release are fixed. `pin` prints the digests of a real build for review; `build` and `check`
  refuse an unpinned closure.

## Static tools build

`scripts/build_vm_initrd_tools.py` builds `cryptsetup` and `veritysetup` (cryptsetup 2.8.4) and
`mke2fs` and `resize2fs` (e2fsprogs 1.47.3). `vm_initrd_tools_inputs.json` pins every source and
development package by URL and sha256. The cryptsetup, LVM2 and Ubuntu package pins are those of
`custom_guest_verity_inputs.json`; the e2fsprogs source is new, and its sha256 equals the `.tar.xz` line
of upstream's PGP-signed `sha256sums.asc`. `fetch` downloads and checks, `build` takes exactly the
pinned files and downloads nothing, builds twice and requires identical static ELFs.

## Tests and CI

- `go test -race ./...` (ci.yml) covers every package here. `tests/test_vm_initrd.py`,
  `tests/test_vm_rewrap_envelope.py` and `tests/test_vm_attest_vectors.py` run in the Python job.
- `.github/workflows/vm-guest.yml` adds two jobs: `vmroot` (root, loop devices, real dm-verity and
  e2fsprogs; the cut-point reruns, a flipped base block, a wrong root hash, the pinned-helper
  refusals, `Finish`) and `tools` (the static build, in an Ubuntu 26.04 container pinned by digest).
- The mailbox tests read `tests/fixtures/vm_mailbox_v1.json` from PR 794 and skip while it is absent.
  Once that PR is on main they must fail instead of skip.

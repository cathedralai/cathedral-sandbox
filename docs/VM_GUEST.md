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

- Open the device with `vmmailbox.OpenDevice`: O_DIRECT, so a poll sees the host's write and not a
  cached page. Every read and write is a whole 64 KiB slot in a 4 KiB aligned buffer (test fake
  fails any other I/O). B's init must use it for the status write and the answer poll.
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

The HKDF info is `cathedral.vm-rewrap.v1 || epk || vm_pub` (the hotel envelope's layout, with this
info string), which goes one step beyond "info = the string" of the 14:44Z decision. `verify_vm.py rewrap`
(VM2) must implement exactly this order; the fixture holds `shared_hex` and `wrapping_key_hex` to check it.

The offer's REPORT_DATA is `sha512("cathedral-vm-rewrap/v1\0" || pubkey || nonce)`
(`vmmailbox.RewrapReportData`).

## Re-wrap answer v2 (AB#1022, spec r3 7.5 with the r4 erratum)

**Why:** `OpenAnswer` proves only that an answer was sealed to the offer's public key, and anyone
can seal to a public key. A host could therefore build a volume that names this VM's identity,
with a recovery slot under a key it chose, and seal that key to the offer: the genuine init would
add its measurement key to the host's header and boot the host's root. So the guest acts only on
an answer signed by the identity's `ssh_public_key`. That key is measured (its sha256 is in the
cmdline and in HOST_DATA), and it is already the VM's only login key, so the signature adds no new
trust root.

**The answer:** `{"schema":"cathedral.vm.rewrap-answer/v2","offer_sha256","epk","nonce","ct","sig"}`,
canonical JSON, at most 4096 bytes. `offer_sha256`, `epk`, `nonce` and `ct` are the v1 envelope
above, unchanged. `sig` is one SSHSIG blob (OpenSSH `PROTOCOL.sshsig`), unarmored, in strict
canonical standard base64, at most 2400 bytes decoded. Every reader refuses v1.

**What is signed:**

```
M = "cathedral.vm.rewrap-answer/v2\0" (30 bytes)
    || offer_sha256 as 32 raw bytes || epk (32) || nonce (12) || ct (48)        154 bytes
D = "SSHSIG" || string(namespace) || string("") || string("sha512") || string(SHA-512(M))
```

- namespace `vm-rewrap-answer-v2@cathedral.computer`; reserved empty; `hash_algorithm` `sha512` only.
- `offer_sha256` binds the answer to one boot's offer (its key, nonce and report); `epk`, `nonce` and
  `ct` bind the ciphertext, so a genuine signature cannot carry a host's sealed key.

**The verifier (Go stdlib only, for every `keyTypes` entry):** the magic is `SSHSIG` and the version
is 1; the five strings fit and nothing trails the blob; `publickey` equals the identity's key blob
byte for byte; namespace, reserved and hash are as above; the signature string's fields lie inside
it, nothing trails them, and its type is:

| Key type | Signature | Check |
|---|---|---|
| `ssh-ed25519` | `ssh-ed25519`, 64 bytes | `ed25519.Verify(key, D, sig)` |
| `ecdsa-sha2-nistp256`, `-nistp384`, `-nistp521` | the key's type; string(mpint r, mpint s) | the key's curve name matches its type; Q is uncompressed (0x04) and on the curve; r and s are minimal mpints in 1..n-1; `ecdsa.Verify(pub, SHA-256/384/512(D), r, s)` |
| `ssh-rsa` | `rsa-sha2-512` only; `ssh-rsa` (SHA-1) and `rsa-sha2-256` are refused | the signature length equals the modulus length; `rsa.VerifyPKCS1v15(pub, crypto.SHA512, SHA-512(D), sig)` |
| `sk-ssh-ed25519@openssh.com` | the type, 64 bytes, then byte flags and uint32 counter | flags bit 0 (user present) is set; `ed25519.Verify(key, SHA-256(application) \|\| flags \|\| counter \|\| SHA-256(D), sig)` |
| `sk-ecdsa-sha2-nistp256@openssh.com` | the type, string(mpint r, mpint s), flags, counter | flags bit 0 is set; ECDSA P-256 over SHA-256(SHA-256(application) \|\| flags \|\| counter \|\| SHA-256(D)) |

The counter is not checked: the guest keeps no state, and `offer_sha256` makes each signature
single-use. The init verifies before `OpenAnswer`; a refused answer is logged once and the guest
keeps polling.

**Vectors:** `tests/fixtures/vm_rewrap_answer_v2.json` and `tests/fixtures/vm_ssh_key_shapes_v1.json`,
made by `scripts/make_vm_rewrap_answer_vectors.py` (`--check` fails if either file differs). All
signatures are deterministic, from test keys: never a real private key; the fixture's test keys
are public by design and must never be used as an identity. Each case carries the refusal code
the guest must give (from the generator's reference verifier, `null` when valid) and, where
known, `openssh_accepts`: `tests/test_vm_rewrap_answer_vectors.py` runs `ssh-keygen -Y
check-novalidate` over those cases, and `ssh-keygen -Y sign` makes the Ed25519 and RSA vectors byte
for byte. Both OpenSSH tests skip on a machine without `ssh-keygen` and fail in CI without it.
The worst case is RSA 8192: 3173 bytes. OpenSSH accepts seven cases the guest refuses (another
key, `sha256`, `rsa-sha2-256`, a short RSA signature, a non-minimal mpint, an sk signature
without the user-present bit, and a reserved field that is not empty), so `verify_vm.py
rewrap` checks those rules itself before it prints an answer. The negatives of erratum 2.6 each
have a case, a blob cut short among them: a reader refuses it and never panics.

**Key shape at VM create only:** a key the guest could not verify within 4096 bytes is refused when
the VM is made (`vm_ssh_key_shapes_v1.json`): a blob of at most 1100 bytes, an RSA modulus of 2048
to 8192 bits with an odd e in 3..2^31-1, a 32-byte Ed25519 key, and an uncompressed point (0x04,
65, 97 or 133 bytes) whose coordinates are below p and satisfy the named curve's equation. The
identity parser that `start`, `rebundle`, `verify` and the init use does not
change, so a VM made before the rule keeps booting; only its re-wrap is refused
(`rewrap_key_unsupported`).

**Customers:** never forward an agent that holds this key to a machine you do not control. A
signing oracle is the only way a host could make an answer, the same exposure as the login key.

## Attest (6.4)

`cathedral-attest CHALLENGE_HEX` hashes the ssh-ed25519 wire blob of
`/etc/ssh/ssh_host_ed25519_key.pub`, the blob `verify_vm.py` reads from the SSH handshake:

    REPORT_DATA = sha512("cathedral-vm-report/v1\0" || challenge[32] || sha256(host_key_blob))

stdout is one JSON object with `report_b64`. The Go result equals `verify_vm.report_data` on
`tests/fixtures/vm_attest_report_data_v1.json`, made by `scripts/make_vm_attest_vectors.py`. It is
not the dedicated guest's path or domain.

## Recovery (7.5)

First boot writes `/var/lib/cathedral-vm/recovery.key` (root only, canonical JSON with `vm_id`,
`identity_sha256` and the 32 byte key). `sudo cathedral-vm recovery show` prints one JSON line with exactly the members of
`verify_vm.py` `RECOVERY_FIELDS` and no others:

    {"chip_id":"<128 hex>","identity_sha256":"<64 hex>","recovery_key_b64":"<base64 of 32 bytes>","vm_id":"vm-..."}

`tests/fixtures/vm_recovery_show_v1.txt` is that line for fixed inputs. The Go test requires `Show`
to produce it byte for byte, and `tests/test_vm_attest_vectors.py` feeds it to
`verify_vm.parse_recovery`.

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
  C tools, the kernel module tree under `usr/lib/modules/<release>/` (each file pinned: all of
  `linux-modules`, plus from `linux-modules-extra` only the boot modules and their `modules.dep`
  dependencies, with the indexes depmod rebuilds for that set; the init loads the boot modules only), and two
  generated files for the init: `usr/lib/cathedral/vm-closure.json` and `usr/lib/cathedral/vm-modules.list`
  (boot modules in load order from `modules.dep`, dependencies first; built-in modules need no file).
  `build-bundle.sh` takes the archive through its existing `VM_BUNDLE_INITRD` hook.
- The check refuses an extra file, a dynamic or non-ELF executable, a missing or changed module, a wrong
  digest, a file with another mode, and any executable that contains the `vmcuttest` build tag.
- `vm_initrd_closure.json` is pinned to the reference build (`.github/workflows/vm-bundle-build.yml`,
  kernel `6.8.0-151-generic` from snapshot `20261126T000000Z`): `pin` printed the digests of both lanes'
  builds, which were identical, and they were committed with the two `room-kit/vm/locks/` files.
  A new snapshot, kernel or tool changes them: build with `VM_BUNDLE_LOCK_UPDATE=1` and an unpinned
  closure, review the pin output the lanes agree on, commit it. `build` and `check` refuse an unpinned
  closure.

## Base root pin (AB#1022)

`room-kit/vm/base_root_pin.json` (schema `cathedral.vm.base-root-pin/v1`) fixes the base root, so a
later bundle (a kernel or init fix) shares it and a VM can `rebundle` to it; another base root is
`base_root_differs`.

- While it is `pinned`, both lanes build with its `source_date_epoch`, not the commit time.
- The summary publishes only a base root whose `base-root.raw`, verity root, data bytes and lock are
  the pin's. The `bundle.env` step also fails when the snapshot, the base lock or the recipe
  (`recipe_sha256`) is not the pin's. The byte check is the gate.
- The pin today: base root `0a200cc3`, verity `45044764`, of bundle `a9585311` (run 46095917678,
  rebuilt byte for byte by run 46103583234 at another commit).
- Bundle B2 `c95300cb` (run 46114654444) replaces B1 `a9585311` and shares its base root. Its firmware is
  `ovmf-amdsev` 2025.11-3ubuntu7.3 (`OVMF.amdsev.fd` `ac27e626`, the sealed kits' firmware), in place of
  noble `ovmf` 2024.02-2ubuntu0.10 (`a50b4bca`). Under SEV-SNP on the proof host, B1's firmware stopped at
  the APIC page before any serial output. A B1 VM can `rebundle` to B2.
- **Take only the `vm-bundle` artifact.** The lanes upload `bundle-first` and `bundle-second`
  before the summary checks the pin, so a run that fails the pin still leaves lane artifacts with a
  base root that is not the pin's.
- A new base root (snapshot, lock or recipe) means a new pin and a new first bundle: set `status`
  to `unpinned`, run the workflow, and commit the pin its summary prints.

## Static tools build

`scripts/build_vm_initrd_tools.py` builds `cryptsetup` and `veritysetup` (cryptsetup 2.8.4) and
`mke2fs` and `resize2fs` (e2fsprogs 1.47.3). `vm_initrd_tools_inputs.json` pins every source and
development package by URL and sha256. The cryptsetup, LVM2 and Ubuntu package pins are those of
`custom_guest_verity_inputs.json`; the e2fsprogs source is new, and its sha256 equals the `.tar.xz` line
of `sha256sums.asc` in the same upstream directory (signed by the kernel.org autosigner; Ts'o's own signature is on the `.tar.sign` file, which this build does not check). `fetch` downloads and checks, `build` takes exactly the
pinned files and downloads nothing, builds twice and requires identical static ELFs.

## Tests and CI

- `go test -race ./...` (ci.yml) covers every package here. `tests/test_vm_initrd.py`,
  `tests/test_vm_rewrap_envelope.py` and `tests/test_vm_attest_vectors.py` run in the Python job.
- `.github/workflows/vm-guest.yml` adds two jobs: `vmroot` (root, loop devices, real dm-verity and
  e2fsprogs; the cut-point reruns, a flipped base block, a wrong root hash, the pinned-helper
  refusals, `Finish`) and `tools` (the static build, in an Ubuntu 26.04 container pinned by digest).
- The mailbox tests read `tests/fixtures/vm_mailbox_v1.json` from main and fail if it is missing.

## Wiring into `cmd/cathedral-vm-init`

`wire_linux_amd64.go` replaces the `unwired` stand-ins:

- `Root()` is `rootAdapter` over `internal/vmroot`. `CheckLink` is `vmroot.ParseLink`. `FirstBoot` runs
  `vmroot.FirstBoot` (copy, resize, user, host key, cloud-init, recovery record), unmounts strictly and
  returns R for the disk package's keyslot step. `Start` mounts, runs `Finish` (modules, `/run`,
  network file, tool binds, cloud-init marker) and then `SwitchRoot(ready)`, where `ready` writes the
  status record. The tool pins (`veritysetup`, `resize2fs`, and the two bound tools) come from the
  measured `usr/lib/cathedral/vm-closure.json`; a manifest missing any of them makes every call refuse.
- `Mailbox()` is `mailboxAdapter` over `vmmailbox`. The init already opens the disk with O_DIRECT after
  proving it is the block device sysfs names (`openDisk`, stronger than a path open), so it hands that
  file to `vmmailbox.New`, not `OpenDevice`. It zeroes the offer slot, then writes the status.
- `wire_root_linux_amd64_test.go` runs the real `vmdisk` and the real adapter on loop devices: blank
  disk, first boot, power off, ready boot (same host key and recovery record, status `new` then `open`),
  plus refusals (an unpinned tool, a flipped base block, a bad link). `switch_root` cannot run in a test;
  the hybrid stops after `ready`.

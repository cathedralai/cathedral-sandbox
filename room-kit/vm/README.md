# Customer VM host runtime (AB#991, AB#999)

Long-lived sealed customer Linux VMs on an AMD SEV-SNP host: a persistent disk,
the customer's SSH key, explicit start, stop, reboot and delete. Same pattern as
the sealed hotel unit (`../sealed/launch-guest.sh`, `write-units.sh`, `host-net.sh`).

**VMs are SEV-SNP only.** There is no plain KVM mode and no flag for one.
`launch-vm.py` builds every argv through `snp_qemu.snp_argv`, which always has
the `sev-snp-guest` object (policy `0x30000`, `kernel-hashes=on`), and checks it
again before QEMU runs. Off by default, on three switches: the broker refuses a
VM create (409 `vm_runtime_not_sealed`) unless the host is sealed and declares
`snp_vm_runtime`; `create` refuses (`snp_vm_host_disabled`) and every launch
refuses (exit 78) unless the host file `/etc/cathedral/snp-vm-host.json` exists
and lists the VM's bundle.

## Files

| File | Role |
|------|------|
| `vm-ctl.sh` (`vm_ctl.py`) | The control command. One JSON line on stdout per call. |
| `launch-vm.py` | `ExecStart` of `cathedral-vm-<name>.service`, as the VM's user: QEMU in the foreground, exit 75 on a guest reset, 0 on a poweroff. `--print` shows the argv. |
| `snp_qemu.py` | The SEV-SNP argv lines and their property check, shared with `ops/custom-guest/launch-custom-guest.py`. |
| `vm-net.sh up\|down\|check vm.env` | Tap /30 owned by the VM user, NAT out, SSH port forward, isolation. |
| `vm.env.example` | What `create` writes per VM. |
| `vm_mailbox.py` | The mailbox disk layout and its strict record, offer and answer parsers (re-wrap). |
| `vm_measure.py` | Sealed VM launch values: identity document, measured cmdline, HOST_DATA, expected measurement; bundle manifest. |
| `build-bundle.sh`, `bundle.env.example` | Recipe for one sealed VM bundle: base root, kernel and modules, manifest. |

## Use

```
# once per host: the bundle at $VM_ROOT/bundles/<id>/ and /etc/cathedral/snp-vm-host.json (mode 0644):
# {"version": 1, "cpu_family": "genoa", "bundles": ["<id>"], "default_bundle": "<id>",
#  "sev_snp_measure": "/opt/vm-measure/bin/sev-snp-measure"}
sudo ./vm-ctl.sh create vm1 --vcpus 2 --mem-gib 4 --disk-gib 40 --ssh-key-file key.pub --ssh-port 22001
sudo ./vm-ctl.sh authorize vm1 <paid_through_unix> <generation>
sudo ./vm-ctl.sh start vm1                  # ssh -p 22001 cathedral@<host>
sudo ./vm-ctl.sh reboot|stop|status vm1
sudo ./vm-ctl.sh list | enforce
sudo ./vm-ctl.sh cancel vm1 <generation>    # close a run in any state (see Execution history)
./vm-ctl.sh history vm1 <generation>         # read only, works after delete
sudo ./vm-ctl.sh rebundle vm1 --generation G --from <B1> --to <B2> --expect-revision R --op-id <32 hex>
sudo ./vm-ctl.sh rewrap vm1 --generation G < answer.json   # the answer on stdin only
sudo ./vm-ctl.sh delete vm1 --confirm vm1   # the only command that removes the disk
```

`VM_ROOT` (default `/srv/cathedral-vms`) and `SYSTEMD_UNIT_DIR` (default
`/etc/systemd/system`) can be set in the environment. Exit codes: 0 ok,
2 invalid request, 3 authorization refused, 4 unpaid, 5 no such VM or conflict,
17 stale bundle selection (`rebundle`), 1 other. Callers map a refusal by its `error` token, not
by the exit code alone.

## What a VM is

- `$VM_ROOT/<name>/` (root, 0700): `vm.env`, `vm-identity.json` (immutable: VM id, salt,
  first-boot key, base root hash), `launch.json` (bundle, identity sha256, expected
  measurement, HOST_DATA; `status` returns them), `root.raw` (sparse, `--disk-gib`, all
  zero until the guest formats it), `mailbox.raw` (1 MiB), `authorization.json`,
  `stop.json`, `run/` (the two QMP sockets). `root.raw`, `mailbox.raw` and `run/` belong
  to the VM's user; everything else stays root's.
- One system user `cvm-<slot>` per VM, made at create and removed at delete. QEMU runs
  as it (no `-runas`), with groups `kvm` and `cvm-sev` (a udev rule gives `cvm-sev` rw on
  `/dev/sev`).
- `cathedral-vm-<name>.service` (spec r2 8.2, the dedicated unit's confinement): root
  steps (`+`) load KVM, wait for `/dev/kvm`, check `paid_through` and the start line,
  bring the link up with a tap the VM user owns. `TemporaryFileSystem=/srv:ro` (and
  `$VM_ROOT` when it is elsewhere) hides every other VM and kit; `BindReadOnlyPaths`
  gives back the kit code, the bundle, `vm.env` and `vm-identity.json`, `BindPaths` the
  two disks and `run/`. `Restart=on-failure`, at most 5 starts in 15 min,
  `RestartForceExitStatus=75`, `RestartPreventExitStatus=78`. Enabled while it should
  run, so it returns after a host reboot.
- Reboot is a relaunch (`-no-reboot`): a guest reset ends QEMU, the launcher exits 75
  and systemd starts it again in the same generation; `vm-ctl reboot` asks the guest to
  power off, waits up to 60 s, then restarts the unit. Neither adds a history line. A
  `vm-ctl reboot` cut after the powerdown leaves `reboot-pending.json`, and its retry
  relaunches the same paid, open generation.
- QEMU starts paused (`-S`); the launcher lets the guest run (`cont`) only after it
  listens for QMP events, so no poweroff or reset goes unseen.
- Root's QMP commands (`stop`, `reboot`, the unit's `ExecStop`) connect as the VM's
  user from inside `run/`, so a link put there reaches nothing that user cannot.
- Network: guest `.2` on its own /30 in 10.216.0.0/16, NAT to the internet,
  no access to private ranges or to this host, and one way in: the host's
  `--ssh-port` forwarded to guest port 22.

## Credit cutoff (polariscomputer#2290 rules 3, 5, 6)

- `authorize` is idempotent and monotonic: an older generation is refused, the
  same generation may only keep or raise `paid_through`, a newer one replaces.
  The file is written atomically.
- `start` and the unit's `ExecStartPre` refuse when `now >= paid_through`.
- `stop` disables the unit, asks the guest to power off (QMP, up to 60 s),
  stops the unit, prints `stopped_at`, and closes the generation: that run can
  never start again, so a resume needs a fresh generation.
- `start`, `stop` and `reboot` take `--generation N` (the broker always sends it):
  a call for any other run than the current one is refused (exit 3,
  `stale_generation`) and changes nothing, so a delayed Stop of an old run
  cannot stop the new one.
- `cathedral-vm-enforce.timer` runs `enforce` every 30 s: any running VM past
  `paid_through` is stopped (reason `paid_through`) and keeps its disk. It
  also restores a running VM's link rules after a firewall reload. None of
  this needs the API or the broker.

## Execution history (AB#992)

One durable fact per run for billing settlement: when it started, or proof it never did.
Spec: `docs/VM_EXECUTION_HISTORY.md` (H1 to H9).

- `$VM_ROOT/.history/<name>.jsonl`, mode 0600, outside the VM directory (the leading dot cannot match
  a VM name), append-only, one flock per append. Every
  line is fsynced (file and `history/`) before anything that depends on it. `delete` keeps it,
  and `create` refuses a name that has one.
- Lines: `tracked_from` (first line, written under the VM lock by the first command after the
  upgrade: 1 for a new VM, else `generation + 1`), `start`, `close`. Each start and close line
  carries `wall_us`, `boot_id`, `mono_ns` and `synced` (kernel NTP state from `adjtimex`).
- `start` writes the `start` line before `systemctl enable` or `start`. The unit's
  `check-paid` refuses a launch when the current generation has no `start` line, or has a
  `close` line, or when the journal is corrupt (`history_corrupt`), so a reboot relaunch cannot skip
  any of them. A VM with no journal at all (from before the upgrade) is not gated. Every path that
  decides from the journal (`start`, `stop`, `cancel`, `check-paid`, `history`) fsyncs the file and
  directory first, so it never acts on a line a power loss could drop.
- A durable `close` line is authoritative. Every command that decides something first
  raises `closed_generation` to the highest close line.
- `authorize G'` over an open G: exit 3 `generation_open` if the unit is active (tracked or
  not) or G was started, else G is closed as never started (reason `superseded`).
- `stop` first runs `disable` and `stop` on the unit whatever it looks like (a queued start job is
  cancelled), verifies it inactive (`stop_failed` otherwise), and only then touches history, so
  the credit cutoff never depends on history I/O. It appends the `close` line first (reusing one if present), then writes
  `authorization.json` and `stop.json` from it, so every retry returns the same `stopped_at`.
- `cancel <name> <G>` is idempotent and closes G in any state: above the authorized
  generation it is fenced, the authorized one is stopped (reason `cancelled`). It returns
  `{name, generation, closed, stopped_at, close_reason}`; a repeat returns the same record.
  Cancelling above a started generation is refused (`generation_open`).
- `history <name> <G>` (no lock): closed G at or above `tracked_from` answers
  `{generation, closed, started_at, stopped_at, tracked_from, close_reason, history: "v2"}`.
  `started_at` is ISO 8601 with microseconds and `Z`, or null when the run never started, and is a
  conservative lower bound: never later than real execution. Same boot: the lesser of
  `close.wall_us - close.maxerror_us - ceil(elapsed_us / 0.9995)` and
  `start.wall_us - start.maxerror_us`, where `elapsed_us` comes from `boot_ns`
  (`CLOCK_BOOTTIME`, which counts suspend) and 0.9995 covers a clock 500 ppm slow.
  Different boots: `start.wall_us - start.maxerror_us`. `started_at_error_us` is the
  total subtracted. `maxerror_us` is `adjtimex` `.maxerror`; a line used must be `synced` with
  `maxerror_us` present and at most 1 s, else `history_unknown`. Exit 3 `history_open` while G is
  open; exit 3 `history_unknown` for G below `tracked_from`, a corrupt file, a missing first line,
  an untrusted clock or an unbounded start.
- A final line with no newline is a torn write: readers ignore it and the next writer cuts it.

## Broker access

For an `authorized_keys` forced command:

```
command="/opt/cathedral/room-kit/vm/vm-ctl.sh --from-broker",restrict ssh-ed25519 AAAA... broker
```

`SSH_ORIGINAL_COMMAND` must hold only letters, digits, spaces, `.`, `_`, `-`;
it is split on spaces, never passed to a shell, and only the public
subcommands are allowed. `create` takes the customer key on stdin (no
`--ssh-key-file`) and the host's default bundle unless `--bundle` names another
enabled one.

## Sealed VM bundle and launch values (AB#999, PR VM1a)

`create` writes the identity and the launch values below; the launcher recomputes the
cmdline and HOST_DATA from the identity on every launch.

- **Bundle:** one directory addressed by `sha256(manifest.json)`: `OVMF.amdsev.fd`,
  `vmlinuz`, `initrd.cpio.zst` (the VM initrd, PR VM1b), `base-root.raw` (ext4 plus its
  dm-verity tree after the data), the two `packages.lock` files and `manifest.json`
  (schema `cathedral.vm.bundle/v1`, canonical JSON, every file's sha256 and size, the
  cmdline template, CPU family and model, policy `0x30000`, QEMU, kernel and initrd
  versions, snapshot, verity root hash). `build-bundle.sh` builds the base root and the
  kernel from one pinned snapshot, then writes the manifest.
- **Identity:** `vm-identity.json` (schema `cathedral.vm.identity/v1`): `vm_id`, a random
  salt, the first-boot SSH key and the bundle's base root hash. Written once at create.
- **Cmdline:** the bundle template with `cathedral.vm=<sha256 of vm-identity.json>`, so
  every VM has its own launch measurement. It masks every getty, the emergency, rescue
  and debug shells, and the guest agent.
- **HOST_DATA:** `sha256(b"cathedral-vm-v1\0" || sha256(vm-identity.json))`: 64 hex in a
  report, base64 for QEMU `host-data=`.
- **Measurement:** `sev-snp-measure 0.0.12 --mode snp` (requirements/vm-measure.txt) over
  digest-checked private copies. Every VM runs QEMU `-cpu EPYC-v4`, on Genoa and Turin
  alike (Toby, 27 Nov 12:19Z: until the tool supports Turin); a manifest naming another
  model is refused. Only the model's CPUID signature (family, model, stepping) is
  measured, not its feature set: EPYC-v1 and EPYC-v4 give one digest. The guest checks
  its features itself (VM1b).

```
vm_measure.py identity --bundle B --vm-id vm-0123456789ab --ssh-key-file key.pub --out vm-identity.json
vm_measure.py launch --bundle B --identity vm-identity.json --vcpus 2 --cpu-family genoa
vm_measure.py check-bundle B
```

Shared vectors: `tests/fixtures/vm_measure_v1.json` (identity, cmdline, HOST_DATA, five
measurements) for the VM init (VM1b) and the verifier (VM2).

## Re-wrap: rebundle and rewrap (AB#999, PR VM6 host side; spec r3 7.5)

A VM moves to another bundle (a kernel fix) only with its customer: the new measurement
derives a new disk key, the guest finds its root `locked`, and the customer's tool wraps
their pinned recovery key to the guest's offer.

**`rebundle <name> --generation G --from B1 --to B2 --expect-revision R --op-id X`**
(step 1). A restore is the same verb with `--to` the old bundle.

- Every VM has `bundle_selection_revision` (in `launch.json`, 0 when absent; `status`
  returns it). Each accepted change adds exactly 1. `X` is 32 hex (128 random bits) from
  the caller; the last 64 applied op_ids are kept with their results.
- Under the VM lock, in this order: an applied `X` returns its stored result unchanged
  (the same `X` with another request: `op_id_conflict`, exit 2). Then G must be the
  current generation (`stale_generation`, exit 3) and closed, or 0 for a VM never
  authorized (`generation_open`, exit 3: an authorized run that never started must be
  cancelled first); R must equal the revision (`stale_selection`, exit 17); B1 must be the
  current bundle (`bundle_changed`, exit 3); the unit must be stopped (`vm_not_stopped`,
  exit 3). B2 must be enabled in the host file (`bundle_not_enabled`), its manifest must be
  the one its directory names (`no_bundle`) and it must have the identity's base root
  (`bundle_incompatible`), all exit 1.
- The new launch values (expected measurement; the identity and HOST_DATA do not
  change), the revision and the op are committed in one rename of `launch.json`. Then
  `vm.env` `VM_BUNDLE`, the unit's bundle bind and `daemon-reload` follow, and
  `selection-synced.json` records the revision. A cut anywhere after the commit is
  finished by the retry (same op_id) or by the next `start`, before it reads `VM_BUNDLE`;
  until then `check-paid` refuses every launch (`selection_unsynced`).
- The host's verified list (VM5) is not checked here: a bundle this host build is not
  verified for is refused at the next start, not at rebundle.

**`rewrap <name> --generation G`**, the answer on stdin (step 4). Never an argument:
the broker's argument check allows 64 characters, and nothing secret goes on a command
line. At most 4096 bytes; one JSON object, any key order, exactly the fields of
`vm_mailbox.ANSWER_FIELDS` (`invalid_rewrap_answer`, exit 2). It is written only while G
is the current, open generation (`stale_generation`, `generation_closed`) and the unit is
active, and only for the offer now in the mailbox, named by `offer_sha256` (the sha256
of the offer's report): `no_rewrap_offer` or `rewrap_offer_changed`, exit 3. The same
answer again is not written again (`"written": false`).

**The mailbox** (`vm_mailbox.py`, vectors `tests/fixtures/vm_mailbox_v1.json`): status
at 0 and offer at 64 KiB, written by the guest; answer at 128 KiB, written by the host.
Each region is empty or one record (`CVMMBX1\0`, kind, length, sha256, canonical JSON).
`mailbox.raw` belongs to the VM user and its bytes are the guest's:

- Opened without following a link (`O_PATH | O_NOFOLLOW` through the root-owned VM
  directory) and checked by its descriptor: a regular 1 MiB file with one link, owned by
  the VM user (`mailbox_invalid`, exit 1).
- The answer write runs as the VM user with no supplementary groups, through that
  descriptor (reopened from `/proc/self/fd`), as the QMP commands do: a hard link to a
  root file fools nothing even if root's checks did.
- `status` shows `rewrap_offer` only while the unit is active, strictly parsed, and
  still guest data: the broker and the API pass it on; the customer's tool verifies it.

## Not here yet

Admission across VMs and kits (VM4), the pre-launch gates and host change gate (VM5),
the guest side of re-wrap (VM1b, VM2), resize, snapshots.

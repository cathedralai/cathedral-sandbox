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
| `vm_capacity.py` | The host admission ledger across VMs and sealed hotel kits (AB#999). |
| `launch-vm.py` | `ExecStart` of `cathedral-vm-<name>.service`, as the VM's user: QEMU in the foreground, exit 75 on a guest reset, 0 on a poweroff. `--print` shows the argv. |
| `snp_qemu.py` | The SEV-SNP argv lines and their property check, shared with `ops/custom-guest/launch-custom-guest.py`. |
| `vm-gates.sh` (`vm_gates.py`) | Pre-launch gates and the host change gate (spec 8.3): `check <name>` before every start and launch, `enforce` on the enforce tick. Exit codes in `vm_gates.py`. |
| `vm-net.sh up\|down\|check vm.env` | Tap /30 owned by the VM user, NAT out, SSH port forward, isolation. |
| `vm.env.example` | What `create` writes per VM. |
| `vm_mailbox.py` | The mailbox disk: slots, records, the body pre-scan and strict parsers (re-wrap). |
| `vm_measure.py` | Sealed VM launch values: identity document, measured cmdline, HOST_DATA, expected measurement; bundle manifest. |
| `build-bundle.sh`, `bundle.env.example` | Recipe for one sealed VM bundle: base root, kernel and modules, manifest. |
| `verify_vm.py` | The customer's verifier, run on their own machine: one SSH connection, a fresh challenge, the SNP report checked against their bundle and identity. `pin` also keeps the recovery key, chip and host key locally. |

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
sudo ./vm-ctl.sh rebundle vm1 --generation G --expect-revision N --op-id <32 hex> --to <B2>
sudo ./vm-ctl.sh rewrap vm1 --generation G < answer.json   # the answer on stdin only
sudo ./vm-ctl.sh delete vm1 --confirm vm1   # the only command that removes the disk
sudo ./vm-ctl.sh capacity [--broker-max-vcpus N --broker-max-mem-gib N --broker-max-disk-gib N]
```

`VM_ROOT` (default `/srv/cathedral-vms`) and `SYSTEMD_UNIT_DIR` (default
`/etc/systemd/system`) can be set in the environment. Exit codes: 0 ok,
2 invalid request, 3 authorization refused, 4 unpaid, 5 no such VM or conflict, or no room on
the host (`{"error": "host_capacity", "resource": ...}`, see Host admission), 10 to 18 a
pre-launch gate (`start`, `vm_gates.EXIT`), 19 stale bundle selection, 20 bundle
incompatible and 21 selection committed but not synced (`rebundle`), 1 other. A refusal may carry a `reason` token. Callers map a
refusal by its exit code and `error` token together, per command.

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
  run the pre-launch gates (`vm-gates.sh check`), bring the link up with a tap the VM
  user owns. `TemporaryFileSystem=/srv:ro` (and
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
- Pre-launch gates (`vm-gates.sh check`): `start` runs them after the paid check and
  before the start line, so a refused start bills nothing; the unit runs them again, so
  a host boot, a crash restart and a guest reboot pass them too; `reboot` runs them
  before the powerdown, so a host that would refuse the relaunch leaves the VM running.
  A gate refusal is the gate's own error and exit code (10 to 18; 17
  `sev_platform_changed`, 18 `sev_state_unavailable`), which the broker answers with 502
  `vm_host_refused`, the VM kept stopped. Any other gate answer refuses as
  `gates_failed`, exit 1. The enforce service runs `vm-gates.sh enforce` after the
  credit cutoff: a SEV change refuses new starts and leaves running VMs alone.
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

## Host admission (AB#999, VM spec r2 section 9)

One SNP host shares memory, disks, SNP ASIDs and threads between the sealed hotel kits and the
VMs. `vm_capacity.py` counts both. It runs only while the VM host switch
`/etc/cathedral/snp-vm-host.json` exists (also the VM3 host config: without it no VM is created,
and `install-sealed.sh` behaves as before).

- **Rollout:** turn the switch on only while no kit install is running on the host. An install
  that started before it has no record and no install lock, so the ledger would count that kit
  by its unit alone until its next install.

- **Kits:** every `room-sealed-<name>.service` unit file, enabled or not, and the env file on its
  `ExecStart` line, wherever `SEALED_DIR` is. A `-net` unit is skipped only when it is exactly the
  check unit `write-units.sh` writes (`Type=oneshot`, `ExecStart=<dir>/host-net.sh check <env>`),
  and a `-escape` unit only when it is exactly the fresh slot supervisor
  `scripts/escape_slots/write-escape-units.sh` writes (`Type=simple`, `ExecStart=/usr/bin/python3 -I
  <SEALED_DIR>/escape-slot/supervise_escape_slot.py --sealed-env <SEALED_DIR>/sealed.env`): it runs
  no guest, only stops and starts its kit's own unit, which is counted. Any other unit, whatever
  its name, is a kit and must parse. Plus the kits being installed:
  each install of a kit records `/var/lib/cathedral-snp/kits/<name>.<install id>.json` before
  its build. Counted by name, each size the larger of the unit and every open record. A kit that
  is removed must have its records removed too. A unit, env file or record that cannot be read (missing, a line that is not
  `KEY=value`, a size only a shell could read) refuses every create and start: resource
  `kit_unaccounted`.
- **One install of a kit at a time:** with the switch on, `install-sealed.sh` holds
  `/run/lock/cathedral-kit-<name>.install.lock` from its assess step to its exit (unlocked by its
  EXIT trap). A second install of the same kit stops at once; it does not wait.
- **Rolls:** `assess-kit` prints the install id; the install's record holds the larger of the
  running build and the replacement. When the new guest's measurement matched (after
  `systemctl enable`), `commit-kit --install-id <id>` drops every open record of the kit: the
  guest now runs from the current `sealed.env`. An id with no open record is refused (exit 1).
  Any other exit (refused for live rooms, a failed build, a crash) keeps the record, because the
  env may already be copied while the old guest runs; the exit step logs its id, and `capacity`
  lists each kit's `open_installs`.
- **A stale record** may be removed only after the kit's guest has restarted from the current
  `sealed.env`, or by the next confirmed install. Right after a failed install the running build
  is still the old one.
- **Data-volume reset:** reserved before `data.raw` moves (`assess-kit --install-id <id>
  --data-reset`). The fresh `data.raw` is charged its own new size. `data.raw.prev` is detached
  and cannot grow, so it counts only the blocks it holds (already out of `df` avail) until it is
  removed. A roll that is not confirmed puts the volume back; it is then charged the larger of
  its own growth and the replacement's size while that install's record stays.
- **VMs:** every `vm.env`, in any state.
- **create** (commit), exit 5 on the first resource that does not fit:
  - `memory`: kits + VMs + this VM, each plus `VM_GUEST_OVERHEAD_MIB` (default 1024), plus a
    32 GiB reserve, at most `MemTotal`;
  - `disk`: on this VM's file system, `df` avail less the remaining growth of every sparse file on
    it (VM disks, kit `scratch.raw` and `data.raw`: full size less allocated) less this VM's full
    size, at least the reserve (the largest `SEALED_MIN_HOST_FREE_GIB` of a kit on that file
    system, and `VM_MIN_HOST_FREE_GIB`, default 64);
  - `asid`: one per kit, running or not, one per VM, and this one, at most `misc.capacity sev_es`;
  - `vcpu`: kits + VMs + this VM at most threads less 4.
- **start** (live): `MemAvailable` at least the VM, its overhead and the reserve; the disk rule
  without adding the VM again; ASIDs in use (`misc.current sev_es`, or the running kits and the
  VMs that run or are enabled, whichever is more) plus one per stopped kit plus one, at most the
  capacity. A start of a running VM is not checked again. The check runs before the history start
  line, so a refused start bills nothing.
- **Custom-guest hosts:** create always refuses (resource `custom_guest_host`) on a host with
  `/etc/cathedral/custom-guest.allow`, a `custom-guest.hold` marker in a kit's `SEALED_DIR` or in
  `/srv/sealed-hotel-*/`, or a launch folder `/srv/custom-guest/<hotel>/[inbox/|staging/]cg-*`.
- **Lock:** `/run/lock/cathedral-snp-capacity.lock`, held only from the check to the record:
  create until `vm.env` is written, start until the unit is enabled, the kit install until its
  record is written. `stop`, `enforce`, `cancel` and `delete` never take it.
- **`capacity`** (read only): kits, VMs, host figures, each file system's growth and reserve, and
  the VM share left after the kits. With the broker's `max_vcpus`, `max_mem_gib` and
  `max_disk_gib` for this host it checks they fit that share (exit 1 when not): the broker's
  static maxima must stay at or under it.
- The broker maps exit 5 `host_capacity` to 409 `no_vm_capacity`; other exit 5 answers stay 502.

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
  kernel from one pinned snapshot (its release, `-updates` and `-security` pockets), then
  writes the manifest. The reference build is `.github/workflows/vm-bundle-build.yml`:
  two lanes on fresh hosted runners, with the pinned static `mke2fs` and `veritysetup`,
  and a summary that publishes only when every file is byte-identical across the lanes.
- **Identity:** `vm-identity.json` (schema `cathedral.vm.identity/v1`): `vm_id`, a random
  salt, the first-boot SSH key and the bundle's base root hash. Written once at create.
  `create`'s answer, `status` and `list` carry it as `identity_document`, the file's exact
  text (the customer's input to `verify_vm.py`; its sha256 is `identity_sha256`), or `null`
  when the file is not the one `launch.json` names. It is not secret: the salt and the key
  are the customer's own.
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

## Verify a VM (AB#999, PR VM2)

The customer runs `verify_vm.py` on a machine they trust, with their own bundle
directory, their `vm-identity.json` and the AMD root fingerprint they trust for the CPU
family (spec r3 6.4). It opens one SSH connection to the VM (no user config, agent, mux or
proxy; an empty known_hosts; ed25519 host keys only), runs
`sudo -n /run/cathedral/bin/cathedral-attest <challenge>` there, and checks the report:

| Check | Refusal code |
|---|---|
| the identity names the SSH key you gave at create (`--create-key`, default `<--ssh-key>.pub`), before any connection | `identity_key_mismatch`; no readable key: `create_key` (exit 2) |
| bundle and identity agree (CPU family, base root) | `bundle_cpu_family` (exit 2), `identity_bundle_mismatch` |
| report version 3, 4 or 5 (2 has no CPUID: refused) | `report_version` |
| CPU family, and the exact CPUID its floor is approved for | `cpu_family_mismatch`, `cpuid_unapproved` |
| ARK pin, ASK and VCEK from AMD KDS, validity, CRL, report signature | `amd_chain` |
| REPORT_DATA = `sha512(b"cathedral-vm-report/v1\0" \|\| challenge \|\| sha256(host key blob))` | `report_data_mismatch` |
| POLICY `0x30000`, VMPL 0, VCEK signer with the chip key not masked | `policy`, `vmpl`, `signer` |
| every component of the four TCBs at or above the floor | `tcb_floor` |
| MEASUREMENT and HOST_DATA equal `vm_measure.py launch` over their files | `measurement_mismatch`, `host_data_mismatch` |
| when this identity has a pin: the same SSH host key and CHIP_ID as pinned | `host_key_changed`, `chip_id_changed`; an unsafe pin store: `pin_store_invalid` (exit 2) |

Floors: Turin `1a:02:01` at `fmc=1,bl=3,tee=3,snp=8,ucode=118` (D 10.4); Genoa `19:11:01`
at `bl=12,tee=0,snp=30,ucode=88`, the current sealed floor, to confirm at the first Genoa
live proof. `--min-tcb` may only raise a floor.

```
verify_vm.py verify --bundle B --identity vm-identity.json --vcpus 2 --cpu-family genoa \
  --ark-sha256 "$AMD_ARK_SHA256" --host <host> --port <ssh port> --ssh-key ~/.ssh/id_ed25519
```

`AMD_ARK_SHA256` is the SHA-256 of the AMD root certificate (ARK) for the VM's product,
`Genoa` or `Turin`. Fetch AMD's chain yourself and compute it locally; never take it from
the VM, the report or the API. The chain is the ASK, then the ARK:

```
curl -fsS -o chain.pem https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain   # or .../Turin/cert_chain
awk '/BEGIN CERTIFICATE/{n++} n==2' chain.pem | openssl x509 -outform DER | openssl dgst -sha256 -r
```

It should equal the pin for that product in `broker/amd_chain.go` (Genoa `4c6598d1...`,
Turin `1f084161...`); a mismatch is a reason to stop, not to pick one.

One JSON line: `PASS` (exit 0), `FAIL` with a code (exit 1, the VM's evidence was refused)
or `ERROR` with a code (exit 2, the check could not run). The guest side of the command
(path, user, output) is PR VM1b's to confirm; the constants sit in one block at the top.

### Pin (spec r3 7.5)

Run `verify_vm.py pin` once, after first login, with the same flags. On the same SSH
connection it runs `cathedral-attest <challenge> && cathedral-vm recovery show`, so the
recovery key R is printed only after the guest's attest command succeeded. It keeps a pin
only when every verify check passed, ssh exited 0, and the guest's recovery record names
your identity's `vm_id` and `identity_sha256` and the CHIP_ID of the verified report
(`recovery_identity_mismatch`, `recovery_chip_mismatch`, `recovery_invalid` otherwise).
A host key comes only from a run that exited 0: OpenSSH writes an accept-new key before it
checks the key exchange signature.

The pin is `${XDG_DATA_HOME:-~/.local/share}/cathedral/vm-pins/<identity sha256>.json`
(`--pin-dir` to choose another): canonical JSON, schema `cathedral.vm.pin/v1`, with R,
`vm_id`, `identity_sha256`, CHIP_ID, the SSH host key and the time. The directory is 0700 and
the file 0600, created exclusively and never through a link; a pin that is a link, not
yours, or open to others refuses (`pin_store_invalid`). R is never printed. Pinning again
with the same values is a no-op (`unchanged`); other values refuse `pin_exists` and leave
the pin as it was. VM6 re-wrap reads R with `load_pin`.

## Rebundle (AB#999, PR VM6 host side; spec r3 7.5 step 1)

A VM moves to another bundle (a kernel fix) only with its customer: the new measurement
derives a new disk key, the guest finds its root `locked`, and the customer's tool wraps
their pinned recovery key to the guest's offer (`rewrap`, below). A restore is the
same command with `--to` the old bundle.

**`rebundle <name> --generation G --expect-revision N --op-id X --to B2`**, all four
required. `launch.json` holds `bundle_selection_revision` (0 when absent; `status` returns
it) and `selection_ops`, the last 64 applied requests with their results. Every accepted
rebundle adds exactly 1 to the revision, also one whose `--to` is the current bundle.

Under the VM lock, in this order:

1. **Retry:** `X` in `selection_ops` with the same G, N and B2 returns its stored result
   (the state right after it) and changes nothing in `launch.json`. The same `X` with any
   other field: `stale_selection`, exit 19, reason `op_id_reused`.
2. **Generation fence:** G is the current generation, closed (or 0 for a VM never
   authorized), and the unit is stopped; else `stale_generation`, exit 3, reason
   `not_current`, `generation_open` (an authorized run that never started is cancelled
   first) or `unit_active`.
3. **Revision fence:** N is `bundle_selection_revision`; else `stale_selection`, exit 19.
4. **B2 can start here:** the host file reads (as create and start's gate read it), B2 is
   enabled in it, its manifest is its id, it is built for this host's CPU family, it has a
   verified build for this host's QEMU and kernel and the VM's vCPUs (or the VM is a canary;
   the `vm_gates.py` helpers start uses), and it carries the identity's base root. Else
   `bundle_incompatible`, exit 20, reason `host_config_invalid`, `bundle_not_enabled`,
   `no_bundle`, `cpu_family_differs`, `no_verified_build` or `base_root_differs`. Start runs
   its gates again.
5. **Apply:** B2's launch values (the expected measurement; the identity and HOST_DATA do
   not change), the revision + 1 and the request are written in one rename of
   `launch.json`, the commit point. Then `vm.env` `VM_BUNDLE`, the unit's bundle bind and
   `daemon-reload` follow, and `selection-synced.json` records the revision.

Refused requests are not recorded. A retry whose `X` has left the last 64 is evaluated as
new and refused by the revision fence. A cut before the commit changes nothing; a cut after
it is finished by the retry or by the next `start`, which derives `vm.env` and the unit from
`launch.json` before its gates read `VM_BUNDLE`. A sync step that fails after the commit
(for example `daemon-reload`) exits 21, `selection_committed_sync_failed`, not 1: the change is
committed, and the same `X` again finishes it. Until then `check-paid` refuses every launch
(`selection_unsynced`, exit 3). The marker exists because a cut between the unit write and
`daemon-reload` leaves a right file and a stale systemd. **A caller retries any failure it
cannot read as a refusal (a lost answer, exit 21, any broker 5xx) with the same `X`.**

## Re-wrap: rewrap and the mailbox (AB#999, PR VM6 host side; spec r3 7.5)

**The mailbox** (`mailbox.raw`, 1 MiB, owned by the VM user; `vm_mailbox.py`, vectors in
`tests/fixtures/vm_mailbox_v1.json`): the status record at 0 and the offer at 64 KiB, written by
the guest; the answer at 128 KiB, written by the host. A record is `CVMMBX1\0`, a kind byte, a
4-byte big-endian body length, the body's sha256 and a canonical JSON body (at most 64 KiB minus
the 45-byte header; 4096 bytes for the answer).

- **Read:** magic, kind, length bound and sha256; a mismatch is a torn read. `status` and `list`
  read each slot once (a torn slot is empty there); only `rewrap`, under that VM's lock, reads
  the offer again, 5 times 200 ms apart. Then a bounded pre-scan refuses any nesting before the parser runs, and the keys
  must be exactly the schema's, each with its type and length. Any failure, of any exception
  type, is an empty slot: it never fails `status`, `list` or another VM.
- **Host access:** the VM directory (root's, 0700) opened with `O_DIRECTORY|O_NOFOLLOW`, then
  `openat(dirfd, "mailbox.raw", O_NOFOLLOW)` (`O_RDONLY` to read, `O_RDWR` to write, never
  `O_CREAT`), then `fstat` on the open file: a regular file of 1 MiB, one link, owned by the VM
  user, else `mailbox_invalid` (exit 3) and nothing is touched. The VM user owns the bytes, not
  the entry, and the checks run on the descriptor that is used.
- **`status`** (only for a sealed VM) shows `vm_state` and `guest_status` from the status
  record and, while the unit runs, `rewrap_offer` (the offer and its `offer_sha256`, the sha256 of
  its body). All of it is guest data: the broker and the API pass it on, the customer's tool
  verifies it.

**`rewrap <name> --generation G`**, the answer on stdin (step 4), never an argument: the
broker's argument check allows 64 characters. The envelope is canonical JSON of at most 4096
bytes with exactly `schema`, `offer_sha256`, `epk`, `nonce`, `ct` (`invalid_rewrap_answer`,
exit 2). It is written only while G is the current, open generation (`stale_generation`,
`generation_closed`) and the unit is active, and only for the offer now in the offer slot:
`no_rewrap_offer` or `rewrap_offer_changed`, exit 3. One `pwrite` of the answer slot, then
`fsync`; the same answer again is not written again (`"written": false`).

## Not here yet

Admission across VMs and kits (VM4), the guest side of re-wrap (VM1b, VM2), the status
record's measurement check (`vm_measurement_differs`, spec 7.2), resize, snapshots.

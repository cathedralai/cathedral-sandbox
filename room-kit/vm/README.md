# Customer VM host runtime (AB#991)

Long-lived customer Linux VMs on a KVM host: a persistent disk, the customer's
SSH key, explicit start, stop, reboot and delete. Same pattern as the sealed
hotel unit (`../sealed/launch-guest.sh`, `write-units.sh`, `host-net.sh`).

**VMs are SEV-SNP only.** There is no plain KVM mode and no flag for one.
`launch-vm.sh` refuses to start QEMU (exit 78, "VM launch refused: SEV-SNP is
required (AB#999)") and the broker refuses a VM create (409
`vm_runtime_not_sealed`) unless the host is sealed and declares
`snp_vm_runtime`. Both stay refused until the SNP VM launch ships (AB#999).

## Files

| File | Role |
|------|------|
| `vm-ctl.sh` (`vm_ctl.py`) | The control command. One JSON line on stdout per call. |
| `vm_capacity.py` | The host admission ledger across VMs and sealed hotel kits (AB#999). |
| `launch-vm.sh` | `ExecStart` of `cathedral-vm-<name>.service`: QEMU in the foreground. |
| `vm-net.sh up\|down\|check vm.env` | Tap /30, NAT out, SSH port forward, isolation. |
| `images.lock`, `fetch-image.sh` | Pinned Ubuntu 24.04 cloud image and its sha256. |
| `vm.env.example` | What `create` writes per VM. |

## Use

```
sudo ./fetch-image.sh                       # once per host: $VM_ROOT/images/
sudo ./vm-ctl.sh create vm1 --vcpus 2 --mem-gib 4 --disk-gib 40 --ssh-key-file key.pub --ssh-port 22001
sudo ./vm-ctl.sh authorize vm1 <paid_through_unix> <generation>
sudo ./vm-ctl.sh start vm1                  # ssh -p 22001 cathedral@<host>
sudo ./vm-ctl.sh reboot|stop|status vm1
sudo ./vm-ctl.sh list | enforce
sudo ./vm-ctl.sh cancel vm1 <generation>    # close a run in any state (see Execution history)
./vm-ctl.sh history vm1 <generation>         # read only, works after delete
sudo ./vm-ctl.sh delete vm1 --confirm vm1   # the only command that removes the disk
sudo ./vm-ctl.sh capacity [--broker-max-vcpus N --broker-max-mem-gib N --broker-max-disk-gib N]
```

`VM_ROOT` (default `/srv/cathedral-vms`) and `SYSTEMD_UNIT_DIR` (default
`/etc/systemd/system`) can be set in the environment. Exit codes: 0 ok,
2 invalid request, 3 authorization refused, 4 unpaid, 5 no such VM or conflict, or no room on
the host (`{"error": "host_capacity", "resource": ...}`, see Host admission), 1 other.

## What a VM is

- `$VM_ROOT/<name>/`: `vm.env`, `disk.qcow2` (overlay on the pinned image,
  sized to `--disk-gib`), `seed.iso` (cloud-init NoCloud: user `cathedral`
  with the customer key and sudo, no password login, root login off, static
  IP), `authorization.json`, `stop.json`, `run/` (QMP socket, serial log).
- `cathedral-vm-<name>.service`: loads KVM, waits for `/dev/kvm`, checks
  `paid_through`, brings the link up, runs QEMU. `Restart=on-failure`, at most
  5 starts in 15 min. Enabled while it should run, so it returns after a host
  reboot. A guest reboot stays inside the same QEMU process.
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
`/etc/cathedral/snp-vm-host.json` exists; without it create, start and `install-sealed.sh`
behave as before.

- **Kits:** every `room-sealed-<name>.service` unit file, enabled or not (not the `-net` check
  units), and the env file on its `ExecStart` line, wherever `SEALED_DIR` is. Plus the kits
  being installed: `install-sealed.sh` records `/var/lib/cathedral-snp/kits/<name>.json` before
  its build. Counted by name, each size the larger of unit and record. A kit that is removed must
  have its record removed too. A unit, env file or record that cannot be read (missing, a line
  that is not `KEY=value`, a size only a shell could read) refuses every create and start:
  resource `kit_unaccounted`.
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
subcommands are allowed. `create` takes the customer key on stdin and always
uses the pinned image (no `--ssh-key-file`, no `--image`).

## Not in v1

The SNP launch itself (AB#999), resize, snapshots.

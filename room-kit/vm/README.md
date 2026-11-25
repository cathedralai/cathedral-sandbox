# Customer VM host runtime (AB#991)

Long-lived customer Linux VMs on a KVM host: a persistent disk, the customer's
SSH key, explicit start, stop, reboot and delete. Same pattern as the sealed
hotel unit (`../sealed/launch-guest.sh`, `write-units.sh`, `host-net.sh`), but
plain KVM: **v1 is not SEV-SNP**, so the host operator can read guest memory
and disk. Sealed disk boot is a follow-up.

## Files

| File | Role |
|------|------|
| `vm-ctl.sh` (`vm_ctl.py`) | The control command. One JSON line on stdout per call. |
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
sudo ./vm-ctl.sh delete vm1 --confirm vm1   # the only command that removes the disk
```

`VM_ROOT` (default `/srv/cathedral-vms`) and `SYSTEMD_UNIT_DIR` (default
`/etc/systemd/system`) can be set in the environment. Exit codes: 0 ok,
2 invalid request, 3 authorization refused, 4 unpaid, 5 no such VM or conflict, 1 other.

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

SEV-SNP, broker routes (`/v1/broker/vms`, next PR), resize, snapshots.

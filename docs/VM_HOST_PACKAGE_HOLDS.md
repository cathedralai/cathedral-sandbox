# VM host package holds and the pre-launch gates (AB#999)

Runbook for an SNP host that runs sealed customer VMs (`room-kit/vm`). It covers the package
holds, a planned QEMU or kernel upgrade, and the SEV baseline. The gates themselves are in
`room-kit/vm/vm_gates.py` (VM runtime spec r2 8.3). Nothing here is on by default: a host without
`/etc/cathedral/snp-vm-host.json` runs no sealed VM, and every gate refuses.

## What the gates check

`vm-gates.sh check <name>` runs before a VM's start line is written (`vm-ctl.sh start`) and again as
the unit's `ExecStartPre`, so a host boot, a crash restart and a guest reboot pass the same gates.

| Exit | Error | Refused when |
|---|---|---|
| 10 | `vm_invalid` | no such VM, or its `vm.env` has no valid `VM_NAME`, `VM_BUNDLE` or `VM_VCPUS` |
| 11 | `vm_host_not_enabled` | the host file is missing, unsafe or invalid |
| 12 | `vm_bundle_not_enabled` | the VM's bundle is not in the host file's `bundles` |
| 14 | `vm_host_changed` | this host's QEMU binary and kernel release, with the VM's vCPU count, are not a verified build of the bundle |
| 15 | `sev_baseline_missing` | no SEV baseline, or it is unsafe or invalid |
| 16 | `sev_status_unreadable` | `/dev/sev` did not answer the status commands |
| 17 | `sev_platform_changed` | the SEV status differs from the baseline, now or earlier in this boot |
| 18 | `sev_state_unavailable` | this boot's SEV state cannot be held or kept (lock busy, `/run/cathedral-snp` unsafe or not writable) |
| 13 | `vm_bundle_mismatch` | a bundle file is missing or differs from its manifest |

The gates run in the order of the table. A refusal prints one JSON line on stdout and one line,
`vm-gates: <error>: <reason>`, on stderr. Exit 1 is an internal error and exit 2 a usage error; both
refuse too.

`vm-gates.sh enforce` runs on the enforce tick. It compares only the SEV status. It never stops a
running VM. A change refuses new starts for the rest of the boot.

The SEV state of a boot is in `/run/cathedral-snp/` (tmpfs, so a reboot clears it). The first
compare of a boot arms the boot. A change replaces the armed token with a changed marker, and a
durable copy goes to `/var/lib/cathedral-snp/vm-sev-changed.json` when the boot id is known. A full
disk cannot lose the change, because the token is renamed and a rename needs no free space. Only a
host reboot or `baseline --replace` ends the refusal.

## Host file

`/etc/cathedral/snp-vm-host.json`, owned by root, mode 0644 or stricter:

```json
{
  "bundles": ["<bundle id>"],
  "verified": {
    "<bundle id>": [
      {"qemu_sha256": "<sha256 of /usr/bin/qemu-system-x86_64>", "qemu_version": "<x.y.z>",
       "kernel_release": "<uname -r>", "vcpus": [2, 4]}
    ]
  },
  "canary_vms": []
}
```

- `bundles`: the bundles this host may launch. The launcher reads this key too.
- `verified`: per bundle, the host builds on which a canary VM booted and its report matched
  `expected_measurement`, with the vCPU counts that were tested. The QEMU sha256 pins the binary, so
  a rebuild of the same upstream version is a new build.
- `canary_vms`: test VMs that may start on a build that is not verified yet. Never list a customer
  VM. Empty outside an upgrade.

The file also holds the keys that the launcher and `vm-ctl.sh` read. The gates read only
`bundles`, `verified` and `canary_vms`, and they ignore every other key. Keep the file at mode
0644, because the launcher reads it as the VM's own user. If the gates cannot read the host file
in full, they refuse every VM on the host.

A refused start counts as a unit failure. The unit tries again every 15 seconds until it has
started 5 times in 15 minutes, and then it stays failed until the next `vm-ctl.sh start`.

## 1. Hold the packages

Unattended upgrades must not change QEMU, the firmware or the kernel between two gates. A held
package is skipped by `apt upgrade` and by unattended-upgrades.

1. See if unattended upgrades run on the host:

   ```sh
   systemctl is-enabled apt-daily-upgrade.timer unattended-upgrades.service
   apt-config dump APT::Periodic::Unattended-Upgrade
   ```

2. List the kernel metapackages that are installed:

   ```sh
   dpkg-query -W -f='${Package}\n' 'linux-generic*' 'linux-image-generic*' 'linux-headers-generic*' 2>/dev/null
   ```

3. Hold QEMU, OVMF, the running kernel and each metapackage from step 2:

   ```sh
   sudo apt-mark hold qemu-system-x86 qemu-system-common qemu-system-data ovmf
   sudo apt-mark hold "linux-image-$(uname -r)" "linux-modules-$(uname -r)" <metapackages from step 2>
   ```

4. Also hold `amd64-microcode` and `linux-firmware`. A microcode or SEV firmware change can change
   the SEV status (`current_tcb`, `build_id`) at the next boot, which refuses every new start until
   a new baseline (section 3).

   ```sh
   sudo apt-mark hold amd64-microcode linux-firmware
   ```

5. Check the result. No held package may appear in the simulated upgrade:

   ```sh
   apt-mark showhold
   apt-get -s dist-upgrade | grep -E '^Inst ' || true
   ```

## 2. Planned QEMU or kernel upgrade

Running VMs keep running on the QEMU binary they started with. A new QEMU binary on disk refuses
every later start with `vm_host_changed`, and that includes a guest reboot, because a reboot is a
relaunch. A new kernel takes effect at the next host boot; after that boot every VM refuses until
the canary of step 4 passes. Plan the upgrade in a window, and tell the customers on the host first.

1. List the bundles and vCPU counts in use on the host:

   ```sh
   sudo grep -h -E "^VM_(BUNDLE|VCPUS)=" /srv/cathedral-vms/*/vm.env | paste - - | sort -u
   ```

2. Release the holds you need, upgrade, and hold again:

   ```sh
   sudo apt-mark unhold qemu-system-x86 qemu-system-common qemu-system-data
   sudo apt-get install --only-upgrade qemu-system-x86 qemu-system-common qemu-system-data
   sudo apt-mark hold qemu-system-x86 qemu-system-common qemu-system-data
   ```

   For a kernel, do the same with the kernel packages, then reboot the host in the window.

3. Read the new build. This runs `qemu-system-x86_64 --version` and hashes the binary; it changes
   nothing:

   ```sh
   sudo room-kit/vm/vm-gates.sh host-build
   ```

4. For each bundle and vCPU count from step 1, run one canary: a test VM that holds no customer data.
   - Add its name to `canary_vms`.
   - Create, authorize and start it.
   - Verify its report from another machine with the VM verifier: the MEASUREMENT must equal the
     `expected_measurement` that `vm-ctl.sh status` gives for it.
   - Stop and delete it.

5. Add the build of step 3 to `verified` for each bundle, with the vCPU counts whose canary passed.
   Remove the canaries from `canary_vms`.

6. Start the VMs that were refused. A refused unit stops after 5 tries in 15 minutes.
   `vm-ctl.sh start` resets the failed state, and it adds no second start line for a run that has
   one:

   ```sh
   sudo room-kit/vm/vm-ctl.sh start <name>
   ```

Keep the entries of the old build while the old package can return. A rollback to the old package
gives the old sha256 back, and that build is already verified.

If a canary fails, do not add the build. Roll the package back, or remove the bundle from
`bundles` on this host. The disks are not touched in either case.

## 3. SEV baseline

The baseline is the output of `sev_status.py read` (the D 5.9 tool, `ops/custom-guest/`). The gates
compare the fields that `sev_status.py` compares: API version, firmware build, the chip ID and chip
key masks, VLEK, current and reported TCB, owner and config flags. Guest count and state are not
compared.

**First baseline.** After the host boots with a platform you have verified (TCB at or above the
floor, D 10.4):

```sh
sudo room-kit/vm/vm-gates.sh baseline
sudo python3 -I ops/custom-guest/sev_status.py compare /var/lib/cathedral-snp/vm-sev-baseline.json
```

`baseline` does not replace a baseline unless you pass `--replace`. A baseline, new or replaced, is
your explicit accept of the current status: it also clears a change that this boot saw, and it arms
the boot again.

**`sev_platform_changed`.** A platform command reached the chip through a writable `/dev/sev`, or
the firmware changed.

1. Running VMs keep running. New starts stay refused for the rest of this boot, even when the status
   changes back.
2. Find the cause: who can write `/dev/sev` (the `cvm-sev` group, VM spec Q10), and the journal of
   `cathedral-vm-enforce.service` (one `vm-gates: sev_platform_changed: <field>: <old> -> <new>`
   line per tick).
3. Reboot the host in a window. After the boot, run `sudo room-kit/vm/vm-gates.sh enforce`.
   - `"sev": "equal"`: start the refused VMs (section 2, step 6).
   - exit 17: the change is persistent, for example a firmware or microcode update. Go to step 4.
     The enforce tick may also report it before you do.
4. Read the status with `sudo python3 -I ops/custom-guest/sev_status.py read`. Verify the new TCB
   against the floor (D 10.4). Make sure the chip key and chip ID masks and VLEK are as you expect.
   Then accept the new status:

   ```sh
   sudo room-kit/vm/vm-gates.sh baseline --replace
   sudo room-kit/vm/vm-gates.sh enforce        # must answer "sev": "equal"
   ```

   Start the refused VMs (section 2, step 6).

Do not take `baseline --replace` to skip the reboot after a change in the middle of a boot. The
replace accepts whatever status the chip reports now.

**Planned firmware or microcode update.** Do it in a window like section 2. After the reboot, do
steps 3 and 4.

## 4. Off

Remove `/etc/cathedral/snp-vm-host.json`. Every launch then refuses (the gates with 11, the
launcher with 78), the enforce compare stops, and no disk is touched. Remove one bundle from
`bundles` to stop only the launches of that bundle.

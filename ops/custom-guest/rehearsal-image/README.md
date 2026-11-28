# Rehearsal test image for the dedicated custom SNP guest (AB#1008)

**REHEARSAL ONLY. Never offered to customers.** This image stands in for the Cathedral test image in rehearsal B (spec-r9 14.3) until the reference PID1 of #776 is complete. It lets the rehearsal run the real operator path (`ops/custom-guest/custom-guest.sh`: fetch, intake, measure, hold, boot, stop, return) instead of a guest staged by hand.

## What it is

- **Kernel:** the #776 reference kernel, built with `scripts/build_custom_guest_kernel.sh` from the pinned `linux-source-7.0.0_7.0.0-44.44_all.deb`. It has IKCONFIG, every needed driver built in, and no module support, so the intake validator (`custom_guest_stage.py`, spec-r9 5.5) accepts it. A distribution kernel that loads `sev-guest`, `tsm_report` or `dm-verity` as modules is refused with `custom_guest_kernel_config_refused`.
- **Initrd:** a busybox `/init` (`init.sh`) that never does `switch_root`. It loads no module. In order:
  1. `cathedral-rehearsal-bootcheck` (`room-kit/custom-guest/testdata/smoke-bootcheck`, outside `./...`, built against #776's `bootstrap.Validate` without changes) checks the three fw_cfg documents, the owner signature, the cmdline owner and the guest-observed CPUs, memory, disks and NIC.
  2. `cathedral-attest --boot-host-data` (#776) checks HOST_DATA in a native report.
  3. It brings up the network from the signed bootstrap.
  4. It runs OpenSSH sshd from RAM with a host key made at boot.

  Any failure powers the guest off.
- **root.raw:** 1 MiB of zeros plus its dm-verity tree, with a fixed salt and uuid. The init never opens it. It exists because the launcher always attaches a root drive, and the cmdline allowlist requires a verity hash and size. Intake runs `veritysetup verify` on it.
- **sit0:** the reference kernel recipe leaves `CONFIG_IPV6_SIT=y` from x86_64_defconfig, so the kernel makes a `sit0` tunnel with no backing device at boot. The rehearsal bootcheck skips only that interface. #776's `internal/bootstate` refuses it today, and the reference image will need either `CONFIG_IPV6_SIT=n` in the recipe or a matching rule there.
- **Not a reference initrd** (spec-r9 5.6). It has no verity `switch_root`, its sshd is dynamic musl, and the closure is not static. It is listed as a reference initrd only in the rehearsal's own configuration (below), never on the site.

## Build and check

```sh
# 1. Reference kernel, on an x86_64 Ubuntu 26.04 host with gcc 15.2.0 and make 4.4.1:
scripts/build_custom_guest_kernel.sh linux-source-7.0.0_7.0.0-44.44_all.deb <empty work dir> <new kernel dir>
# 2. Initrd, root, cmdline and measurements (any Docker host):
CG_OWNER_PUB=<owner public key, 32 raw bytes> ops/custom-guest/rehearsal-image/build.sh <kernel dir> <OVMF.amdsev.fd> <out dir>
# 3. Offline checks with throwaway keys (intake validator, documents, TCG boot, sshd):
ops/custom-guest/rehearsal-image/test-offline.sh <out dir> <OVMF.amdsev.fd> <plain OVMF.fd> <test dir>
```

- `CG_KIT_DIR` and `CG_KIT_MEASUREMENT` add a positive control to step 2. sev-snp-measure 0.0.12 must reproduce a live kit's measurement from that kit's inputs.
- The OVMF is the edk2 2025.11 AmdSev build (sha256 `ac27e626b097cf6f9eae09b79fc87fc2d3fb6e99c8d97b27f0603993c06a28bb`), the file the operator's measure phase copies from the host.

## Build of 27 Nov 2026

Two kernel builds gave identical bytes. Two image builds, one from each kernel build, gave identical bytes too.

| File | sha256 |
|---|---|
| `vmlinuz` (reference kernel, 9605632 bytes) | `667fda47b31d66625d48250fe5b183a6c1649f864419c31050e97fe137e76b54` |
| `kernel.config` | `c5d2c0d1b2364b4e66c6b165aa9a5e0eca8afa65a41dc796cc8c08fbd5f4605f` |
| `initrd.cpio.zst` | `45ad5f1053d2622269d74ff6ce83035a67eda8fdf304d140c51683a804c33daf` |
| `root.raw` | `0be4012bce6fd4460b706171df4f522ec8985f956d02e30c0053519a4004c59e` |
| `cmdline` (test owner key) | `420641757c8120da7993f3e837fc6c942f6ed600ae29c39010dec273f441c071` |

- **Expected measurement, 4 vCPUs, EPYC-v4:** `1a796519af57485fb466f93399231c8099d20325e62ac6ea01beab12a8ea5068f80beac016d8f8780e9af64aab9225fa`.
- **56 vCPUs:** `0fb99d7606c3ab4b6223b4e12d3877b47716ebcf5887e50a79eea7a290710a1c81c55d02f8fd5370fba1bb55324b33b5`.
- The cmdline carries the rehearsal's test owner public key. A different owner key gives a different cmdline and a different measurement.

## Using it in a rehearsal

The operator's configuration declares it, and only for the rehearsal:
- `test-image.json` in `CG_HOME`: `kernel_sha256`, `initrd_sha256` and `root_sha256` above. The 4.1 intake gate then treats it as the Cathedral test image.
- `inputs.json` in `CG_HOME`, and the API's `CATHEDRAL_CUSTOM_GUEST_REFERENCE_INITRDS`: `{"rehearsal-test-v1": "<initrd sha256>"}`.
- The request names `"initrd": {"reference": "rehearsal-test-v1", ...}`.

Remove both entries when the rehearsal ends.

## Stock-systemd root (run 7b)

**REHEARSAL ONLY.** A second root for the reference initrd v2 test image, so a rehearsal can show v2 handing off to a root where dbus and systemd-networkd are active. The v1 root (`e674d5a5`, runs 6 and 7) has no dbus and masks networkd, so it cannot show either.

- **Build:** `build-ref-root.sh <cathedral-attest> <out dir> stock-systemd`. This is v1's snapshot, InRelease pin and epochs, plus `dbus` and `udev` in the base, through `stock_systemd.py`. That is the reference recipe with its `customize` hook; the recipe itself passes no hook.
- **What `customize()` changes:**
  - networkd's service and socket are unmasked and enabled;
  - `cathedral-network.service` runs `/usr/lib/cathedral/write-network`, which writes `/run/systemd/network/10-cathedral.network` from `network.env` at boot. A networkd drop-in orders networkd after it;
  - `99-default.link` is masked;
  - dbus.socket and udev's sockets and coldplug trigger are enabled where the packages did not;
  - `/var/lib/systemd/linger` ships empty.
- **Kept byte for byte:** cathedral-attest, the sshd config and unit, and every other mask.
- **Checks in `.github/workflows/rehearsal-ref-root.yml`:**
  - `check_stock_root.py` passes on this root, and fails on v1 on dbus and networkd;
  - both lanes are byte-identical;
  - `boot-smoke.sh` boots it under QEMU (no SNP) behind a shim that hands off as v2 does. Over SSH, dbus, udevd, networkd and cathedral-sshd must be active, eth0 routable (configured), and the system running with no failed unit.
- **The workflow artifact** is `rehearsal-ref-root-stock-systemd`.

| File | Value |
|---|---|
| `base.tar` | `0a5b09478e1c9d87a4184f9bef481de127bcbffda5fc49aff8b09823f2f7ca67` |
| `root.raw` | `2d33e12e031a9a6b203cdea0199d33cb739c547a9d8983dbf9dfe7a73c9d2dbc` |
| `root_verity` | `897cbbd1ec7ce1f88d27bb9c110e01915b6471741f78978cce750b2b5e17c582` |
| `root_data_bytes` | `76357632` |

A launch with this root has its own cmdline (`cathedral.root_verity`, `cathedral.root_data_bytes`) and so its own measurement. Compute it from these files, as for v1.

### Root requirements found

These hold for any owner root under reference initrd v2, not only this one:

- **(a) A root that uses systemd-networkd needs udev, or eth0 stays pending.** v2 hands the root a read-write /sys, and then systemd's networkd waits for udev to initialize each link (systemd v252 `udev_available()`). udev's coldplug trigger must run too: the NIC exists before udevd starts.
- **(b) With udev present, configs must not assume eth0 unless `99-default.link` is masked.** udev's default policy renames interfaces, and `network.env` names the one the initrd saw.
- **(c) On a read-only root, every enabled unit's `StateDirectory=` must ship in the image.** systemd cannot create it at boot. Once dbus is installed, bookworm's systemd-logind fails with 238/STATE_DIRECTORY without `/var/lib/systemd/linger`.

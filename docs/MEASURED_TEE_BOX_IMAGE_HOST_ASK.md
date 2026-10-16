# Measured tee-box image — what we need on the SNP host

**Status 2026-10-09:** **FULFILLED** on Cherry — official `:2225` /
dev `:2224` measured images up (see `TEE_BOX_SNP_E2E_RESULTS.md`). Kept as
the historical ask + inventory.

**Why (original):** Phase A (HOST_DATA stamp + #275 gate) was **PASS** on
`84.32.220.48` while the guest was still **stock Ubuntu cloudimg** with
`central-root-keys.json` copied in after boot.

Related: `CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md`, `TEE_BOX_SNP_E2E_RESULTS.md`,
`TEE_BOX_SERVICE.md` (“Our own measured image”).

---

## What “measured image” means here

| Layer | Today (stock guest) | Needed for image-owner close |
| --- | --- | --- |
| HOST_DATA | Official digest stamped at QEMU launch | Keep (already PASS) |
| Root file | Installed at `/usr/share/cathedral/central-root-keys.json` | **Baked into the disk image** at build time (same bytes / same sha256) |
| Guest contents | Generic Ubuntu 26.04 cloudimg | Locked appliance: tee-box stack + root file (+ ideally dm-verity later) |
| SNP `MEASUREMENT` | Whatever this OVMF+disk+launch produced | Stable, recomputable; published on measurement-list with `host_data` |
| Image owner seat | TBD | Named person approves image id + list entry |

HOST_DATA proves **which root** was bound at launch.  
MEASUREMENT proves **which firmware/disk/boot config** launched.  
Both are required for honest sealed language; only HOST_DATA is green today.

---

## Paste-ready ask (ops / launch host)

```text
We need to build and boot a Cathedral tee-box SNP guest image on
84.32.220.48 so the image-owner row can close for #274.

Already true on this host (do not redo):
- Official root file sha256 551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e
- launch-snp-guest.sh stamps HOST_DATA from that file (Inject=NO)
- Phase A / #275 gate PASS on current stock guest

Please provide or confirm on the host:

1) Build workspace under /root/snp-launch/tee-box-image/ (or say the path).
2) Install build helpers if missing:
   - libguestfs-tools (virt-customize) OR approve our cloud-init first-boot bake
   - python3-pip + sev-snp-measure (for expected MEASUREMENT)
   - enough free disk (need ~20–40G for build artifacts; host has ~820G free)
3) Keep available: QEMU 10.x, OVMF (/usr/share/ovmf/OVMF.fd), cloud-localds,
   official central-root-keys.json, launch-snp-guest.sh
4) Name the Image owner (approves image id + measurement-list entry).
5) Allow one reboot window: stop current snp-guest, boot new qcow2 with the
   SAME host-data as today, leave SSH on 2222.

We will bake into the image at least:
- /usr/share/cathedral/central-root-keys.json (exact official bytes)
- snpguest 0.10.0
- cathedral-sandbox @ feat/tee-box-snp-startup-gates tip
- cryptsetup, and runsc (systrap) when the image-owner accepts that pin
- cloud-init disabled for mutable package drift after first boot (freeze)

Deliverables back to #274:
- image id + qcow2 sha256 + OVMF path/version
- sev-snp-measure expected MEASUREMENT hex
- live report MEASUREMENT + HOST_DATA after boot
- draft measurement-list image object:
  {"id":"…","measurement":"<96 hex>","host_data":"551df92e…71c9885e"}
```

---

## Host inventory (2026-10-08)

| Item | Status on `84.32.220.48` |
| --- | --- |
| QEMU / OVMF / cloud-localds | Present |
| `launch-snp-guest.sh` + official root json | Present |
| Free disk / RAM | ~820G / ~50G free — enough |
| libguestfs / virt-customize | **Missing** |
| sev-snp-measure | **Missing** (need install) |
| Guest runsc / docker | **Missing** on stock guest |
| Guest snpguest + cryptsetup + root file | Present |

---

## Build sequence (once host ask is granted)

1. Copy official `central-root-keys.json` into image build context (public file only).
2. Clone `guest-dryrun.qcow2` or rebuild from Ubuntu cloudimg + bake script.
3. Install tee-box package set; freeze; record package digests.
4. `sev-snp-measure` with the same OVMF, vCPU type (`EPYC-v4`), and launch
   shape as `launch-snp-guest.sh`.
5. Boot with existing script (same HOST_DATA).
6. Confirm: file digest == HOST_DATA; report MEASUREMENT == expected; #275 gate PASS.
7. Image owner publishes measurement-list entry; fill seat name in
   `CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md`.

**Out of scope for this ask:** dm-verity root (design follow-on), full B–F
harness day (optional next), miner private/custody path.

---

## Optional item 2 — SNP e2e without `E2E_HOST_DATA_HEX`

Can run on **this** host after the measured image boots (or, weaker, on the
current stamped stock guest for tee-box software checks only).

- Use `scripts/tee_box_snp_e2e/` + port of `tee_box_tdx_e2e` with `--tee snp`.
- Never set `E2E_HOST_DATA_HEX` / `read_binding` override.
- Record PASS/FAIL/BLOCKED in `TEE_BOX_SNP_E2E_RESULTS.md`.
- B.d stays **BLOCKED** (no RTMR3-class register) unless leadership accepts
  the written software-lease substitute.

Prefer: **measured image first**, then e2e on that image — otherwise e2e
proves software on stock Ubuntu, not the sealed appliance measurement.

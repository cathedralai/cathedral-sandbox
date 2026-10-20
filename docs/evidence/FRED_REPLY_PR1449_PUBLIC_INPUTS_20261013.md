# Discord reply → Fred (public inputs only) — draft

Copy/paste to Fred on the review channel. **No secrets.**

---

@wallscaler pulled https://github.com/bigailabs/polariscomputer/pull/1449 (`fix/toby-snp-staging-20261013` @ `30769ea2`). Compared against our installed 66deb72e scaffold; taking the three later deltas + official `cathedral_snp_startup` / `CATHEDRAL_SNP_STARTUP_FILE` path. Our parallel `cathedral_snp_staging_install` helper stays fail-closed and is skipped when the official startup file is set (no second install).

**Corrected image recorded (not booted):** raw `ef0ab84e…95689`, HOST_DATA_B64 `VR35Ls6k4fpnvRDD0rCX13XEvq+LaOxOAF/2bXHJiF4=`, stem `…/images-rootfix/cathedral-staging-snp-rootfix-20261013`. Still treating as UNQUALIFIED_CORRECTED_IMAGE_CANDIDATE. `a7ad573b` remains blocked. Boot script still refuses without policy accept + exact APPEND/roothash.

### 1) Isolated API caller (public only)
- Ed25519 pubkey hex: `3c44952eb0f9f083976691809073357e1d9cd1a18326cbaacfefd08a7f07ecc7`
- Ed25519 pubkey b64: `PESVLrD58IOXZpGAkHM1fh2c0aGDJsuqz+/Qin8H7Mc=`
- pubkey sha256: `89e9d66128db2e39e25a562e2ab8e37ecff4965f26b3a650c982222434f979e7`
- caller_id: `central:3c44952eb0f9f083976691809073357e1d9cd1a18326cbaacfefd08a7f07ecc7`
- isolated API origin: current bore URL in `/tmp/cathedral-snp-staging-url.txt` (ephemeral; re-publish if dropped) — not Railway `acaa2961`
- network/netuid: `finney` / `94`
- customer scope for pilot: deny-all, lifetime 180s, max_spend_usd `1`
- seed retained only on my side (not transmitted)

Please sign the 900s grant to **this** caller (8 scopes as approved). Railway caller pubkey is not a substitute.

### 2) Launch source / public inputs
- Launch draft: `polariscomputer/scripts/snp_staging/boot_new_guest.sh` (dry-run; `--execute` gated)
- Ports: SSH `:2226`, HTTPS `:8444` (will verify free before execute)
- Firmware/kernel/initrd/raw: Fred’s rootfix artifact set above; expected raw SHA pinned in boot script
- HOST_DATA: as published (`VR35Ls6k4fpnvRDD0rCX13XEvq+LaOxOAF/2bXHJiF4=`)
- Still need from image/policy owner: **exact APPEND including verity roothash**, signed policy/measurement accept, verifier pins/checkpoint
- No merge/deploy/boot/signing from my side until those + grant lands

Startup JSON will follow `polariscomputer/docs/SNP_STAGING_STARTUP.md` once TLS pin + binding + policy + journal/observer pubs are filled.

---

# Discord → Fred (copy/paste as a normal message)

@wallscaler Re: https://github.com/bigailabs/polariscomputer/pull/1449 (`fix/toby-snp-staging-20261013` @ `30769ea2`)

Saw the 18:04 recipe / `launch-inputs-public.json` note — answering the public caller + launch-source request below. APPEND/roothash + policy accept are still outstanding on my side.

Pulled and compared against our installed `66deb72e` scaffold. Taking the three later deltas + official `cathedral_snp_startup` / `CATHEDRAL_SNP_STARTUP_FILE`. Our parallel install helper stays fail-closed and is skipped when that startup file is set (no second hook).

**Corrected image recorded, not booted** — still `UNQUALIFIED_CORRECTED_IMAGE_CANDIDATE`:
- raw SHA256 `ef0ab84e57dd6e4c38fec60ee0c06e297cb963afbb47206277eacd6742a95689`
- HOST_DATA_B64 `VR35Ls6k4fpnvRDD0rCX13XEvq+LaOxOAF/2bXHJiF4=`
- stem `/root/snp-launch/cathedral-staging-20261013/images-rootfix/cathedral-staging-snp-rootfix-20261013`
- `a7ad573b` remains blocked
- boot draft still refuses without policy accept + exact APPEND/roothash

**1) Isolated API caller (public only — seed stays with me)**
- Ed25519 pubkey hex: `3c44952eb0f9f083976691809073357e1d9cd1a18326cbaacfefd08a7f07ecc7`
- Ed25519 pubkey b64: `PESVLrD58IOXZpGAkHM1fh2c0aGDJsuqz+/Qin8H7Mc=`
- pubkey sha256: `89e9d66128db2e39e25a562e2ab8e37ecff4965f26b3a650c982222434f979e7`
- caller_id: `central:3c44952eb0f9f083976691809073357e1d9cd1a18326cbaacfefd08a7f07ecc7`
- isolated API origin: `http://bore.pub:53871` (ephemeral bore; not Railway `acaa2961`)
- network / netuid: `finney` / `94`
- pilot customer scope: deny-all, lifetime 180s, max_spend_usd `1`

Please sign the 900s grant to **this** caller (8 scopes as approved). Railway caller pubkey is not a substitute.

**2) Launch source / public inputs**
- Launch draft: `polariscomputer/scripts/snp_staging/boot_new_guest.sh` (dry-run only; `--execute` gated)
- Ports: SSH `:2226`, HTTPS `:8444` (will verify free before execute)
- Firmware/kernel/initrd/raw + HOST_DATA: as published above / pinned in boot script
- Still need from image/policy owner: **exact APPEND including verity roothash**, signed policy/measurement accept, verifier pins/checkpoint
- No merge / deploy / boot / signing from my side until those + grant land

Startup JSON will follow `docs/SNP_STAGING_STARTUP.md` once TLS pin + binding + policy + journal/observer pubs are filled.

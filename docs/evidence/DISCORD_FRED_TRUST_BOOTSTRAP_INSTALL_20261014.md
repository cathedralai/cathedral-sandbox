# Discord → Fred (exact trust-bootstrap install + diagnostic report)

@wallscaler Installed the **exact** approved public trust map per [#1449 comment 6155409032](https://github.com/bigailabs/polariscomputer/pull/1449#issuecomment-6155409032) / Sentinel `Sentinel_edf2b0ac71bc8191b1057c1b38813275`. Observer setup not repeated. No competing trust set. No image rebuild. Diagnostic launch **not** repeated — reporting the existing attempt only.

**#5 — Trusted-keys install (exact bytes)**
- Path: `/Users/user/.cathedral-snp-staging-qualification/image-policy-staging-20261013/trusted-policy-public-keys.json`
- Fresh dir `0700`, file `0600`, UID **501**, no symlink components
- Created with `O_EXCL` (no overwrite)
- Contents (79 bytes = compact UTF-8 JSON + one `0x0a` LF):
  `{"snp-staging-policy-20261014":"Xo4QRPomjFg1j4fcd0WYRSSx+3JoJfDJJcfxtcLEWDg="}\n`
- **Installed whole-file SHA256:** `9e325878406ba2748b5ebd851b475dc0f3730610eb9bb38e10561679ddbd7d65`
- Verifier pin: `sha256:9e325878406ba2748b5ebd851b475dc0f3730610eb9bb38e10561679ddbd7d65`
- Raw pubkey fingerprint (unchanged): `c3533129d8e45a73f6104ba048da35138b53f5cda8910abd3c69c8725b0b3b3f`
- Private key stays with me
- Note: an earlier draft at `…/policy_trusted_keys.json` (78 bytes, no LF, hash `13c30032…`) is **not** the authorized target; authorized file is the path/hash above only

**Diagnostic boot report (existing attempt — no relaunch)**
- Auth: [diagnostic authorization](https://github.com/bigailabs/polariscomputer/pull/1449#issuecomment-6155090014)
- Launcher SHA `64eed232bff47bb08b6a43ba880493898545e6bed18ef7195aa2fd51cd9a4bdf` @ `/root/snp-launch/cathedral-staging-20261013/launch_diagnostic_20261013.py`
- Preflight: existing guest fences matched; image/HOST_DATA/APPEND pins matched; launch exit **0** (not a refusal/early exit)
- Unit `cathedral-staging-guest-20261013.service` started **2026-10-13 21:06:00 UTC**
- MainPID **398611**; start_ticks **44574001**; argv_sha256 `e47dab276f8c38c0a26652480c93e9d2777f139c6436bd310001a92754d6bc2c`
- Inputs: raw `8296f243…`, APPEND `roothash=5607dede… console=ttyS0 systemd.volatile=overlay rw panic=-1`, HOST_DATA `VR35Ls6k…`, nic none / no hostfwd
- Console (~15s): reached `Ubuntu 26.04.1 LTS` / `localhost login:` — **process/console evidence only; not SNP attestation / not customer acceptance**
- Cleanup: stopped only that unit → inactive/dead; new guest gone
- Prior 3 guests preserved: snp-guest/6712, tee-box-dev/63141, tee-box-official/73539 (same pid/startticks/argv hashes)
- Evidence: `docs/evidence/diagnostic-boot-result.json`, `diagnostic-dispatch-result.json`, `DIAGNOSTIC_BOOT_REPORT_20261013.md`

**Board reconcile (your notes)**
- **#4** still blocked on 🤖 admission timeout fix → new customer image (#1452+) → native qualification → then sign (not diagnostic raw)
- **#5** key install done (this message); signed policy/checkpoint still waits on #4
- **#6** grant waits on #4/#5 + HTTPS; root signature not issued yet
- **#13** full customer test not started; waits on #4–#6

Will not qualify/relabel diagnostic `8296f243` as customer image.

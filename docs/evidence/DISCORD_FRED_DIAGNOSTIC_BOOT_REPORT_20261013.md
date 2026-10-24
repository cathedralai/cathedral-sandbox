# Discord → Fred (diagnostic boot + cleanup report)

@wallscaler Diagnostic boot under your approval is complete. Cleanup done. Existing guests untouched.

**Boot**
- Used hash-checked launcher `64eed232…` at `/root/snp-launch/cathedral-staging-20261013/launch_diagnostic_20261013.py` + launch-inputs v2
- Owner command with `CATHEDRAL_APPROVED_DIAGNOSTIC_BOOT_20261013=approved` → exit 0
- Unit `cathedral-staging-guest-20261013.service` active; MainPID **398611**; start_ticks **44574001**; argv_sha256 `e47dab276f8c38c0a26652480c93e9d2777f139c6436bd310001a92754d6bc2c`
- Budget: 4 vCPU / 8 GiB guest, 10 GiB host-process cap; **nic none / no hostfwd**
- `protected_guests_preserved: true` (pre + post)
- Serial (~15s): guest reached `Ubuntu 26.04.1 LTS` / `localhost login:` — console progress only; **not** an SNP attestation claim

**Cleanup**
- Stopped only `cathedral-staging-guest-20261013.service` → inactive/dead, MainPID 0
- New guest gone; qemu count back to **3**
- Existing fences unchanged: snp-guest/6712, tee-box-dev/63141, tee-box-official/73539

**Staging policy-signing key**
- Confirm: I do **not** have a staging policy-signing public key / key ID yet. No private key to retain for that seat. Customer qualification + policy acceptance still outstanding on your/Astra/Sky track.

Evidence: `docs/evidence/diagnostic-boot-result.json`, `diagnostic-dispatch-result.json`, `DIAGNOSTIC_BOOT_REPORT_20261013.md`.

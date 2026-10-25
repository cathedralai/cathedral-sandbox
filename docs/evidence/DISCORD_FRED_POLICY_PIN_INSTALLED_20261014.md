# Discord → Fred (policy pin installed + boot report resend)

@wallscaler Staging/pilot policy key installed. Observer setup not repeated. PR #1452 noted (customer storage/image-import; admission still finishing) — no wait on Sky.

**Trusted-keys install (exact approved pin)**
- `signing_key_id`: `snp-staging-policy-20261014`
- pubkey b64: `Xo4QRPomjFg1j4fcd0WYRSSx+3JoJfDJJcfxtcLEWDg=`
- pubkey sha256 fingerprint: `c3533129d8e45a73f6104ba048da35138b53f5cda8910abd3c69c8725b0b3b3f`
- installed file: `/Users/user/.cathedral-snp-staging-qualification/policy_trusted_keys.json`
- mode `0600`, parent dir `0700`
- contents: `{"snp-staging-policy-20261014":"Xo4QRPomjFg1j4fcd0WYRSSx+3JoJfDJJcfxtcLEWDg="}`
- **installed public-file SHA256:** `13c30032de720a564a8b7ceb30e9560e2c1a8ac74c96df170a70e0bdad3b9ec4`
- private key remains with me; staging-only per your approval

**Diagnostic boot report (resend for reconcile — your exact approved launch)**
- Launcher SHA `64eed232bff47bb08b6a43ba880493898545e6bed18ef7195aa2fd51cd9a4bdf` at `/root/snp-launch/cathedral-staging-20261013/launch_diagnostic_20261013.py`
- Owner command + `CATHEDRAL_APPROVED_DIAGNOSTIC_BOOT_20261013=approved` → exit 0
- Unit `cathedral-staging-guest-20261013.service`; MainPID **398611**; start_ticks **44574001**; argv_sha256 `e47dab276f8c38c0a26652480c93e9d2777f139c6436bd310001a92754d6bc2c`
- 4 vCPU / 8 GiB guest, 10 GiB host-process cap; nic none / no hostfwd
- `protected_guests_preserved: true`
- Serial (~15s): reached `Ubuntu 26.04.1 LTS` / `localhost login:` (console only; not SNP attestation)
- Cleanup: stopped only that unit → inactive/dead; new guest gone; existing 3 fences unchanged (6712 / 63141 / 73539)

Still outstanding on your side for customer path: signed customer policy/checkpoint + fresh grant after HTTPS; new measured customer image incorporating #1452 (+ admission).

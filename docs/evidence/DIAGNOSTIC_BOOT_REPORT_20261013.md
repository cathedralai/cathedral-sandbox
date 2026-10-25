# Diagnostic boot report — 2026-10-13

Fred owner approval: one new guest, 4 vCPU / 8 GiB, 10 GiB host-process cap, ~15 min, no network/ports. Reviewed launcher hash-checked.

## Result: SUCCESS (process-start + console boot progress) + CLEANED UP

| Item | Value |
|---|---|
| Launcher SHA256 | `64eed232bff47bb08b6a43ba880493898545e6bed18ef7195aa2fd51cd9a4bdf` |
| Host path | `/root/snp-launch/cathedral-staging-20261013/launch_diagnostic_20261013.py` |
| Unit | `cathedral-staging-guest-20261013.service` |
| Guest name | `cathedral-staging-snp-20261013` |
| Dispatch UTC | 2026-10-13 21:06:00 UTC |
| MainPID | `398611` |
| start_ticks | `44574001` |
| argv_sha256 | `e47dab276f8c38c0a26652480c93e9d2777f139c6436bd310001a92754d6bc2c` |
| protected_guests_preserved | **true** (pre/post/cleanup) |
| Network | nic none / no hostfwd |
| Serial (~15s) | guest reached `Ubuntu 26.04.1 LTS` / `localhost login:` (console progress; **not** SNP attestation) |
| Cleanup | `systemctl stop` new unit only → inactive/dead; new guest gone; existing 3 fences unchanged |

## Existing guests (unchanged)

| name | pid | start_ticks | cmdline sha |
|---|---:|---:|---|
| snp-guest | 6712 | 46424 | `48ad40b4…` |
| tee-box-dev | 63141 | 4552067 | `1651c97e…` |
| tee-box-official | 73539 | 4620243 | `db06ce97…` |

## Artifacts
- `diagnostic-boot-result.json` — launcher stdout process_proof
- `diagnostic-dispatch-result.json` — host run dir
- `diagnostic-launch-request.json` — durable request

## Explicit non-claims
No SNP report, expected measurement compare, guest HTTPS endpoint, customer allocation, policy accept, or central grant. Customer qualification still outstanding.

## Staging policy-signing key
**None.** No Toby staging policy-signing public key / key ID for SN94 registry. Private key N/A (not minted). Image-owner policy authority remains separate (`@skyrocket2026` historical seat).

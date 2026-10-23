# #313 triage — before subnet e2e — 2026-10-23

Source: [cathedral-sandbox#313](https://github.com/cathedralai/cathedral-sandbox/issues/313) (26 pending design/owner items).

## Blocks or risks subnet e2e (G1–G4 / live broker) — fix or explicitly waive before claiming pass

| ID | Why it matters for e2e |
| --- | --- |
| **B53** | One guest’s long execs can starve shared-hotel broker connections — G4 multi-create / concurrent clients |
| **B70** | Affine sealed lane dormant — G5 Affine sealed path cannot pass; docker pilot is the only Affine route |
| **B16** | Fork of `deny_all` gets internet unless network reset — G4 allowlist/deny claims |
| **B7** | Harbor path ignores hotel choice — CONST / Harbor placement honesty |
| **B42** | Image builds not under room network policy — G4 build-under-gVisor / egress claims |
| **B47** / **B128** | Sealed hotel key on host + plain HTTP tap / scratch XTS — sealed trust story for G2 `--require-sealed` |

## Can wait (design / low / observe) — do not block starting e2e

B21, B22, B26, B30, B51, B76 (receipts lifecycle / verifier pins), B40 (disk_gib enforce), B41 (timeout binary), B44 (bg process children), B112 (build memory cap), B116/B117 (DNS/egress socket), B19 (narrow hotel list leftover rooms), B24 phase 2 (API restart room memory), B27 (wrong hotel key UX), B55/B100 (bg exec prune / broker memory), B61 (reproducible sealed image), B77 (receipts front as root), B86 (bash→sh rewrite), B129 (second service on broker host).

## Eng note

None of these are “flip pay” or “merge #312” blockers. For a staging-first runway, waive B70 for sealed Affine and keep docker-pilot Affine as the G5 path until hosts recover.

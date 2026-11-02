# #274 honesty close — draft for leadership (paste-ready)

Status: **draft (updated 2026-10-12)**. Measured SNP `:2225` Phase A + B
clearout + `serve-snp` worker smoke **PASS** (live HOST_DATA, no inject).
Central-access Path A: **B.b + B.e PASS**; **B.f / B.g PARTIAL** pending Fred
signing batch for f.2 + g least-privilege/revoke. Remaining rows are honest
SKIP / BLOCKED / PARTIAL — not silent gaps. **PARTIAL ≠ full security pass.**

## Ask

Accept the following for this bolt so #274 measured-image + worker-startup can
close without waiting on every parallel track:

| Item | Verdict | Why |
| --- | --- | --- |
| B.b revocation | **PASS** | Fred-signed empty list pushed; `fresh=true` |
| B.e egress | **PASS** | Internet sandbox probes on measured box |
| B.f one-customer | **PARTIAL** | Same-key path PASS; f.2 needs 2nd Fred central key (batch ready) |
| B.g scope / revoke | **PARTIAL** | Wrong-route 401 PASS; box-only + revoke sibling in Fred batch |
| B.d fresh-boot HW | **BLOCKED** | SNP has no RTMR3-class register |
| C receipts | **BLOCKED** | Polaris/prober follow-on |
| D fork density | **SKIP** | `TEE_BOX.md` decision 5 — no snapshot/fork in v1 |
| E customer formats | **BLOCKED** | Spec not agreed |
| measurement-list | **DRAFT filled** | MEASUREMENT live; **@skyrocket2026** publishes |
| panic-on-corruption | **HOLD** | After list publish |

## Evidence

- `docs/TEE_BOX_SNP_E2E_RESULTS.md`
- `docs/evidence/snp-bf-report-*.json`, `snp-bf-efg-20261011T1414Z.json`
- `docs/evidence/fred-signing-batch-bf-fg-20261012.md` (ready for Fred)
- Measurement-list draft (96-hex MEASUREMENT filled)
- Branch: `feat/tee-box-snp-startup-gates` (rebased on main after #253)

## Not asking

- Do not treat HOST_DATA inject as sealed PASS
- Do not enable job-pay / weights / capacity broker
- Do not overwrite measured `central-root-keys.json`
- Do not treat PARTIAL f/g as a full security pass

## Discord paste

```text
#274 honesty close ask (updated)

Measured :2225: A + B clearout + serve-snp PASS (live HOST_DATA).
B.b + B.e PASS with Fred central-access. B.f/g PARTIAL — signing batch
ready for Fred (2nd key + box-only + revoke); not claiming full pass.

Please accept for this bolt:
- B.d BLOCKED (no RTMR3-class HW on SNP)
- C BLOCKED (Polaris/prober follow-on)
- D SKIP (v1 no fork)
- E BLOCKED (formats TBD)
- f.2/g PARTIAL until Fred returns batch (or accept PARTIAL)
- measurement-list: draft filled → skyrocket publishes
- panic-on-corruption: HOLD

Not claiming job-pay; measured roots unchanged.
```

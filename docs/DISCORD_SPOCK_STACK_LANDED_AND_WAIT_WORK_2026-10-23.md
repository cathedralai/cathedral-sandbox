Mr Spock — while we wait on Fred’s staging policy renew:

**cathedral-sandbox stack on main (no Polaris staging bake needed for these):**
- #310 merged `dca1da39` (customer feedback; already was live on thin-broker)
- #311 merged `a71cc715` (rounds 1–5)
- #312 merged `1363af4d` (round 6)

Those are broker/hotel/room-kit. They do **not** change `api-staging` tip `bd8272aa` / `95b8061f…`. Sealed staging smokes still need the **measurement-list policy** past `valid_until` (expired 13:26Z today).

**Eng wait work landed:**
- Retest harness ready: `scripts/staging_sealed_retest_after_policy.sh` (roster → waiting offer → Join+IDE+ditto+reliquary → evidence)
- #1504 stubs: `docs/evidence/TRR_G1_*` … `TRR_G4_*_TEMPLATE.md`
- #313 comment: e2e-risk waive vs fix for #1504
- Live CONST Harbor non-sealed smoke on nc/c46 (evidence file when run)

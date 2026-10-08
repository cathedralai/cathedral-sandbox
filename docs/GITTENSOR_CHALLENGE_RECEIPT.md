# Gittensor challenge receipt — sandbox ownership (#276)

Polaris owns `POST/GET /v1/challenges/runs` and JobIntent `gittensor_challenge`
(CVMHost / Sealed). This repo owns the **workload receipt schema** and verifier
release that customers and Entrians use to check sealed challenge results.

## Contract (additive)

- Receipt binds: challenge_id, image digest / root, REPORT_DATA (or TDX equivalent),
  run_id, and Cathedral customer signing key (existing #266 path).
- Polaris **admits** capacity; sandbox evidence **proves** work. Admit ≠ pay.
- Does **not** change Affline SAT miner lifecycle receipts or tee-box HOST_DATA
  launch gates (#274).

## Status

Schema decision tracked in sandbox #276. Until that ships, Polaris challenge
create returns `detail.receipt=null` even when the challenges flag is on.

## Related

- polaris #1446 — challenges API / packs
- polaris `docs/GITTENSOR_CHALLENGE_PATH.md`
- sandbox #270 — workload receipts launch lane

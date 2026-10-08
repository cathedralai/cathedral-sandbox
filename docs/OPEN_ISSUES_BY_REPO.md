# Open GitHub issues — Cathedral workspace repos

**Generated:** 2026-10-08

Open issues only, by repository (from `gh issue list`).

**Total open issues:** 100

| Repo | Open |
| --- | ---: |
| `cathedralai/cathedral-sandbox` | 6 |
| `cathedralai/cathedral-validator` | 5 |
| `bigailabs/polariscomputer` | 71 |
| `cathedralai/cathedral-site` | 18 |
| `cathedralai/cathedral-audit` | 0 |

## `cathedralai/cathedral-sandbox` — 6 open

### #269 — Launch 1/4: Sealed customer execution and private-input admission

- **URL:** https://github.com/cathedralai/cathedral-sandbox/issues/269
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-05T18:05:08Z
- **Updated:** 2026-10-05T18:05:08Z
- **Description:** One supported customer API/provider path runs multiple isolated sandboxes on one customer-exclusive confidential machine. Preserve customer-sandbox-mvp as the preferred service baseline; integrate, do not overwrite it with the older tee-box executor. Integration owner: Cathedral coordinating agent (GitHub tracking owner: @wallscaler). Implementation stays with the relevant runtime, attestation, miner or validator owner; this issue is the single acceptance ledger for this lane.

### #270 — Launch 2/4: Workload receipts, verifier releases and qualified hardware

- **URL:** https://github.com/cathedralai/cathedral-sandbox/issues/270
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-05T18:05:09Z
- **Updated:** 2026-10-05T18:05:09Z
- **Description:** Customers and validators can independently check truthful receipts bound to the exact approved work, runtime and signing key, using a reproducible supported verifier. Integration owner: Cathedral coordinating agent (GitHub tracking owner: @wallscaler). Implementation stays with the relevant runtime, attestation, miner or validator owner; this issue is the single acceptance ledger for this lane. - [ ] Retain #266 trusted Ed25519 key validation while integrating the #198/#199 evidence libraries...

### #271 — Launch 3/4: Supported miner release, durable admission and one intake ledger

- **URL:** https://github.com/cathedralai/cathedral-sandbox/issues/271
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-05T18:05:10Z
- **Updated:** 2026-10-05T18:05:10Z
- **Description:** Operators have one compatible miner/config/update release, admission stays fresh without a laptop loop, and applicant follow-ups are not scattered across engineering issues. Integration owner: Cathedral coordinating agent (GitHub tracking owner: @wallscaler). Implementation stays with the relevant runtime, attestation, miner or validator owner; this issue is the single acceptance ledger for this lane. - [ ] Ship the explicit network/netuid/runtime-contract configuration from #216 with matchin...

### #272 — Launch 4/4: Customer conformance, capacity, cost and cleanup proof

- **URL:** https://github.com/cathedralai/cathedral-sandbox/issues/272
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-05T18:05:12Z
- **Updated:** 2026-10-05T18:05:12Z
- **Description:** The actual deployed customer path passes the same named workload checks with measured capacity, attributable cost and no leftovers; a clean repository or HTTP 200 is not customer qualification. Integration owner: Cathedral coordinating agent (GitHub tracking owner: @wallscaler). Implementation stays with the relevant runtime, attestation, miner or validator owner; this issue is the single acceptance ledger for this lane. - [ ] Retain the public-API conformance driver and add the chosen bare-r...

### #274 — T12: one full-stack acceptance run on SEV-SNP (tee box, sealed, receipts, fork) on our own guests

- **URL:** https://github.com/cathedralai/cathedral-sandbox/issues/274
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-06T10:59:38Z
- **Updated:** 2026-10-07T10:38:25Z
- **Description:** Owner: Toby. Requested by Fred 2026-10-06: the test should cover everything, Toby's tee box layer plus sealed hardware plus receipts, on machines we control. Why now - Two SEV-SNP guests are ours to use: `cathedral-1` 167.150.153.211 and `cathedral-2` 167.150.153.212 (AMD EPYC 7763 Milan, 8 vCPU, 30 GB, 96 GB, kernel 6.8.0-146, `/dev/sev-guest`, no `/dev/kvm`). User `toby` with sudo on both; 22 (rate-limited, key-only) and 8081 open to all. - Both guests share one host, so they share a CHIP_I...

### #276 — Receipt format for challenge runs: one format or a new kind?

- **URL:** https://github.com/cathedralai/cathedral-sandbox/issues/276
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-07T23:28:30Z
- **Updated:** 2026-10-07T23:31:34Z
- **Description:** Question for @bateesatobi Gittensor (SN74) optimization challenges need a signed receipt for each official run, and more subnets are likely to want the same: a receipt a validator can turn straight into a weight or a merge decision. We already have several receipts: the console receipt contract, the validator-shaped product receipts on `customer-sandbox-mvp`, and the miner lifecycle receipts in #275. **Should the challenge receipt share one format with those, or be its own kind alongside them...

## `cathedralai/cathedral-validator` — 5 open

### #294 — Launch 1/4: Confidential machine trust and durable admission

- **URL:** https://github.com/cathedralai/cathedral-validator/issues/294
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-05T18:05:08Z
- **Updated:** 2026-10-05T18:05:08Z
- **Description:** The direct independent validator admits only qualified, fresh confidential evidence and remains operable across reboot/expiry without a laptop refresher. Integration owner: Cathedral coordinating agent (GitHub tracking owner: @wallscaler). Implementation stays with the relevant runtime, attestation, miner or validator owner; this issue is the single acceptance ledger for this lane. - [ ] Make and encode the Milan admission decision from #293; a reported root-seed concern is not settled by rai...

### #295 — Launch 2/4: Correct miner scoring, chain writes and safe recovery

- **URL:** https://github.com/cathedralai/cathedral-validator/issues/295
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-05T18:05:09Z
- **Updated:** 2026-10-05T18:05:09Z
- **Description:** Eligible serving miners are scored correctly and one authorized writer follows the actual target-chain policy with durable recovery, never silent contradictory retries. Integration owner: Cathedral coordinating agent (GitHub tracking owner: @wallscaler). Implementation stays with the relevant runtime, attestation, miner or validator owner; this issue is the single acceptance ledger for this lane. - [ ] Retain and land #285's permit-holder miner eligibility correction; main currently drops tho...

### #296 — Launch 3/4: Signed release, installer/updater and trustworthy telemetry

- **URL:** https://github.com/cathedralai/cathedral-validator/issues/296
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-05T18:05:10Z
- **Updated:** 2026-10-05T18:05:10Z
- **Description:** An operator installs and updates one supported signed validator release and the board reflects real finalized/revealed evidence, with honest failure/freshness states. Integration owner: Cathedral coordinating agent (GitHub tracking owner: @wallscaler). Implementation stays with the relevant runtime, attestation, miner or validator owner; this issue is the single acceptance ledger for this lane. - [ ] Retain and land #283's exporter module entrypoint fix (#282), then verify an installed export...

### #297 — Launch 4/4: Sealed customer delivery evidence to subnet rewards

- **URL:** https://github.com/cathedralai/cathedral-validator/issues/297
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-05T18:05:12Z
- **Updated:** 2026-10-05T18:05:12Z
- **Description:** Actual customer execution, assignment, resource interval, failure and teardown facts reach independently verified reward accounting without making chain availability a customer lifecycle dependency. Integration owner: Cathedral coordinating agent (GitHub tracking owner: @wallscaler). Implementation stays with the relevant runtime, attestation, miner or validator owner; this issue is the single acceptance ledger for this lane. - [ ] Integrate #273 with Sandbox #250 and the preferred customer-s...

### #300 — Release channel expiry alarm

- **URL:** https://github.com/cathedralai/cathedral-validator/issues/300
- **Labels:** —
- **Author:** app/github-actions
- **Created:** 2026-10-06T13:17:17Z
- **Updated:** 2026-10-07T13:21:07Z
- **Description:** @wallscaler the daily release expiry check failed: https://github.com/cathedralai/cathedral-validator/actions/runs/37469578239 ``` release expiry check FAILED for 2 of 3 artifacts; see docs/RENEW_RELEASE_CHANNEL.md EXPIRES SOON: stable release metadata sequence 5 expires at 2026-10-10T20:33:45Z, in 4.3 days (alarm threshold 5.0 days); re-sign it: docs/RENEW_RELEASE_CHANNEL.md, case (a). ::error title=stable release metadata expiry::EXPIRES SOON: stable release metadata sequence 5 expires at 2...

## `bigailabs/polariscomputer` — 71 open

### #1035 — Runtime 21 — Lazy-grow ephemeral host pool on Verda

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1035
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-05-29T08:38:03Z
- **Updated:** 2026-05-29T19:59:06Z
- **Description:** P1. Ships the architecture that makes the homepage's "lower cost per run" and "pay per second" wedge claims actually true. Without this, every ephemeral one-shot pays the ~82s Verda provision tax and the dollar economics don't fit the marketing. After the Runtime walkback (#1033) and homepage redesign (#1034), the platform tells customers it's *the runtime for AI agents — lower cost per run, pay per second*. Today's implementation provisions a fresh Verda VM per `POST /v1/runtime/run` call (~...

### #1038 — Runtime pool: verify overflow provider before relying on Verda cost model

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1038
- **Labels:** p1-important, infra, runtime
- **Author:** wallscaler
- **Created:** 2026-05-29T15:21:03Z
- **Updated:** 2026-05-29T20:32:08Z
- **Description:** `runtime/24-review-fixes` makes the lazy-grow pool ephemeral-only. When the pool is full, `_provision_ephemeral_host()` falls back to the current per-call overflow path. That overflow path may not be Verda depending on the state of the still-open Verda migration work (#1029). If overflow runs are served by another provider, the homepage/runtime cost model cannot assume Verda economics at capacity. The branch is being deployed with `RUNTIME_POOL_ENABLED=true` for team testing. Before productio...

### #1039 — Runtime pool: add tagged Verda orphan reaper for pool-owned hosts

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1039
- **Labels:** p1-important, infra, runtime
- **Author:** wallscaler
- **Created:** 2026-05-29T15:21:24Z
- **Updated:** 2026-05-29T15:21:24Z
- **Description:** ADR-002 documents that early provider-id capture handles the common partial-provision failure, but there is still no true orphan reaper for Verda pool hosts. If Verda creates a VM and the API process dies before the `runtime_hosts` row is written or updated, the VM may be left running without a durable DB reference. The current implementation cannot safely list-and-destroy untagged instances because the Verda adapter does not tag pool-owned VMs yet.

### #1051 — Customer attestation path: always-up on spot (self-healing warm pool) + adopt Pi TEE fleet work

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1051
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-06-10T10:30:33Z
- **Updated:** 2026-07-18T03:12:14Z
- **Description:** Parking the Pi TEE fleet build for now, but preserving it as a priority — the self-healing mechanism it proved is exactly what the **customer-facing** attestation/compute path needs to stay up on spot. Why this matters - Customer path runs on **GCP c3 TDX spot** (~$0.035/hr; total infra ≈ $20/mo). Spot is what makes the unit economics work (marginal cost per attestation ≈ $0.0003 = the displayed price). - **Spot preempts** — observed ~26 min in during the Pi fleet work. Today the customer GPU...

### #1056 — Attested GPU (Stage 3): correctness levers, the sealed box becomes a judge

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1056
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-07-04T22:54:00Z
- **Updated:** 2026-07-05T23:44:20Z
- **Description:** Context Stage 2 (#1055, in progress on feat/attested-gpu-stage2) makes the sealed sandbox a RECORDER: it proves provenance (which GPU host, what model ref, what input, what output, exclusive channel) by folding the canonical gpu record into the quote. It does not verify that the GPU's output is CORRECT. The hybrid-TEE research synthesis (archived at ~/Documents/LEARNING/hybrid-tee-verifiable-compute-report-2026-07.html) identifies four correctness levers that turn the recorder into a judge, m...

### #1059 — Hybrid rental: pick a TEE CPU + a GPU, provisioned as one auditable pair

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1059
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-07-05T13:37:17Z
- **Updated:** 2026-07-05T13:37:17Z
- **Description:** Product definition (Fred, 2026-07-05) When someone wants to rent a hybrid they select a TEE CPU and which GPU they want attached to it. Our job is to connect the CPU to the GPU so the GPU is only accessible through that CPU, and thus fully auditable, while keeping the compute accessible. This is the productization of the research wedge (see ~/Documents/LEARNING/hybrid-tee-verifiable-compute-report-2026-07.html): the rentable attested-CPU-judge over an untrusted commodity GPU that nobody curre...

### #1060 — Move box lifecycle work off the API service onto a worker

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1060
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-07-05T13:37:32Z
- **Updated:** 2026-07-05T13:37:32Z
- **Description:** Problem (founder-felt, 2026-07-05) Site pages lag whenever boxes are being provisioned or torn down. All gcloud creates/deletes and SSH sessions for attest, sandbox deploy/stop, agent installs, and GPU attach run in-process on the single Railway backend service that also serves every API request. Rails pages that call the API (catalog, billing, lists) queue behind lifecycle work, so one customer clicking Deploy slows another customer reading Pricing. Two contributing symptoms fixed UI-side al...

### #1061 — Demand funnel: weekly review ritual and thresholds

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1061
- **Labels:** p0-critical, strategy
- **Author:** wallscaler
- **Created:** 2026-07-05T23:44:13Z
- **Updated:** 2026-07-05T23:44:13Z
- **Description:** Part of polaris-ui#44 (agent wedge repositioning epic). Set up a weekly review ritual for the demand funnel and the metrics ladder that gates Stage 3. Metrics ladder (funnel stages, defined in polaris-ui#48) 1. Visitor 2. Signup 3. First deploy 4. Card added 5. 7-day retained 6. GPU-waitlist click Per-channel success metric Cost per deployed sandbox. Every paid channel (ads, launch posts) is graded on this number, not clicks or impressions. Kill criterion If by 2026-09-01 fewer than 2 people ...

### #1062 — Recruit 2 design partners for priced locked-GPU pilot

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1062
- **Labels:** p0-critical, demand-side, strategy
- **Author:** wallscaler
- **Created:** 2026-07-05T23:44:14Z
- **Updated:** 2026-07-05T23:44:14Z
- **Description:** Part of polaris-ui#44 (agent wedge repositioning epic). Recruit 2 design partners for a priced locked-GPU pilot (hybrid, #1059) via async email/Discord. Offer terms Priced pilot, locked GPU paired with the sealed TDX sandbox, hybrid provisioning per #1059. Partner commits to a price, not a free trial. Sourcing rules Pull candidates from users who show one or more of: - Card added - 7-day retained - GPU-waitlist joined Written-signal quality bar Count only an explicit written agreement to a st...

### #1063 — Launch: Show HN, community posts, paid experiment

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1063
- **Labels:** p0-critical, launch
- **Author:** wallscaler
- **Created:** 2026-07-05T23:44:15Z
- **Updated:** 2026-07-05T23:44:15Z
- **Description:** Part of polaris-ui#44 (agent wedge repositioning epic). Launch checklist: Show HN, community posts, and a paid experiment, all graded on cost per deployed sandbox (see #6). GTM pack: ~/Documents/BUSINESS/polaris/agent-wedge-gtm/ (folder created, not yet populated as of this issue). Checklist - [ ] Show HN post drafted and scheduled - [ ] Community posts drafted (list target communities) - [ ] Paid ad experiment set up with tracked spend and attribution to funnel events (polaris-ui#48) - [ ] C...

### #1066 — Evaluate AMD SEV-SNP as secondary sealed judge backend

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1066
- **Labels:** infra, compute
- **Author:** wallscaler
- **Created:** 2026-07-08T05:24:37Z
- **Updated:** 2026-07-08T05:24:37Z
- **Description:** Polaris currently uses Intel TDX for the sealed judge / attested CPU path. AMD SEV-SNP may offer cheaper and broader confidential VM supply, but the trust model, attestation flow, performance profile, and custody claims differ from TDX. Evaluate AMD SEV-SNP as a second sealed judge backend without replacing Intel TDX by default. 1. Can we verify an AMD SEV-SNP attestation report end to end from inside the guest, including AMD certificate chain and freshness binding? 2. Which providers expose ...

### #1068 — terminate fallback writes 240-char stop_reason into String(32) column and crashes

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1068
- **Labels:** bug, compute
- **Author:** wallscaler
- **Created:** 2026-07-09T13:27:46Z
- **Updated:** 2026-07-09T13:27:46Z
- **Description:** `polaris/api/routers/compute_v2.py:2517` (fallback terminate path, when `finalize_deployment_stop` is not wired) writes: ```python stop_reason=(f"provider_terminate_failed: {adapter_err or 'unknown'}")[:240], ``` but `Deployment.stop_reason` is `String(32)` (`polaris/db/models.py:555`). Any failed fallback terminate raises `asyncpg.StringDataRightTruncationError` on commit instead of parking the row in STOPPING with a reason. Pre-existing on `runtime/25-sandbox-gateway` @ b1ab36b9 (verified i...

### #1072 — grant-credits CLI (DB mode) writes ledger row but not the cached balance, then hangs

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1072
- **Labels:** bug
- **Author:** wallscaler
- **Created:** 2026-07-09T19:55:07Z
- **Updated:** 2026-07-09T19:55:07Z
- **Description:** `python -m polaris.cli.admin grant-credits --email espilixai@gmail.com --amount-usd 10`: - Printed `previous_usd: 25.00, granted_usd: 10.00, new_usd: 25.00` — new balance UNCHANGED. - The ledger row WAS committed (state=available), but `users.credit_balance_micros` was not bumped — drift between ledger truth and the denormalized cache. - A second invocation in the same shell hung indefinitely (timed out at 120s) with no grant committed. Admin grants silently don't take effect (balance gates r...

### #1080 — Make payment settlement durable on the self-hosted Verda stack

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1080
- **Labels:** infra, P0, billing
- **Author:** wallscaler
- **Created:** 2026-07-15T08:04:27Z
- **Updated:** 2026-07-15T20:47:30Z
- **Description:** Billing recovered onto a self-hosted Verda stack with several unsafe recovery-era assumptions: - Stripe webhook IDs were marked in Redis before database settlement, so a failed settlement could be lost instead of retried - credit top-up metadata could influence credited amounts without matching Stripe currency and total - unpaid and asynchronous payment states were incomplete - admin grant refresh discarded the newly computed cached balance in the active session - balance reconciliation mutat...

### #1082 — Restore TEE Sandbox size and billing contract

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1082
- **Labels:** backend, P1, billing, cathedral
- **Author:** wallscaler
- **Created:** 2026-07-15T14:12:03Z
- **Updated:** 2026-07-15T20:48:17Z
- **Description:** Sandbox provisioning exact-matches the requested size against provider catalog display names. The Rails client sends legacy slugs, so valid launches fail before provisioning. The stored sandbox rate also uses the raw provider amount instead of the public marked-up catalog quote, and legacy top-level option fields are ignored. - Normalize legacy slugs, provider identifiers, and canonical display names - Reject unknown sizes before provisioning - Accept the legacy console payload without breaki...

### #1095 — Enable TEE secret release with HSM/KMS-enforced KEK custody

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1095
- **Labels:** security, backend, P1, blocked, needs-design
- **Author:** wallscaler
- **Created:** 2026-07-17T04:10:05Z
- **Updated:** 2026-07-17T04:10:05Z
- **Description:** TEE-gated secret release is intentionally hard-blocked until the key-encryption key (KEK) has HSM/KMS-enforced custody. The current product must not show raw Attested secrets inputs or claim values are invisible to Polaris while that release path is unavailable. Current fail-closed behavior: - `polaris/api/routers/secrets.py` accepts identity release only and rejects attestation/KBS modes. - `primitives/secrets_service.py` raises `KbsNotEnabled` for the `tee` lane. - `polaris/api/routers/sand...

### #1098 — Preflight public sandbox images before billable provisioning

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1098
- **Labels:** deploy, p1-important, backend
- **Author:** wallscaler
- **Created:** 2026-07-18T01:53:33Z
- **Updated:** 2026-07-18T01:53:33Z
- **Description:** Sandbox Docker images are currently pulled only after the TDX VM boots and passes attestation. A syntactically valid but missing, private, or architecture-incompatible image can therefore fail after billable CPU capacity has already been provisioned. Render-inspired image flows validate or connect the source before instance configuration. Polaris should adopt that safety property without copying the surrounding service model. - Add a bounded public-image preflight for Docker Hub, GHCR, public...

### #1099 — Define a stable taxonomy for overlapping execution surfaces

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1099
- **Labels:** core, rfc, needs-design
- **Author:** wallscaler
- **Created:** 2026-07-18T02:58:25Z
- **Updated:** 2026-07-18T04:43:17Z
- **Description:** Polaris currently exposes several peer surfaces that all look like "run something on compute" while carrying different trust and lifecycle contracts: - `POST /v1/attest`: one-shot ephemeral TEE execution and receipt - `POST /api/v2/compute/instances`: raw CPU/GPU machine rental - `POST /api/v2/sandbox`: persistent Intel TDX machine with SSH, boot receipt, optional Docker workload, and optional Hybrid GPU - `POST /v1/computer`: organization-scoped managed container endpoint - template and agen...

### #1102 — Add a narrow supplier lease API for Cathedral

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1102
- **Labels:** api, backend, P1, cathedral
- **Author:** wallscaler
- **Created:** 2026-07-18T04:58:18Z
- **Updated:** 2026-07-18T04:58:18Z
- **Description:** 1101 moves customer API ownership to Cathedral while still adapting directly to Polaris route handlers. The next infrastructure boundary is a narrow supplier contract so Cathedral can request capacity without inheriting Polaris route families or provider details. - [ ] Define service-authenticated `POST /v1/leases`, `GET /v1/leases/{id}`, and `DELETE /v1/leases/{id}`. - [ ] Accept a bounded capacity request, trust class, region policy, lifetime ceiling, and idempotency key. - [ ] Return suppl...

### #1111 — Migrate Polaris API and UI from Railway to Hetzner

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1111
- **Labels:** deploy, infra, ops
- **Author:** wallscaler
- **Created:** 2026-07-19T06:01:31Z
- **Updated:** 2026-07-19T07:42:35Z
- **Description:** Move the live Polaris API, Rails UI, and Redis from the blocked Railway workspace to a single Hetzner VPS behind Cloudflare Tunnel. - [x] Recover per-service Railway environment exports with `0600` permissions - [x] Confirm Supabase region (`aws us-west-2`) - [x] Confirm current billing deadline and workspace state - [x] Inventory direct consumers of Cathedral Railway URLs - [x] Confirm `polaris-ui` already has a production Dockerfile - [x] Provision a Hillsboro Hetzner VPS with SSH allowlist...

### #1113 — Bind Cathedral key rate limits to authenticated edge identity

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1113
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-07-21T01:55:13Z
- **Updated:** 2026-09-06T21:11:42Z
- **Description:** The Cathedral edge must sign or authenticate the canonical client address before Polaris uses it as a limiter key. The metadata grants no API access. Missing, malformed, non-ASCII, stale, or incorrect metadata must collapse into one strict untrusted-origin bucket. 1. Configure current and previous origin tokens. 2. Release the paired edge change in https://github.com/cathedralai/cathedral-site/issues/208. 3. Merge and deploy the Polaris verifier and limiter key. 4. Remove the previous token a...

### #1128 — Product: aggregate external compute and sandbox suppliers behind Polaris

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1128
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-08-13T08:54:24Z
- **Updated:** 2026-08-13T08:54:24Z
- **Description:** Polaris should aggregate multiple compute and sandbox suppliers behind one customer-facing computer API. Customers choose requirements such as persistence, region, accelerator, price, trust level, and maximum spend. Polaris selects eligible supply, manages lifecycle and billing, and exposes the exact provider capabilities and trust boundary. This expands supply without presenting every backend as equivalent. | Tier | Supply | Customer promise | |---|---|---| | Cathedral Verified | Qualified T...

### #1132 — Measure Fast readiness and confirm the published pricing contract

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1132
- **Labels:** infra, backend, P0, billing, cathedral
- **Author:** wallscaler
- **Created:** 2026-08-20T16:42:19Z
- **Updated:** 2026-09-06T21:15:33Z
- **Description:** Fast is `execution_class=standard_cpu` on `custom.v1` persistent. The host operator remains trusted. Fast has no TDX attestation. Console actions have Cathedral-signed receipts; direct SSH commands are not recorded. Current source configures 3 vCPU at $0.15 per box-hour, or $0.15 / 3 = $0.05 per vCPU-hour. This meets the original numerical ceiling of $0.0504 per vCPU-hour. Source configuration does not by itself prove an invoiced charge. - [ ] Measure cold and ready-capacity startup end to en...

### #1133 — Cathedral identity: decide personal scope migration after team delivery

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1133
- **Labels:** api, backend, P1, cathedral
- **Author:** wallscaler
- **Created:** 2026-08-20T16:42:20Z
- **Updated:** 2026-09-06T21:11:34Z
- **Description:** **Queue: Later.** This is outside the initial browser, SSH, and API launch proof unless its unfinished capability is exposed. - Team-scoped API keys and authorization. - Team membership and pending email invitations. - Personal and team resource isolation. Personal access is represented by `organization_id = NULL`. Decide whether to keep this explicit personal scope or migrate every account to an auto-created personal organization. Do not run a data migration until the API, key, quota, billin...

### #1145 — Per-tenant usage export

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1145
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-08-27T10:44:40Z
- **Updated:** 2026-08-27T10:44:40Z
- **Description:** Scope Add a per-tenant usage export endpoint for org admins. - GET endpoint: usage rows grouped by tenant_id over a date range - JSON and CSV output formats - org-admin auth (404 for non-members/non-admins, following repo convention) - pagination (limit/offset) - Reconciliation invariant test (eval M1): Decimal sum of per-tenant cost_usd across all pages == org total, to the cent Checklist - [ ] Migration: add nullable indexed `tenant_id` UUID column to `usage_records` (no FK) - [ ] `GET /api...

### #1146 — Scope mail inboxes by tenant

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1146
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-08-27T10:44:50Z
- **Updated:** 2026-08-27T10:44:50Z
- **Description:** Scope Add nullable tenant_id to the mail inbox model and filter inbox list/detail/thread reads by tenant when a tenant_id is provided. Why Mail inboxes currently have no tenant boundary. As multi-tenant usage grows, inbox reads need an opt-in tenant filter so one tenant cannot enumerate or read another tenant's inbox by id. Checklist - [ ] Nullable `tenant_id` UUID column on `MailInbox` (indexed, no FK) - [ ] Migration 066 chained onto current alembic head - [ ] `mail_service.create_inbox` / ...

### #1147 — Scope memory router by tenant

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1147
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-08-27T10:44:55Z
- **Updated:** 2026-08-27T10:44:55Z
- **Description:** Summary Add optional tenant_id scoping to the memory router (`polaris/api/routers/memory.py`) so agent memory can be partitioned by tenant while staying backward compatible when no tenant is specified. Scope - Nullable `tenant_id` UUID column on `AgentMemory` (plain column, no FK to a tenants table — keeps this independent of the tenant-model branch). - Migration adds the column and replaces the existing unique constraint with two partial unique indexes (untenanted vs tenanted rows), since Po...

### #1149 — Approvals: idempotency before interrupt + resume-refresh hook

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1149
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-08-27T10:46:11Z
- **Updated:** 2026-08-27T10:46:11Z
- **Description:** Harden the approval flow in `polaris/api/routers/approvals.py` for Polaris v2 (evals G3): 1. **Idempotency key minted before the interrupt surfaces.** Every `AgentApproval` row gets a persisted `idempotency_key` in the same INSERT that creates it (both the auto-approved and pending trust branches), before anything is returned to the agent or shown to a human. 2. **Duplicate resolve becomes a no-op.** Resolving an already-resolved approval with the same decision returns 200 with the original s...

### #1150 — BYO secret provider interface + Infisical adapter

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1150
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-08-27T10:46:46Z
- **Updated:** 2026-08-27T10:46:46Z
- **Description:** PRD P3 (Secrets that never enter the box): BYO vault, one provider first. This issue covers the provider interface plus the first adapter (Infisical) wired into the existing runtime secret resolution path. - `SecretProvider` abstract interface: `get_secret(name)`, `list_secrets()`, `health()` - Infisical HTTP adapter: token auth, injectable transport, fixture-based tests, no live calls - Connection model: reuse `PlatformConnection` (credentials already encrypted via `primitives.crypto.encrypt...

### #1151 — Slack adapter on channel_routing

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1151
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-08-27T10:47:04Z
- **Updated:** 2026-08-27T10:47:04Z
- **Description:** Inbound Slack Events API integration that routes workspace messages to a deployment through the unified channel-routing envelope, plus outbound replies via the Slack Web API. - `POST /api/slack/events` (public, signature-verified, no JWT): handles `url_verification` challenge echo and `event_callback` deliveries. - Request signature verification: `v0:{timestamp}:{raw_body}` HMAC-SHA256 against `SLACK_SIGNING_SECRET`, constant-time compare, stale-timestamp rejection (>300s). Dev-mode skip mirr...

### #1153 — Per-tenant spend and runtime caps with kill switch

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1153
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-08-27T10:48:39Z
- **Updated:** 2026-08-27T10:48:39Z
- **Description:** Polaris v2 governance (eval G1/G4 from POLARIS-V2-EVALS.md): tenants need hard spend and runtime ceilings, and admins need a kill switch that halts every session a tenant owns. - Nullable `max_spend_usd` (NUMERIC(10,4)) and `max_runtime_minutes` (INTEGER) caps per tenant, own migration - Nullable indexed `tenant_id` on deployments so sessions can be attributed to a tenant - Enforcement at session create: deploy refused with 429 when a cap is met or exceeded - Enforcement in the metering path:...

### #1155 — SPA /roadmap and /never pages

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1155
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-08-27T10:50:48Z
- **Updated:** 2026-08-27T10:50:48Z
- **Description:** Add two public marketing routes to the v2 shell frontend, modeled on the existing `/about` page: - `/roadmap` - three honesty tiers: - **In preview** (built, dormant): agent-to-agent messaging + directory, memory search, webhooks to agent, scheduled prompts, streaming fleet chat, workspace snapshots + versioning, trust levels - **Coming soon**: end-user tenancy, BYO vault secrets, receipts in your product, white-label agent email, per-tenant metering you can mark up - Link to `/never` with on...

### #1165 — Secret redemption gate: guest-generated key and fresh verifiable quote

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1165
- **Labels:** security, backend, P1
- **Author:** wallscaler
- **Created:** 2026-08-31T06:05:40Z
- **Updated:** 2026-09-06T21:11:36Z
- **Description:** **Queue: Later.** Protected inputs must remain disabled until all redemption gates pass. Mounted box secrets do not satisfy these guarantees. Current main rejects `protected_inputs` for every worker profile. Keep that fail-closed gate. The former control-plane redemption design does not provide zero-Cathedral-trust secret release. - Generate the ephemeral key inside the guest. - Bind the key and redemption freshness into a new TDX quote. - Send the quote to the customer endpoint for independe...

### #1166 — Secret redemption gate: generation-bound lifecycle lease

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1166
- **Labels:** security, backend, P1
- **Author:** wallscaler
- **Created:** 2026-08-31T06:05:51Z
- **Updated:** 2026-09-06T21:11:43Z
- **Description:** **Queue: Later.** Protected inputs must remain disabled until all redemption gates pass. Mounted box secrets do not satisfy these guarantees. Keep `protected_inputs` disabled until redemption holds an atomic lease bound to worker id, provider instance id, deployment generation, and fresh quote digest. Stop, replacement, and re-attestation must revoke or wait for the same lease before eligibility changes. Cover stop during redemption, replacement during redemption, lease expiry, retry, cancell...

### #1167 — Secret redemption gate: reserve before any webhook call

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1167
- **Labels:** backend, P1
- **Author:** wallscaler
- **Created:** 2026-08-31T06:06:03Z
- **Updated:** 2026-09-06T21:11:52Z
- **Description:** **Queue: Later.** Protected inputs must remain disabled until all redemption gates pass. Mounted box secrets do not satisfy these guarantees. Keep `protected_inputs` disabled until one durable, row-locked request claim is created before any webhook call. A concurrent request with the same idempotency key must return or wait on that claim without redeeming again. Redemption refusal, timeout, cancellation, and restart must produce explicit terminal or retryable states. Closure requires a concur...

### #1168 — Secret redemption gate: release DB sessions before webhook I/O

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1168
- **Labels:** backend, P2, tech-debt
- **Author:** wallscaler
- **Created:** 2026-08-31T06:06:15Z
- **Updated:** 2026-09-06T21:11:50Z
- **Description:** **Queue: Later.** Protected inputs must remain disabled until all redemption gates pass. Mounted box secrets do not satisfy these guarantees. Keep this deferred while `protected_inputs` is disabled. Before enablement, load and validate every reference in a short database transaction, release the connection before webhook I/O, then write audits through fresh bounded sessions. Prove eight slow or timing-out redemptions do not hold request-scoped pooled connections, and preserve reservation, aud...

### #1169 — Secret redemption: pin resolved address to fully close DNS rebinding on webhook_url

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1169
- **Labels:** security, backend, P2
- **Author:** wallscaler
- **Created:** 2026-08-31T06:06:26Z
- **Updated:** 2026-08-31T06:06:26Z
- **Description:** PR #1164, `utils/webhook_url.py` and `primitives/attestation_broker.py`. `validate_public_https_url` blocks loopback/private/link-local/CGNAT/ multicast/reserved/metadata targets, checked at connection registration and again immediately before every redemption call, with redirects disabled on the outbound request. The redemption-time check resolves the hostname, validates the result, then `httpx` resolves the *same hostname* again independently when it actually opens the connection. A custome...

### #1180 — Trigger post-deploy acceptance deterministically after the deployed source changes

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1180
- **Labels:** bug
- **Author:** wallscaler
- **Created:** 2026-09-02T01:45:51Z
- **Updated:** 2026-09-06T21:11:53Z
- **Description:** The acceptance logic exists and a schedule now fires. The schedule is delayed, shares the constrained runner, and is not a deterministic response to a successful deployment. Emit an authenticated deployment-success event carrying the deployed source SHA, or use another trigger proven not to create a Railway check deadlock. Deduplicate by source SHA and preserve manual dispatch for recovery. For two consecutive deployments, acceptance starts once without a manual command, tests the exact deplo...

### #1193 — Runtime host pool: reap_idle_hosts and retry_pending_releases are never scheduled in production

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1193
- **Labels:** bug, infra, P1, runtime
- **Author:** wallscaler
- **Created:** 2026-09-03T07:01:37Z
- **Updated:** 2026-09-03T07:01:37Z
- **Description:** `polaris/services/runtime_host_pool.py` exposes `reap_idle_hosts()` (destroy idle rented hosts after `RUNTIME_POOL_IDLE_TTL_MINUTES`) and `retry_pending_releases()` (retry failed slot releases). Neither has a production caller: `git grep` over `polaris/` and `app_server.py` finds only the module docstring. Only `ensure_min_warm_hosts` is scheduled (`polaris/workers/lifecycle.py:333`). - An idle rented Verda host is never destroyed by Polaris. The idle TTL is documentation only. This is how th...

### #1194 — Agent deploy scripts: signal SSH-unreachable with an exit code, not a stderr substring

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1194
- **Labels:** enhancement, tech-debt, P3, runtime
- **Author:** wallscaler
- **Created:** 2026-09-03T07:01:39Z
- **Updated:** 2026-09-03T07:01:39Z
- **Description:** 1190 retires a runtime pool host when the deploy script output contains `SSH did not become ready` (from `wait_for_ssh_ready` in `agents/_agent_common.sh`). It matches on raw stdout+stderr so the tail filter in `_format_capture_error` cannot drop it, but it is still a substring match on a human-readable line. Any later edit to that message in `_agent_common.sh` silently disables host retirement with no failing test outside the branch that made the edit.

### #1196 — Fast CPU: isolate staging and production provider inventory

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1196
- **Labels:** bug
- **Author:** wallscaler
- **Created:** 2026-09-03T07:17:27Z
- **Updated:** 2026-09-06T21:11:41Z
- **Description:** Staging and production share the provider account. Current Fast server labels and pool matching do not include an environment identity. A staging server can therefore enter production inventory, or the reverse, when warm capacity is enabled. - Write a stable environment label on every created Fast server. - Require the configured environment in inventory, warm-pool, recovery, and audit selectors. - Define how legacy unlabeled servers are quarantined or adopted. - Prefer separate provider proj...

### #1197 — Replace the home-grown Hermes runtime with the real Nous Hermes Agent

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1197
- **Labels:** P1, epic, deploy-pipeline, agent-compute, runtime
- **Author:** wallscaler
- **Created:** 2026-09-03T07:23:59Z
- **Updated:** 2026-09-06T21:29:40Z
- **Description:** We should not maintain our own runtime called Hermes. The `hermes` deploy preset must run the real [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent), not `docker/hermes/server.py`. Hermes desktop v0.21.0 ("Pantheon", 2026-09-02) connects to any number of remote `hermes gateway` processes at once and shows every bot and chat across them. A Polaris-hosted real Hermes would appear in a customer's desktop next to their local agents. Our current preset cannot: it exposes `P...

### #1199 — Make paid attest.v1 jobs survive API restarts

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1199
- **Labels:** bug
- **Author:** wallscaler
- **Created:** 2026-09-03T11:05:01Z
- **Updated:** 2026-09-06T21:11:49Z
- **Description:** A routine API restart still interrupts an in-flight paid attest job. Refund is necessary compensation, but it is not job continuity. Persist the run state, provider identity, billing reservation, attempt, and terminal outcome before long work begins. On restart, one reconciler must resume or safely terminalize the same run without duplicate compute or debit. Stop accepting new long jobs during shutdown and give claimed jobs a bounded handoff window.

### #1203 — SSH identity binding: verify legacy duplicate-key reconciliation in production

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1203
- **Labels:** bug
- **Author:** wallscaler
- **Created:** 2026-09-03T15:40:01Z
- **Updated:** 2026-09-06T21:11:48Z
- **Description:** The gateway now parses exact canonical SSH keys, uses a unique durable digest binding, serializes onboarding by key, and returns 409 for ambiguous legacy matches. Regression coverage includes identity, payment, and concurrent onboarding paths. - Run a read-only production audit for duplicate normalized legacy keys and ambiguous or orphaned bindings. - Resolve any duplicates through an approved account-ownership process. - Repeat the formerly failing key login and confirm the intended account,...

### #1213 — Add the Google-signed vTPM quote as Google-rooted boot and identity evidence on Confidential G4

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1213
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-09-03T23:28:12Z
- **Updated:** 2026-09-03T23:28:12Z
- **Description:** Follow-up to #1212, which stopped the confidential GPU receipt asserting `cpu_tee: "amd_sev"` from a constant and made it declare `"unattested"` unless evidence backs a name. This issue is the other half: collect the one piece of CPU-side evidence G4 can actually produce. **AMD-rooted CPU attestation is not reachable on GCP alongside a GPU, today, at all.** - An AMD-rooted attestation report requires SEV-SNP. `g4-standard-48` rejects `SEV_SNP` and `TDX` at the API: "Confidential Instance Conf...

### #1237 — Egress approvals: authenticated in-box ingestion and enforceable allow once

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1237
- **Labels:** new-feature, cathedral
- **Author:** wallscaler
- **Created:** 2026-09-05T03:43:29Z
- **Updated:** 2026-09-07T06:02:19Z
- **Description:** **Queue: Next, after this week's API-only design-partner launch.** Keep the unfinished capability unavailable until its complete path is supported. Current main lists approval requests but advertises `allow_once: false` and rejects an allow-once decision. Implement the smallest authenticated box-to-control-plane contract that: records a request with box identity, destination, protocol, process context, timestamp, and nonce; prevents one box from filing for another; lets the daemon consume one...

### #1238 — Decide Fast paused pricing and retained capacity cost

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1238
- **Labels:** billing, cathedral
- **Author:** wallscaler
- **Created:** 2026-09-05T03:43:30Z
- **Updated:** 2026-09-06T21:15:35Z
- **Description:** A paused Fast box retains a provider allocation which still costs Cathedral money. Decide and document the customer price and retention policy for this state. Current metering selects running deployments. Confirmed pause closes and settles the active usage segment. Confirmed resume opens a fresh segment. Budget accrual uses closed segment cost plus the elapsed time of open segments. A regression covers stopping after 12 paused hours without additional usage or debit.

### #1245 — Restore reliable API CI and post-deploy acceptance execution

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1245
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-09-05T16:23:33Z
- **Updated:** 2026-10-02T04:32:40Z
- **Description:** Both UI repair PRs now pass all five GitHub checks. [UI #108](https://github.com/bigailabs/polaris-ui/pull/108) remains at e40e3510cdf96e444c87819257d2e17cb690a2bd. [UI #109](https://github.com/bigailabs/polaris-ui/pull/109) is now a8c63bb4902b230611583547c87164ba4de6d55c. The six failed browser scenarios were outdated history responses missing the required account namespace. The corrected fixtures use the real Rails namespace. A billing fixture now waits for the initial visible status and ch...

### #1246 — Computer launch: critical customer outcomes and acceptance

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1246
- **Labels:** P1, agent-compute, release-blocker
- **Author:** wallscaler
- **Created:** 2026-09-05T23:17:47Z
- **Updated:** 2026-09-07T06:10:23Z
- **Description:** Both UI repair PRs now pass all five GitHub checks. [UI #108](https://github.com/bigailabs/polaris-ui/pull/108) remains at e40e3510cdf96e444c87819257d2e17cb690a2bd. [UI #109](https://github.com/bigailabs/polaris-ui/pull/109) is now a8c63bb4902b230611583547c87164ba4de6d55c. The six failed browser scenarios were outdated history responses missing the required account namespace. The corrected fixtures use the real Rails namespace. A billing fixture now waits for the initial visible status and ch...

### #1260 — Launch acceptance: finish selected-computer Stop, final billing and automatic cleanup

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1260
- **Labels:** P1, billing, agent-compute, release-blocker
- **Author:** wallscaler
- **Created:** 2026-09-06T21:23:22Z
- **Updated:** 2026-09-06T21:23:22Z
- **Description:** A customer must stop only the selected computer, see the final bill and know cleanup finished. A stopped database row alone is insufficient. Current evidence The tested run charged exactly $0.008091 for 971 whole seconds at $0.03/hour. Repeated Stop and a later read more than 14 hours afterward preserved the original cutoff and charge. A prior legacy tunnel required manual deletion. PR1253 deployed automatic exact-resource recovery. UI PR104 deployed charge refresh. The browser Stop-to-final-...

### #1261 — Launch acceptance: recover interrupted Computer setup after allocation

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1261
- **Labels:** P1, testing, agent-compute, release-blocker
- **Author:** wallscaler
- **Created:** 2026-09-06T21:23:25Z
- **Updated:** 2026-09-06T21:23:25Z
- **Description:** A timeout or lost installer must not strand a paid computer, create a duplicate or release capacity while work still runs. Current evidence Production handlers returned the same computer for an identical request and 409 for conflicting input under the same request ID. Pre-commission cancellation reached stopped with settled zero, no billing start and no provider VM commissioned. The recovery repairs in PR1250 and PR1253 are deployed. Later allocation, installer and worker-loss recovery still ...

### #1262 — Public launch acceptance: fund the intended account and resume one Computer launch

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1262
- **Labels:** P1, billing, agent-compute, release-blocker
- **Author:** wallscaler
- **Created:** 2026-09-06T21:23:28Z
- **Updated:** 2026-09-06T21:23:28Z
- **Description:** A first-time customer must fund the intended account, retain the chosen task and launch one computer at the accepted price. Existing account credit does not prove this outcome. Current evidence The reviewed Computer offer is $0.03/hour with $1 minimum available credit. Managed inference has no separate Polaris inference charge under this offer. External provider keys bring separate provider charges. The live service tests began with existing credit. First-time payment-to-launch and delayed se...

### #1270 — Deliver reserved Workers execution through the shared CLI and a separate Reliquary adapter

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1270
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-09-10T09:14:38Z
- **Updated:** 2026-09-11T05:06:51Z
- **Description:** Customer qualification still FAILS. API #1285 is deployed at 8a20dae9e4ffbd8fdbcb06672f0e322418531956. CLI and the separate adapter 0.5.5 are merged, built and installed through cathedralai/cathedral-pool#21. The path remains normal Cathedral login, the public Workers API and the unchanged pinned executor. No customer grading logic was added to ctcli. Latest unchanged load: 32 callers returned 3,000/3,000 correct, p95 773 ms, PASS. Fifty callers returned 3,000/3,000 correct, p95 1,046 ms, FAI...

### #1272 — Deliver Boxes and reserved Workers with explicit capacity and connected supply

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1272
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-09-10T11:49:37Z
- **Updated:** 2026-09-11T05:06:53Z
- **Description:** Customer qualification still FAILS. API #1285 is deployed at 8a20dae9e4ffbd8fdbcb06672f0e322418531956. CLI and the separate adapter 0.5.5 are merged, built and installed through cathedralai/cathedral-pool#21. The path remains normal Cathedral login, the public Workers API and the unchanged pinned executor. No customer grading logic was added to ctcli. Latest unchanged load: 32 callers returned 3,000/3,000 correct, p95 773 ms, PASS. Fifty callers returned 3,000/3,000 correct, p95 1,046 ms, FAI...

### #1299 — Sealed canary cannot write /workspace as the customer SSH user

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1299
- **Labels:** bug
- **Author:** wallscaler
- **Created:** 2026-09-15T09:25:57Z
- **Updated:** 2026-09-15T09:25:57Z
- **Description:** On 15 September 2026 around 09:21 UTC, Fred authorized a deploy canary on Sealed box `grey-gate`, deployment `de3c215c-830d-49d4-a5b2-7beaf4da1af9`. The first acceptance step must write a sentinel before deploying, so a successful deploy cannot hide a workspace wipe. The supported SSH login succeeds, but: ```text $ date +%s | tee /workspace/sentinel tee: /workspace/sentinel: Permission denied $ id uid=1004(polaris) gid=1005(polaris) ... $ stat -c 'owner=%U group=%G mode=%a' /workspace owner=r...

### #1312 — Deliver repeatable non-attested dedicated sandbox packages from the console

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1312
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-09-21T07:15:34Z
- **Updated:** 2026-09-21T07:27:46Z
- **Description:** A customer buys one fixed-duration, fixed-fee package containing 25 Firecracker VMs, or a smaller count supported by actual workload qualification, wholly on one dedicated Hetzner host. Buying again commissions a separate host. Existing packages must not be moved, stopped or oversubscribed to fulfil the next order. This is on-demand provisioning with visible progress, not an instant-start SLA. Before payment the site must display the total customer price and currency, duration, exact per-gues...

### #1362 — Run GitHub Actions runners as a Cathedral job type (dogfood on our CI)

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1362
- **Labels:** enhancement, cathedral
- **Author:** wallscaler
- **Created:** 2026-09-25T23:31:38Z
- **Updated:** 2026-09-25T23:31:38Z
- **Description:** Offer GitHub Actions runners as a Cathedral job type: a repo points its workflows at Cathedral, and each queued job gets a fresh sandbox on the customer's own box, billed per box-second like any other work. We would be our own first customer. On 2026-09-25 our CI ran on one Hetzner machine (`polaris-ci-runner-1`). A jammed runner and a single-job queue held three merged security fixes out of production for hours, and hosted Actions are on a billing hold. A second runner on the same machine is...

### #1374 — Spaces phase 2: self-serve handles with abuse controls

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1374
- **Labels:** future, security, cathedral
- **Author:** wallscaler
- **Created:** 2026-09-26T05:28:19Z
- **Updated:** 2026-09-26T05:28:19Z
- **Description:** Phase 1 of Spaces (public pages at cathedral.computer/@handle) ships allowlisted only: bigailabs/polariscomputer#1369 (API), cathedralai/cathedral-site#412 (edge), cathedralai/cathedral-pool#69 (ctcli space, 0.5.17). The one Space is `wallscaler`. Opening Spaces to every signup would let anyone host phishing pages on our domain, so it needs the controls below first. - [ ] Self-serve handle claim with the reserved list (`RESERVED_HANDLES` in polaris/services/cathedral_spaces.py) and a lookalik...

### #1387 — Sell a dedicated Hetzner workspace box as a monthly SKU (Ditto option C)

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1387
- **Labels:** new-feature, P1, billing, supply-side, cathedral
- **Author:** wallscaler
- **Created:** 2026-09-26T17:12:36Z
- **Updated:** 2026-09-26T17:12:36Z
- **Description:** Decision (Fred, 2026-09-26): go on Ditto option C, sold as a SKU paid monthly. Goal A customer buys one dedicated Hetzner bare-metal host (AX102 class, 32 threads / 128 GB) as a **workspace box** for a flat monthly price. Their agents use it exactly like a workspace box today: `POST /v1/sandboxes` with `box_id`, no lifetime, never idles out. Ditto fits about 14 agents at 2 vCPU / 8 GB on one host. What already exists (verified on main e4365b2a unless noted) - **Supplier seam:** `Supplier` Pro...

### #1388 — Serve sandbox preview links through a links-only named tunnel beside direct IP

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1388
- **Labels:** new-feature, P2, demand-side, cathedral
- **Author:** wallscaler
- **Created:** 2026-09-26T17:13:06Z
- **Updated:** 2026-09-26T17:13:06Z
- **Description:** Decision (2026-09-26): **direct IP stays the API path; browser-facing preview links go through a per-box, links-only Cloudflare named tunnel.** Not tunnels everywhere, not direct IP everywhere. Why - **Direct IP for the API:** removes the tunnel hop from every exec (Affine's latency target). #1361 and cathedralai/runtime#15 already carry it. - **Tunnel for links:** a link must work in a browser, an iframe and a third party's Playwright `connect_over_cdp`. The direct front door serves a *pinne...

### #1407 — PR test selection misses 34% of direct test importers

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1407
- **Labels:** infra, testing
- **Author:** wallscaler
- **Created:** 2026-09-28T21:45:19Z
- **Updated:** 2026-09-28T21:45:19Z
- **Description:** The PR test selection from #1404 scopes a PR to the tests its path map names. Measured against the import graph, that drops tests which import the changed module. - Static import graph over all first-party Python. For the 132 modules under `polaris/services`, `polaris/api/routers`, `polaris/providers`, `polaris/workers`, `polaris/resources`, `ops/`, `utils/`, `deployment/` and `docker/` that the map scopes (not full-suite), 570 direct `test_*.py -> module` import edges exist. - The map select...

### #1409 — 64 concurrent sandbox creates from one account return proxy 5xx but still take effect

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1409
- **Labels:** bug
- **Author:** wallscaler
- **Created:** 2026-09-29T01:45:43Z
- **Updated:** 2026-09-29T01:45:43Z
- **Description:** One live run on 2026-09-29, test account (user 654ffd2b), main `de8765dc` deployed (includes #1398), `CATHEDRAL_BOX_WARM_POOL_SIZE=0`. The Reliquary adapter (cathedral-pool 0.9.0) asked for 64 prewarmed sandboxes at once: 64 concurrent `POST /v1/sandboxes` with `image_id` (python:3.12-slim pinned), `network: deny_all`, while 1 box was ready and more had to be bought. | 20 s bucket | creates | confirmed id | 5xx without the Cathedral envelope | transport lost | |---|---|---|---|---| | +0 s | 6...

### #1411 — Imported-image sandboxes: /usr/local/bin is mode 0777, so unprivileged code can replace python3

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1411
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-09-29T19:37:38Z
- **Updated:** 2026-09-29T19:37:38Z
- **Description:** **Seen once** (Reliquary live proof, 2026-09-29, one sandbox): in a sandbox created from the imported `python:3.12-slim` image, `/usr/local/bin` is mode `0777`. The expected mode is `0755`. **Why it matters** - Some workloads drop from root to an unprivileged user inside the sandbox to contain untrusted code. Reliquary's grader, for example, runs graded code as uid 65534. - With `/usr/local/bin` world-writable, that code can replace `python3`, or anything else there, and root runs the replace...

### #1412 — Public E2B-compatible sandbox endpoint at cathedral.computer

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1412
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-01T23:33:15Z
- **Updated:** 2026-10-02T00:53:09Z
- **Description:** Goal: an existing E2B user (e.g. FineEnvs multi-harness RL) switches to Cathedral by changing only the E2B SDK domain/API key. State today (checked 2026-10-02): - Public API is Cathedral's own `/v1/sandboxes` (#1317 merged, the 'e2b-product-api' branch built this Cathedral-shaped API, not an E2B-compatible one). - E2B's own API exists only per Standard box (runtime `/sandboxes`), reached by the service layer via `polaris/providers/e2b_product.py`. - #1319 deliberately kept runtime branding in...

### #1413 — Receipts endpoint for /v1/sandboxes runs

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1413
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-01T23:33:17Z
- **Updated:** 2026-10-02T02:28:40Z
- **Description:** Goal: every sandbox created through the public `/v1/sandboxes` API gets signed receipts a customer or validator can fetch and verify offline. Foundation for harness-trajectory receipts (proxy model calls + sandbox actions) and for SN94 re-run-only-winners. State today (checked 2026-10-02): - Live OpenAPI has no receipt route under /v1/sandboxes. - Receipts exist only for console boxes (`/v1/console/boxes/{name}/receipts`); every `receipts.append` is in cathedral_console.py. - #1296 (birth rec...

### #1418 — E2B SDK sandbox port routing (get_host)

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1418
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-02T00:52:14Z
- **Updated:** 2026-10-02T00:52:14Z
- **Description:** Follow-up to #1412 / #1414. `<port>-<sandbox id>.sandbox.cathedral.computer` routes only envd (49983) today; other ports answer 502 `port_unavailable`. Cathedral creates sandboxes with `allowPublicTraffic: false`, and the runtime's client proxy then needs the traffic access token, which the runtime returns only at create and Cathedral does not keep. - [ ] Persist the runtime traffic token (encrypted) at create, or proxy user ports with a Cathedral-minted traffic token checked in `e2b_envd_pro...

### #1439 — Large workspace boxes are refused for the first ~5 days of every month under the default $1,000 account cap

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1439
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-02T19:35:57Z
- **Updated:** 2026-10-02T19:35:57Z
- **Description:** Found while diagnosing the date-dependent CI failure fixed by #1419. **Mechanism:** a workspace box reserves its cost for the rest of the UTC month at the supplier rate (`require_supplier_budget` in `polaris/services/cathedral_box_billing.py`). A large workspace costs $1.614/h. With the default $1,000 monthly account cap, the reservation exceeds the cap whenever more than about 620 hours of the month remain (roughly days 1 to 5), so the buy returns 429 `box_monthly_limit_reached` even for an ...

### #1440 — Console box groups: a customer label on the pack, carried on every member row

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1440
- **Labels:** enhancement, api, P2, cathedral
- **Author:** wallscaler
- **Created:** 2026-10-02T21:35:57Z
- **Updated:** 2026-10-02T21:35:57Z
- **Description:** Cathedral sells one offering since 2026-10-02: sealed sandboxes as a pack of 2, 4 or 6 (Fred). The console orders a pack as one `POST /v1/console/box-groups`. A customer names a job (`rl-41`), but the pack has no name: `CreateBoxGroupRequest` has no label field, members get generated names, and `GET /v1/console/boxes` rows carry no group id, so the Sandboxes list cannot say which sandboxes belong to which pack without a second read of `/v1/console/box-groups`.

### #1441 — POST /v1/workers: create a pack of sealed sandboxes in one call (count), for agents

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1441
- **Labels:** enhancement, api, P2, cathedral
- **Author:** wallscaler
- **Created:** 2026-10-02T21:36:00Z
- **Updated:** 2026-10-02T21:36:00Z
- **Description:** Since 2026-10-02 the offering is a pack of 2, 4 or 6 sealed sandboxes. The console has `POST /v1/console/box-groups` (console-origin only, `_require_console`). An agent on `/v1/workers` has no pack primitive: `/agents.md` tells it to create the pack one `POST /v1/workers` at a time with one `Idempotency-Key` each, named `<job>-1` to `<job>-<n>`, and to delete the accepted ones if a later create is refused (all or nothing by instruction, not by the API).

### #1442 — GET /v1/usage?summary=day: one sandbox count and hours figure across the three lanes

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1442
- **Labels:** enhancement, api, P2, cathedral
- **Author:** wallscaler
- **Created:** 2026-10-02T21:36:03Z
- **Updated:** 2026-10-02T21:36:03Z
- **Description:** `GET /v1/usage?summary=day` reports `sample_size: {sandboxes, boxes, vms}` and `sandbox_seconds`, `box_seconds`, `vm_seconds` per period. Since 2026-10-02 the customer word is sandbox and only sealed sandboxes are sold; the console and Billing add the three lanes into one count and one hours figure client-side (cathedral-site `feature/one-offering-sealed-packs`, `account-dashboard.client.ts` and the Sandboxes tiles). The split still matters to operators and to customers on the closed Standard...

### #1446 — Challenge run API on Sealed for Gittensor challenges

- **URL:** https://github.com/bigailabs/polariscomputer/issues/1446
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-07T23:28:31Z
- **Updated:** 2026-10-07T23:28:31Z
- **Description:** Goal Run the official Gittensor (SN74) challenge evaluation on Cathedral Sealed and return a signed receipt their maintainer bot can check. Miners pay per run with their own Cathedral key; entrius pays nothing and only verifies the receipt, so a miner cannot fake a result. What it should achieve - **`POST /v1/challenges/runs` and `GET /v1/challenges/runs/{id}`:** accept a solver, run it, return status and the receipt. Idempotent, owner-scoped, billed to the caller. - **Cathedral fetches `chal...

## `cathedralai/cathedral-site` — 18 open

### #204 — Publish supported Cathedral SDKs and CLI

- **URL:** https://github.com/cathedralai/cathedral-site/issues/204
- **Labels:** enhancement, demand-side
- **Author:** wallscaler
- **Created:** 2026-07-18T04:58:18Z
- **Updated:** 2026-09-07T06:02:18Z
- **Description:** **Queue: Next.** This is the important self-service integration immediately after the API-only design-partner launch. Keep unsupported controls unavailable until this complete path is supported. A developer creates a scoped Cathedral key, installs a supported client, runs either a one-shot job, a persistent box, or an authenticated remote grader transport through documented Cathedral routes, retrieves the result and evidence, and cleans up without Polaris names or hand-written HTTP.

### #208 — Authenticate Cathedral edge identity for key rate limits

- **URL:** https://github.com/cathedralai/cathedral-site/issues/208
- **Labels:** bug, launch
- **Author:** wallscaler
- **Created:** 2026-07-21T02:14:11Z
- **Updated:** 2026-09-06T21:12:02Z
- **Description:** Two legitimate clients receive independent key-request limits. Forged client headers and direct-origin callers cannot choose arbitrary limiter identities. The Worker forwards the Cloudflare client address through its header allowlist, but current main does not implement authenticated edge metadata. Keep the frontend and origin halves as paired delivery issues. - [ ] The Worker replaces browser-supplied identity headers with canonical, authenticated edge metadata on key request and verificatio...

### #252 — Align trust documentation and launch materials with verified guarantees

- **URL:** https://github.com/cathedralai/cathedral-site/issues/252
- **Labels:** documentation, launch
- **Author:** wallscaler
- **Created:** 2026-08-12T23:23:00Z
- **Updated:** 2026-09-06T21:12:00Z
- **Description:** Every current customer-facing claim states what Cathedral verifies, who is trusted, and which capabilities are available. The evidence-page source already describes physical-access and malicious-hypervisor limits. Current docs source labels confidential GPU unavailable and not for sale. The old homepage GPU price defect is closed in #250. These source changes do not establish the state of every shared deck. The original issue names slide 5 of a deck. Its current file and distribution state ha...

### #265 — Prove the API box lifecycle for the design-partner launch

- **URL:** https://github.com/cathedralai/cathedral-site/issues/265
- **Labels:** enhancement, demand-side, launch
- **Author:** wallscaler
- **Created:** 2026-08-20T16:41:55Z
- **Updated:** 2026-09-07T06:02:16Z
- **Description:** **Queue: Now. Critical for the API-only design-partner launch.** A named design partner with manually granted credit uses the public API to create a paid box, reach the first command, reconnect, and end the allocation with one correctly attributed charge and confirmed provider cleanup. Fast is `execution_class=standard_cpu` on `profile=custom.v1` with `lifetime.mode=persistent` or `bounded_service`. It is not `fast.v1`. The Fast host operator remains trusted. Console actions have Cathedral-si...

### #303 — Pause blocked outbound connections for a customer decision

- **URL:** https://github.com/cathedralai/cathedral-site/issues/303
- **Labels:** enhancement
- **Author:** wallscaler
- **Created:** 2026-09-05T03:43:14Z
- **Updated:** 2026-09-07T06:02:18Z
- **Description:** **Queue: Next, after this week's API-only design-partner launch.** Keep unsupported controls unavailable until this complete path is supported. When a box attempts an outbound connection that policy does not permit, Cathedral holds that connection, shows one real request in Needs you, and applies Allow once, Deny, or Always allow without inventing activity. The request ledger, decision route, and receipt shape exist. No in-box daemon files requests. `allow_once` is therefore advertised as una...

### #304 — Give each box a persistent browser terminal

- **URL:** https://github.com/cathedralai/cathedral-site/issues/304
- **Labels:** enhancement
- **Author:** wallscaler
- **Created:** 2026-09-05T03:43:16Z
- **Updated:** 2026-09-06T21:11:21Z
- **Description:** **Queue: Later.** Keep unsupported controls unavailable until this complete path is supported. A customer opens a terminal in the console, runs interactive programs, resizes the window, interrupts the foreground process, leaves, and reconnects to the same bounded session. The released WebSSH view sends one command at a time through the box control channel. Each submission starts a fresh shell. Ctrl-C only stops the browser wait. Direct SSH through `box.cathedral.computer` is a separate two-ho...

### #305 — Let an eligible customer complete one isolated free verified run

- **URL:** https://github.com/cathedralai/cathedral-site/issues/305
- **Labels:** enhancement, launch
- **Author:** wallscaler
- **Created:** 2026-09-05T03:43:18Z
- **Updated:** 2026-09-06T21:11:22Z
- **Description:** A verified new customer runs one bounded TDX workload at no charge, receives its result and execution receipt, verifies the receipt, and leaves no reusable machine behind. The shared writable sample-box proposal is superseded because shared root access does not isolate visitors. `POST /v1/workers/free-test` is the separate isolated one-shot contract and documents replay refusal. The supplied live journey does not yet prove an eligible account's initial completion or subsequent replay refusal....

### #306 — Prove active Sealed controls in the released browser console

- **URL:** https://github.com/cathedralai/cathedral-site/issues/306
- **Labels:** launch
- **Author:** wallscaler
- **Created:** 2026-09-05T03:43:19Z
- **Updated:** 2026-09-06T21:11:24Z
- **Description:** A customer uses the released browser console on a running Sealed box and completes each supported control with clear evidence, failure states, and cleanup. The released API completed environment, command, file, mounted-secret, and log round trips on an owned Sealed box. Fresh quote requests and in-browser receipt checks were also observed. This does not prove active browser controls, saved downloads, or phone behavior. - [ ] In the released desktop browser, select an upload destination, uploa...

### #316 — Enable and prove Sealed public HTTPS publishing

- **URL:** https://github.com/cathedralai/cathedral-site/issues/316
- **Labels:** bug, blocked, launch
- **Author:** wallscaler
- **Created:** 2026-09-06T21:12:03Z
- **Updated:** 2026-09-15T09:27:11Z
- **Description:** A customer deploys a small app to an owned Sealed box, opens its HTTPS URL, unpublishes it, and stops the box without orphaned resources or misleading success. The 6 September release record shows public Sealed publishing unavailable because the dedicated operator ingress configuration is absent. The released readiness check stops before upload and presents a Cathedral availability message. The operator setup does not belong in customer errors. - [ ] An administrator configures the narrowly s...

### #317 — Prove checkout credits the intended account exactly once

- **URL:** https://github.com/cathedralai/cathedral-site/issues/317
- **Labels:** bug, launch
- **Author:** wallscaler
- **Created:** 2026-09-06T21:12:03Z
- **Updated:** 2026-09-06T21:12:03Z
- **Description:** A signed-in customer buys credit, returns to the same account, sees the correct balance, and uses it without duplicate charges or missing funds. Checkout handoff and balance views were exercised during the 6 September journey review. No new external payment was charged in that audit. Full settlement remains unproved. - [ ] Obtain authorization for one explicitly bounded test purchase, then complete checkout from the intended account. - [ ] Match the payment, ledger credit, balance, and subseq...

### #318 — Save a production receipt bundle and verify it offline

- **URL:** https://github.com/cathedralai/cathedral-site/issues/318
- **Labels:** launch
- **Author:** wallscaler
- **Created:** 2026-09-06T21:12:04Z
- **Updated:** 2026-09-07T06:02:17Z
- **Description:** **Queue: Now. Critical for the API-only design-partner launch.** A customer downloads the real receipt bundle, verifies it offline against an explicitly trusted signer, and sees altered evidence rejected. Earlier local verifier checks and production browser checks exist. Current production checks using the API-supplied signer do not establish independently trusted verification of a saved production bundle. File bytes reached the API test client; a saved browser download remains a separate che...

### #319 — Cathedral launch: canonical work list

- **URL:** https://github.com/cathedralai/cathedral-site/issues/319
- **Labels:** launch
- **Author:** wallscaler
- **Created:** 2026-09-06T21:13:55Z
- **Updated:** 2026-09-15T09:27:13Z
- **Description:** The initial launch path is the public API for one named design partner with manually granted credit. Browser and SSH entry paths remain supported product work outside this initial launch gate. Each linked issue owns its acceptance criteria and proof. This list sets the order. The journey map links back here and does not create a second backlog. Baseline reviewed 6 September 2026. Scope and measurements updated 7 September 2026. Site PR #314 is deployed. API PR https://github.com/bigailabs/pol...

### #345 — Wire the one-box customer model across site, ctcli, batch and deploy

- **URL:** https://github.com/cathedralai/cathedral-site/issues/345
- **Labels:** enhancement, demand-side, launch
- **Author:** wallscaler
- **Created:** 2026-09-15T08:52:20Z
- **Updated:** 2026-09-15T09:27:09Z
- **Description:** One box: keep it, run a job and retire its environment, or serve an app from it. Deploy is an action on a box; run submits one job through the same engine as batch. This does not replace the narrower API-only design-partner launch gate in #319 or its active-work limit. **Picked: Delete, not Sealed pause/resume.** Sealed is the default tier and cannot pause. The existing stop operation deletes its allocation and files. Customer surfaces must say **Delete box** and state the file-deletion conse...

### #384 — Rebuild Cathedral from the customer's side: website, console, CLI and API

- **URL:** https://github.com/cathedralai/cathedral-site/issues/384
- **Labels:** enhancement, demand-side
- **Author:** wallscaler
- **Created:** 2026-09-24T06:48:34Z
- **Updated:** 2026-09-24T09:48:11Z
- **Description:** Our website, console, CLI and API were built without intimate knowledge of our customers. We will rebuild them from the customer's side, grounded in evidence about how our three real accounts work: - an eval team running Harbor and verifiers jobs; - a subnet validator grading untrusted code; - a small agent-product team. Working folder (local): `~/Documents/PROJECTS/cathedral-customer-first/`. - **"Sandbox" is the one shared word.** Customers and the eval market use it. We split it across thr...

### #447 — Decide what to do with source no page loads (13 files, 4,183 lines)

- **URL:** https://github.com/cathedralai/cathedral-site/issues/447
- **Labels:** enhancement
- **Author:** wallscaler
- **Created:** 2026-09-30T14:32:34Z
- **Updated:** 2026-09-30T14:32:34Z
- **Description:** Found while proving #446 safe. On `main` at `9fc77de`, 13 source files (4,183 lines) reach no built page. #446 removes two files of the same kind; these are left for a decision. **Components nothing imports.** A fixed-string search of `src/`, `astro.config.mjs`, `scripts/` and `public/` finds no reference outside the file itself. | File | Lines | Its route today | | --- | --- | --- | | `src/components/AboutPage.astro` | 123 | `/about` redirects to `/` | | `src/components/NetworkPage.astro` | ...

### #450 — Workbench recipe: multi-harness RL rollouts (Claude Code, Codex, OpenCode)

- **URL:** https://github.com/cathedralai/cathedral-site/issues/450
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-01T23:33:19Z
- **Updated:** 2026-10-01T23:33:19Z
- **Description:** Goal: a Workbench recipe at /console/experiments: pick harness(es) x task set x model; Cathedral runs each rollout in a sandbox with the harness pointed at a recording proxy; returns trajectories, rewards and cost, with receipts. Inspired by FineEnvs' multi-harness RL guide (github.com/adithya-s-k/FineEnvs, PR #13): train inside the harnesses people use by proxying model calls, harness unmodified. - [ ] Recipe definition and UI in the Workbench - [ ] Harness templates (Claude Code, Codex, Ope...

### #452 — Distribution: default sandbox inside the RL frameworks

- **URL:** https://github.com/cathedralai/cathedral-site/issues/452
- **Labels:** —
- **Author:** wallscaler
- **Created:** 2026-10-02T00:52:34Z
- **Updated:** 2026-10-02T01:32:32Z
- **Description:** Strategy (Fred, 2026-10-02): be the default sandbox inside the RL frameworks, not a destination. One ICP: teams running agent rollouts for RL and evals (Affine-shaped). One metric: external rollouts per week, by framework. Message: the sandbox where every rollout is provable (capture proxy proves what the model said, Cathedral receipts prove what ran). - [ ] **Harbor upstream** `harbor run -e cathedral`: port of cathedralai/cathedral-harbor into laude-institute/harbor (in progress). Affine of...

### #468 — Workbench customer copy still says VM in places

- **URL:** https://github.com/cathedralai/cathedral-site/issues/468
- **Labels:** bug
- **Author:** wallscaler
- **Created:** 2026-10-04T07:07:20Z
- **Updated:** 2026-10-04T07:09:01Z
- **Description:** The one-offering rule (DESIGN.md, product truth) says customer copy talks about sealed sandboxes and never about VMs, boxes, workers or packages. The RL Workbench on main predates it and still says "VM" in customer-visible places; #467 removed the word from everything it added but left main's copy alone. On main today: - `src/pages/console/experiments.astro`: 6 lines ("Cathedral runs it on a VM of your own", "Your first run waits 5 to 10 minutes while Cathedral starts a VM", "Release the VM n...

## `cathedralai/cathedral-audit` — 0 open

_No open issues._


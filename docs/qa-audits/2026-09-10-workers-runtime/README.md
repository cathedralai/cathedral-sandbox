# Workers operator package verification

The operator package builds the pinned Reliquary executor, issues distinct TLS identities, prepares a disabled 50-slot deployment, installs grants atomically, fences/drains execution and starts the trusted shadow grader. The client qualification command runs the unchanged upstream load and attack scripts through the separate local adapter.

Local validation: 31 tests passed with no skips. These include real OpenSSL certificate generation, hostname verification, client/server key separation, private file modes, disabled installation, enable/disable, backup preservation, conflicting ownership and malformed-package rejection. Qualification checks reject wrong runtime/executor, incomplete request accounting, non-finite latency and missing cleanup counters.

One independent review found two admission defects: installing a disabled same-owner allocation created an overlapping active grant, and installing a malformed disabled allocation poisoned the shared snapshot for other owners. Both were repaired before release. The producer validates the complete snapshot and refuses an overlapping unexpired owner grant before any file replacement. Reproductions against the real API configuration consumer confirmed the existing assignment and store bytes remain unchanged after either rejected installation.

No live host, paid provider, production database or customer credential was used by these tests. The source revision is `0be0cda0c9a73dc3f08e3af2a07dda9407635aa7`. Image IDs in local preparation tests are synthetic and are never presented as built images.

The client acceptance command requires an installed adapter, active exclusive allocation and dedicated-host confirmation. Its reports preserve `trial_delivery: NOT_PROVEN` until the remaining host, saturation, overload, network, failure/recovery and actual customer shadow checks are recorded. A synthetic load soak does not complete the real-grader corpus.

Deployment instructions: `deploy/reliquary-workers/README.md`. Local acceptance: `python3 -m pytest tests/reliquary_workers -q`.

Tracks bigailabs/polariscomputer#1270 and #1272. Host selection, paid rental authorization, configured account access and live acceptance remain open.

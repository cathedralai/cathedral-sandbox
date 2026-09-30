# TEE box end to end on a real Intel TDX guest (T6b2), 2026-09-30

On 2026-09-30 the end-to-end harness (`scripts/tee_box_tdx_e2e/README.md`) ran
once, start to finish, on a rented Intel TDX guest. It ran the real worker and
drove it with central-access delegations over HTTPS.
- **Required checks:** all seven passed, a to g. The main phase had 46 passing
  checks and the pre-LUKS phase 1; none failed.
- **cathedral-sandbox suite:** passed in full on the TD.
- **cathedral-validator suites:** 24 failures. All 24 also fail on a developer
  machine at the same commits, so none is caused by the TD.

The service design is in `docs/TEE_BOX_SERVICE.md`. Its "Done on hardware"
and "Not done" sections take this run into account.

## Environment

| Item | Value |
|---|---|
| Machine | Polaris "Sealed CPU Small" Intel TDX guest on Google Cloud, 4 vCPU, 14 GiB |
| Guest | Ubuntu 24.04, kernel 6.17.0-1020-gcp, Docker 29.1.3 (Ubuntu package), Python 3.12.3 |
| Launch | Chosen by the provider, with MRCONFIGID all zero |
| runsc | 20260817.0 (sha256 `048b89aa…`, the `Dockerfile.tee-box-runsc` pin), `--platform=systrap --network=sandbox` |
| Scratch | A 2 GiB loop-backed file under LUKS2: `aes-xts-plain64` with a 512-bit key, `--integrity hmac-sha256`, full integrity wipe, ext4 on top. Docker's data root was moved onto it. |
| Central state | tmpfs at `/run/cathedral-tee-box` (64 MiB, mode 0700) |
| Verifier | `cathedral-tdx-verifier` v1.0.0 (sha256 `4b6fbaf1…`, `docs/TDX_VERIFIER_RELEASE.md`) |
| Test image | `docker.io/library/alpine`, pulled by digest (`sha256:d9e853e8…`) |
| Run | 07:59 to 08:06 UTC, 412 s end to end. It cost about $0.04, and the box was deleted afterwards. |

## Commits

- **cathedral-sandbox:** main at `40f818b58a5de19274332050b0140a30f4fdd47e`.
- **cathedral-validator:** main at `2e197b9eb81a3c15da4476d215ca0735481811e0`.
- **The harness:** the files in `scripts/tee_box_tdx_e2e/`. The committed copy
  differs from the one that ran only in packaging. ruff formatted
  `harness.py`, and its syntax tree is unchanged. A few shellcheck warnings
  were fixed. `run.sh` got a new output directory and new repository defaults,
  and it now fetches the verifier from its release instead of copying a local
  file. The checks are unchanged.

## Required checks

| Check | Result | What the TD showed |
|---|---|---|
| a. Storage and measured root | PASS (a.1 to a.12) | Startup refused Docker's data root on plain ext4. It accepted the data root on the LUKS2 mapping: uuid `CRYPT-LUKS2-…`, table `capi:authenc(hmac(sha256),xts(aes))-plain64 … integrity:32:aead`. Central state on disk refused, and on tmpfs was accepted. There was no swap, and runsc ran with systrap. The real TDREPORT reader refused ("MRCONFIGID is zero: the launch bound no central root"), and a binding for another root key file refused. The egress table was verified at startup. |
| b. Revocation freshness gate | PASS (b.1 to b.6) | `GET /v1/box` was served before any list, and other routes got `409 revocation_list_required`. A list issued 25 hours earlier got `409 revocations_stale`, both before and after a fresh one. A fresh list opened the routes. |
| c. Lease and sandbox lifecycle | PASS (c.1 to c.8) | Customer A leased the box and imported the image by digest. A `deny_all` sandbox ran under runsc from the pinned image id, with gVisor's `dmesg` and a `4.19.0-gvisor` uname. `exec echo hello` returned `hello`. List by label, delete, and a `404` afterwards all worked. |
| d. RTMR3 and fresh-boot admission | PASS (d.1 to d.5) | Before the lease, RTMR3 read zero in sysfs and in `GET /v1/box`. A fresh quote bound to the nonce, hotkey and TLS key passed the strict verifier, and `admit(require_fresh_boot=True)` admitted it. After the lease RTMR3 held `RTMR3_CONSUMED`, and the next quote carried it at body 472:520. Admission then refused for `boot_consumed` only, and admitted without `require_fresh_boot`. |
| e. Egress | PASS (e.1 to e.7, e.10) | The `internet` sandbox had its tc cap attached and verified. It got no answer from the GCP metadata server, the VPC gateway, the box's own address or the bridge gateway. `http://1.1.1.1/` answered `301` from Cloudflare. |
| f. One customer per boot | PASS (f.1 to f.4) | After A released, the box reported `needs_relaunch`. Customer B, holding another delegated key, got `409 relaunch_required` on lease and list. A leased again with a re-delegated key, and RTMR3 was not extended a second time. |
| g. Scope and revocation | PASS (g.1 to g.4) | A delegation scoped to the box route alone got `401` everywhere else. A request signed for `GET /v1/box` and sent to `/v1/lease` got `401`. A revoked delegation got `401` although the offline tool still verified it, while a sibling delegation minted before it kept working. |

## Observations

- **Quotes.** Both quotes had TCB status `UpToDate`, no advisories, current
  collateral, and debug off. The fresh quote's measurement
  (`tdx-measurement-sha256:83e10f55…`) differs from the consumed quote's
  (`…9e38f69d…`) because the measurement covers the RTMRs. That is why each
  image needs two list entries ("Two measurements per image" in
  `docs/TEE_BOX_SERVICE.md`).
- **Egress controls.** From the TD itself, outside the sandbox, the metadata
  server answered `200`, and so did a listener on the box's own address. The
  sandbox reached neither, and the listener saw no connection from it. The VPC
  gateway answered neither HTTP nor ping from the TD, so the e.4 probe shows
  only that it gave no answer.
- **DNS.** A name lookup from inside gVisor on the `cathsbx0` bridge failed
  (`wget: bad address 'one.one.one.one'`). This is informational (e.8), and
  egress to IP addresses worked. It is listed as open in
  `docs/TEE_BOX_SERVICE.md`.
- **Storage.** `luksFormat` and `open` with the full integrity wipe took 18 s
  for 2 GiB. The key was shredded and its ramfs unmounted right after.
- **Load.** The main phase made 46 HTTPS calls and minted 18 delegations, and
  its checks took 60 s.

## What was injected, and what was not covered

- **Injected.** The worker's MRCONFIGID reader: `serve_worker.py` passes
  `build_tee_box_api` a `read_binding` that returns
  `mrconfigid_for_root_keys` of a throwaway root key file. The harness
  installed that file at `/usr/share/cathedral/central-root-keys.json`.
- **Done by hand.** `setup.sh` prepared the guest after boot, not an image's
  boot step. The scratch device was a loop-backed file. The worker's TLS key
  sat on disk. The worker ran with `--tee-box-no-disk-quota`.
- **Not covered.**
  - a launch with MRCONFIGID bound to our root;
  - dm-verity;
  - SEV-SNP;
  - a relaunch and its timing;
  - the egress lapse drill;
  - the tc cap's measured rate;
  - disk quotas under runsc;
  - integrity write throughput.

## Test suites

| Suite | On the TD | Local baseline, same commits |
|---|---|---|
| cathedral-sandbox, `tests` | 4075 passed, 17 skipped, 0 failed (219 s) | 0 failures |
| cathedral-validator, `tests/thin` and `scaffold/publisher/tests` against sandbox main | 24 failed, 4859 passed, 4 skipped (130 s) | The same 24 fail |

The 24 validator failures all failed again when re-run one at a time, and none
was flaky:
- **22 in the publisher's external-score tests.** These are
  `test_external_scores_epoch_bound.py` (11), `test_external_scores_evidence.py`
  (10) and `test_external_score_storage_key.py` (1). All of them stop at
  `score_audience_not_configured`.
- **2 in `test_confidential_cpu_publisher_canary.py`.** Both stop at "canary
  isolation cleanup did not complete".

## Reproduce

On a fresh TDX guest, run `SSH_KEY=… HOST=… ./run.sh` from
`scripts/tee_box_tdx_e2e/`. A second run in the same boot skips the "RTMR3
reads zero" checks. `scripts/tee_box_tdx_e2e/README.md` covers what the run
needs, how long it takes, and the local baseline.

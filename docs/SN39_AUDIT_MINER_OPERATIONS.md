# SN39 audit-miner operations

This page is the canonical operator runbook for the fixed SN39 audit-miner
image. It covers the independent UID30 path only. General provider onboarding
stays in [MINING.md](../MINING.md), and the image build and trust contract stays
in [SN39_AUDIT_MINER_IMAGE.md](SN39_AUDIT_MINER_IMAGE.md).
The fixed two-guest metadata delivery and publisher procedure is in
[SN39_GCP_SIGNED_FLEET_DELIVERY.md](SN39_GCP_SIGNED_FLEET_DELIVERY.md).

The signed-fleet image source accepts a public hotkey, public axon endpoint,
and public-key-file digest. It serves fresh Intel TDX evidence, signed fleet
discovery, and validation work over native TLS on TCP `8081`, and contains no
wallet. Registration, axon signing, snapshot signing, verification, and weight
submission happen outside the guest.

## Current reviewed pin

The reviewed activation pin published from merged `main` on 2026-08-29 is:

```text
Source merge: 78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8
Image: ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99
Platform: linux/amd64
Listener: native TLS on TCP 8081
```

GitHub Actions run `33266307118` published the immutable commit tag and digest.
The digest passed GitHub/Sigstore build-provenance verification and a separate
anonymous manifest inspection. Its fixed entrypoint invokes
`worker migrate --migration-mode public-legacy-audit` and emits the
`cathedral_effective_startup_v1` posture record. The digest remains an
operator-enforced supply-chain pin. It is not included in TDX MRTD or an RTMR
automatically.

The preserved legacy rollback pin is source merge
`8ad7f6e127ad7dcc4dd150f0e1eb47ce72c5ab22` and image
`ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:61a1806fce13d987323e7c418f1260ba1cd8c9ace8e5b9f9be3c193bdba7228a`.
That image invokes `worker serve --tee tdx --allow-public-legacy-audit`, does
not emit `cathedral_effective_startup_v1`, and must not be used with the new
signed-fleet launcher contract.

Publication is not deployment or live proof. The first-activation rollback was
captured and exercised on 2026-08-29 using the preserved legacy image. A bounded
TDX guest booted, the pinned QVL passed, the TLS SPKI remained bound through
canonical SAT, and the worker returned 20 SAT units. The sanitized evidence is
[SN39_UID124_LEGACY_ROLLBACK_PROOF_20260829.json](SN39_UID124_LEGACY_ROLLBACK_PROOF_20260829.json).
This closes the rollback gate for this activation. It does not prove a future
restore until the same procedure is repeated.

## One-UID bounded fleet invariant

One hotkey has one SN39 UID and one canonical chain axon. Under the signed fleet
contract, that attested axon is the bootstrap candidate and returns up to 32
controlled endpoint candidates for the same UID. Additional machines do not
need more hotkeys, registrations, UIDs, axon announcements, or independent
weight rows.

Every counted machine must independently pass fresh vendor evidence, policy,
hotkey binding, same-SPKI work, and stable hardware-identity checks. Counted
machines need distinct endpoints, distinct attested TLS SPKIs, and distinct
attested hardware identities. Repeating one machine at several IPs produces
one machine of verified compute. Copying one TLS private key between machines
also fails the distinct-compute gate. Generate each TLS key inside its own
guest.

A UID advertises at most 32 endpoints. Fleet overflow zeros the UID and is
never truncated. Each verified machine receives one canonical SAT per scoring
window, capped at 20 raw work units. `raw_uid_units` is the sum across distinct
verified machines and is capped at 640 raw units per UID per window.

A verified duplicate endpoint, stable hardware identity, or TLS SPKI and
channel identity zeros every verified claimant in that collision. The
validator never chooses a winner. An unverified manifest claim does not poison
a verified claim. Declared machine count, vCPU, RAM, capacity, idle uptime, and
attestation alone earn zero. Every counted machine needs fresh evidence,
assigned-hotkey binding, QVL-derived stable hardware identity, TLS SPKI
binding, global uniqueness, and replayed canonical SAT.

The public miner hotkey value is the same UID identity across the fleet. Its
private material stays outside every guest. Never copy a miner or validator
private key into an audit guest.

This policy is implemented in the general worker and the published signed-fleet
activation image. Do not attach a second machine to the live UID30 path until
the two-machine edge proof and the remaining activation gates in
[WORK_REQUEST_V2.md](WORK_REQUEST_V2.md) complete.

Intel TDX is the only multi-machine class eligible for scoring. AMD SEV-SNP
serving and channel binding remain supported in source. AMD multi-machine
scoring is `NOT_PROVEN` and disabled until a friend-owned hardware test proves
stable `CHIP_ID` uniqueness and deduplication across distinct machines.

## Historical single-machine launch sequence

The following sequence records the bounded 2026-08-28 UID124 proof. It is not a
current authorization to register another UID, announce another axon, submit
another weight row, or attach a fleet endpoint.

1. Confirm the hotkey is accepted. If it is already registered, confirm it maps
   to exactly one finalized SN39 UID owned by the intended coldkey. If it is not
   registered, record the exact registration action and current fee before any
   write.
2. Record the reviewed source commit, immutable image digest, platform, runtime
   limit, spend limit, endpoint, and intended validator outcome.
3. Provision one Intel TDX guest with only the required TLS ingress. Keep wallet
   files, cloud credentials, SSH credentials, and validator secrets off the VM.
4. Pull the exact digest anonymously and start the container with the reviewed
   host script and narrow read-write configfs TSM report bind documented in
   [SN39_AUDIT_MINER_IMAGE.md](SN39_AUDIT_MINER_IMAGE.md#run-inside-the-tdx-guest).
5. Before registration or any chain announcement, prove fresh QVL acceptance,
   canonical SAT, and
   one TLS SPKI across evidence and SAT.
6. If the hotkey has no UID, register it once through the reviewed flow. Confirm
   the finalized UID, hotkey, and coldkey ownership before continuing. If it was
   already registered, repeat the finalized mapping and ownership readback.
7. Announce the exact IP and port once through the reviewed validator flow.
   Confirm the signed call and exact axon state at inclusion and later finalized
   heads.
8. Generate a no-write weight preview from finalized UID and endpoint state.
   Submit only the reviewed vector, then confirm it at inclusion and later
   finalized heads.
9. Preserve immutable previews, journals, hashes, extrinsic identifiers, and
   finalized readbacks. Remove the bounded VM and ingress when its window ends.

A container restart creates a new TLS key and SPKI. An endpoint change creates a
new axon claim. Either event requires fresh evidence and SAT verification before
more work or another weight decision.

The one-shot UID30 launch command and axon authorization used by this sequence
are consumed historical controls. They pinned UID124 and the exact vector
`[124]`, `[65535]`. Do not reuse or widen their journals for fleet activation.
The future fleet keeps one UID and one chain axon. It requires a new reviewed
image, signed discovery configuration, validator scoring preview, and live
two-machine proof instead of a second registration.

## 2026-08-28 bounded proof

The bounded UID30 test produced this historical record:

| Item | Proven result |
|---|---|
| Miner identity | Hotkey `5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G`, SN39 UID `124` |
| Endpoint | `34.68.36.156:8081` |
| Axon | Finalized at block `8946161`, with matching later reads at `8946176` and `8946179` |
| Hardware | Fresh Intel TDX QVL `PASS` |
| Work | Canonical `sat_work_units_v1`, `20` verified units, with the same TLS SPKI as evidence |
| UID30 allocation | Mechanism `0` row exactly `[[124,65535]]`, with zero burn destination |
| Weight write | Finalized at block `8945370` |
| Subnet economics | Subnet emission reported `0` |

This proves one bounded machine, finalized identity and endpoint state, fresh
hardware verification, canonical SAT, and UID30's exact allocation. It does not
prove that the endpoint is still online, that onboarding is self-service, that
future validators will assign the same weight, or that the miner earned TAO.
The machine had a four-hour automatic deletion bound.

## Stop conditions

Stop before registration, announcement, or weighting when any required state is
ambiguous. Treat each of these as `FAIL` or `NOT_PROVEN`, not as a retry signal:

- an already-registered hotkey maps to no UID or more than one candidate
  identity, or a new-registration preview unexpectedly resolves to an existing
  UID;
- the image is tag-only, the digest differs, or anonymous pull or provenance is
  not proven;
- QVL, measurement policy, nonce binding, hotkey binding, or same-SPKI SAT fails;
- the endpoint differs from the reviewed preview;
- the chain call outcome or finalized readback is ambiguous;
- two fleet candidates reuse an endpoint, attested TLS SPKI, or stable hardware
  identity;
- the fleet advertises more than 32 endpoints;
- a TLS private key is copied between machines;
- AMD SEV-SNP is included in multi-machine scoring before stable `CHIP_ID`
  uniqueness is proven on friend-owned hardware;
- the signed-access measured image or validator activation gates remain open; or
- the intended weight vector, burn outcome, runtime bound, or spend bound is not
  explicit.

Weight allocation and token earnings are different claims. Report the exact
on-chain weight row when it is proven. Report TAO earnings only after positive
emission and a verified reward or balance delta.

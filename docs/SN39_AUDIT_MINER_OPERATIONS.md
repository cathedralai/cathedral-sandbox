# SN39 audit-miner operations

This page is the canonical operator runbook for the fixed SN39 audit-miner
image. It covers the independent UID30 path only. General provider onboarding
stays in [MINING.md](../MINING.md), and the image build and trust contract stays
in [SN39_AUDIT_MINER_IMAGE.md](SN39_AUDIT_MINER_IMAGE.md).

The audit image accepts a public hotkey, serves fresh Intel TDX evidence and
canonical SAT over native TLS on TCP `8081`, and contains no wallet. Registration,
axon signing, verification, and weight submission happen outside the guest.

## Current reviewed pin

The bounded 2026-08-28 proof used:

```text
Source merge: 4d9c263f2329a0d5f577f864410025fbd260baec
Image: ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:b7ca9ff7a24f933a7f04ec4b31f3d1ac5cf6937b1ccc5b3adcc2fdc7f12a3c76
Platform: linux/amd64
Listener: native TLS on TCP 8081
```

The digest had a successful anonymous pull and build-provenance verification.
The digest remains an operator-enforced supply-chain pin. It is not included in
TDX MRTD or an RTMR automatically.

## Identity invariant

One hotkey has one SN39 UID, one active enrollment identity, and one canonical
axon endpoint at a time. Re-enrolling or announcing a successor endpoint updates
that identity. It does not create another independently listed miner.

Do not run two machines as separate supply behind one hotkey. A second axon
announcement for the same hotkey replaces the endpoint validators resolve for
the existing UID. The two machines do not receive separate UID mappings, proof
records, or weights.

A second independently listed and scored machine requires all of the following:

1. a second hotkey whose private material stays outside both guests;
2. separate acceptance and SN39 registration, producing a second UID;
3. a separate active enrollment and axon endpoint;
4. fresh QVL and same-SPKI SAT proof for that endpoint; and
5. an explicit validator preview that names both UIDs and the intended weights.

The current UID30 launch command is a consumed one-shot. It pins one miner and
the exact vector `[124]`, `[65535]`. It cannot be reused or widened for a second
target. Two weighted miners require a separately reviewed multi-target policy
and writer plus a new chain submission after the weight cooldown.

The current axon announcement authorization is also specific to UID124 and its
one reviewed successor has been consumed. A second hotkey requires a separately
reviewed announcement policy and tool. Do not reuse the UID124 journal or treat
its finalized successor as authorization for another endpoint.

Never copy one hotkey's private key into either audit guest. Each container gets
only its own public `CATHEDRAL_MINER_HOTKEY` value.

## Launch sequence

1. Confirm the hotkey is accepted. If it is already registered, confirm it maps
   to exactly one finalized SN39 UID owned by the intended coldkey. If it is not
   registered, record the exact registration action and current fee before any
   write.
2. Record the reviewed source commit, immutable image digest, platform, runtime
   limit, spend limit, endpoint, and intended validator outcome.
3. Provision one Intel TDX guest with only the required TLS ingress. Keep wallet
   files, cloud credentials, SSH credentials, and validator secrets off the VM.
4. Pull the exact digest anonymously and start the container with the narrow
   configfs TSM report bind documented in
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
- a second machine reuses the first machine's hotkey or UID; or
- the intended weight vector, burn outcome, runtime bound, or spend bound is not
  explicit.

Weight allocation and token earnings are different claims. Report the exact
on-chain weight row when it is proven. Report TAO earnings only after positive
emission and a verified reward or balance delta.

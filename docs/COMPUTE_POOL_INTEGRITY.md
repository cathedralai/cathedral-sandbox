# Compute pool integrity: enclave checks and signed receipts

This is a design reference for reviewers. It records how the direct validator
stops a miner from being paid for a machine it does not run, where that
protection ends today, and the changes that close the remaining gaps. It is not
an operator guide; the repository [README](../README.md) is.

Paths prefixed `cathedral-validator/` are in the validator repository at
`7533d9d`. Other paths are in this repository at `e4f8e92`.

## What a paid machine must prove

The validator pays one unit per distinct verified machine per UID
(`cathedral-validator/cathedral_thin/independent_runtime/direct_validator.py`,
lines 445-448). A row counts only when all of these hold in the same round:

1. **Fresh vendor evidence bound to this connection.** The quote or report
   carries REPORTDATA v2: SHA-512 over a domain tag, the validator's nonce, the
   miner hotkey, and the SHA-256 of the TLS SubjectPublicKeyInfo the validator
   is connected to (`cathedral/common.py` lines 249-295, re-derived
   independently in `cathedral-validator/cathedral_thin/independent/collect.py`
   lines 192-233). The nonce is new per machine per round and starts with a
   hash of the validator's hotkey, so a quote collected by someone else cannot
   be replayed as this validator's challenge (`collect.py` lines 53-59,
   236-258).
2. **The same TLS key throughout.** The validator records the peer SPKI at the
   handshake and refuses the round's evidence or SAT response if it changes
   (`cathedral-validator/cathedral_thin/independent_runtime/fleet_score.py`
   lines 183-189 and 230-246).
3. **A verified hardware identity.** Intel TDX: a stable platform id derived
   from the PPID in the verified PCK certificate
   (`cmd/cathedral-tdx-verifier/main.go` lines 430 and 472-481). AMD SEV-SNP:
   a hash of the processor generation and CHIP_ID
   (`cathedral-validator/cathedral_thin/independent_runtime/snp_production.py`
   lines 243-250). A TDX pass without a verified stable identity earns zero
   (`fleet_score.py` lines 315-327).
4. **A correct SAT answer over the attested channel.** The instance is seeded
   from the finalized anchor block, the miner hotkey and the machine's TLS key,
   so each machine gets its own challenge. The validator prices the work
   itself and discards the miner's number
   (`cathedral-validator/cathedral_thin/independent/sat.py` lines
   286-304 and 377-414).
5. **No shared identity anywhere in the round.** Any endpoint, TLS key or
   hardware identity claimed by more than one row, across all UIDs, zeroes
   every claimant (`fleet_score.py` lines 1040-1067;
   `cathedral-validator/cathedral_thin/independent_runtime/multicompute.py`
   lines 140-210).

A round with any unproven step writes no weights: an infrastructure error,
a blocked feature, or a missing identity adapter stops the whole cycle
(`direct_validator.py` lines 355-361).

## Copying attacks and what stops each

| Attack | Stopped by |
|---|---|
| Replay an old quote | Fresh per-round nonce (`fleet_score.py` line 175) |
| Present a quote collected for another validator | Validator-derived nonce prefix (`collect.py` lines 236-258) |
| Relay machine A's quote through front end B | REPORTDATA must name the TLS key the validator observed; the key must not change between evidence and SAT |
| One physical machine behind several UIDs or endpoints | Hardware dedupe zeroes every claimant |
| One TLS key on several endpoints | Channel dedupe zeroes every claimant |
| Copy another miner's SAT answer | The seed includes the hotkey and TLS key, so the challenge differs |
| Inflate claimed work | The validator derives the units; the miner's figure is ignored |

## Where protection ends today

**Intel TDX boot state is not checked.** The released verifier already emits a
launch measurement over TD attributes, XFAM, MRTD, MRCONFIGID, MROWNER,
MROWNERCONFIG and RTMR0-3 (`cmd/cathedral-tdx-verifier/main.go` lines 483-513;
[MRTD.md](MRTD.md)). The direct validator never reads it: its quote wrapper
checks only `intel_verified` and `report_data_match`, then the platform
identity fields
(`cathedral-validator/cathedral_thin/independent_runtime/qvl.py` lines 206-210
and 250-269). Any genuine TDX guest passes, whatever it booted. A modified
guest can write REPORTDATA for a TLS key held outside the enclave and answer
SAT from anywhere; hardware dedupe still limits this to one paid identity per
physical TDX platform.

**AMD SEV-SNP boot state is checked.** Each validator's owner policy admits an
exact measurement per processor generation and applies a component-wise TCB
floor to the current, reported, committed and launch TCB, with VMPL0, debug
and migration refused and SINGLE_SOCKET required by default
(`snp_production.py` lines 122-182 and 305-452).

**Neither path proves the container image.** A measurement describes measured
boot state. The OCI image digest is checked only by the local launcher
([MRTD.md](MRTD.md);
[AMD_SEV_SNP_FRIEND_TEST.md](AMD_SEV_SNP_FRIEND_TEST.md)).

**An Intel collateral outage zeroes TDX machines instead of stopping the
round.** The verifier exits with status 1 on every error, including a failed
collateral fetch (`cmd/cathedral-tdx-verifier/main.go` lines 555-564), and the
validator maps any nonzero exit to FAIL rather than INFRA (`qvl.py` lines
198-199). SNP separates the two cases: a vendor key-server outage is an
infrastructure failure (`snp_production.py` lines 470-477).

**No receipt reaches the weight path.** The assurance receipts in
[RECEIPTS.md](RECEIPTS.md) and the customer receipts in
[CUSTOMER_RECEIPTS.md](CUSTOMER_RECEIPTS.md) are library features; the direct
validator consumes neither. Its only signed outputs are the chain weight write
and a telemetry event that carries the digest of its evidence document
(`direct_validator.py` lines 451-469;
`cathedral-validator/cathedral_thin/independent_runtime/telemetry.py`). A miner
cannot learn from any signed artifact why a machine was or was not paid.

## Design

### 1. Gate TDX on a signed measurement policy

Mirror the SNP owner policy. The validator loads a root-owned policy file,
`cathedral_intel_tdx_policy_v1`, containing a sorted, non-empty list of
`tdx-measurement-sha256:` values, and refuses to start without one when TDX
scoring is enabled.

- `qvl.py` returns the verifier's `measurement` claim with the verdict.
- `fleet_score.py` fails a TDX row whose measurement is not admitted, with the
  reason `tdx_measurement_not_admitted`, before SAT is sent.
- The verifier binary does not change. The measurement format is already
  released and documented in [MRTD.md](MRTD.md).
- Changing an admitted value follows the existing approval path
  (`scripts/cathedral_measurement_approval.py`): live capture through the
  pinned verifier, an operator identity and reason, and a new policy release.

Roll out in shadow first: log the reason for one release without changing
weights, publish the observed measurements, then enforce.

### 2. Keep an Intel outage out of miner scores

Give the verifier distinct exit codes for "the quote is wrong" and "Intel's
collateral service did not answer", and map the second to INFRA in `qvl.py`.
The round then stops as it does for an SNP key-server outage, instead of
zeroing every TDX machine.

### 3. Sign a per-machine receipt each cycle

After the weight write is confirmed, the validator signs one
`cathedral_machine_receipt_v1` per probed machine with its hotkey (sr25519,
the key that already signs telemetry). The receipt carries:

- the anchor block and the validator's evidence digest;
- the UID, miner hotkey, endpoint and TLS SPKI digest;
- the hardware identity and measurement that were checked;
- the SAT challenge id and the units the validator derived;
- the outcome: `paid`, or the exclusion reason already recorded internally
  (for example `duplicate_hardware_identity` or `snp_tcb_floor_not_met`).

Each receipt is a leaf of the evidence document, so anyone holding the
receipt, the telemetry event and the validator's public key can check that it
belongs to the round that set weights. This gives miners a verifiable reason
per machine, and gives central tracking a signed per-machine record to count.

### 4. Bind the image into measured state

Close the image gap on SNP first, where boot state is already gated: the
launcher derives HOST_DATA or the guest's measured command line from the
pinned image digest, so the admitted measurement implies the image. For TDX,
extend the image digest into RTMR3 before the worker starts and admit the
resulting measurement under design item 1.

## Order of work

1. TDX measurement policy, in shadow, then enforced.
2. Intel outage mapped to INFRA.
3. Per-machine signed receipts.
4. Image binding, SNP then TDX.

Items 1-3 change only the validator. Item 4 changes the miner images and the
launch procedure.

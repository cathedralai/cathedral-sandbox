# Attested customer work

Status: **draft, and not ready to build**. This document exists to record a
problem with the obvious design before anyone implements it. The small
admission decision in this change is implemented and tested. The guarantee the
feature is meant to sell is **not** delivered by that decision, and this
document says why.

## The problem, honestly stated

The runtime sends customer work to any miner that answers
`{"customer_sat": true}` on `/v1/capabilities`
(`cathedral/runtime.py:1446-1464`). That is a claim made by code the machine's
operator controls.

The obvious fix is to pin the TEE measurement, so only an approved guest image
can receive work. **That fix does not do what it appears to do.**

The measurement is a hash of boot-time state — MRTD plus the runtime
measurement registers (`docs/MRTD.md`). The worker is a Python package sitting
on the guest filesystem (`Dockerfile.sn39-audit-miner:21`), started after boot.
Nothing extends a measurement register when that code is read, and no OCI layer
digest is in the measurement. So an operator can:

1. boot the approved guest,
2. edit the worker code, or the data it reads, on the guest disk,
3. obtain a quote that is byte-identical to the approved one.

The repository already concedes the general shape of this: `docs/MRTD.md`
states that a matching measurement does not by itself prove a particular OCI
image, and the AMD miner documentation states the validator does not remotely
attest the OCI image digest.

**So "pin the boot measurement" is not a workload control.** It constrains the
boot stack and nothing about the code that handles customer work. A design sold
on "only approved software runs" would be selling something it does not
deliver.

## What a boot measurement *is* good for

Not nothing. It is a real control for:

- proving the machine is a genuine TEE of an expected platform family,
- proving a known, approved boot stack with an acceptable TCB and no
  debug or migration mode,
- distinguishing an approved platform from an arbitrary one.

That is worth having. It is simply not the same claim as "your workload ran in
approved code".

## What would actually bind the workload

Four options. Two of them reuse machinery that **already ships in this
repository**, which changes what each costs.

**1. Gate the payload on an attestation-bound key release.** An earlier draft
of this document omitted this and it is worth real consideration.
`cathedral/key_release.py` already requires fresh attestation under 60
seconds, an allowed measurement, passed hardware/software/channel claims, and
an X25519 key bound into that attestation before it issues a data key at
assignment time. Bind the grant to the signed workload manifest digest and
the operator cannot decrypt the payload without passing the gate. The library
exists; it is not on this path, and `docs/KEY_RELEASE.md` marks it as such.

**Its limit, stated honestly:** this does not bind the code that consumes the
plaintext. An operator who controls the guest holds a legitimately attested
key, decrypts with it, and then feeds the plaintext to modified worker code.
It protects the payload from non-approved platforms and from passive
observers, not from the operator running it.

**2. Reuse the signed OCI-digest admission contract.** Nearly free.
`cathedral/workload.py` mints `cathedral_workload_manifest_v1` from a
digest-pinned image plus an external signature verdict, and
`docs/WORKLOAD_ADMISSION.md` already names its canonical digest as *"the typed
integration value for future key release and public receipts"*. Putting it into REPORTDATA per request is
the smallest real first step, and it composes with option 1 rather than
competing with it.

**3. Extend a runtime measurement register with the workload.** Put the
workload digest into RTMR before the work runs, so a fresh quote commits to
it. Needs a measured workload loader on the guest and a verifier that reads
the register. This is the only option that binds the *code* rather than a
digest the worker reports. Genuinely new work.

**4. Ship the worker as a measured minimal image.** Strongest in principle,
requires verifiable image provenance end to end, and does not cover code
fetched after boot. Genuinely new work.

Options 1 and 2 are configuration and integration against code that is
already written and tested. Options 3 and 4 are new systems. They should not
be presented as four peers.

## What this document records

This is a findings document, not a change. An earlier version of this branch
also carried a caller-side admission module,
`customer_work_admission.py`. Review recommended removing it, and it has been removed. The reasons
are worth recording, because the same module will otherwise be rebuilt:

- **It is not a security boundary.** `Attested` is a plain dataclass whose
  `verification_status` defaults to `"VERIFIED"` and whose `chain_verified`
  defaults to `True`. A hand-built or defaulted verdict is therefore admitted.
  The module's own docstring said so.
- **It has no callers.** Nothing in the dispatcher or the worker imports it.
- **A security-shaped object that is not a security boundary is a net
  negative.** A future engineer grepping for it finds a plausible control,
  whose existence substitutes for its function.
- **It was bypassed seven times** by adversarial review, every time through the
  same class of defect: the gate read a field the verifier does not guarantee.

### The field class, in full

Fields of `Attested` whose **default is the admitted value**:

| Field | Default | Consequence |
|---|---|---|
| `verification_status` | `"VERIFIED"` | the admitted value itself |
| `chain_verified` | `True` | the admitted value itself |
| `advisory_ids` | `()` | `set(()).issubset(allowed)` passes vacuously |
| `policy_mode` | `None` | coerced to "compatibility", the weaker mode |

The TDX, mock and GPU builders never set the first two. Every bypass found
across four review rounds was an instance of this one class.

### Where the decision belongs instead

The worker never verifies anything. It collects and serialises quotes; the
caller verifies them. So a worker-side gate cannot exist in this topology, and
an admission decision must live in the process that runs the verifier.

The durable fix is to make the verdict carry provenance: a required field with
no default, assigned only by the verifier, so a defaulted or hand-built verdict
fails everywhere at once. Cost: `proto/evidence.proto`, four construction
sites, gate reads, and the receipt and ledger schema. A cheaper partial is to
delete the two permissive verdict defaults and use an explicit sentinel for
`advisory_ids`.

## What this change does not do

- **No dispatcher wiring.** `runtime.py` still admits on the self-reported
  flag. Wiring the decision in is the change that matters, and this document
  argues it should wait until the workload-binding question is settled.
- No route change, no entrypoint posture, no measurement extraction.
- No workload-agnostic route. Building one is step 5 below and is not
  justified while there is one workload.

## Order of work

1. **Decide the binding mechanism.** Until this is answered, more
   enforcement code is premature. The four options above are not equivalent
   and one of them is a product decision about cost per job.
2. **Wire the decision into dispatch**, using the existing `Policy` and a
   verified `Attested`.
3. **Report capability honestly.** `/v1/capabilities` should say which
   workloads a worker accepts and how its evidence is bound, so the dispatcher
   knows what to ask for. Keep `customer_sat` for compatibility.
4. **Entrypoint posture**, opt-in and deliberate, only after 2 and 3.
5. **Generalise the route** from `sat-work` to workload-parameterised
   submission, keeping the first workload registered by name.

## Why not simply enable it now

The pinned image already contains `--allow-customer-sat`
(`cathedral/cli.py:4282` at revision `78e588e`), and `docker run --entrypoint`
lets an operator run it without the bundled entrypoint, which is the only thing
currently in the way.

That is an argument for building a control, not for switching the posture on.
Enabling it before the workload-binding question is answered would remove the
only current obstacle and replace it with a measurement check that a
determined operator can satisfy with a different worker on the same guest.

## Limits to publish with any customer-work offering

- Confidentiality covers guest memory and register state. It does **not** cover
  the guest's persistent disk, and it does **not** detect an operator restoring
  an earlier disk image.
- On the Intel TDX path as the direct SN39 validator is currently configured,
  no measurement allowlist is applied at all.
- Capacity is whatever miners are online. Bursty, unreserved, no SLA.
- Results are verified, not merely reported.
- State the resource ceiling per workload rather than implying one general
  ceiling.

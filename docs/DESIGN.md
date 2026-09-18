# Developer architecture

This is a code map, not a mining guide. Use the repository
[README](../README.md) to run a miner.

The repository contains both the current SN39 worker and reusable or retired
library components. The current validator reads miners directly. It does not
use the older enrollment service, signed weight publisher, provenance bundle,
or burn mechanism.

## 3. Hardware profiles

Intel TDX and AMD SEV-SNP both encrypt guest memory and CPU state, so a host
operator cannot read a running guest. Those two scored paths are not equivalent
in what the direct validator checks, and the difference decides what a customer
is actually guaranteed.

- **AMD SEV-SNP.** The direct validator counts a machine only after its
owner-controlled policy accepts the exact measurement and TCB, then fresh
evidence, TLS binding, and SAT pass. The admitted measurement constrains the
guest's boot state.
- **Intel TDX.** The direct validator verifies a current quote, the
nonce/hotkey/TLS binding, and the stable platform identity, and requires SAT.
It applies no measurement allowlist, so it does not constrain the guest's boot
state. That is a missing code path rather than an operator setting: the direct
validator accepts no TDX measurement policy as input, while the verifier
library accepts one and the reward-receipt lane requires one. See
[TDX_LAUNCH.md](TDX_LAUNCH.md).

A boot measurement describes measured boot state, not a disk image. Image
identity can be extended into measured state, but the repository states
elsewhere that a matching measurement does not by itself prove a particular OCI
image, and neither path attests a container digest.

Neither path protects the guest's persistent disk, and neither detects a host
operator restoring an earlier disk state. Disk encryption and any freshness
check belong to the guest.

This code map does not define a GPU mining path.

## 4. Work lane

`cathedral/lanes/sat.py` defines the bounded SAT request and result grammar.
The current validator sends one canonical SAT task to each candidate machine
after fresh evidence verification.

## 5. Scoring

The direct validator sums verified SAT work from distinct machines. Every
verified claimant involved in a duplicate endpoint, platform identity, or TLS
key receives zero for that round. The current mechanism has zero burn.

## 6. Attestation and binding

`cathedral/verify/` verifies vendor evidence. A successful Intel TDX check
binds the challenge, miner hotkey, and live TLS public key. Platform identity
is also used to prevent one machine from being counted more than once.

## 7. Local control-plane library

`cathedral/api.py`, `cathedral/runtime.py`, and related modules provide local
library primitives. They do not define a public Cathedral service or a second
miner launch path.

## 9. Reference neurons

`cathedral/neuron/` contains in-process reference implementations used by the
test suite. The production validator is maintained in the separate
`cathedral-validator` repository.

## 10. Host census

`cathedral census` reports locally visible confidential-compute capabilities.
It is a prerequisite check, not remote attestation and not proof of weight.

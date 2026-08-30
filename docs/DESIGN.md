# Developer architecture

This is a code map, not a mining guide. Use the repository
[README](../README.md) to run a miner.

The repository contains both the current SN39 worker and reusable or retired
library components. The current validator reads miners directly. It does not
use the older enrollment service, signed weight publisher, provenance bundle,
or burn mechanism.

## 3. Hardware profiles

Intel TDX and AMD SEV-SNP are confidential CPU profiles. The direct validator
counts an SNP machine only after its released SNP policy accepts the exact
measurement and TCB, then fresh evidence, TLS binding, and SAT pass. This code
map does not define a GPU mining path.

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

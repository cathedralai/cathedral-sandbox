# Validated CPU capacity

`cathedral.capacity` is the shared library for paying miners by real, reachable CPU capacity.
The prober, the sandbox it probes and every validator use the same code.

## Roles

- **Miner:** turns a server into a Cathedral runtime box (the runtime's
  `install-runtime-host.sh`) and registers it with their hotkey.
- **Prober (run by the SN94 owner):** each round, for each box: creates a sandbox through the
  box's front door, runs the challenge in it, checks the answer, deletes the sandbox, and signs
  a receipt. It runs in a measured TDX guest.
- **Validators (any netuid; Cathedral runs SN39 and SN94):** fetch their own receipts, verify
  them with the prober keys they pin, and pay each box the market value of its verified
  capacity. They never contact miner boxes.

## Challenge (`challenge.py`)

One lane per claimed vCPU, together holding 80% of the claimed memory. Each lane is
scrypt-like over SHA-256: fill `blocks` 32-byte blocks, then take two data-dependent reads per
block, writing each back. A box with fewer cores or less memory cannot finish within the
prober's deadline.

Commit, then sample:

1. the prober sends `spec_for(seed, vcpus=, memory_gib=)` with a fresh seed. The parameters
   are fixed by the protocol, and a claim the challenge cannot prove (over 1024 vCPUs, or over
   10 GiB per vCPU) is refused, not proven in part;
2. the box returns every lane's output (`python -m cathedral.capacity.challenge`, or a native
   worker computing the same function), which commits it: `result_digest`;
3. only then does the prober draw a fresh 32-byte nonce and recompute the lanes
   `sample_lanes(spec, digest, nonce, 4)` picks (`verify`). Since the nonce comes after the
   commitment, a box cannot steer the sample onto the few lanes it computed honestly.

**Rules for the prober** (the library cannot enforce the order of events):

- draw `sample_nonce` from a CSPRNG only after all outputs have arrived, and never derive it
  from anything public (seed, round, box);
- one attempt per seed, and a capped number of attempts per box per round; a retry with the
  same seed and a new nonce gives a dishonest box another chance;
- probe a memory-heavy box (over 10 GiB per vCPU) at `provable_memory_gib(vcpus, memory_gib)`,
  which is also what it is paid for;
- set `deadline_ms` from a published formula over the spec, so validators can tell a tight
  deadline from a loose one (to be fixed before enforcement);
- the lanes hold 80% of the claimed memory; watch shadow mode for honest boxes failing for
  lack of headroom.

**Cost.** Proving a box holds `M` of memory across `C` cores needs lanes of `M / C` each, and
checking a lane means recomputing it. The pure-Python reference computes about 32 MiB of lane
per second (a full 2 GiB lane for an 8 vCPU, 32 GiB box takes about two minutes), so the
prober and the sandbox should run a native implementation of the same function. Validators
check receipt signatures; recomputing a sampled lane is an optional audit, sensibly done for a
few boxes per round.

## Receipts (`receipt.py`)

Schema `cathedral_capacity_receipt_v1`: canonical JSON plus a base64 Ed25519 signature by the
key named in `prober_key_id`. `verify_receipt` checks:

- **audience:** the netuid, the requesting validator's nonce and (optionally) the round;
  anything else is refused, so copying another validator's weights gains nothing;
- **box:** `box_id`, the miner's hotkey, its kind, and a hardware identity for dedup:
  `ppid` or `chip_id` for a `tee` box, a `probe_fingerprint` for `bare_metal`;
- **capacity equals proof:** the spec must be exactly `spec_for(seed, vcpus=, memory_gib=)`
  for the vCPUs and memory the receipt pays for;
- **sample:** the committed digest, the post-commitment `sample_nonce`, and the outputs of
  exactly the lanes that nonce picks, so anyone can recompute which lanes were checked and
  re-check them with `lane_output`;
- **timing:** the exec time fits the prober's `deadline_ms`;
- **validity:** a window of at most two hours, a signature by a pinned key.

## Pricing (`pricing.py`)

Schema `cathedral_capacity_price_table_v1`, signed by an SN94 owner key that validators pin.

- `rates`: `vcpu_hour` and `gib_hour` for `tee` and for `bare_metal`, in integer micro-units
  of `currency` per hour, set from market prices.
- `consumer_profiles`: the minimum shape each consuming subnet needs (for example `sn120`,
  `sn81`).

`value(kind=, vcpus=, memory_gib=)` = `vcpus × vcpu_hour + memory_gib × gib_hour` at the rate
for the box's kind, or zero when the box is below every consumer profile.

Each table has a `sequence`. A validator passes the highest it has verified as
`minimum_sequence`, so whoever serves tables cannot roll it back to an older signed one.

## Not here yet

The prober service, box registration and routing live in the Cathedral control plane. The
validator-side scoring (dedup, then value) lands in cathedral-validator.

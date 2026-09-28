# Validated CPU capacity

`cathedral.capacity` is the shared library for paying miners by real, reachable CPU capacity.
The prober, the sandbox it probes and every validator use the same code. Citations are
`file:line` in `cathedral/capacity/`.

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
block, writing each back. What this proves today is narrower than "the box has these cores and
this memory": the sampled lanes were computed correctly, and the deadline keeps a vCPU claim
within about 2.5 times (up to 2.9 at the smallest lane) what the box's cores can compute at the
measured native speed (see Timing and "What a receipt proves today").

Commit, then sample:

1. the prober sends `spec_for(seed, vcpus=, memory_gib=)` with a fresh seed. The parameters
   are fixed by the protocol, and a claim the challenge cannot prove (over 1024 vCPUs, over
   10 GiB per vCPU, or under 0.625 GiB per vCPU, the 512 MiB lane floor) is refused, not proven
   in part (`challenge.py:127-148`);
2. the box returns every lane's output, computed by a native worker (the pure-Python
   `python -m cathedral.capacity.challenge` is the reference and a checker only: it cannot meet
   the deadline, see Cost), which commits it: `result_digest`;
3. only then does the prober draw a fresh 32-byte nonce and recompute the `sample_count` lanes
   `sample_lanes(spec, digest, nonce, sample_count)` picks (`verify`, `challenge.py:251-265`).
   Since the nonce comes after the commitment, a box cannot steer the sample onto the lanes it
   computed honestly.

### How many lanes are sampled

`sample_count` must be at least `required_samples(lanes) = min(lanes, max(4, ceil(lanes / 2)))`
(`challenge.py:168-174`) and at most `lanes`. So a box of 4 vCPUs or fewer has **every** lane
recomputed (not "at least 4": a 2-vCPU box has 2 lanes, both checked), a box of 5 to 8 vCPUs has
4, and a larger box at least half. The prober may sample more, up to every lane; the receipt
records the count it used.

A box that returns garbage for `f` of its `n` lanes passes a `k`-lane sample with probability
`C(n - f, k) / C(n, k)`, which is at most `(1 - k/n)^f`, so at most `2^-f` once `k >= n/2`
(checked in `tests/test_capacity.py`, `test_the_documented_pass_probabilities_hold`):

| lanes `n` | sampled `k` | fake 1 lane | fake 2 | fake 3 |
|---|---|---|---|---|
| 1 to 4 | `n` | 0 | 0 | 0 |
| 5 | 4 | 0.20 | 0 | 0 |
| 6 | 4 | 0.33 | 0.07 | 0 |
| 8 | 4 | 0.50 | 0.21 | 0.07 |
| 16 | 8 | 0.50 | 0.23 | 0.10 |
| 64 and up | `n/2` | 0.50 | 0.25 | 0.12 |

**Sampling alone cannot catch a box one core short.** A box with `n - 1` cores claiming `n`
can compute `n - 1` lanes honestly and fake one, and passes the floor sample about half the
time. In expectation that does not pay while value is linear in vCPUs (half of `n` lanes' pay
is less than `n - 1` lanes' pay for `n > 2`), but it does pay at a consumer-profile threshold,
where `n - 1` vCPUs earn zero. The deadline cannot fully carry that case either: a short box
that fakes nothing runs `n` lanes on `n - 1` cores by time-slicing, which takes only `n / (n - 1)`
as long (about 1.6% longer at 64 lanes), well inside any deadline that tolerates normal CPU
variance. Timing can separate large shortfalls, not one missing core. So:

- a prober that needs certainty for a box at a profile threshold sets `sample_count = lanes`
  (it recomputes the whole answer);
- a failed sample is evidence of cheating, not bad luck: the prober should withhold receipts
  for that box for several rounds, which makes a 50% pass rate cost more than it earns.

### Rules for the prober

The library cannot enforce the order of events:

- draw `sample_nonce` from a CSPRNG only after all outputs have arrived, and never derive it
  from anything public (seed, round, box);
- one attempt per seed, and a capped number of attempts per box per round; a retry with the
  same seed and a new nonce gives a dishonest box another chance;
- probe a memory-heavy box (over 10 GiB per vCPU) at `provable_memory_gib(vcpus, memory_gib)`
  (`challenge.py:151-156`), and a CPU-heavy box (under 0.625 GiB per vCPU) at
  `provable_vcpus(vcpus, memory_gib)` (`challenge.py:159-165`); that is also what it is paid
  for;
- probe boxes that may share a host **at the same time** (see Hardware identity);
- the lanes hold 80% of the claimed memory; watch shadow mode for honest boxes failing for
  lack of headroom.

### Timing

`deadline_ms` must be at least 1 and at most `max_deadline_ms(spec) = 5 000 +
ceil(steps × 1 000 ns / 1e6)` (`challenge.py:177-185`, constants `challenge.py:59-76`,
enforced at `receipt.py:384-386`), and the exec time must fit it (`receipt.py:393-394`). So the
bound is on `exec` alone; creating the sandbox is timed separately (`timings_ms.create`). Lanes
are meant to run in parallel, so it follows one lane's `steps`:

- **startup allowance, 5 s** (`DEADLINE_STARTUP_MS`): the exec round trip, starting the native
  worker and first-touching the lane memory, each about a second or less. It adds 15% to the
  smallest lane's 34 s per-step budget.
- **per-step budget, 1 µs** (`DEADLINE_NS_PER_STEP`), 2.5 times the measured native speed.
  `ASSUMED_NATIVE_NS_PER_STEP = 400` comes from a plain C lane over OpenSSL's SHA-256 (the same
  function, fill included, 4 KiB pages) on one EPYC 9354P development VM with 4 cores: about
  0.38 µs per step on one core, 0.40 to 0.46 µs with all four busy, on 512 MiB lanes. This is
  **one measurement on one VM**, not a calibration. An 8 vCPU, 16 GiB box computes its challenge
  in about 43 s against a 112 s bound; an 8 vCPU, 32 GiB box has about 3.7 minutes.
- **lane floor, 512 MiB** (`MIN_LANE_BYTES`, `challenge.py:54-58`): `spec_for` refuses a
  claim of less than 0.625 GiB per vCPU. Without it, many vCPUs over little memory make lanes so
  short that the bound is almost all startup allowance. The SN120 profile shapes of 1 vCPU x
  4 GiB and 2 vCPU x 4 GiB (3.2 and 1.6 GiB lanes) are well above it
  (`test_the_lane_floor_admits_the_consumer_shapes_and_refuses_thin_claims`).

**Why the old bound failed.** A challenge's total work is fixed by the claimed memory, whatever
the vCPU count, while one lane's steps shrink as vCPUs grow. The first bound was a flat 120 s
base plus 5 µs per step, so it fell to about 120 s for a large vCPU claim: 8 cores claiming
1024 vCPUs over 16 GiB finished in the same 95 s as the honest 8 vCPU claim, under a 124 s
cap, and the receipt verified. The next one (10 s plus 2 µs per step, set against a hashlib-speed
"native" figure of 0.89 µs per step) still allowed about 5 times: 4 cores computed all 20 lanes
of a 20 vCPU, 13 GiB claim in 77.2 s under its 79.8 s bound, holding about 2.1 GiB of the 13
GiB claimed. Both claims are now refused: the first by the lane floor, the second by the
deadline (its bound is now 39.9 s), and `verify_receipt` refuses such receipts even when they
are signed (`test_the_reviewers_inflated_receipt_is_refused`,
`test_verify_receipt_refuses_an_exec_over_the_bound`).

**Residual inflation factor.** A box with `C` cores computing `V > C` lanes takes `V / C` times
as long as one lane, so it meets the bound only while `V / C` is at most the per-step budget over
the native per-step time: 1 µs / 0.4 µs = 2.5 for large lanes, up to about 2.9 at the lane
floor, where the startup allowance counts most (checked by brute force in
`test_a_vcpu_claim_inflates_at_most_the_documented_factor`). That is down from 128 times, but
it is not 1, and it holds only for workers no faster than the measured C lane: a faster worker
(huge pages, a tighter SHA-256, a faster CPU) raises it in proportion.
**Validator #257 must stay shadow-only, and must not let receipts affect weights, until the
per-step budget is calibrated on native workers across real CPUs** and set just above the
fastest honest one.

**What a receipt proves today.** The sample proves the lanes were computed correctly for the
claimed shape. The deadline proves the box computed them at no less than about 1 / 2.5 (1 / 2.9
at the lane floor) of the claimed vCPUs' native throughput, and so held at least about that
fraction of the lane memory at once (a box with `C` cores needs only `C` lanes in memory at a
time). It does not prove the exact core count or the total memory: one core short of the claim
is invisible to timing (see How many lanes are sampled), and both bounds rest on one VM's
native-speed measurement. Treat a receipt as evidence that the box computed the challenge for
the claimed shape within that factor, not as proof that it has that many cores or that much
memory.

### Cost

Proving a box holds `M` of memory across `C` cores needs lanes of `M / C` each, and checking a
lane means recomputing it. The pure-Python reference takes about 1.5 to 1.6 µs per step on the
development VM (about 9 MiB of lane per second; a full 3.2 GiB lane for an 8 vCPU, 32 GiB box
takes about six minutes). That is over the 1 µs budget, so it **cannot** answer a probe in
time: it is the reference and a checker only, and the box must run a native worker computing
the same function. The prober should check sampled lanes with a native build too. With half the
lanes sampled, the prober spends about half the box's CPU time per probe. Validators check
receipt signatures; recomputing a sampled lane is an optional audit, sensibly done for a few
boxes per round.

## Receipts (`receipt.py`)

Schema `cathedral_capacity_receipt_v1`: canonical JSON plus a base64 Ed25519 signature by the
key named in `prober_key_id`. The prober signs only a body that passes the same checks
(`sign_receipt`, `receipt.py:266-273`; it refuses a body that already carries a signature).
`verify_receipt` checks, and every date, time and `now` error is a `ReceiptError`
(`receipt.py:142-155`), never a bare `ValueError` or `TypeError`:

- **shape:** exactly the known fields and schema (`receipt.py:315-316`), non-negative integer
  netuid and round (`receipt.py:317-318`), a well-formed `prober_key_id`
  (`receipt.py:320-324`);
- **signature:** by a pinned prober key (`receipt.py:294-301`);
- **audience:** the netuid, the requesting validator's nonce and the round, all required
  (`receipt.py:288-289`, `receipt.py:302-307`); anything else is refused, so copying another
  validator's weights gains nothing and a receipt from an earlier round cannot be replayed;
- **box:** `box_id`, the miner's hotkey, its kind, and one hardware identity fixed by the kind
  (`receipt.py:326-345`, below);
- **capacity equals proof:** the spec must be exactly `spec_for(seed, vcpus=, memory_gib=)`
  for the positive vCPUs and memory the receipt pays for (`receipt.py:348-364`);
- **sample:** the committed digest, the post-commitment `sample_nonce`, a `sample_count` from
  `required_samples(lanes)` to `lanes`, and the outputs of exactly the lanes that nonce and
  count pick (`receipt.py:367-383`), so anyone can recompute which lanes were checked and
  re-check them with `lane_output`;
- **timing:** `deadline_ms` within `max_deadline_ms(spec)`, non-negative integer
  `timings_ms`, and the exec time within the deadline (`receipt.py:384-394`); see Timing for
  what this does and does not prove;
- **validity:** a window of more than zero and at most two hours (`receipt.py:396-399`),
  containing `now` within five minutes of clock skew (`receipt.py:308-310`).

### Hardware identity

Validators pay one unit per distinct machine, so each kind of box has exactly one identity
kind (`HARDWARE_ID_KINDS`, `receipt.py:61-65`; checked at `receipt.py:335-344`):

| `kind` | `tee_kind` | `hardware_id_kind` | raw id |
|---|---|---|---|
| `tee` | `tdx` | `ppid` | the 16-byte PPID from the PCK certificate in the TDX quote |
| `tee` | `sev_snp` | `chip_id` | the 64-byte `CHIP_ID` from the SEV-SNP attestation report |
| `bare_metal` | null | `probe_fingerprint` | 9 bytes: the probed IPv4 address, or IPv6 `/64`, tagged with its family (`probe_fingerprint(address)`, below) |

`hardware_id = derive_hardware_id(hardware_id_kind, raw)`: SHA-256 over a domain tag, the id
kind and the raw id (`receipt.py:170-186`). The prober takes the raw id from attestation
evidence it has verified itself, never from a field the box reports. An all-zero id (SEV-SNP
with `MASK_CHIP_ID` set, or a missing PPID) is refused, since every such machine would share
it. A receipt cannot name a TDX machine by chip id or the other way round, so one machine
cannot appear under two identities.

**Bare metal has no hardware root of trust**, so its identity is weaker. `probe_fingerprint`
(`receipt.py:189-210`) is derived from the address the prober itself connected to and ran the
challenge through, never from anything the box reports: the whole IPv4 address, or only the
`/64` of an IPv6 address, and never the port. An IPv4-mapped IPv6 address counts as its IPv4
address, and the address family is part of the raw id, so an IPv4 address cannot collide with a
`/64`. One host behind one address is therefore one identity however many ports, box ids,
hotkeys or IPv6 interface ids it registers under
(`test_one_host_on_many_ports_is_one_bare_metal_box`).

**It fails closed.** Honest boxes behind one address, such as several machines behind one NAT
address or in one IPv6 `/64`, count as **one** box, and only one of them is paid. That is the
conservative choice: a miner with several machines gives each its own public address (or its
own `/64`). The residual weakness runs the other way: the id names an address, not a machine,
so one host reachable at two unrelated addresses has two identities.

**Two addresses, one host.** Boxes are probed one at a time by default, so one host behind two
registered addresses can pass both probes at different times, each with the host's whole
capacity. Mitigation, a rule for the prober: probe every box of one hotkey **concurrently**, so
the host must prove the sum of the capacity it claims at once. That only works as far as the
deadline forces the lanes to run in parallel, which today is within the residual inflation
factor (see Timing). What remains: a host reachable at two unrelated addresses under two
hotkeys, probed at different times. The full fix is to start every box's challenge within one
short window per round; until the prober does that, validators should treat bare-metal capacity
as at most as trustworthy as one box per address.

## Pricing (`pricing.py`)

Schema `cathedral_capacity_price_table_v1`, signed by an SN94 owner key that validators pin.

- `rates`: `vcpu_hour` and `gib_hour` for `tee` and for `bare_metal`, in integer micro-units
  of `currency` per hour from 0 to 10^12, set from market prices (`pricing.py:92-95`,
  `pricing.py:123-133`).
- `consumer_profiles`: the minimum shape each consuming subnet needs (for example `sn120`,
  `sn81`); `min_vcpus` is at most 1024, what the challenge can prove, and `min_memory_gib` at
  most 4096 (`pricing.py:143-150`).
- `effective_from` must be a real date and time, and `key_id` well formed
  (`pricing.py:152-163`).

`value(kind=, vcpus=, memory_gib=)` = `vcpus × vcpu_hour + memory_gib × gib_hour` at the rate
for the box's kind, or zero when the box is below every consumer profile; a non-positive or
non-integer shape is a `PriceTableError` (`pricing.py:78-89`).

`load_price_table` (`pricing.py:190-248`) requires a timezone-aware `now`, a
`minimum_sequence` and a `pinned_digest`, all keyword-only with no default. `minimum_sequence`
is the highest sequence this validator has verified, so whoever serves tables cannot roll it
back to an older signed one (`pricing.py:240-241`). `pinned_digest` is that table's `digest`
(`table_digest`, `pricing.py:98-104`), so a different table signed at the same sequence is
refused (`pricing.py:242-247`). A validator passes an explicit `pinned_digest=None` only on its
very first load, when it has verified no table yet; after that it keeps the sequence and digest
of every table it accepts and passes both. Omitting the keyword is a `TypeError`, so the
same-sequence check is never skipped by accident.

## Not here yet

The prober service, box registration and routing live in the Cathedral control plane. The
validator-side scoring (dedup, then value) lands in cathedral-validator.

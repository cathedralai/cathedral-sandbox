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
block, writing each back. A box with fewer cores or less memory cannot finish within the
prober's deadline.

Commit, then sample:

1. the prober sends `spec_for(seed, vcpus=, memory_gib=)` with a fresh seed. The parameters
   are fixed by the protocol, and a claim the challenge cannot prove (over 1024 vCPUs, or over
   10 GiB per vCPU) is refused, not proven in part (`challenge.py:104-119`);
2. the box returns every lane's output (`python -m cathedral.capacity.challenge`, or a native
   worker computing the same function), which commits it: `result_digest`;
3. only then does the prober draw a fresh 32-byte nonce and recompute the `sample_count` lanes
   `sample_lanes(spec, digest, nonce, sample_count)` picks (`verify`, `challenge.py:209-223`).
   Since the nonce comes after the commitment, a box cannot steer the sample onto the lanes it
   computed honestly.

### How many lanes are sampled

`sample_count` must be at least `required_samples(lanes) = min(lanes, max(4, ceil(lanes / 2)))`
(`challenge.py:130-136`) and at most `lanes`. So a box of 4 vCPUs or fewer has **every** lane
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
where `n - 1` vCPUs earn zero. The deadline carries that case: to fake nothing, the short box
must run `n` lanes on `n - 1` cores, which takes about twice as long, and misses a deadline set
for `n` cores. That works only once the deadline is tight (see Timing), so until then:

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
  (`challenge.py:122-127`), which is also what it is paid for;
- probe boxes that may share a host **at the same time** (see Hardware identity);
- the lanes hold 80% of the claimed memory; watch shadow mode for honest boxes failing for
  lack of headroom.

### Timing

`deadline_ms` must be at least 1 and at most `max_deadline_ms(spec) = 120 000 +
ceil(steps × 5 000 ns / 1e6)` (`challenge.py:139-144`, constants `challenge.py:48-53`,
enforced at `receipt.py:376-378`), and the exec time must fit it (`receipt.py:385-386`). Lanes
run in parallel, so the bound follows one lane's `steps`: a 120 s base for creating the sandbox
and starting the worker, plus about three times the pure-Python reference's per-step time
(1.8 µs per step measured on a 4-core development VM). For an 8 vCPU, 32 GiB box that is
about 20 minutes.

This bound only stops a receipt from carrying an absurd deadline (a receipt with
`deadline_ms = 10^15` was accepted before). It is deliberately generous, so an honest box
running the pure-Python reference is not refused, and it is far looser than a native worker
needs. **Validators must not treat the timing check as a capacity signal until the formula is
benchmarked** on native workers across real CPUs and tightened; until then the sample is the
only capacity evidence in a receipt, with the limits above.

### Cost

Proving a box holds `M` of memory across `C` cores needs lanes of `M / C` each, and checking a
lane means recomputing it. The pure-Python reference computes about 9 MiB of lane per second on
a 4-core development VM (a full 3.2 GiB lane for an 8 vCPU, 32 GiB box takes about six
minutes), so the prober and the sandbox should run a native implementation of the same
function. With half the lanes sampled, the prober spends about half the box's CPU time per
probe. Validators check receipt signatures; recomputing a sampled lane is an optional audit,
sensibly done for a few boxes per round.

## Receipts (`receipt.py`)

Schema `cathedral_capacity_receipt_v1`: canonical JSON plus a base64 Ed25519 signature by the
key named in `prober_key_id`. The prober signs only a body that passes the same checks
(`sign_receipt`, `receipt.py:258-265`; it refuses a body that already carries a signature).
`verify_receipt` checks, and every date, time and `now` error is a `ReceiptError`
(`receipt.py:141-154`), never a bare `ValueError` or `TypeError`:

- **shape:** exactly the known fields and schema (`receipt.py:307-308`), non-negative integer
  netuid and round (`receipt.py:309-310`), a well-formed `prober_key_id`
  (`receipt.py:312-316`);
- **signature:** by a pinned prober key (`receipt.py:286-293`);
- **audience:** the netuid, the requesting validator's nonce and the round, all required
  (`receipt.py:280-281`, `receipt.py:294-299`); anything else is refused, so copying another
  validator's weights gains nothing and a receipt from an earlier round cannot be replayed;
- **box:** `box_id`, the miner's hotkey, its kind, and one hardware identity fixed by the kind
  (`receipt.py:318-337`, below);
- **capacity equals proof:** the spec must be exactly `spec_for(seed, vcpus=, memory_gib=)`
  for the positive vCPUs and memory the receipt pays for (`receipt.py:340-356`);
- **sample:** the committed digest, the post-commitment `sample_nonce`, a `sample_count` from
  `required_samples(lanes)` to `lanes`, and the outputs of exactly the lanes that nonce and
  count pick (`receipt.py:359-375`), so anyone can recompute which lanes were checked and
  re-check them with `lane_output`;
- **timing:** `deadline_ms` within `max_deadline_ms(spec)`, non-negative integer
  `timings_ms`, and the exec time within the deadline (`receipt.py:376-386`); see Timing for
  what this does and does not prove;
- **validity:** a window of more than zero and at most two hours (`receipt.py:388-391`),
  containing `now` within five minutes of clock skew (`receipt.py:300-302`).

### Hardware identity

Validators pay one unit per distinct machine, so each kind of box has exactly one identity
kind (`HARDWARE_ID_KINDS`, `receipt.py:60-64`; checked at `receipt.py:327-336`):

| `kind` | `tee_kind` | `hardware_id_kind` | raw id |
|---|---|---|---|
| `tee` | `tdx` | `ppid` | the 16-byte PPID from the PCK certificate in the TDX quote |
| `tee` | `sev_snp` | `chip_id` | the 64-byte `CHIP_ID` from the SEV-SNP attestation report |
| `bare_metal` | null | `probe_fingerprint` | `probe_fingerprint(address, port)`, below |

`hardware_id = derive_hardware_id(hardware_id_kind, raw)`: SHA-256 over a domain tag, the id
kind and the raw id (`receipt.py:169-185`). The prober takes the raw id from attestation
evidence it has verified itself, never from a field the box reports. An all-zero id (SEV-SNP
with `MASK_CHIP_ID` set, or a missing PPID) is refused, since every such machine would share
it. A receipt cannot name a TDX machine by chip id or the other way round, so one machine
cannot appear under two identities.

**Bare metal has no hardware root of trust**, so its identity is weaker. `probe_fingerprint`
(`receipt.py:188-202`) hashes the IP address and TCP port the prober itself connected to and
ran the challenge through (an IPv4 address in its IPv6-mapped form, so each endpoint has one
fingerprint). The box does not choose it independently of where it is reached, and the same
endpoint registered twice, under two box ids or two hotkeys, collapses to one identity. Its
residual weakness: it names an endpoint, not a machine. One host behind two addresses, or two
ports, has two fingerprints.

**Two endpoints, one host.** Boxes are probed one at a time by default, so one host behind two
registered endpoints can pass both probes at different times, each with the host's whole
capacity. Mitigation, a rule for the prober: probe boxes that share an IP address (an IPv6
`/64`) **concurrently**, so the host must prove the sum of the capacity it claims at once, and
preferably also every box of one hotkey. What remains: a host reachable at two unrelated
addresses under two hotkeys, probed at different times. The full fix is to start every box's
challenge within one short window per round; until the prober does that, validators should
treat bare-metal capacity as at most as trustworthy as one box per address.

## Pricing (`pricing.py`)

Schema `cathedral_capacity_price_table_v1`, signed by an SN94 owner key that validators pin.

- `rates`: `vcpu_hour` and `gib_hour` for `tee` and for `bare_metal`, in integer micro-units
  of `currency` per hour from 0 to 10^12, set from market prices (`pricing.py:91-94`,
  `pricing.py:122-132`).
- `consumer_profiles`: the minimum shape each consuming subnet needs (for example `sn120`,
  `sn81`); `min_vcpus` is at most 1024, what the challenge can prove, and `min_memory_gib` at
  most 4096 (`pricing.py:142-149`).
- `effective_from` must be a real date and time, and `key_id` well formed
  (`pricing.py:151-162`).

`value(kind=, vcpus=, memory_gib=)` = `vcpus × vcpu_hour + memory_gib × gib_hour` at the rate
for the box's kind, or zero when the box is below every consumer profile; a non-positive or
non-integer shape is a `PriceTableError` (`pricing.py:77-88`).

`load_price_table` (`pricing.py:185-237`) requires a timezone-aware `now` and a
`minimum_sequence`: the highest sequence this validator has verified, so whoever serves tables
cannot roll it back to an older signed one (`pricing.py:229-230`). A validator should also
keep that table's `digest` (`table_digest`, `pricing.py:97-103`) and pass it as
`pinned_digest`, so a different table signed at the same sequence is refused
(`pricing.py:231-236`).

## Not here yet

The prober service, box registration and routing live in the Cathedral control plane. The
validator-side scoring (dedup, then value) lands in cathedral-validator.

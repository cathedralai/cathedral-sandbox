# Validated CPU capacity

`cathedral.capacity` is the shared library for paying miners by real, reachable CPU capacity.
The prober, the sandbox it probes and every validator use the same code. Citations are
`file:line` in `cathedral/capacity/` unless they give a full path.

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
within about 4 times (up to 4.6 at the smallest lane) what the box's cores can compute at the
fastest measured native speed, huge pages included (see Timing and "What a receipt proves
today").

Commit, then sample:

1. the prober sends `spec_for(seed, vcpus=, memory_gib=)` with a fresh seed. The parameters
   are fixed by the protocol, and a claim the challenge cannot prove (over 1024 vCPUs, over
   10 GiB per vCPU, or under 0.625 GiB per vCPU, the 512 MiB lane floor) is refused, not proven
   in part (`challenge.py:131-152`);
2. the box returns every lane's output, computed by a native worker (the pure-Python
   `python -m cathedral.capacity.challenge` is the reference and a checker only: it cannot meet
   the deadline, see Cost), which commits it: `result_digest`;
3. only then does the prober draw a fresh 32-byte nonce and recompute the `sample_count` lanes
   `sample_lanes(spec, digest, nonce, sample_count)` picks (`verify`, `challenge.py:255-269`).
   Since the nonce comes after the commitment, a box cannot steer the sample onto the lanes it
   computed honestly.

### How many lanes are sampled

`sample_count` must be at least `required_samples(lanes) = min(lanes, max(4, ceil(lanes / 2)))`
(`challenge.py:172-178`) and at most `lanes`. So a box of 4 vCPUs or fewer has **every** lane
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
  (`challenge.py:155-160`), and a CPU-heavy box (under 0.625 GiB per vCPU) at
  `provable_vcpus(vcpus, memory_gib)` (`challenge.py:163-169`); that is also what it is paid
  for;
- probe boxes that may share a host **at the same time** (see Hardware identity);
- for a TEE box, create the sandbox and run the challenge only over a TLS connection whose peer
  SPKI hashes to the evidence's `tls_spki_sha256`, every round (see Evidence);
- the lanes hold 80% of the claimed memory; watch shadow mode for honest boxes failing for
  lack of headroom.

### Timing

`deadline_ms` must be at least 1 and at most `max_deadline_ms(spec) = 5 000 +
ceil(steps × 1 000 ns / 1e6)` (`challenge.py:181-189`, constants `challenge.py:59-80`,
enforced at `receipt.py:513-515`), and the exec time must fit it (`receipt.py:522-523`). So the
bound is on `exec` alone; creating the sandbox is timed separately (`timings_ms.create`). Lanes
are meant to run in parallel, so it follows one lane's `steps`:

- **startup allowance, 5 s** (`DEADLINE_STARTUP_MS`): the exec round trip, starting the native
  worker and first-touching the lane memory, each about a second or less. It adds 15% to the
  smallest lane's 34 s per-step budget.
- **per-step budget, 1 µs** (`DEADLINE_NS_PER_STEP`), 4 times the assumed native speed.
  `ASSUMED_NATIVE_NS_PER_STEP = 250` is the fastest native lane measured, rounded down. The
  box picks its own page size, and a cheater would use huge pages from day one, so the bound
  assumes them. Measured with a plain C lane over OpenSSL's SHA-256 (the same function, checked
  byte for byte against `lane_output`, fill included), pinned to one core of a 4-core EPYC 9354P
  development VM, in CPU time:

  | lane | pages | µs per step |
  |---|---|---|
  | 256 or 512 MiB | 4 KiB | 0.38 to 0.41 |
  | 256 MiB | 2 MiB, the whole lane (`madvise(MADV_HUGEPAGE)`) | 0.29 to 0.32 |
  | 512 MiB | 2 MiB, about half the lane (the host's free memory was too fragmented for more) | 0.38 to 0.41 |

  On that VM huge pages gain about 1.3 times. A reviewer's run of the same C lane on a shared
  12-core EPYC VM gained 2.8 to 2.9 times (0.97 to 1.19 µs per step with 4 KiB pages, 0.35 to
  0.41 µs with huge pages, on a 512 MiB lane). 1 GiB pages could not be tested: the VM has no
  hugetlb pool, and making one needs root. So 0.25 µs is taken, about 15% below the fastest
  0.29 µs anyone measured, to cover 1 GiB pages and run-to-run spread. These are
  **measurements on two VMs**, not a calibration. An honest native worker should put its lanes
  on huge pages too, which costs it nothing. An 8 vCPU, 16 GiB box computes its challenge in
  about 27 s at the assumed speed (43 s with 4 KiB pages) against a 112 s bound; an 8 vCPU,
  32 GiB box has about 3.7 minutes.
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
the native per-step time: 1 µs / 0.25 µs = 4 for large lanes, up to about 4.6 at the lane
floor, where the startup allowance counts most (checked by brute force in
`test_a_vcpu_claim_inflates_at_most_the_documented_factor`). That is down from 128 times, but
it is not 1, and it holds only for workers no faster than the assumed 0.25 µs per step: huge
pages are already counted, but a tighter SHA-256 or a faster CPU raises it in proportion.
**Validator #257 must stay shadow-only, and must not let receipts affect weights, until the
per-step budget is calibrated on native workers across real CPUs** and set just above the
fastest honest one.

**What a receipt proves today.** The sample proves the lanes were computed correctly for the
claimed shape. The deadline proves the box computed them at no less than about 1 / 4 (1 / 4.6
at the lane floor) of the claimed vCPUs' native throughput, and so held at least about that
fraction of the lane memory at once (a box with `C` cores needs only `C` lanes in memory at a
time). It does not prove the exact core count or the total memory: one core short of the claim
is invisible to timing (see How many lanes are sampled), and both bounds rest on native-speed
measurements from two VMs. Treat a receipt as evidence that the box computed the challenge for
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

Schema `cathedral_capacity_receipt_v2` (`receipt.py:74`; a v1 receipt, which has no evidence,
is refused): canonical JSON plus a base64 Ed25519 signature by the key named in
`prober_key_id`. The prober signs only a body that passes the same checks (`sign_receipt`,
`receipt.py:346-366`; it refuses a body that already carries a signature, and a bare-metal body
unless allowed, below). `verify_receipt` checks, and every date, time and `now` error is a
`ReceiptError` (`receipt.py:197-210`), never a bare `ValueError` or `TypeError`:

- **shape:** exactly the known fields and schema (`receipt.py:444-445`), non-negative integer
  netuid and round (`receipt.py:446-447`), a well-formed `prober_key_id`
  (`receipt.py:449-453`);
- **signature:** by a pinned prober key (`receipt.py:395-402`);
- **audience:** the netuid, the requesting validator's nonce and the round, all required
  (`receipt.py:385-386`, `receipt.py:403-408`); anything else is refused, so copying another
  validator's weights gains nothing and a receipt from an earlier round cannot be replayed;
- **box:** `box_id`, the miner's hotkey, its kind, and one hardware identity fixed by the kind
  (`receipt.py:455-474`, below);
- **capacity equals proof:** the spec must be exactly `spec_for(seed, vcpus=, memory_gib=)`
  for the positive vCPUs and memory the receipt pays for (`receipt.py:477-493`);
- **sample:** the committed digest, the post-commitment `sample_nonce`, a `sample_count` from
  `required_samples(lanes)` to `lanes`, and the outputs of exactly the lanes that nonce and
  count pick (`receipt.py:496-512`), so anyone can recompute which lanes were checked and
  re-check them with `lane_output`;
- **timing:** `deadline_ms` within `max_deadline_ms(spec)`, non-negative integer
  `timings_ms`, and the exec time within the deadline (`receipt.py:513-523`); see Timing for
  what this does and does not prove;
- **validity:** a window of more than zero and at most two hours (`receipt.py:525-528`),
  containing `now` within five minutes of clock skew (`receipt.py:409-411`);
- **evidence:** required for a TEE box and `null` for bare metal (`receipt.py:529`,
  `receipt.py:552-591`, below).

### Evidence

A TEE box's receipt names the attestation the prober verified before it took the hardware id.
`make_body(..., evidence=)` has no default: the prober passes the seven fields for a TEE box
(`dataclasses.asdict` of the `ReceiptEvidence` admission returned) and `None` for bare metal
(serialised as `"evidence": null`). `VerifiedReceipt.evidence` is a frozen `ReceiptEvidence`
(`receipt.py:154-164`), or `None` for bare metal. Each field has exactly one format
(`receipt.py:95-115`), and any other value, type or key set is a `ReceiptError`:

| field | format |
|---|---|
| `evidence_kind` | the box's `tee_kind`: `tdx` or `sev_snp` |
| `evidence_sha256` | 64 lowercase hex: SHA-256 of the raw TDX quote or SEV-SNP report bytes |
| `measurement` | TDX: `tdx-measurement-sha256:<64 hex>`, the launch measurement `cathedral/verify/tdx_quote.py:91-104` computes (and cathedral-validator's TDX measurement allowlist uses). SEV-SNP: 96 lowercase hex, the report's 48-byte `MEASUREMENT` as `cathedral/verify/snp.py:162` reads it. All zeros is refused, as `cathedral/verify/snp.py:485` does. |
| `verifier_digest` | `sha256:<64 lowercase hex>`, the form of the TDX verifier implementation digest (`cathedral/verify/__init__.py:262`, `cathedral/verify/__init__.py:459`) and of cathedral-validator's SNP verifier digest. A verifier known by a bare SHA-256 (cathedral-validator's `qvl_digest`) is written with the prefix, so one verifier has one spelling. |
| `tls_spki_sha256` | 64 lowercase hex: SHA-256 of the DER SubjectPublicKeyInfo of the TLS key the evidence attests, as `tls_spki_binding` computes it (`cathedral/channel.py:76-80`) |
| `attestation_nonce` | 64 lowercase hex, not all zeros: the 32-byte nonce the prober sent with its evidence request, which the quote's REPORT_DATA was made over |
| `attested_at` | `YYYY-MM-DDTHH:MM:SSZ`, a real date and time no later than the receipt's `issued_at`: when the prober verified the quote |

**What it proves.** The prober's signature binds the hardware id, the measurement, the verifier,
the TLS key the prober pinned, the nonce and the time of verification to one piece of evidence,
named by its hash. A validator can check that the receipt's measurement is one it allows and
that the verifier is one it trusts, can see which quote the prober relied on, and can refuse
evidence older than it accepts: `verify_receipt(..., max_evidence_age=)` refuses a TEE receipt
whose `attested_at` is more than that before `now` (`receipt.py:387-390`,
`receipt.py:412-415`). The evidence comes from admission and is reused for every round's
receipt, so without a bound a receipt can rest on an attestation of any age.

**Auditing a receipt end to end.** The receipt carries the quote's hash, not the quote, so a
validator cannot re-verify the quote, or check that the hardware id really came out of it, from
the receipt alone; it trusts the prober for that, as it does for the challenge. With the quote
(from an archive the prober keeps, or from the box itself) anyone can check all of it:

1. hash the quote and compare `evidence_sha256`;
2. verify it with the named verifier and compare the measurement and the hardware id
   (`tdx_hardware_id` or `derive_hardware_id`);
3. compare its REPORT_DATA with `expected_report_data(verified)` (`receipt.py:419-440`), which
   is `report_data_v2(attestation_nonce, box.miner_hotkey, tls_spki_sha256)`
   (`cathedral/common.py:260-295`). That shows the quote was made for this box's hotkey, for
   the TLS key the prober pinned and for the prober's nonce, not replayed from an older round
   or lifted from another box.

Freshness beyond that rests on the prober: the nonce proves the quote answered one request, and
`attested_at` says when, but only the prober's signature says it drew that nonce fresh.

**Rule for the prober: run each round's challenge over the attested TLS key.** The library
cannot check this. Each round, the prober must create the sandbox and run the challenge only
over a TLS connection whose peer SPKI hashes to `evidence.tls_spki_sha256`, and must not sign a
receipt otherwise. That step is what puts the measured capacity inside the attested VM: the
quote binds the TLS key, and the pinned connection binds the challenge to it.

### TEE first: the bare-metal gate

TEE boxes come first and bare metal is deferred. `sign_receipt` refuses a bare-metal body unless
the prober passes the keyword-only `allow_bare_metal=True` (exactly `True`; any other value is a
refusal) (`receipt.py:360-364`). `verify_receipt` still accepts a correctly signed bare-metal
receipt: whether to pay for bare-metal capacity is each validator's own policy flag, not the
library's.

### Hardware identity

Validators pay one unit per distinct machine, so each kind of box has exactly one identity
kind (`HARDWARE_ID_KINDS`, `receipt.py:77-81`; checked at `receipt.py:464-473`):

| `kind` | `tee_kind` | `hardware_id_kind` | raw id |
|---|---|---|---|
| `tee` | `tdx` | `tdx_platform` | the 32-byte digest in the strict TDX verifier's `stable_platform_id`, `tdx-platform-sha256:<64 hex>` (`tdx_hardware_id(stable_platform_id)`, below) |
| `tee` | `sev_snp` | `chip_id` | the 64-byte `CHIP_ID` from the SEV-SNP attestation report |
| `bare_metal` | null | `probe_fingerprint` | 9 bytes: the probed IPv4 address, or IPv6 `/64`, tagged with its family (`probe_fingerprint(address)`, below) |

`hardware_id = derive_hardware_id(hardware_id_kind, raw)`: SHA-256 over a domain tag, the id
kind and the raw id (`receipt.py:225-242`). The prober takes the raw id from attestation
evidence it has verified itself, never from a field the box reports. An all-zero id (SEV-SNP
with `MASK_CHIP_ID` set) is refused, since every such machine would share it. A receipt cannot
name a TDX machine by chip id or the other way round, so one machine cannot appear under two
identities.

**TDX: from `stable_platform_id`, not the raw PPID.** No TDX verifier outputs the raw PPID.
The pinned Go verifier emits only `stable_platform_id = "tdx-platform-sha256:" +
hex(SHA-256("cathedral-tdx-platform-v1\0" + lowercase hex PPID))`
(`cmd/cathedral-tdx-verifier/main.go:430`, `main.go:472-481`), and strict mode accepts it only
when `platform_identity_verified` and `claims_bound_to_quote` are true
(`cathedral/verify/__init__.py:200-206`). cathedral-validator dedupes on the same value
(`machine_id_from_stable_platform_id` in `cathedral_thin/independent/compute.py`).
`tdx_hardware_id(stable_platform_id)` (`receipt.py:245-259`) checks that format, takes the
32-byte digest as the raw `tdx_platform` id and passes it through `derive_hardware_id`. It is
as unique as the PPID: one platform per value unless SHA-256 collides.

The TDX hardware id is stable only under the pinned Go verifier. The Polaris wrapper
(`scripts/tdx_verify_json.py:150-154`) hashes Polaris's own `stable_platform_id` under the
same domain and prefix, so it emits a different `stable_platform_id`, and so a different
hardware id, for the same platform. A prober must take TDX hardware ids from the pinned Go
verifier only.

**Bare metal has no hardware root of trust**, so its identity is weaker. `probe_fingerprint`
(`receipt.py:262-283`) is derived from the address the prober itself connected to and ran the
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

## Admission (`admission.py`)

Before a TEE box is routed sandboxes or probed for receipts, the control plane (or the prober)
admits it. `admit` (`admission.py:274-381`) is a pure function: no network, clock or files. The
caller first verifies the box's quote itself with the pinned verifier (`cathedral/verify/__init__.py`
in strict mode for TDX, `cathedral/verify/snp.py` for SEV-SNP), on the TLS connection that serves
the sandbox API, then passes what it established as a `VerifiedAttestation`
(`admission.py:100-121`): the kind (`tdx` or `sev_snp`), the measurement, the verifier digest,
the SHA-256 of the raw quote or report, the quote's 64-byte REPORT_DATA and exactly one hardware
identity: for TDX the verifier's `stable_platform_id`, for SEV-SNP the raw 64-byte `chip_id`
(bytes or lowercase hex). There is no raw PPID input: no TDX verifier outputs one. With it go the
certificate (or SPKI) from the caller's own handshake, the miner hotkey, the caller's 32-byte
nonce, the box id, a measurement policy and the already-admitted hardware ids.

It checks, and reports every failure together (`admission.py:355-367`):

- **REPORT_DATA** must equal `report_data_v2(nonce, miner_hotkey, binding)`
  (`admission.py:357-361`), the worker's existing v2 construction (`cathedral/common.py:260-295`,
  byte for byte cathedral-validator's `cathedral_thin/independent/collect.py` `report_data_v2`).
  It is SHA-512 over a domain tag, version 2, and four tagged, length-prefixed fields: the nonce,
  the hotkey (UTF-8), the binding type `tls_spki_sha256`, and SHA-256 of the SPKI of the
  certificate the caller saw (`cathedral/channel.py:78-82`). So a quote made for another nonce,
  hotkey or TLS key, or with an `application_key_sha256` binding, is refused
  (`report_data_mismatch`). No new format is added.
- **Hardware id** (`admission.py:325-336`), exactly as receipts name the machine. TDX:
  `tdx_hardware_id(stable_platform_id)`, the `tdx_platform` id over the digest in the pinned Go
  verifier's `stable_platform_id` (see Hardware identity, including why it is stable only under
  that verifier). SEV-SNP: `derive_hardware_id("chip_id", ...)` over the CHIP_ID read from the
  report itself (`cathedral/verify/snp.py:163`). A malformed or missing id is an `AdmissionError`.
- **Measurement** against the policy (`admission.py:362-364`): in `enforce` an unlisted
  measurement is refused (`measurement_not_allowed`); in `shadow` the box is admitted with
  `measurement_allowed: false` recorded, so operators collect the fleet's measurements first.
- **One box per host, first claim wins** (`admission.py:365-367`). TEE boxes are whole hosts: a
  TDX platform id or a CHIP_ID names the physical machine, so co-resident guests share it. If the
  hardware id is already admitted to a different box (another `box_id`, or the same `box_id` under
  another hotkey) the new claim is refused (`hardware_id_admitted_to_another_box`); the first box
  keeps it until the caller removes its entry. The same box presenting the same host again is
  re-admitted. Every key of the registry must be a canonical hardware id
  (`admission.py:253-271`), so a registry keyed another way cannot let a duplicate slip past.

The result is an `Admission` (`admission.py:132-144`): `admitted`, `reasons`, `hardware_id`,
`hardware_id_kind`, `measurement`, `measurement_allowed`, `mode`, the policy digest and, only
when admitted, the `ReceiptEvidence` for the box's receipts (`admission.py:380`). That evidence
goes through the receipt's own evidence check (`admission.py:339-348`), with `tls_spki_sha256`
taken from the caller's handshake, never from the box.

**Policy.** `parse_policy(raw)` (`admission.py:156-212`) takes the file's bytes. The TDX policy
is cathedral-validator #256's file unchanged: `{"schema": "cathedral_tdx_measurement_policy_v1",
"mode": "shadow" | "enforce", "allowed_measurements": ["tdx-measurement-sha256:<64 hex>", ...]}`.
The SEV-SNP policy has the same shape with schema `cathedral_snp_measurement_policy_v1` and
96-hex measurements (`admission.py:63-71`). Exactly those three keys, no repeated key
(`admission.py:147-153`), a sorted, unique list (`admission.py:200-201`), and a non-empty list when
enforcing (`admission.py:205-206`); at most 128 KiB of UTF-8 JSON. Reading the file safely (owner,
mode) stays with the caller, as #256's loader does. A policy of the other kind is an error.

**Errors.** Any malformed input, of any type, raises `AdmissionError` (`admission.py:85-86`),
never a bare exception (`test_fuzzed_input_is_an_admission_error_or_a_decision_never_another_exception`).

**Not bound, and why.** Admission trusts the caller to have run the verifier on the same
connection whose certificate it passes, and, for TDX, to pass the `stable_platform_id` of a strict
verification with `platform_identity_verified` and `claims_bound_to_quote` true; the library
cannot see the connection or the verifier run.

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

**Merge order with cathedral-validator.** Validator #257 still calls
`load_price_table(document["price_table"], owner_keys=, now=)` without `minimum_sequence` and
`pinned_digest`. Against this library that raises `TypeError`, which its
`except pricing.PriceTableError` does not catch, and its test still uses
`hardware_id_kind="ppid"`, which is refused now (TDX is `tdx_platform`). Validator #265, stacked
on it, passes both keywords and uses `tdx_platform`, so #257 must not land without #265's
changes.

## Not here yet

The prober service, box registration and routing live in the Cathedral control plane; it calls
`admit` but keeps the registry of admitted hardware ids itself. The
validator-side scoring (dedup, then value) lands in cathedral-validator.

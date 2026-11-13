# Measured memory: design and threat model (proposal)

**Status: design proposal (AB#702). Nothing here is implemented, scored or paid.** It
answers one question: how could SN94 pay a miner for memory it has proven, in GiB times hours
online, so that memory that is absent, aliased or parked on disk earns nothing? It is the check
behind the capacity commitment (AB#331) and feeds the uptime score and downtime weight rule
(AB#326, AB#327). Where this page says "unproven", the claim must not be relied on until the
testnet proof below has run.

## Why memory, and what is paid

- Memory decides how many sandboxes a machine holds: one sandbox is 4 GiB in the pricing rule.
- **Paid unit: proven GiB-hours.** GiB counted inside one attested boot, times the hours between
  consecutive passing probes of that boot. A restart, a failed probe or a missed probe earns
  nothing for that interval. This is the capacity side; delivered room-hours are the usage side.
- Memory proves how much, not how useful. Pair it with the warm pool probe (AB#535: claim a
  room, run one command, time it) so a far or slow machine does not earn the same.

## What exists today, and the gap

- The capacity challenge (docs/CAPACITY.md, "Challenge") fills lanes holding 80% of the claimed
  memory, but its deadline proves only that the box held about 1/4 of the lane memory at once
  (1/4.6 at the lane floor), so roughly 1/5 of the claimed memory ("What a receipt proves
  today"). It is a CPU-and-memory throughput proof, not a residency proof.
- An SEV-SNP or TDX quote proves no memory size (docs/TEE_BOX.md, step 3 of the probe). The SNP
  launch measurement covers the pages measured at launch (firmware, kernel, initrd), not the
  guest RAM size, which the host chooses and passes in the memory map.
- `report_data_v2` binds nonce, hotkey and the TLS key (`cathedral/common.py`); it carries no
  memory field. This design does not change it.
- The broker's `host_mem_used_gib` (`broker/main.go`) is usage telemetry for display and the
  memory-full gate, not a capacity claim. Nothing in this repository measures capacity memory.

## Roles

As in docs/CAPACITY.md: the **prober** (SN94 owner, measured TDX guest) talks to boxes and signs
receipts; **validators** verify receipts and never contact boxes. The card says "timed by the
validator"; in this design the prober is the timer and validators trust its signature, exactly as
for the capacity challenge. Having each validator time its own probes is a role change and an
open decision (see Open points).

## Layer 1: count from the inside

The measured SNP guest counts its own memory; it does not ask the host.

1. **Accept every page at boot.** The guest kernel boots with `accept_memory=eager`, so every
   private page is PVALIDATEd before user space starts. Lazy acceptance would let the host
   advertise memory it never backs until touched.
2. **No balloon, no hot-unplug.** The measured image ships without virtio-balloon or memory
   hot-unplug, so the host has no in-guest channel to take memory back.
3. **Write every page once.** A measured counter writes a nonce-derived pattern into every free
   page and reads it back, then reports `validated_bytes` (pages accepted) and `counted_bytes`
   (pages written and read back correctly) for this boot.
4. **Report over the attested channel.** The count is served only over the TLS connection whose
   SPKI the attestation binds (CAPACITY.md, "Rule for the prober: run each round's challenge
   over the attested TLS key"). Because the image is measured, the code that produced the count
   is the reviewed code. No new REPORT_DATA format.

What Layer 1 proves: at count time, this boot had that many validated guest pages. What it does
not prove: that every page is backed by distinct DRAM (Layer 2), or that pages stay in DRAM
afterwards (Layer 3). In particular, firmware page swap and page move keep the guest's validated
state, so **Layer 1 cannot see parking at all**.

## Layer 2: the chip (unproven on our hosts)

The claim, from AMD's SEV-SNP white paper (2020, "integrity" and "remapping" sections) and the
SEV-SNP firmware ABI (AMD publication 56860):

- The Reverse Map Table (RMP) has one entry per 4 KiB system physical page, recording the owning
  ASID and the one guest physical address it is assigned to, plus a Validated bit. A guest access
  through a nested page table entry whose RMP entry names another ASID or another GPA faults.
- So one physical page cannot back two guest pages of one guest, nor pages of two guests.
- PVALIDATE on an already-validated page reports "no change" (CF=1), so a guest that tracks its
  own validations can detect a host trying to make it validate a page twice.

Status: **assumed, not proven.** We have not tested these properties on a miner host. The design
relies on them only for the within-guest aliasing threat, and the testnet proof below includes
a check. Separately:

- Two guests on one host report the same CHIP_ID (docs/AMD_SEV_SNP_FRIEND_TEST.md, "Hardware
  identity dedup is not optional"), and cathedral-validator zeroes every claimant of a repeated
  hardware identity. That stops one host earning twice; it is a scoring rule, not an aliasing
  defence. The cross-socket case is not established (same section), and the socket policy is
  per validator.
- Standard Linux keeps SNP guest memory unmovable and unevictable (guest_memfd). That is honest
  host behaviour, not a defence: a miner controls the host kernel. The ABI defines firmware page
  move and page swap commands, and kernel work toward reclaiming SNP memory is in progress. So
  the design does not rely on "cannot be swapped".

## Layer 3: prober-timed random-page probe

The cheat left after Layers 1 and 2 is keeping guest pages on fast disk (firmware swap) and
selling the freed DRAM elsewhere, restoring pages when touched. A random, timed touch catches it.

**Probe.** Over the pinned TLS connection the prober sends a fresh 32-byte nonce and a count
`K`. A measured in-guest component runs a dependent chase over `K` pages of the counted set:
page `i+1` is chosen from SHA-256 over the nonce, `i` and a word read from page `i`, so the reads
are sequential and cannot be issued in parallel or precomputed. It returns a digest over the
nonce and the visited page numbers, never page contents. Customer pages are read, never written
or returned. Reading any guest-physical page needs a small in-guest kernel component, which is new
surface in the measured image and must be reviewed with it.

**Timing.** The prober measures wall time on its own clock, never the guest's: without Secure
TSC the host can intercept or offset the guest's TSC. It subtracts the minimum RTT of no-op calls
interleaved with the probe on the same connection, so the host cannot inflate the allowance by
delaying a separate calibration call.

**Detection.** With a fraction `f` of counted pages parked, each touched page is parked with
probability `f`; a probe of `K` pages touches at least one with probability `1 - (1 - f)^K`, and
adds about `K x f x L` of swap-in time, where `L` is the per-page restore latency. A probe fails
when its time exceeds the DRAM baseline plus a jitter allowance `J`. Illustrative numbers, to be
replaced by testnet measurements: a DRAM chase step of about 0.3 µs, `L` of 20 µs or more, `K`
of 20,000 (80 MiB read, about 6 ms of one vCPU): parking 5% adds about 20 ms, which is well above
a few ms of jitter after the minimum-RTT subtraction. Small `f` (under about 1%) is not
detectable this way and is accepted as noise.

**Schedule.** Probes come at random times, several per hour, and every prober request on the
connection is padded to one size so the host cannot tell a probe from a health call and restore
pages just in time. A probe proves residency at that instant; parking between probes is a
sampling-rate question, bounded by the probe rate and by the fact that GiB-hours accrue only
between two passing probes.

**Customer cost.** One `K`-page read-only chase per probe, single-threaded, a few ms. Sample, do
not sweep.

## Threat model

| # | Threat | Attack | Defence | Status |
|---|---|---|---|---|
| 1 | Absent memory | host advertises more RAM than it backs | Layer 1 eager accept and write-every-page count | design |
| 2 | Lazy backing | host backs pages only when touched | eager acceptance; count writes every page | design |
| 3 | Take back after count | host reclaims pages (RMP update) after counting | guest faults on next touch of an unvalidated page and stops; probe fails; boot earns nothing after | assumed (Layer 2) |
| 4 | Balloon or hot-unplug | in-guest channel returns memory to host | measured image has neither | design |
| 5 | Alias within one guest | one physical page backs two GPAs | RMP GPA check | **unproven**, testnet check |
| 6 | Alias across guests | one host runs two counted guests | RMP ASID check; CHIP_ID dedup zeroes both claimants | ASID unproven; dedup in validator; cross-socket open |
| 7 | Parked on disk | firmware swap-out or page move of counted pages | Layer 3 timed probe | design, threshold to calibrate |
| 8 | Just-in-time restore | host detects a probe and restores pages first | persistent connection, padded requests, random schedule, chase starts at once | design, testnet check |
| 9 | Clock tampering | host skews guest TSC to hide slow pages | prober wall clock only | design |
| 10 | RTT inflation | host delays calibration calls to widen the allowance | interleaved no-op calls, minimum RTT | design |
| 11 | Relay | an unvetted image attests a TLS key on another machine | measurement allowlist, attested TLS rule (CAPACITY.md, "Why shadow is not paid") | existing |
| 12 | Slow or remote memory | CXL or far NUMA memory counted as local | none: about 100 ns versus 300 ns is under WAN jitter | open, pricing question |
| 13 | Griefing | host deschedules vCPUs during a probe to fail an honest box | none needed: the miner only hurts itself | accepted |
| 14 | Honest box under load | customer load slows the chase and fails the probe | allowance from testnet load runs; retry on a fresh nonce counts as a new probe, capped | open |

## Testnet proof (the done line)

The proof that closes the card's done line: **on one testnet SEV-SNP host, measured GiB-hours
accrue for an honest guest, and neither a parked page nor an aliased page earns them.** It needs
an SNP testnet host and, for the adversarial runs, a patched host kernel; neither exists today,
so this is the next step after this design is reviewed, not part of it.

1. **Honest run.** Boot the measured guest with `N` GiB and eager acceptance. Pass: the counter
   reports `counted_bytes` within the guest's reserved overhead of `N` GiB; probes pass at the
   chosen `K` over 24 hours, idle and under a full sandbox load; GiB-hours equal `counted` times
   the passing interval.
2. **Restart.** Reboot mid-run. Pass: no GiB-hours between the last passing probe before the
   reboot and the first passing probe after the new attestation.
3. **Parked pages.** On a host kernel patched to swap out a fraction `f` of the guest's pages
   (firmware swap, or page move to a slow tier), run probes at `f` of 50%, 10% and 5%. Pass: the
   probe fails at every `f` at or above the calibrated threshold, and the interval earns nothing.
   Record `L`, the DRAM baseline and `J`; they set `K` and the threshold.
4. **Aliased pages.** On a patched host kernel, map two GPAs of the guest to one physical page.
   Pass: the guest faults (or PVALIDATE reports no change) and stops counting, so nothing is
   paid. If the guest instead runs on, Layer 2 is false and this design is not safe to pay.
5. **Reclaim after count.** Reclaim counted pages from the host side. Pass: the guest faults on
   next touch, the probe fails, nothing earns after.
6. **Just-in-time restore.** Patch the host to restore parked pages when prober traffic arrives.
   Pass: probes still fail at the threshold `f`.

Until runs 1, 3 and 4 pass, measured memory stays shadow-only and does not reach weights, as for
capacity receipts (docs/CAPACITY.md, "Timing").

## Open points

- **Trustworthy time.** Prober wall clock only, or Secure TSC in the guest (Genoa and later) for
  a tighter in-guest measurement the prober cross-checks.
- **Who times.** Prober-signed receipts (this design) or each validator probing directly (a role
  change from docs/CAPACITY.md).
- **Sample size against cost.** `K`, probe rate and the jitter allowance come from run 3.
- **Dual-socket hosts.** CHIP_ID across sockets and `require_single_socket` per validator
  (docs/AMD_SEV_SNP_FRIEND_TEST.md, "Socket policy and hardware identity").
- **Slow memory.** Whether far or CXL memory is paid at the DRAM rate; timing cannot tell.
- **Fit with AB#326 and AB#327.** How a failed probe counts against uptime and weight.
- **Receipt shape.** Whether proven GiB-hours ride in the capacity receipt (a new schema
  version) or a separate signed record. Not decided here.
- **TDX.** This page covers SEV-SNP. TDX has its own page acceptance (TDG.MEM.PAGE.ACCEPT) and
  would need its own Layer 2 review.

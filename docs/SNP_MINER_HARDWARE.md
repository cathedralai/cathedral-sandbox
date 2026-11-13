# SNP miner hardware list (2026-11-13)

Which bare-metal AMD servers a miner applicant can rent for a sealed SEV-SNP
hotel, what one slot costs on each, and whether Cathedral's admission code
accepts it today. Prices were read from public pages on 2026-11-13. They change
often; recheck before you buy.

Two kinds of row, never mixed:

- **Proven**: Cathedral has run an admitted SNP guest on that provider's
  hardware, with evidence in this repository.
- **Quote**: a public list price. Nobody at Cathedral has booted an SNP guest
  on it. "SNP" in a quote row only repeats what the provider's page says.

## 1. What the admission policy requires of the hardware

A host passes only if every row holds. Check these with the provider before you
pay.

| Requirement | Why | Source |
| --- | --- | --- |
| AMD EPYC Genoa family: family 0x19, models 0x10 to 0x1F (Genoa 9xx4) or 0xA0 to 0xAF (Bergamo 97x4, Siena 8004) | The shipped SN94 validator policy admits only `genoa`. Milan and Turin are refused (`snp_processor_generation_not_admitted`) | `cathedral-validator/deploy/validator-update/sn94-snp-policy.json`; `cathedral/verify/snp.py` `_snp_generation` |
| Turin (EPYC 9xx5, family 0x1A) is not admissible today, on either path | Validator: not in the policy. Broker: the AMD chain verifier reads only the Milan and Genoa TCB layouts and fails a Turin report, though `amd_chain.go` already pins the Turin ARK | `room-kit/verify_receipts.py` `product()` and the "only Milan and Genoa TCB layouts" check; `broker/amd_chain.go` |
| SEV-SNP enabled in BIOS (SMEE, SNP memory coverage, IOMMU, SEV-SNP) and a host kernel and QEMU that launch SNP guests | Without it there is no `/dev/sev-guest` in the guest | [Check the hardware](SNP_OWN_SERVER_ONBOARDING.md#1-check-the-hardware) |
| Firmware and microcode at or above the TCB floor `0x581c00000000000c`: boot loader SVN 12, TEE 0, SNP firmware 28, microcode 88 | The validator compares bytes 0, 1, 6 and 7 of all four TCBs (current, reported, committed, launch) | `cathedral-validator/cathedral_thin/independent_runtime/snp_production.py` `_tcb_meets_minimum` |
| Attestation report version 3, 4 or 5, VCEK-signed, real CHIP_ID | Version 6, VLEK-signed and masked or zero chip IDs are refused | `cathedral/verify/snp.py` `_SUPPORTED_REPORT_VERSIONS` and the signing-key check |
| Prefer one populated socket | Validators require the guest SINGLE_SOCKET bit by default. Upstream KVM cannot launch such a guest on a host with two or more populated sockets. A validator operator may set `require_single_socket` to false, for all SNP miners at once | [Socket policy](AMD_SEV_SNP_FRIEND_TEST.md#socket-policy-and-hardware-identity) |
| One SNP guest per physical host | Every guest on a host reports the same CHIP_ID. The validator zeroes every machine sharing one; the broker refuses a second miner hotel on a chip (`chip_in_use`). Operator hotels are exempt | `broker/admission.go`; [Check the hardware](SNP_OWN_SERVER_ONBOARDING.md#1-check-the-hardware) |
| Guest launched with the reviewed measurement, VMPL 0, debug and migration agent off | The policy pins one measurement. vCPU count, vCPU type and OVMF are part of it, so the guest shape is fixed by the image, not the host | `sn94-snp-policy.json`; `snp_production.py` |

Not admissible at all: EPYC 4004 (AM5, not a verifier family), Ryzen, Intel, and
cloud confidential VMs (Azure uses vTPM attestation, AWS signs with VLEK, and a
shared host shares its CHIP_ID).

## 2. What a slot is and what it costs

One slot is the catalog's base sealed size, `sealed-1x2`: 1 vCPU, 2 GiB memory,
10 GiB disk. The live catalog sold it at $0.0175 per hour on 2026-11-13
(`GET https://api.polaris.computer/v1/profiles`), which is $12.78 per month at
full occupancy. That is the customer price, not a miner payout.

Slots per host use the `room-kit/size.py` defaults with no overcommit: reserve 2
threads and 12% of memory, then

    slots = min(threads - 2, floor(RAM_GiB * 0.88 / 2))

Disk can also cap it: plan at least `slots * 10 GiB / 0.7` of data disk. Cost per
slot is the monthly list price divided by slots. Rows keep the provider's
currency; there is no FX conversion. Setup fees are listed, not spread.

## 3. Proven

| Provider | Hardware | Evidence | Price paid |
| --- | --- | --- | --- |
| Cherry Servers | Genoa SNP hosts running Cathedral's operator sealed hotels (`nc-sealed`, and `c46-sealed` on another chip) | Live broker hotel list on 2026-10-23 shows `nc-sealed (SEV-SNP)` beside "New Cherry" ([baseline](evidence/BROKER_ISOLATION_BASELINE_20261023T173448Z.md)); `broker/admission.go` names both chips; Cherry is the launch owner's Genoa SNP host ([ownership](CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md)) | Not recorded in this repository. The exact Cherry plan and SKU are not recorded either |

Running but not proven for admission:

- **Contabo**: hosts the SN94 SNP miner ([review rounds](evidence/REVIEW_ROUNDS_2026-10-23.md)).
  This repository records neither its CPU generation nor an SN94 admission, and
  the mining guide states SN94 admission remains unverified.
- **Testnet**: on 2026-10-16 a Genoa SNP guest was admitted on netuid 584
  ([image contract](SN94_SNP_MINER_IMAGE.md)). The host provider is not recorded.

## 4. Quotes (2026-11-13)

| Provider | Plan | CPU (gen) | Sockets | Threads | RAM | List price / month | Slots | Per slot / month | SNP on the page | Admissible today |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Cherry Servers | AMD EPYC 9354P | 9354P (Genoa) | 1 | 64 | 192 GB | $642.33 ($545.98 annual) | 62 | $10.36 | Not stated | Yes, if BIOS has SNP on (same provider as the proven row) |
| Hetzner | AX162 | 9454P (Genoa) | 1 | 96 | 128 GB base | from EUR 319.00 + EUR 304 setup | 56 | EUR 5.70 | Not stated; BIOS access not offered on the page | Unknown: needs SNP enabled by support |
| Contabo | Genoa 24 | 9224 (Genoa) | Not stated | 48 | Not stated | EUR 239.00, no setup | at most 46 | at least EUR 5.20 | Not stated | Unknown; 2P-capable SKU |
| Latitude.sh | rs4.metal.xlarge | 9554P (Genoa) | 1 | 128 | 1.5 TB | from $2,779.67 | 126 | $22.06 | "SEV-SNP attestation" | Likely; the only page that names SNP |
| Teraswitch | Genoa 9254 | 9254 (Genoa) | Not stated | 48 | 128 GB base | $460 (page says estimate) | 46 | $10.00 | Not stated | Unknown; 2P-capable SKU |
| Teraswitch | Genoa 9354 | 9354 (Genoa) | Not stated | 64 | 128 GB base | $490 (estimate) | 56 | $8.75 | Not stated | Unknown; 2P-capable SKU |
| Teraswitch | Genoa 9554P | 9554P (Genoa) | 1 | 128 | 128 GB base | $665 (estimate) | 56 | $11.88 | Not stated | Unknown |
| Teraswitch | Genoa 9754 | 9754 (Bergamo, Genoa family) | Not stated | 256 | 128 GB base | $785 (estimate) | 56 | $14.02 | Not stated | Unknown; 2P-capable SKU |
| Teraswitch | Turin 9575F | 9575F (Turin) | Not stated | 128 | 128 GB base | $1,520 (estimate) | 56 | $27.14 | Not stated | No: Turin |
| OVHcloud | Scale-a1 2026 (US) | 9135 (Turin) | Not stated | 32 | Not stated | $708 + $708 install | at most 30 | at least $23.60 | "SEV", not SNP | No: Turin |
| Vultr | Bare metal 9254 | 9254 (Genoa) | 1 | 48 | 384 GB | $825 (third-party listing only) | 46 | $17.93 | Not stated | Unknown; price unverified |

Rows with "128 GB base" are RAM-bound: more memory raises the slot count, at a
price the page did not give. Sources: cherryservers.com/pricing/dedicated-servers/amd-epyc-9354p,
hetzner.com/dedicated-rootserver/matrix-ax, contabo.com blog "Introducing the
new AMD Genoa 24", latitude.sh/solutions/confidential-compute,
teraswitch-website.pages.dev/pricing, us.ovhcloud.com Scale range, and
onedollarvps-com.pages.dev/pricing/vultr-pricing for Vultr.

## 5. Before a quote becomes proven

1. Ask the provider in writing: SEV-SNP enabled in BIOS (or BIOS access), one
   populated socket, and SEV firmware and microcode versions.
2. Rent one box, boot a guest, and run the
   [observed HTTPS and SAT test](AMD_SEV_SNP_FRIEND_TEST.md#run-the-observed-https-and-sat-test).
3. Move the row to Proven only with the transcript, the date and the price
   paid.

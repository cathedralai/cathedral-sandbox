# Bring your compute to Cathedral

For SN94 miners with an AMD SEV-SNP bare-metal server. You keep root and the
hardware; the AMD chip proves what runs in the guests, so Cathedral does not
have to trust your host. Tracking: AB#844 (epic AB#317).

The rule: no valid chip-signed report, no rooms and no weight. A box takes
rooms only while its miner hotel's attestation verifies at the broker. It
earns weight only while its SN94 miner guest verifies at the validator, and
Cathedral keeps a hotkey on the approved list only while its hotel is live
(checked by Cathedral ops at least weekly; a hotkey with no live hotel comes
off at the next signed validator release).

## Status (20 Nov 2026)

- Open for applications. Founding miners are reviewed by hand. No outside box
  has been admitted yet.
- Generation we admit: EPYC 9004 Genoa family. Milan and Turin can apply; they
  are not admitted yet (below).
- Pay today: SN94 weight from the compute lane, per verified machine of an
  approved hotkey. Not per hour or per TB yet (section 6).
- Rooms: an admitted miner hotel takes test traffic first. Customer rooms on
  miner hotels start after a separate reviewed switch. Dedicated customers
  stay on Cathedral's own machines.

## 1. Check your box

On the bare-metal host, as root:

```
curl -fsSLO https://raw.githubusercontent.com/cathedralai/cathedral-sandbox/main/scripts/snp_host_check.py
less snp_host_check.py      # read it first: read-only, no network, no writes
sudo python3 snp_host_check.py
```

Each line is PASS, WARN, FAIL, UNKNOWN or INFO; a JSON summary follows. Exit 0
means ready, 1 means a FAIL to fix, 2 means something could not be read. A
pass is not admission; step 5 is.

| Item | Needs | Source of the rule |
|---|---|---|
| CPU | AMD EPYC 9004 Genoa (also Bergamo 97x4, Siena 8004). 7003 Milan: WARN, needs a guest measurement Cathedral has not published. 9005 Turin: WARN, the validator policy and the broker verifier lack it | Validator policy `sn94-snp-policy.json`; `broker/amd_chain.go` header; [SEALED_CAPACITY_ADD_HOTEL.md](SEALED_CAPACITY_ADD_HOTEL.md#1-pick-the-host) |
| BIOS | SMEE, SEV-SNP, SNP memory coverage, IOMMU on; SEV-ES ASID space above 0 | [SNP_OWN_SERVER_ONBOARDING.md](SNP_OWN_SERVER_ONBOARDING.md#1-check-the-hardware) |
| Firmware | Genoa TCB at or above boot loader 12, TEE 0, SNP 28, microcode 88 (FAIL below). SNP 28 or 29: WARN, the broker floor planned under AB#809 is 30 | validator `snp_production.py` `_tcb_meets_minimum`; [broker README](../broker/README.md) `min_genoa_snp_spl` |
| CHIP_ID | Not masked | `cathedral/verify/snp.py` |
| Host | Bare metal, root, `kvm_amd sev_snp=Y`, `/dev/sev` | `room-kit/sealed/install-sealed.sh` |
| Sockets | Exactly one populated socket (FAIL on two): validators require the SINGLE_SOCKET guest bit | [Socket policy](AMD_SEV_SNP_FRIEND_TEST.md#socket-policy-and-hardware-identity) |
| RAM | 128 GB minimum, 384 GB or more ideal | Slots: [SNP_MINER_HARDWARE.md](SNP_MINER_HARDWARE.md#2-what-a-slot-is-and-what-it-costs) |
| Disk | About 1 TB local NVMe for room scratch | Same |
| Network | Public IPv4, one open TCP port for the guest HTTPS | `room-kit/sealed/README.md`, "On the host" |

The host can see only current and reported TCB. Committed and launch TCB are
in the guest's report and are checked at admission.

Not admissible: Ryzen, EPYC 4004, Intel, and cloud confidential VMs.

## 2. Apply

Fill in the founding form linked from <https://cathedral.computer/miners.md>.
Paste the JSON from step 1. Cathedral answers with a yes or no, and for a yes,
the values in step 3.

## 3. Install the two guests

Both run on the same chip, as on Cathedral's own hosts:

- The SN94 SNP miner guest, which the validator scores: follow
  [Run an SNP miner on your own server](SNP_OWN_SERVER_ONBOARDING.md). This is
  what earns weight. That page warns that a second guest costs the first its
  weight: that is about two scored guests on one chip. The hotel is not
  scored by the validator, so the validator still sees one machine per chip,
  as on Cathedral's own hosts.
- The miner hotel, which hosts rooms. You install it; Cathedral never needs
  your root password. Follow
`room-kit/sealed/README.md`, "Miner hotel": `SEALED_MINER=1` in `sealed.env`
with the control plane install signer Cathedral gives you, then
`sudo ./install.sh --sealed sealed.env`. The guest makes its TLS key, hotel
key slot and receipt key inside SNP memory; your host never holds them.

One miner hotel per chip: a second hotel on the same CHIP_ID is refused
(`chip_in_use`).

After a BIOS or SEV firmware update, make sure the new TCB is committed
(`snphost commit`, or your BIOS vendor's equivalent) and relaunch both guests.
Validators check committed and launch TCB, which the host check cannot see.

## 4. Check the guest and sign the offer

- Self check: `python3 room-kit/verify_receipts.py --origin https://<ip>:<port> --require-sealed --expected-measurement <m> --ark-sha256 <pin>`.
- Offer: `python3 room-kit/hotel_offer.py --origin <public origin> --attestation-url <guest url> --hotkey-file <hotkey> --post <offers url>`.
  It signs with your hotkey; the coldkey stays in your wallet. Every reboot is
  a new binding and needs a new offer: [ANCHOR_HOTEL_RUNBOOK.md](ANCHOR_HOTEL_RUNBOOK.md)
  section 1 sets up `hotel-offer-refresh` to post it for you.

## 5. Admission

Cathedral adds your hotkey to the broker's per-hotkey cap list
(`miner_hotkey_caps`; a hotkey not on it is refused), to the control plane's
per-hotkey cap for offers, and to the validator's approved list. Your miner
guest must be on the validator roster (the offer names a roster machine).
Then:

- The control plane fetches your attestation over the pinned TLS key, checks
  the AMD chain and the published measurement, installs
  the hotel key into the guest, and joins it to the broker.
- The broker checks again every 60 s; a pass lasts 600 s. A failed check or a
  reboot takes the hotel out of placement until it passes again.
- Probation first: 24 hours of test traffic (`broker/probation.go`).
- A miner hotel takes rooms only from guests whose policy opts in to miner
  hotels (`broker/capacity.go`, label `miner=true`). Today only Cathedral's
  test guest does. Customer guests opt in after a reviewed switch; dedicated
  customers never do.
- At most 64 miner hotels in total and at most half the shared pool for now.

## 6. Pay

- The validator pays the compute lane only to hotkeys on the approved list in
  the signed validator release (`cathedral-validator`
  `cathedral_thin/independent_runtime/approved_miners.py`).
- The lane is about 10% of the weight vector; the rest is burned. Today it is
  split by the count of distinct verified machines of approved hotkeys
  (`direct_contract.py` and `GATED_COMPUTE.md` in cathedral-validator), so a 128 GB box and a
  1 TB box earn the same.
- Pay by delivered room-seconds on attested hotels (AB#822) runs in shadow
  mode: it is computed, not paid. Running the hotel now means the switch
  costs you nothing.

## What is honest to tell your customers and yourself

- SNP protects guest memory and the keys inside it from your host. You keep
  power, network and BMC: you can stop the box, and your upstream sees traffic
  metadata.
- Customer rooms on miner hotels wait for the switch above and for the open
  hotel-key hardening (AB#392) to roll out.
- Cathedral does not claim "no one can see" until the open hardening work
  (AB#353, AB#392) lands. Its public pages say what is proven and what is not.
- A pass of the self-check, registration or uptime earns nothing by itself.

## Remove

Stop the guest or power off; the broker drops the hotel within one check.
Rooms on it end; Cathedral bills customers only to the unreachable mark.
Tell Cathedral if you leave for good so your hotkey comes off the approved
list.

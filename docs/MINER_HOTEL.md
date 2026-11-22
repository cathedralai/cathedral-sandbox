# Miner hotel: operator procedure (AB#347)

**Status: internal, not for publishing.** Peer review and public-copy approval
come first. Nothing here has run verbatim on a testnet host. No outside miner
hotel has been admitted.

Scope:

- A **miner hotel** is a room-kit sealed guest built with `SEALED_MINER=1`. It
  hosts customer rooms behind the shared broker, on a host the miner controls.
  Design: [room-kit/sealed/README.md, "Miner hotel"](../room-kit/sealed/README.md#miner-hotel).
- It is **not** the SNP validator worker image
  ([SN94_SNP_MINER_IMAGE.md](SN94_SNP_MINER_IMAGE.md),
  [SNP_OWN_SERVER_ONBOARDING.md](SNP_OWN_SERVER_ONBOARDING.md)). That guest is
  scored by the validator. The hotel is not. The two share a chip, and the
  hotel needs the worker guest only as a roster prerequisite (below).
- `miner_axon_cli.py preview` and `announce` (cathedral-validator) are
  historical recovery paths. They are not onboarding and are not used here.
- Testnet and production are separate sections. Use only the one you were
  authorized for.

Source read on 22 Nov 2026: cathedral-sandbox `47cf203`, polariscomputer
`53bcc3f`, cathedral-validator `6eb8568`.

## 1. Requirements (all true before any command)

### Hardware (active admission policy)

The roster needs the chip's SNP worker guest verified by the validator, and the
shipped validator policy names one generation:
cathedral-validator `deploy/validator-update/sn94-snp-policy.json:3-7`
(`genoa`, `minimum_tcb` `0x581c00000000000c`).

| Item | Requirement | Source |
|---|---|---|
| CPU | AMD EPYC Genoa family: 9004 Genoa, 97x4 Bergamo, 8004 Siena (family 0x19, models 0x10 to 0x1F or 0xA0 to 0xAF) | `sn94-snp-policy.json:4`; `room-kit/hotel_offer.py:101-112` |
| Not admitted | Milan, Turin, EPYC 4004, Ryzen, Intel, cloud confidential VMs | `sn94-snp-policy.json` (Genoa only); `broker/amd_chain.go:41-42` (Turin report fails) |
| TCB | Roster worker guest: every TCB value in the report (current, reported, committed and launch) at or above `0x581c00000000000c` per component (boot loader 12, TEE 0, SNP 28, microcode 88), not as one packed number. The broker also enforces its own configured hotel floor (`min_genoa_snp_spl`, `min_genoa_microcode_spl`). Polaris offer verification applies no TCB floor of its own | `sn94-snp-policy.json:6`; cathedral-validator `cathedral_thin/independent_runtime/snp_production.py:229-246, 410-420`; `broker/admission.go:321-327` |
| Sockets | One populated socket | [AMD_SEV_SNP_FRIEND_TEST.md](AMD_SEV_SNP_FRIEND_TEST.md#socket-policy-and-hardware-identity) |
| Host kernel | Bare metal, root, `kvm_amd sev_snp=Y`, `/dev/sev` | `room-kit/sealed/install-sealed.sh:27-28` |
| Chip | One miner hotel per chip (`chip_in_use`) | `broker/admission.go:56` |
| Guest shape | The vCPUs, memory and CPU model of the build Cathedral publishes; they are in the measurement. Defaults 96 vCPUs, 384 GiB, `EPYC-Genoa-v1` | `room-kit/sealed/sealed.env.example:10-16` |
| Disk | Scratch plus `SEALED_MIN_HOST_FREE_GIB` (default 600 GiB) free | `sealed.env.example:18-20` |
| Network | Public IPv4, one TCP port (default 9443) open in every outside firewall | `room-kit/sealed/README.md:451-458` |
| Build | Not a debug build: `SEALED_DEBUG_SSH_PUBKEY` empty | `sealed.env.example:142`; `room-kit/sealed/README.md:464-466` |

Pre-purchase check: `scripts/snp_host_check.py`
([BRING_YOUR_COMPUTE.md](BRING_YOUR_COMPUTE.md#1-check-your-box)). A pass is
not admission.

### Accounts and approval

- A hotkey registered on the subnet you are authorized for. The hotkey seed
  is on the hotel host (root, 0600). The coldkey never is.
- The chip's SNP worker guest is in the newest signed validator roster
  (cathedral-validator `cathedral_thin/independent_runtime/snp_roster.py:118`
  builds it, `:220` posts it; the offer names that roster machine).
- Cathedral has added the hotkey to the broker `miner_hotkey_caps`
  (`broker/main.go:203-205`) and the reconciler caps
  (polariscomputer `polaris/core/config.py:857`). A hotkey on neither is refused.

### Values Cathedral gives the miner on approval

| Value | Used in |
|---|---|
| The miner hotel `sealed.env` values (shape, measured flags) | Step 1 |
| `SEALED_HOTEL_KEY_INSTALL_SIGNERS` (control plane install public key) | Step 1 |
| Expected launch measurement | Step 2 |
| Polaris offer URL for your network | Step 3 |

The Genoa ARK pin is in source: `4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1`
(`broker/amd_chain.go:38`).

## 2. Entry-point inventory

| Step | Who | Current entry point | State |
|---|---|---|---|
| Install the guest | Miner | `sudo ./install.sh --sealed sealed.env` (`room-kit/install.sh:12`, `room-kit/sealed/install-sealed.sh:29-31`, prints origin, `tls_spki_sha256` and attestation path at `:225-226`) | Supported |
| Guest attestation | Guest | `GET /room/attestation` (`room-kit/room_receipts.py:3518`; plain HTTP tap serves only this, `:3478-3481`) | Supported |
| TLS binding | Guest, Polaris, broker | Binding names `tls_spki_sha256` (`room-kit/room_receipts.py:1512-1527`); Polaris pins the peer SPKI (polariscomputer `polaris/services/cathedral_hotel_offers.py:232`, `:288-316`); broker pins it (`broker/miner_tls.go:22`, `:53`, `:140`) | Supported |
| Self check | Miner | `room-kit/verify_receipts.py --require-sealed --expected-measurement --ark-sha256` | Supported |
| Signed offer | Miner | `room-kit/hotel_offer.py` (`main` at `:277`, `--network`/`--netuid` at `:284-285`); re-offer timer `room-kit/hotel-offer-refresh/hotel_offer_refresh.py:156` ([ANCHOR_HOTEL_RUNBOOK.md](ANCHOR_HOTEL_RUNBOOK.md) section 1). Intake `POST /v1/cathedral/snp/hotel-offers` (polariscomputer `polaris/api/routers/cathedral_snp_join.py:74`) | Supported (production) |
| Key install | Polaris to guest | `GET /room/hotel-key-install-key`, `POST /room/hotel-key` (`room-kit/room_receipts.py:3571-3573`); sender polariscomputer `polaris/services/cathedral_hotel_reconciler.py:425-436` | Supported, no miner action |
| Broker join | Polaris reconciler | `POST /v1/broker/hotels` (`broker/main.go:3042`), reconciler `cathedral_hotel_reconciler.py:199`, `:655` | Supported, no miner action |
| Validator roster | Validator | `snp_roster.py:118`, `:220`, called from `direct_validator.py:1346-1349`; intake `cathedral_snp_join.py:44` | Supported, no miner action |
| Offer status | Miner | Only the POST answer (`cathedral_snp_join.py:93-94`: `state`). `GET /v1/cathedral/snp/join` needs the roster token (`:35-42`, `:64-65`) | **GAP** |
| Measurement and install key | Cathedral | Given by hand on approval. Not published in this repository; reconciler list is an env value (`config.py:866`) | **GAP** (publication) |
| Signed update | Miner host | Miner auto-update covers `audit-miner` and `snp-miner` only (`cathedral/miner_products.py:34-45`). A hotel rolls by `install.sh --sealed` with a new measurement | **GAP** |
| Testnet acceptance | Cathedral | Polaris binds one network per deployment, default `finney`/94 (`config.py:822-823`); offers route is off unless the reconciler is on (`cathedral_snp_join.py:75-76`). Staging answered 404 `not_found` on 22 Nov; production answered 422 to an empty body | **GAP** |

## 3. Testnet procedure

**Blocked at step 3:** no Polaris deployment accepts testnet offers (GAP
"Testnet acceptance"). Steps 1 and 2 have current entry points and can run
on an authorized testnet host now.

1. Install the guest. In `room-kit/`:

   ```
   cp sealed/sealed.env.example sealed.env
   # set the values Cathedral gave you, including:
   #   SEALED_MINER=1
   #   SEALED_HOTEL_KEY_INSTALL_SIGNERS="<given install public key>"
   sudo ./install.sh --sealed sealed.env
   ```

   The last line names the guest HTTPS origin, `tls_spki_sha256` and the
   attestation file.

2. From a second machine (the host's own path skips the outside firewall):

   ```
   python3 verify_receipts.py --origin https://<public ip>:9443 --require-sealed \
     --expected-measurement <given measurement> \
     --ark-sha256 4c6598d19c18719c5dfd4a7d335f674e5bfe1d8f800cea2cf270c10d103db2f1
   ```

3. Sign the offer for testnet. Printing works today; `--post` waits for a
   testnet intake URL:

   ```
   python3 hotel_offer.py --origin https://<public ip>:9443 \
     --attestation-url https://<SEALED_GUEST_IP>:18443 \
     --hotkey-file <hotkey file> --network test --netuid <testnet netuid>
   ```

## 4. Production procedure

Only after Cathedral approves the hotkey (section 1). The path ran once in
production for a Cathedral-run hotel (AB#822, joined 17 Nov 2026). That is
not an outside admission, and customer rooms on miner hotels wait for a
separate reviewed switch ([BRING_YOUR_COMPUTE.md](BRING_YOUR_COMPUTE.md#5-admission)).

1. Install the guest: testnet step 1, with the production values.
2. Self check: testnet step 2.
3. Sign and post the offer, then keep it fresh across reboots:

   ```
   python3 hotel_offer.py --origin https://<public ip>:9443 \
     --attestation-url https://<SEALED_GUEST_IP>:18443 \
     --hotkey-file <hotkey file> \
     --post https://api.polaris.computer/v1/cathedral/snp/hotel-offers
   ```

   It exits 1 on a refused offer. Then install the re-offer timer:
   [ANCHOR_HOTEL_RUNBOOK.md](ANCHOR_HOTEL_RUNBOOK.md) section 1.

The control plane then verifies the guest, installs the hotel key and joins
the broker. The miner runs nothing more. A restart with rooms needs a drain
first and `SEALED_RESTART_WITH_ROOMS=1` (`room-kit/sealed/README.md:460-462`).

## 5. Open items

| GAP | Owner |
|---|---|
| Testnet acceptance: a Polaris deployment with the reconciler on, bound to the testnet netuid, plus a testnet broker, then the staged run in `polariscomputer/docs/SNP_ROSTER_BROKER_BOUNDARY.md` "Before the first live receipt" item 8 | Toby (decision: testnet or production equivalent), Fred (host, AB#349) |
| Offer status for the miner without the roster token | Polaris (Toby to assign) |
| Signed update channel for miner hotels, or a decision that the manual `install.sh --sealed` roll is the supported path | Toby |
| Publish the miner hotel `sealed.env`, measurement and install public key | Fred (key custody), Mr Spock (doc) |
| Verbatim run on an authorized testnet host, peer review, public-copy approval | Mr Spock (run), Reviewbot (review), Fred (copy) |

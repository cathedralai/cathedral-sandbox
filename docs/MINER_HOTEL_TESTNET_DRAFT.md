# Miner hotel on testnet (internal draft, AB#347)

**Status: internal draft. Do not publish. Not run on hardware.** This page is
the source inventory and the draft procedure for a founding-miner hotel. It is
not linked from [Mining Cathedral](MINING.md) and is not an operator guide yet.
It becomes one only after the gates in "Before this page is published" pass.

Scope:

- A **miner hotel** is a room-kit sealed hotel with `SEALED_MINER=1`. It runs
  customer rooms on a host the miner controls, behind the shared broker. It is
  customer room supply.
- It is **not** the SNP validator worker image
  ([SN94_SNP_MINER_IMAGE.md](SN94_SNP_MINER_IMAGE.md)) and not the
  [AMD SEV-SNP friend test](AMD_SEV_SNP_FRIEND_TEST.md). Those prove a machine
  to the validator. They do not join a hotel to the broker.
- The `preview` and `announce` commands of
  `cathedral-validator/cathedral_thin/independent_runtime/miner_axon_cli.py`
  are historical recovery paths. They are not onboarding and this page does
  not use them.
- This page covers **testnet only**. Production is a separate section that is
  empty on purpose.

## 1. Requirements (check all before any command)

### Hardware

The broker admits a miner hotel only on a launch measurement that Cathedral
publishes (broker `sealed_measurements`, Polaris
`CATHEDRAL_HOTEL_RECONCILER_MEASUREMENTS`). The vCPU count, the CPU model and
every measured `room.env` flag change that measurement. So the hardware is the
hardware of the published build, not "any SNP host".

| Item | Requirement | Source |
|---|---|---|
| CPU | AMD EPYC with SEV-SNP. The default build uses `SEALED_CPU_MODEL=EPYC-Genoa-v1`, which needs a Zen 4 host (EPYC 9004, Genoa). | `room-kit/sealed/sealed.env.example`, `room-kit/sealed/guest-constants.sh` |
| Turin | Not claimed. The verifier parses Turin reports (`cathedral/verify/snp.py`), but no Turin miner hotel has been admitted. | Fred, AB#347 comment, 13 Nov |
| Host kernel | `kvm_amd` with `sev_snp=Y` and `/dev/sev` present. `install.sh --sealed` stops when any is missing. | `room-kit/sealed/install-sealed.sh` step 1 |
| Guest shape | Exactly the vCPUs, memory and CPU model of the published build. Defaults: 96 vCPUs, 384 GiB. | `sealed.env.example` |
| Disk | Scratch disk (default 900 GiB, sparse) plus `SEALED_MIN_HOST_FREE_GIB` (default 600 GiB) free after it is full. | `sealed.env.example` |
| Network | A public IPv4 address. One public TCP port (default 9443) open in every firewall outside the host (cloud security group, router). | `room-kit/sealed/README.md`, "On the host" |
| Chip | One miner hotel per chip. A second hotel on an admitted CHIP_ID is refused (`chip_in_use`). | `broker/README.md` |
| Build | Not a debug build. `SEALED_DEBUG_SSH_PUBKEY` must be empty. | `room-kit/sealed/README.md` |

**Open:** the exact published sealed.env for miner hotels (vCPUs, memory,
CPU model, measured flags) is not in this repository. Cathedral must publish
it with its measurement before this table is final.

### Accounts and chain

- A hotkey registered on the testnet subnet.
- That hotkey and the machine (`machine_id`, derived from the chip) are in
  the **newest** signed roster of a pinned validator. The roster is
  eligibility only: no URL, no key
  (polariscomputer/docs/SNP_ROSTER_BROKER_BOUNDARY.md).
- The hotkey is in the founding cut: the reconciler
  `CATHEDRAL_HOTEL_RECONCILER_MINER_HOTKEY_CAPS` and the broker
  `miner_hotkey_caps` hold the same entry.

### Values Cathedral gives the miner

| Value | Used in |
|---|---|
| Published sealed.env for miner hotels | Step 1 |
| `SEALED_HOTEL_KEY_INSTALL_SIGNERS`: the control plane install public key | Step 1 (measured into `room.env`) |
| Expected launch measurement | Step 2 |
| AMD ARK sha256 pin | Step 2 |
| Testnet Polaris API origin, network name and netuid | Step 3 |

## 2. Entry-point inventory

Each command of the procedure needs a current, supported entry point. This
table is the check, read from source on 14 Nov 2026
(cathedral-sandbox `cde061c`, polariscomputer `6a20726`).

| Stage | Who | Entry point | State |
|---|---|---|---|
| Install the miner guest | Miner | `sudo ./install.sh --sealed sealed.env` with `SEALED_MINER=1` (`room-kit/install.sh`, `room-kit/sealed/install-sealed.sh`) | In source. Prints the guest HTTPS origin, `tls_spki_sha256` and the saved attestation path. Unit tests only for the miner path. |
| Guest attestation and TLS binding | Guest | `GET /room/attestation` over HTTPS; binding names `tls_spki_sha256` and the install key | In source (#366). |
| Self check | Miner | `python3 verify_receipts.py --origin https://<ip>:<port> --require-sealed --expected-measurement <m> --ark-sha256 <pin>` (`room-kit/verify_receipts.py`) | In source. |
| Signed offer | Miner | **None.** Polaris accepts `POST /v1/cathedral/snp/hotel-offers` (schema `cathedral_hotel_offer_v1`, sr25519 by the hotkey over `cathedral-hotel-offer-v1\0` + `offer_id`), but no repository ships a miner-side command that builds, signs and posts it. | **Gap.** |
| Offer verification | Polaris | polariscomputer/polaris/services/cathedral_hotel_offers.py | In source. Off unless the reconciler is enabled. |
| Key install | Polaris to guest | `GET /room/hotel-key-install-key`, `POST /room/hotel-key` | In source (#366, polariscomputer #1588). |
| Broker join | Polaris reconciler | `POST /v1/broker/hotels` with the scoped miner enrollment key; broker pins the attested SPKI (`broker/miner_tls.go`) | In source (#365, #1588). |
| Offer status | Miner | None for the miner. `GET /v1/cathedral/snp/join` needs the roster token. | **Gap.** |
| Signed update | Miner host | [Miner auto-update](MINER_AUTO_UPDATE.md) covers the products `snp-miner` and `audit-miner` only (`cathedral/miner_products.py`). A room-kit miner hotel rolls with `install.sh --sealed` and a new measurement; `room-kit/make-dist.sh` prints a tarball sha256 but signs nothing. | **Gap.** No signed update path for a miner hotel. |
| Validator admission proof | Validator, Polaris | Roster intake (`POST /v1/cathedral/snp/roster`) and the AMD-verified offer. No testnet run of roster plus offer plus join is recorded. | **Gap** until the testnet run. |
| Testnet acceptance | Cathedral | Staged proof in polariscomputer/docs/SNP_ROSTER_BROKER_BOUNDARY.md, "Before the first live receipt", item 8 | Not run. |

Note: the "Still open (broker)" list in `room-kit/sealed/README.md` predates
the broker TLS pin in `broker/miner_tls.go`. Check it against source before
it is quoted.

## 3. Procedure (testnet, draft)

Do these steps only on an authorized testnet host, and only after every row
in section 1 is true.

### Step 1. Install the miner guest

On the host, from a checkout of the published revision:

```
cd cathedral-sandbox/room-kit
cp sealed/sealed.env.example sealed.env   # then set the published miner values
# in sealed.env:
#   SEALED_MINER=1
#   SEALED_HOTEL_KEY_INSTALL_SIGNERS="<published install public key>"
#   SEALED_MINER_TLS_PORT=18443
#   SEALED_MINER_PUBLIC_PORT=9443
sudo ./install.sh --sealed sealed.env
```

Expect the last line to name the guest HTTPS origin, `tls_spki_sha256` and
the attestation file. A measurement mismatch stops the install and disables
the unit.

### Step 2. Check the guest from another machine

The host's own connections to its public address are not forwarded, so run
this from a second machine:

```
python3 verify_receipts.py --origin https://<public ip>:9443 --require-sealed \
  --expected-measurement <published measurement> --ark-sha256 <published pin>
```

### Step 3. Sign and post the hotel offer

**Blocked: no supported entry point.** The offer must carry the hotkey, the
`machine_id`, the HTTPS origin, the `binding_sha256` of this boot, a sequence
and a fresh `issued_at`, signed with the hotkey. No command does this today.
This page will not tell a miner to hand-build and sign the JSON.

After a valid offer, the Polaris reconciler verifies the guest, installs the
hotel key and joins the broker. The miner runs nothing more. A new boot makes
a new binding, so the miner must sign a new offer after every guest restart.

## 4. Production

Empty on purpose. No production admission, no customer room supply and no
Turin support is claimed from image-build or unit-test evidence.

## Before this page is published

1. A supported miner-side offer command exists (decision: where it lives and
   who owns it).
2. Cathedral publishes the miner sealed.env, its measurement, the install
   public key and the ARK pin.
3. A signed update path for miner hotels exists, or the page states the
   manual roll and its drain step as the supported path.
4. The three steps run verbatim on an authorized testnet host, with the
   roster, offer, join and one canary room create, exec and delete recorded,
   and `verify_receipts.py --require-sealed` on the receipt chain.
5. Peer review, then public-copy approval.

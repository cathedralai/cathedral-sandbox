# Add a shared sealed hotel on a rented host

Operator runbook for adding sealed capacity: one more shared (operator, not miner)
SEV-SNP hotel on a rented machine, admitted by the broker and placed for every guest
whose policy reaches the sealed class. Tracking: AB#176.

Done for AB#176: 8 or more shared sealed hotels admitted, and a 1,000-sandbox sealed
commission that never answers `hotels_unavailable`.

This is not the miner path. A founding miner hotel joins with `miner_hotkey`, guest TLS
and the control-plane install key (`room-kit/sealed/README.md`, "Miner hotel"). The miner
seed-box recipe is [SNP_SEEDBOX_JOIN_HOST.md](SNP_SEEDBOX_JOIN_HOST.md). Neither is needed
here.

## 1. Pick the host

- SEV-SNP enabled: `kvm_amd sev_snp=Y` and `/dev/sev` (the installer checks both).
- CPU: `SEALED_CPU_MODEL=EPYC-Genoa-v1` needs a Zen 4 host (EPYC 9004). Any other SNP
  host needs `EPYC-v4`, which is a different measurement (step 2).
- Product ARK: the broker verifies the AMD chain only against the ARKs in
  `amd_verifier.ark_sha256` (values per product in `broker/amd_chain.go`). A host of a
  product whose ARK is not listed is refused at admission.
- Disk: room for `SEALED_SCRATCH_GIB` plus `SEALED_MIN_HOST_FREE_GIB` (the installer
  refuses less), plus `SEALED_DATA_GIB` if workspaces persist.
- Memory and threads: the guest takes `SEALED_VCPUS` and `SEALED_MEM_GIB` for real (SNP
  memory cannot be shared). Inside the guest the room kit sizes slots with
  `room-kit/size.py` at the overcommit set in `room-kit/sealed/build-guest.sh`
  (`CPU_OVERCOMMIT`, `MEM_OVERCOMMIT`), capped by `SEALED_ROOM_MAX_SLOTS`.

## 2. Match the pinned measurement

The broker admits a sealed hotel only if its measurement is in `sealed_measurements` and
its HOST_DATA is in `sealed_host_data` (`broker/README.md`, "Admission of sealed hotels").
Reuse the live pin instead of adding a new one:

- Do not rebuild. A fresh `build-guest.sh` run does not give the live bytes: the base
  root file system and the kernel come from `mmdebstrap` against the live mirror
  (`SEALED_SUITE`, `SEALED_MIRROR`), so a later build picks up newer packages.
  `SOURCE_DATE_EPOCH` only fixes the timestamps in the initrd pack, and builds are not
  yet reproducible (`docs/SEALED_SECRETS.md`, AB#380).
- Copy the live image instead: the whole `images/<stamp>/` directory of a live shared
  sealed hotel (`vmlinuz`, `initrd.cpio.zst`, `cmdline`, `OVMF.amdsev.fd`,
  `manifest.json`) to `$SEALED_DIR/images/<stamp>/` on the new host, point
  `$SEALED_DIR/images/current` at it, and set `SEALED_SKIP_BUILD=1` in `sealed.env` (step 3).
  The install then computes the expected measurement from those files.
- Copy the measured settings from that hotel's `sealed.env` too: `SEALED_VCPUS` and
  `SEALED_CPU_MODEL` are inputs to the measurement at launch, and the rest
  (`SEALED_DEBUG_SSH_PUBKEY` empty, `SEALED_DATA_GIB`, `SEALED_MINER=0`, every
  `SEALED_ROOM_*`) must agree with the copied image.
- Shared machine: leave `SEALED_OWNER_PUBKEY_FILE` empty. HOST_DATA is then
  `sha256(manifest.json)` (`launch-guest.sh`), so the copied `manifest.json` gives the
  same HOST_DATA.
- Change only what is not measured: `SEALED_NAME` (the new hotel id),
  `SEALED_API_KEY_FILE`, `SEALED_SCRATCH_GIB`, `SEALED_MIN_HOST_FREE_GIB`, `SEALED_DIR`.

If any measured value must differ (another vCPU count, `EPYC-v4`), the new measurement
and HOST_DATA must be added to the broker config before the hotel can take rooms. That is
a broker change: plan it, do not improvise it.

## 3. Install

```
sudo ./install.sh --sealed sealed.env
```

With `SEALED_SKIP_BUILD=1` in `sealed.env` and `images/current` in place the install skips the build
(`install-sealed.sh` step 3); without them it builds a new image, which needs a new pin.
It prints the expected measurement, boots the guest, compares the
measurement in the guest's report with the build and logs `host_data`. Check both
against the broker's pins before going on.

## 4. Give the broker a private path

Hotel APIs must not be public (`broker/README.md`, "Run"). The broker reaches a remote
hotel through an SSH tunnel per hotel: an entry in `/etc/thin-broker/tunnels.env`
(`TUN_<id>="<dest> <api> <health> <receipts>"`) with a matching `permitopen` on the
tunnel key in the host's `authorized_keys`. In a sealed guest the API, health and
receipts all go through the receipt front on the guest's `:18090` (`10.215.0.2`, an
image constant in `guest-constants.sh`). Point `api` and `health` at that front, or no
receipt is signed.

## 5. Join

```
POST /v1/broker/hotels   (operator key)
{"id": "<SEALED_NAME>", "api": "http://127.0.0.1:<tunnel port>",
 "key": "<hotel key>", "sealed": true, "concurrency": 16}
```

- `sealed: true` adds the `sealed=true` label, so the hotel is in the sealed class.
- Do not send `"verify": false`: a sealed join is refused without verify (400
  `verify_required`). The broker calls `GET /v1/status` with the key, then checks the
  attestation, and refuses a bad one at join (422 `attestation_failed`).
- `max_slots` is optional: 0 takes the slots the hotel reports.
- The broker needs `state_dir` set (409 `no_state_dir` otherwise); the hotel is saved in
  `state_dir/hotels.json`.

## 6. Check

`GET /v1/broker/capacity` with the operator key:

- the new hotel: `class: sealed`, `up: true`, `admission` passed, `free_rooms` > 0;
- `classes.sealed`: `hotels`, `placeable` and `slots` went up by this hotel.

## 7. Prove the 1,000

Run a 1,000-sandbox sealed commission (console, or `broker/blast` with
`-n 1000` against a guest whose policy reaches only the sealed class) and keep the
result.

What `hotels_unavailable` means (`noRoom` in `broker/images.go`): 503
`hotels_unavailable` only when at least one matching hotel is down, draining, resting
after a failed create or not admitted. Every matching hotel full is 429
`no_free_rooms`. So the earlier failure at about 676 of 1,000 says a sealed hotel left
placement under load, not only that the pool ran out of slots. More hotels spreads the
load, but the proof must show the error `reason` counts (`down`, `resting`,
`pending_admission`, `full`) per failed create, and the run passes only with none of
them.

## Remove

`PATCH /v1/broker/hotels/<id>` with `{"drain": true}`, wait for its rooms to end,
`DELETE /v1/broker/hotels/<id>`, then the host steps in `room-kit/sealed/README.md`,
"Remove".

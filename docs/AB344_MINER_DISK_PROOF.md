# AB#344: miner guest disk proof

Status: testnet proof plan. No miner hotel or production disk was changed by this document.

## Source boundary

`room-kit/sealed/guest-boot.sh` opens the scratch disk inside the guest with
dm-crypt, AES-XTS-512 and a new random key each boot. With a measured
`ROOM_WORKSPACES_SOURCE` and `SEALED_DATA_GIB > 0`, it calls
`sealed-data.sh` before the room kit starts. That script derives the LUKS2
key inside the SNP guest, verifies the active mapping and header, and mounts
the data volume only in state `new` or `open`. A damaged header, missing file
system token, wrong key, or changed cipher leaves the volume untouched.

`room_health.py` reports `workspaces_storage`. When the persistent volume
cannot open, the guest may still serve rooms with workspaces on encrypted
scratch; `persistent: false` means those workspaces end at the next guest
restart. Thus a healthy room alone is not evidence of persistent disk
encryption. The existing c48 hardware proof in `SEALED_DATA_VOLUME.md` used
an operator test hotel, not the miner hotel path. Unit tests use fake disk and
cryptsetup commands; they do not prove the real kernel refuses `cipher_null`.

## Testnet acceptance run

Use one disposable, registered SN94 miner hotel with no customer rooms and a
separate throwaway data disk. Record its approved build commit, image digest,
SNP measurement, CHIP_ID, signed binding, miner hotkey, guest attestation and
broker admission decision. Check that the attestation names the same build and
hotel as the testnet broker record. Keep keys and raw reports in private
evidence; publish only hashes and the verifier verdict.

1. Build with measured `ROOM_MINER=1`, `SEALED_ROOM_WORKSPACES=1` and
   `SEALED_DATA_GIB > 0`. On first boot, record `workspaces_storage.state=new`,
   `persistent=true`, LUKS2 metadata, and the active dm-crypt cipher and sector
   size from inside the guest. Record the host disk hash and confirm a unique
   marker written to a room workspace is absent from raw host disk bytes.
2. Restart the **same build**. Require `state=open`, the same `key_id`, and the
   marker present through the room API. Confirm the guest reports the same
   attested identity and that the broker still admits it. Record the host disk
   hash and verify that raw host bytes still omit the marker.
3. On copies of the throwaway disk, run three negative controls, resetting
   from the clean copy each time: damage both LUKS signatures while retaining
   payload bytes; remove the Cathedral file system token and damage the xfs
   signature; alter the LUKS data segment to `cipher_null`. Require `broken`,
   `broken`, and either `tampered` or `locked` respectively, with
   `persistent=false`. A real cryptsetup build may refuse the altered header
   before the guest's post-open check. Compare each disk hash before and after
   boot. No negative run may call `luksFormat`,
   `mkfs.xfs`, or mount the data volume, and no old marker may be exposed.
4. Boot a different approved measurement against a copy of the original disk.
   Require `locked`, `persistent=false`, and no disk format or mount. Restore
   the original build and disk and require `open` plus the marker.
5. Run the disk checks on a **real SNP guest and kernel**. In particular,
   capture the device-mapper table and LUKS2 metadata for the `cipher_null`
   control rather than relying only on the fake-command unit suite. Destroy
   only the disposable testnet rooms and disks after recording results.

The operator should attach a table to AB#344 with each run's build and
measurement, attestation verdict, `workspaces_storage` state, active cipher,
pre/post disk hashes, marker readback, and broker admission result. Include
the testnet room receipt and a link to the pinned build. A missing or
ambiguous result keeps the card open. AB#598's operator-hotel proof cannot
stand in for this miner-path run.

## Local checks before the run

- `pytest -q tests/test_room_kit_sealed_data.py` covers blank and existing
  disks, damaged signatures, missing tokens, null-cipher metadata and the
  workspace-health fallback.
- `bash -n room-kit/sealed/sealed-data.sh room-kit/sealed/guest-boot.sh`
  checks the two boot scripts' syntax.
- Review the exact guest image pin and broker policy before scheduling the
  testnet run. This plan authorizes no production roll or flag change.

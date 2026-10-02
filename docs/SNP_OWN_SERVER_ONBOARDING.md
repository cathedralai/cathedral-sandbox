# Run an SNP miner on your own server: from a server to a scored machine

This page puts the path for running the AMD SEV-SNP miner on your own server
in order, from "I have a server" to a machine the validator scores. It adds no new commands: each step links to the
section that owns them. The repository [README](../README.md) remains the only
active operator guide; where this page and the README differ, the README wins.

Here your own EPYC host runs an SNP guest, and the miner runs inside that guest.
The machine is a TEE box: its evidence comes from the AMD hardware. That is not
what the capacity documents call "bare metal", which is a host with no TEE at
all, a path that is currently deferred ([CAPACITY.md](CAPACITY.md)). When a
registration asks for the kind of box, an SNP host is `--kind tee`
([MINER_BOX_RUNBOOK.md](MINER_BOX_RUNBOOK.md)). Intel TDX mining runs in a TDX
confidential VM, usually rented; see
[Run one Intel TDX machine](../README.md#run-one-intel-tdx-machine).

Each step ends with what must be true before the next one. Stop at the first
step that does not hold, as [Stop and get help](../README.md#stop-and-get-help)
describes.

## 1. Check the hardware

The verifier accepts AMD attestation report versions 3, 4 and 5 from the
Milan, Genoa-family and Turin processor generations, through native
`/dev/sev-guest`. Plain AMD SEV and vTPM attestation are not accepted. Details:
[Supported hardware](AMD_SEV_SNP_FRIEND_TEST.md#supported-hardware).

Plan for these facts the code enforces:

- **One SNP guest per physical host.** Every guest on a host reports the same
  CHIP_ID, and the validator zeroes every machine that shares a hardware
  identity. A second guest on the same host costs the first one its weight.
- **The report must be VCEK-signed with a real CHIP_ID.** The verifier refuses
  VLEK-signed reports, reports with the chip ID masked, and an all-zero chip
  ID (`cathedral/verify/snp.py`).
- **The guest policy must refuse debug and the migration agent.**
- **SINGLE_SOCKET.** A validator's SNP policy requires the guest's
  SINGLE_SOCKET policy bit unless its operator sets `require_single_socket` to
  `false`, for all SNP miners at once. Launch the guest with the bit set if
  your host allows it.

The repository does not fix an EPYC SKU, BIOS settings, SEV firmware version,
host kernel, QEMU or OVMF build, and publishes no reference guest image or
launch measurement. Record what you used; step 3 needs it.

**Before step 2:** the guest boots with `/dev/sev-guest` readable and writable
by root.

## 2. Prove the hardware

Inside the guest, install the reviewed source and the pinned `snpguest`, then
run the observed HTTPS and SAT test with a challenge from the validator
operator who will review it:

- [Install the reviewed source and verifier](AMD_SEV_SNP_FRIEND_TEST.md#install-the-reviewed-source-and-verifier)
- [Run the observed HTTPS and SAT test](AMD_SEV_SNP_FRIEND_TEST.md#run-the-observed-https-and-sat-test)

The test checks the AMD chain against the pinned root, the binding of nonce,
hotkey, measurement, TCB and TLS key, VMPL 0 with debug and migration off, and
one SAT round. It writes a transcript that never contains the raw report, raw
CHIP_ID or TLS private key. It counts as live proof only if the reviewer
watches it run.

**Before step 3:** the transcript says `LOCAL_PASS`.

## 3. Get admitted by each validator

Each validator owns its SNP policy and admits a machine only by adding its
observed measurement and a TCB floor for its processor generation
([Production worker](AMD_SEV_SNP_FRIEND_TEST.md#production-worker)). Send each
validator operator you expect to score you:

- the transcript's measurement and reported TCB. Once #222 lands, the
  transcript also carries the processor generation and a ready-made policy
  entry in the validator's format; until then, name the generation yourself;
- whether your guest sets SINGLE_SOCKET;
- the host facts from step 1.

The validator's floor applies to the current, reported, committed and launch
TCB, component by component, so the floor you are admitted at must not be
above any of the four. There is no wildcard or shared default policy.

**Before step 4:** the validator operators confirm their policy admits your
measurement and TCB. Do not register a hotkey before this; registration and
admission are not weight.

## 4. Set up validator access on a control host

The worker answers only validators on a list your own control host signs. Set
that host up once, keep its signing seed there, and run the refresh timer on
it and the fetch timer on each worker:

- [Refresh validator access from a control host](../README.md#2-refresh-validator-access-from-a-control-host)
- [Keep the snapshot fresh with two timers](../README.md#keep-the-snapshot-fresh-with-two-timers)

The snapshot is valid for at most an hour, and the timers alarm before it
expires. A worker whose snapshot expires refuses every validator and scores
nothing.

**Before step 5:** the worker holds a fresh `validator-access.json` and the
pinned `snapshot-keys.json`.

## 5. Start the miner

Start the fixed SNP image with its root-owned launcher, either by hand or
through the signed miner updater:

- [Start the miner](AMD_SEV_SNP_FRIEND_TEST.md#start-the-miner) and the image
  contract in [SN94 AMD SEV-SNP miner image](SN94_SNP_MINER_IMAGE.md);
- or [Install (once per host)](MINER_AUTO_UPDATE.md#install-once-per-host) for
  signed automatic updates, which can roll back a later release that fails
  its probation.

The launcher (`scripts/run_sn94_snp_miner.sh`) refuses an image outside its
canonical repository or not pinned by one sha256 digest, missing or unsafe
access files, and a missing `/dev/sev-guest`. It runs the container read-only with all capabilities
dropped.

**Before step 6:** the miner stays running and passes the reachability check
in [Rehearse before renting or registering](../README.md#rehearse-before-renting-or-registering).

## 6. Register and announce the hotkey

Only now, from the separate wallet machine, register the hotkey and announce
the guest's public IPv4 and port `8081` as its axon:
[Register and announce the hotkey](../README.md#4-register-and-announce-the-hotkey).
Never copy the wallet into the guest.

**Before step 7:** the subnet shows your hotkey at that IP and port.

## 7. Confirm the machine is scored

[Confirm chain state](../README.md#5-confirm-chain-state) shows how to read
your UID and the validator weight rows. The validator pays one unit per
distinct verified machine, so your row should appear once a validator has
verified fresh evidence and SAT and written its weights.

There is no public validator-result feed yet. Until validators publish a
per-cycle inventory, ask the validator operator for the machine's result.

## 8. Add more machines

Each additional machine is its own physical host with its own SNP guest, the
same hotkey, and an entry in the primary worker's `fleet.json`:
[Add more machines to one UID](../README.md#add-more-machines-to-one-uid).
Each needs its own measurement admitted (step 3) if it differs.

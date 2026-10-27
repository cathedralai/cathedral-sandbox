# SNP hardware and admission: steps 1 to 3

These are steps 1 to 3 of [Mining Cathedral](MINING.md#run-one-amd-sev-snp-machine).
They take you from "I have a server" to a machine that the validator
operator has admitted. Your own EPYC host runs an SNP guest, and the miner
runs inside that guest. Continue at
[step 4](MINING.md#4-refresh-validator-access-from-a-control-host).

Where this page and the mining guide differ, the guide wins.

Each step ends with what must be true before the next one. Stop at the first
step that does not hold, as [Stop and get help](MINING.md#stop-and-get-help)
describes.

## 1. Check the hardware

The verifier accepts AMD attestation report versions 3, 4 and 5 from the
Milan, Genoa-family and Turin processor generations, through native
`/dev/sev-guest`. Plain AMD SEV and vTPM attestation are not accepted. Details:
[Supported hardware](AMD_SEV_SNP_FRIEND_TEST.md#supported-hardware).

The code enforces these facts:

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
launch measurement. Record what you used. Step 3 needs it.

**Before step 2:** the guest boots with `/dev/sev-guest` readable and writable
by root.

## 2. Prove the hardware

Inside the guest, install the reviewed source and the pinned `snpguest`. Then
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

## 3. Get admitted

The validator owns its SNP policy. It admits a machine only after its operator
adds your observed measurement and a TCB floor for your processor generation
([Production worker](AMD_SEV_SNP_FRIEND_TEST.md#production-worker)). Send the
validator operator:

- the transcript's `validator_policy_entry`. It holds your processor
  generation, measurement, and minimum TCB in the validator's policy format;
- whether your guest sets SINGLE_SOCKET;
- the host facts from step 1.

The validator's floor applies to the current, reported, committed and launch
TCB, component by component. The floor you are admitted at must not be above
any of the four. There is no wildcard or shared default policy.

**Before step 4:** the validator operator confirms that the policy admits your
measurement and TCB. Do not register a hotkey before this. Registration and
admission are not weight.

Each additional machine needs its own measurement admitted if it differs. See
[Add more machines to one UID](MINING.md#add-more-machines-to-one-uid).

# Direct report from a dedicated SNP guest

AB#1004 supplies a collector and verifier for a customer's own sealed SEV-SNP
guest. The collector calls `/dev/sev-guest` directly. This does not make that
ioctl work inside a gVisor sandbox, and does not use the existing report socket.
The custom image launch and HOST_DATA setup are separate release requirements.
This document is not evidence that either has been deployed.

## Prerequisites

The guest must run a 64-bit little-endian Linux kernel with the SEV guest driver
(`CONFIG_SEV_GUEST`) and expose `/dev/sev-guest` as a character device. The caller
needs permission to open it read/write and obtain a VMPL 0 report. Image authors
must include the driver or arrange for its module to load. The collector does
not load modules, change permissions, or fall back to a proxy if the device or
ioctl is absent. It needs only Python 3's standard library.

Run verification on a trusted machine outside the guest, using Python 3.11+,
`cryptography`, and both `verify_guest_report.py` and `verify_receipts.py` from
the same reviewed repository revision. The existing verifier retrieves AMD
certificates from KDS or its local cache. A cache must have been populated for
this chip and TCB before an offline check. Never adopt a root fingerprint from
the guest's answer.

Before launch, independently obtain:

- The expected 48-byte SNP launch measurement for the exact kernel, initrd,
  command line, launch policy and VM configuration.
- The expected 32-byte HOST_DATA, recomputed from the approved R3 launch
  contract and customer-owned inputs, including the owner public key and
  bootstrap digest. Use that contract's exact manifest encoding and version;
  do not hash an arbitrary JSON serialization or copy HOST_DATA from the report.
- A trusted AMD ARK SHA-256 fingerprint, and any required chip identity or
  minimum TCB policy.

The verifier compares the expected HOST_DATA bytes. It does not construct the
R3 bootstrap or decide which image and bootstrap the customer intended.

### Approved HOST_DATA domain

The dedicated launch uses the existing `cathedral-dedicated-v2` domain:

```text
HOST_DATA = SHA256(
    b"cathedral-dedicated-v2\0"
    || SHA256(exact_manifest_file_bytes)
    || owner_ed25519_public_key_raw_32_bytes
    || bootstrap_sha256_raw_32_bytes
)
```

`||` means byte concatenation; the domain ends with one zero byte. Both digests
and the owner key contribute raw bytes, not their hexadecimal or base64 text.
The result is 32 bytes; pass its 64 hexadecimal digits to `--expected-host-data`.
QEMU's base64 `host-data` representation encodes those same result bytes.

Hash the exact approved manifest file without parsing or reserializing JSON.
Use the owner's public key, never its private key. Obtain the bootstrap digest
from the reviewed launch contract: retaining the v2 domain does not define the
custom-guest manifest schema or bootstrap canonicalization. Do not substitute
an old hotel-create recipe unless that contract explicitly uses it. A missing
bootstrap digest must not silently select the older v1 formula for this release.

This encoding matches `room-kit/sealed/launch-guest.sh` and the v2 checks in
`room-kit/verify_receipts.py`. It does not prove the custom launcher is deployed
or that the measured guest enforced the bootstrap.

## Collect and verify

On the trusted verifier machine, generate a new challenge for this attempt and
retain it locally. Send only its value into the guest over your chosen channel:

```sh
NONCE_HEX=$(openssl rand -hex 64)
printf '%s\n' "$NONCE_HEX"
```

Inside the SNP guest, set `NONCE_HEX` to that supplied value and collect:

```sh
python3 room-kit/snp_guest_report.py --report-data-hex "$NONCE_HEX" > guest-report.json
```

Copy `guest-report.json` back to the verifier machine. Keep the original nonce
there; do not replace it with a nonce claimed by the guest. Set the three
expectation variables below from the independent inputs above, then run:

```sh
python3 room-kit/verify_guest_report.py guest-report.json \
  --report-data-hex "$NONCE_HEX" \
  --expected-measurement "$EXPECTED_MEASUREMENT_HEX" \
  --expected-host-data "$EXPECTED_HOST_DATA_HEX" \
  --ark-sha256 "$TRUSTED_ARK_SHA256"
```

The collector returns `verification: not_checked`. Only the verifier can return
`verdict: PASS`, with exit status 0. It requires a valid AMD certificate chain
and report signature, the original challenge, the expected measurement and
HOST_DATA, VMPL 0, and debug and migration-agent policies disabled. Invalid
input, a missing expectation, or a failed check exits nonzero.

Use `--expected-chip-id` when the contract pins a physical chip. Use repeated
`--min-tcb GEN:bl=N,tee=N,snp=N,ucode=N` arguments for a supported TCB floor, as documented
by `verify_receipts.py`. With no floor supplied, `tcb_floor` is `not checked`;
a PASS does not assert firmware meets an unstated minimum. The existing
verifier's product/version and TCB-floor support limits still apply.

## What the result establishes

REPORT_DATA binds this report to the verifier's fresh challenge. HOST_DATA is
signed launch metadata supplied by the host; matching it proves those bytes
were supplied at launch. It does **not** by itself prove arbitrary customer
code consumed the bootstrap, verified an owner signature, or enforced access
control. Those claims require the customer's measured image to implement the
corresponding checks. The report also does not prove application correctness,
disk freshness, uninterrupted availability, or account ownership.

The JSON `source` label is informational. A signed report alone cannot prove
which userspace transport retrieved it. The release proof must also record
the collector running inside the intended guest and the direct device call.

## Release acceptance

Every customer VM in this release must run as a sealed SEV-SNP guest. A custom
image does not permit an unsealed VM, a plain QEMU fallback, or a debug-enabled
guest. If SNP launch or attestation fails, refuse the launch or release instead
of downgrading protection. An SNP-capable host or an existing `/dev/sev-guest`
device alone is not proof that the intended customer VM is sealed.

Before calling that VM ready, require its fresh, verified AMD-signed report
against the independently expected measurement, HOST_DATA and approved TCB
floor, with debug and migration-agent policies disabled. The authenticated
connection must be bound to that intended guest by the reviewed launch/channel
contract; this standalone report verifier does not establish that connection.

Spock owns the end-to-end run with the authorized dedicated key. First rehearse
on separate SNP capacity without customer work. Record the deployed launch
revision, image digests, independently calculated measurement and HOST_DATA,
device/driver evidence, collection exit status, and verifier output. Negative
checks must reject a changed nonce, measurement and HOST_DATA. Preserve customer
rooms, workspaces, volumes and snapshots throughout the rollout.

Unit tests use an injected ioctl response and synthetic AMD certificates. They
prove parsing and refusal behavior, not hardware support or a live release.

The collector follows the [Linux SEV guest UAPI](https://docs.kernel.org/virt/coco/sev-guest.html)
and `include/uapi/linux/sev-guest.h`: a 96-byte report request, 32-byte ioctl
argument, 4000-byte response buffer, and MSG_REPORT_RSP's 32-byte header followed
by the 1184-byte report. Firmware/VMM errors, unexpected lengths, and nonce or
VMPL mismatches are refused.

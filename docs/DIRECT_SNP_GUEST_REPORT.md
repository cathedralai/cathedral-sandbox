# Direct report from a dedicated SNP guest

AB#1004 supplies a collector and verifier for a customer's own sealed SEV-SNP
guest. The collector calls `/dev/sev-guest` directly. This does not make that
ioctl work inside a gVisor sandbox, and does not use the existing report socket.
The custom image launch and HOST_DATA setup are separate release requirements.
This document is not evidence that either has been deployed.

## Account access and owner signing

The agreed UR API flow uses the customer's existing Cathedral `cat_sk_` key.
Do not mint a second dedicated booking key for this flow. Account authentication
and the dedicated owner check still apply; an API key alone does not establish
the guest's bootstrap binding.

The Ed25519 owner signing pair is separate from the API key and the guest's SSH
host key. Its public half is an input to the HOST_DATA hash below. The measured
guest must enforce the corresponding signature/bootstrap contract. Keep the
private half with the signer, never in the report or public evidence.

An administrator-generated pair is suitable for the authorized rehearsal.
Record it as operator-controlled test ownership, not customer-exclusive control.
Use one agreed pair across signing, launch inputs and verification. For
customer-controlled operation, use their public key while they retain the
private key. Changing that input changes HOST_DATA and requires a new verified
launch; it is not a Cathedral API-key rotation.

## Prerequisites

The guest must run a 64-bit little-endian Linux kernel with the SEV guest driver
(`CONFIG_SEV_GUEST`) and expose `/dev/sev-guest` as a character device. The caller
needs permission to open it read/write and obtain a VMPL 0 report. Image authors
must include the driver or arrange for its module to load. The collector does
not load modules, change permissions, or fall back to a proxy if the device or
ioctl is absent. It needs only Python 3's standard library.

Run verification on a trusted machine outside the guest, using Python 3.11+,
`cryptography>=42`, and both `verify_guest_report.py` and `verify_receipts.py` from
the same reviewed repository revision. The existing verifier retrieves AMD
certificates from KDS or its local cache. For offline verification, populate the certificate cache and supply a current
AMD KDS DER CRL with `--ark-crl`. The verifier checks all three certificate
validity periods against its own UTC clock, and requires an ARK-signed, current,
full CRL that does not revoke the ASK. It fetches that CRL from KDS on every
on-offline check; a fetch failure, future or expired CRL fails closed.
VCEK firmware acceptability is checked through the required TCB floor. Never adopt a root fingerprint from
the guest's answer.

Before launch, independently obtain:

- The expected 48-byte SNP launch measurement for the exact kernel, initrd,
  command line, launch policy and VM configuration.
- The expected 32-byte HOST_DATA, recomputed from the approved R3 launch
  contract and customer-owned inputs, including the owner public key and
  bootstrap digest. Use that contract's exact manifest encoding and version;
  do not hash an arbitrary JSON serialization or copy HOST_DATA from the report.
- A trusted AMD ARK SHA-256 fingerprint and the expected physical chip identity.
- An approved CPU family/model/stepping and its complete minimum TCB policy.
  This entry point supports Turin report versions 3, 4 and 5 only. It refuses
  version 2 and Genoa. The legacy receipt verifier keeps its broader support.

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
there; do not replace it with a nonce claimed by the guest. Set all
expectation variables below from the independent inputs above, then run:

```sh
python3 room-kit/verify_guest_report.py guest-report.json \
  --report-data-hex "$NONCE_HEX" \
  --expected-measurement "$EXPECTED_MEASUREMENT_HEX" \
  --expected-host-data "$EXPECTED_HOST_DATA_HEX" \
  --ark-sha256 "$TRUSTED_ARK_SHA256" \
  --expected-chip-id "$EXPECTED_CHIP_ID_HEX" \
  --expected-cpuid "$APPROVED_CPUID_HEX" \
  --min-tcb "$APPROVED_TURIN_FLOOR"
```

The collector requests VCEK explicitly (`KEY_SEL=1`) and returns
`verification: not_checked`. The verifier returns `verdict: report_verified`
with exit status 0 only after checking the current AMD chain and revocation
status, report signature, original REPORT_DATA, expected measurement and
HOST_DATA, chip pin, CPU-specific floor, VMPL 0, VCEK signing with an unmasked
chip key, and exact launch policy `0x30000`. It also rejects platform SMT without
guest permission. Invalid input or any missing expectation exits nonzero.

`--expected-cpuid` is three hexadecimal bytes, `family:model:stepping`.
`--min-tcb` must be one complete
`turin:fmc=N,bl=N,tee=N,snp=N,ucode=N` policy. These two inputs form one approved
profile: that floor applies only to that exact CPU tuple. Unknown or different
steppings fail; they cannot inherit another stepping's floor. Replace every `N`
with an independently approved decimal minimum (0 through 255). Every component
is checked on the current, reported, committed and launch TCB. No production
floor is selected by this tool. Never copy a floor, chip pin or CPU tuple from
the untrusted guest report; fixture values are not an approved security policy.

This primitive deliberately never returns a final `PASS`. Its output includes
`ssh_channel_binding: not_checked`. The launch's SSH wrapper must derive the
64-byte REPORT_DATA from the fresh 32-byte challenge, purpose tag and the host
key of the actual SSH connection, using the reviewed launch protocol, and
verify that binding before returning the final PASS. The random 64-byte example
above exercises only this report primitive; it is not that channel protocol.

Policy and field layouts follow [AMD's SNP ABI, tables 9 and 22–24](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf).
The CRL is the product's `/vcek/v1/Turin/crl` resource in
[AMD's KDS specification](https://docs.amd.com/v/u/en-US/57230).

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

Spock owns the end-to-end run using the authorized Cathedral account key and
the agreed test owner signing pair in their separate roles. First rehearse
on separate SNP capacity without customer work. Record the deployed launch
revision, image digests, independently calculated measurement and HOST_DATA,
device/driver evidence, collection exit status, and verifier output. Negative
checks must reject a changed nonce, measurement and HOST_DATA. Preserve customer
rooms, workspaces, volumes and snapshots throughout the rollout.

Tests use injected ioctl responses and synthetic, signed Turin chains and CRLs.
The shared legacy verifier also checks an archived Turin report with its AMD
chain; that archive is not a current admission or revocation proof. They prove parsing and refusal
behavior, not fresh hardware acceptance or a live release.

The collector follows the [Linux SEV guest UAPI](https://docs.kernel.org/virt/coco/sev-guest.html)
and `include/uapi/linux/sev-guest.h`: a 96-byte report request, 32-byte ioctl
argument, 4000-byte response buffer, and MSG_REPORT_RSP's 32-byte header followed
by the 1184-byte report. Firmware/VMM errors, unexpected lengths, and nonce or
VMPL mismatches are refused.

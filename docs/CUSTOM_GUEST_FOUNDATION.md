# Custom guest foundation (AB#1004, AB#1008)

This is a draft component of the custom SNP guest build. It does not enable custom guests or change an existing hotel. The platform API key authenticates the Cathedral account; the Ed25519 owner key below signs launch documents and is a separate credential.

## Implemented component

`room-kit/custom_guest_protocol.py` implements the versioned manifest/bootstrap readers and the domains from spec-r9 sections 8 and 10. Inputs must be canonical JSON bytes, with integer versions, printable ASCII strings and no unknown fields. The owner key is supplied independently. The bootstrap signature, the measured cmdline owner, and the manifest hash must agree before deriving HOST_DATA.

Shared interoperability inputs and expected outputs are in `tests/fixtures/custom_guest_v1.json`. These are synthetic test values, never production credentials. The optional omitted `data_disk_gib` means zero; its original canonical bytes are retained for hashing. Producers should always write that field.

`owner_sign.py --custom-guest-bootstrap --key OWNER_KEY --body bootstrap.json` prints a base64 signature over the custom-guest domain and the digest of the exact bootstrap bytes. It refuses a bootstrap naming another owner. The existing room-create signing path is unchanged. The owner must inspect the launch documents before signing.

`cathedral_attest.py`, to be installed as `/usr/bin/cathedral-attest` in the verified root, requires root. It combines the verifier's 32-byte challenge with the wire-format Ed25519 host key from `/run/cathedral/ssh_host_ed25519_key.pub`, then uses the native `/dev/sev-guest` collector. It has no proxy or emulated fallback. The init must generate the matching private/public host key pair in RAM and configure sshd to use that private key.

`verify_custom_guest.py` makes one fresh OpenSSH connection, runs the report command there and reads the host key OpenSSH accepted after key exchange. It verifies the report against that key, the fresh challenge and the owner's launch expectations. An existing SSH config, agent, proxy or multiplexed connection cannot silently replace this connection. Response size and elapsed time are bounded.

A trust file is created only after every check succeeds, with mode 0600 and exclusive creation. Existing trust files are never overwritten. `PASS` applies to this SSH-bound report. It does not prove a future connection, application behavior, disk freshness, or that arbitrary guest code consumed the bootstrap. Re-attest after a relaunch or changed report identity; do not automatically release secrets.

## Owner-side invocation

Supply the independently computed measurement, approved chip/CPU/complete firmware floor and AMD root fingerprint. The launch files must be the owner's retained copies, not values taken from the report or substituted by an API response. `owner.pub` is exactly 32 raw bytes and `bootstrap.sig` is exactly 64 raw bytes (decode the signing tool's base64 output).

```sh
python3 room-kit/verify_custom_guest.py \
  --host HOST_FROM_SIGNED_BOOTSTRAP --port SSH_PUBLIC_PORT \
  --identity OWNER_SSH_PRIVATE_KEY \
  --manifest manifest.json --bootstrap bootstrap.json \
  --bootstrap-signature bootstrap.sig --owner-public-key owner.pub \
  --expected-measurement EXPECTED_MEASUREMENT \
  --expected-chip-id EXPECTED_CHIP_ID --expected-cpuid FAMILY:MODEL:STEPPING \
  --min-tcb turin:fmc=FMC,bl=BL,tee=TEE,snp=SNP,ucode=UCODE \
  --ark-sha256 TRUSTED_AMD_ROOT_SHA256 \
  --known-hosts-out newly_verified_known_hosts
```

The endpoint must match the owner-signed public host and first port mapping. The wrapper currently supports the strict Turin verifier; Genoa rehearsal evidence is a separate, partial qualification and must not be presented as Turin acceptance.

## Evidence and remaining work

Tests exercise real OpenSSH key exchange and a forced report command on a loopback sshd, with explicitly synthetic SNP reports/certificates. The command is refused for tampered reports, and no key is saved on failure. Signed reports for another challenge or host key also fail. This is transport/cryptographic integration evidence, not a chip or customer-host test.

Before this foundation can be marked ready:

- Build and qualify the static reference `/init`, its pinned static helper closure and deterministic single-archive initrd.
- Enforce the bootstrap against guest-observed state before networking/root use; enforce root-only SNP and configfs report access.
- Build the reference kernel and verified-root test image, configure SSH, verify the helper digest and disable cloud-init/imported credentials.
- Add the owner-unlocked data-disk helper, archive closure checks and reproducible artifact evidence.
- Cross-review the complete result, then run the approved hardware rehearsals through Spock's launcher/operator path.

The launcher, broker hold and API are separate Spock-owned PRs. No host operation, customer interruption, new compute or production switch is part of this component.

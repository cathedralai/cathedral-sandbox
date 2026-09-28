# Intel TDX miner image

This page records the immutable image contract. Use the repository
[README](../README.md) for the mining sequence.

## Current release

```text
Source: 78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8
Image: ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99
Platform: linux/amd64
Runtime contract: signed-validator-fleet-v1
```

The digest was published by GitHub Actions run
[`33266307118`](https://github.com/cathedralai/cathedral-sandbox/actions/runs/33266307118)
with build provenance and anonymous registry access. This proves the published
artifact, not a live deployment.

## Pin order for the v2 runtime contract

Images built from this source declare runtime contract
`signed-validator-fleet-v2` (TDX) or `snp-signed-validator-fleet-v2` (SNP).
A `-v2` image takes `CATHEDRAL_NETWORK` and `CATHEDRAL_NETUID` from the
launcher. Every image pinned today, including the `a66d7c4` images that #226
pins, declares `-v1` and refuses those inputs. The launchers in this source,
and the signed updater that checks a release's launcher against its image,
require `-v2` and refuse a `-v1` image before starting it, with an error that
names both contracts.

The README's launcher digest always follows the launcher in the tree (a test
checks it), so it changes in the same commit as the launcher. The image pins
cannot, because the images are published from `main` after the merge. The
README's pins form one release only after these steps, in this order:

1. Merge the `-v2` launcher and entrypoint change (#216). The publish
   workflows build `-v2` images from that commit.
2. Repin in one change: every image digest (README, the image docs,
   `docs/AMD_SEV_SNP_FRIEND_TEST.md`, the SNP env example, the tests), the
   revision-label and runtime-contract checks, and the README's
   `cathedral-runtime` and `cathedral-access` checkouts move to those `-v2`
   images and their source commit. This replaces the #226 pins; do not merge
   #226's `-v1` pins after #216.
3. Only then direct operators to the README's launcher digest. Between steps 1
   and 2 the launcher digest and the image pins come from different releases,
   and the launcher refuses the pinned image.

The image path must also match. #227 moves the publish workflows to the
`cathedral-sn94-*` packages only, while the launchers' `IMAGE_PATH` and the
updater's check that a release image is in its launcher's repository
(`cathedral/miner_updater.py`, `_check_launcher`) still require
`cathedral-sn39-*`. If #227 merges before the step 1 images are published,
those images exist only at the sn94 path, where these launchers refuse them.
Either publish the `-v2` images before #227 merges, or move the launchers,
docs and tests to the sn94 path in the step 2 repin.

## Inputs

The default entrypoint accepts no arguments and exactly five Cathedral
environment values:

```text
CATHEDRAL_MINER_HOTKEY=<public Bittensor SS58 hotkey>
CATHEDRAL_PUBLIC_ENDPOINT=https://<public-ip>:8081
CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST=sha256:<64-lowercase-hex>
CATHEDRAL_NETWORK=<chain network name>
CATHEDRAL_NETUID=<canonical decimal netuid>
```

They are public identity, integrity and deployment values. The network and
netuid have no default: the entrypoint refuses to start without them, and
refuses a netuid that is not one canonical decimal number from 0 to 65535. They
must equal the network and netuid the control host signs validator-access
snapshots for. The entrypoint rejects every
other `CATHEDRAL_*` environment value.

The image fixes the remaining runtime contract:

```text
Snapshot: /etc/cathedral/validator-access/validator-access.json
Public keys: /etc/cathedral/validator-access/snapshot-keys.json
Fleet: /etc/cathedral/validator-access/fleet.json
Replay state: /var/lib/cathedral/validator-access/validator-access.sqlite
Validator stake floor: 0 Rao plus validator permit
Listener: native TLS on 0.0.0.0:8081
TEE: Intel TDX
```

The snapshot signer and its private Ed25519 seed stay outside the guest. The
worker receives only the signed snapshot, its public keys, the key-file digest,
and public fleet candidates.

## Attested channel

At each start, the entrypoint creates a fresh Ed25519 TLS key and self-signed
certificate inside the guest. A validator observes that TLS SPKI and requires
the fresh TDX quote to bind the same SPKI, challenge, and miner hotkey. It then
requires SAT to use the same TLS key.

The validator does not trust the self-signed certificate as a public CA
identity. It trusts the vendor-verified quote binding the live key.

The only writable host hardware mount is the guest's
`/sys/kernel/config/tsm/report` subtree. Quote collection needs to create a
report directory and write its challenge. Do not mount broader sysfs or a
wallet directory.

## Host boundary

`scripts/run_sn94_signed_fleet_miner.sh` requires the immutable digest and:

- verifies the pulled repository digest, platform, and runtime label;
- mounts config read-only and replay state separately;
- uses a read-only container filesystem and a bounded TLS tmpfs;
- drops Linux capabilities and blocks privilege escalation;
- applies process, memory, swap, file-descriptor, and shutdown limits;
- installs one dedicated nftables table for TCP `8081`; and
- removes only its container and dedicated table on exit.

These controls limit ordinary misuse and connection pressure. They do not
prove DDoS resistance or which image a remote host runs. Fresh attestation is
the remote proof.

## Temporary compatibility bridge

The current image invokes the bounded `public-legacy-audit` migration posture.
It keeps fresh evidence and canonical audit SAT public while fleet discovery
and all non-public routes require signed validator requests. Operators cannot
change this posture through environment variables.

Moving to signed-only `worker serve` requires a new reviewed image. Do not
describe the current digest as signed-only.

## Build contract

- Dockerfile: `Dockerfile.sn94-audit-miner`
- Entrypoint: `cathedral/audit_miner_entrypoint.py`
- Host launcher: `scripts/run_sn94_signed_fleet_miner.sh`
- Exact Python wheels and hashes: `requirements/sn94-audit-miner.txt`
- Publication workflow: `.github/workflows/publish-sn94-audit-miner.yml`

Use [SN94 miner image operations](SN94_AUDIT_MINER_OPERATIONS.md) for the
current pin, fleet rules, and stop conditions.

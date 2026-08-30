# SN39 GCP signed-fleet delivery

## Status

This is a source-reviewed activation bridge. It is not evidence of a deployment.
It creates no chain authority and it never submits weights.

The bridge has two explicit operator modes. The one-machine-first mode creates
only the UID124 primary at `35.222.166.235:8081` and gives it an empty fleet
candidate list. The retained two-machine mode creates the primary and secondary
at `35.222.166.235:8081` and `34.46.19.69:8081`. The acknowledgement strings are
different, so one mode does not authorize the other.

Both modes are fixed to:

- GCP project `polaris-tdx-attest`, zone `us-central1-b`.
- Named `c3-standard-4` Intel TDX guests with 20 GB NVMe boot disks.
- The selected static endpoint or endpoints from the two fixed addresses.
- UID124 hotkey `5CJTD6znKPfsQFjPQtTvRiHHcLtpXJr7P16dF4VuEtx9qn7G`.
- UID30 validator hotkey `5FF6FtDUhn7XdPYmEdH5XjLAmLfmwLTCNVBgcrj3A4sstwaw`.
- Finney, netuid 39, minimum validator stake 0 Rao.
- One immutable `linux/amd64` GHCR image digest.
- Four-hour automatic instance deletion.
- One public TCP 8081 ingress rule, no service account, no scopes, and project
  SSH keys blocked.
- A five-minute snapshot refresh and a maximum 900-second signed snapshot.

Each selected old guest must finish deleting and its static address must return
to `RESERVED` before the provisioner proceeds. Primary-only mode neither creates
nor updates the secondary.

## Trust and secret boundary

The control host reads finalized chain state and signs one public
`cathedral_validator_access_snapshot_v1` with a dedicated Ed25519 artifact key.
The seed stays on the control host. It is not a Bittensor wallet key.

The guest receives only public material through GCP instance metadata:

- the signed snapshot;
- its digest-pinned public verification keys;
- its exact digest-pinned fleet file;
- the digest-pinned guest poller and launcher;
- the immutable miner image reference and public endpoint identity.

The fleet file has no separate signature. Its integrity boundary is the
root-controlled GCP instance configuration, its SHA-256 pin, the attested TLS
channel, and the validator-signed request required to read it. Anyone able to
rewrite instance metadata is inside this deployment's control-plane trust
boundary.

No wallet, wallet password, Bittensor RPC configuration, bearer token, cloud
service-account credential, or private artifact seed enters either guest.

## One-time artifact key

Use a Bittensor-compatible Python environment which also contains
`cryptography`. Create the dedicated seed once in an owner-controlled directory:

```bash
umask 077
python scripts/cathedral_validator_access.py init-key \
  --signing-key-id cathedral-validator-access-1 \
  --signing-key-out /absolute/owner-only/validator-access.seed \
  --keys-out /absolute/public/validator-access-keys.json
```

Record the printed public key and `keys_digest`. Never copy the seed into GCP
metadata, a guest, a shell argument log, or a repository.

## No-write plan

The one-machine-first plan contacts neither GCP nor the chain:

```bash
python scripts/sn39_gcp_snapshot_publisher.py plan-primary-only
```

It must list only `cathedral-sn39-uid124-fleet-primary-20260829`, static IP
`35.222.166.235`, and an empty `fleet_candidates_beyond_self` value.

The plan prints a conservative four-hour estimate of `$1.00` for the selected
primary. This is a planning estimate, not the `$20.00` operator hard cap, and the
script does not enforce billing limits. The estimate uses the August 30, 2026
Iowa on-demand list prices:

- C3 standard-4: `4 * $0.201608 = $0.806432`.
- Intel TDX: `4 * (4 * $0.0033982 + 16 * $0.0004555) = $0.0835232`.
- 20 GiB balanced persistent disk:
  `4 * 20 * $0.000136986 = $0.01095888`.
- One in-use external IPv4: `4 * $0.005 = $0.02`.

The listed total is `$0.92091408`, rounded up to `$1.00`. It excludes network
egress, taxes, and reserved-address time outside the four-hour VM window. Verify
rates before execution against the official [C3 price table](https://cloud.google.com/products/compute/pricing/general-purpose),
[Confidential VM price table](https://cloud.google.com/confidential-computing/confidential-vm/pricing),
[disk price table](https://cloud.google.com/compute/disks-image-pricing), and
[external IP price table](https://cloud.google.com/vpc/pricing).

The retained two-machine plan is:

```bash
python scripts/sn39_gcp_snapshot_publisher.py plan
```

Review every fixed field. Any difference from the selected UID124 operator mode
is a stop condition.

## Bounded provision

The activation image is fixed to this reviewed, immutable reference:

```text
ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99
```

After anonymous pull and provenance verification, run the one-machine-first
provisioner:

```bash
python scripts/sn39_gcp_snapshot_publisher.py provision-primary-only \
  --signing-key-file /absolute/owner-only/validator-access.seed \
  --keys-file /absolute/public/validator-access-keys.json \
  --image ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99 \
  --acknowledge CREATE_ONLY_UID124_PRIMARY_TDX_GUEST_35_222_166_235_FOR_FOUR_HOURS
```

This command creates only the fixed UID124 primary. Its fleet bytes contain no
additional endpoint. It retains the same TDX, immutable image, 20 GB disk,
four-hour automatic deletion, VPC, TCP 8081, no-service-account, and blocked-SSH
contract.

The retained two-machine provisioner is:

```bash
python scripts/sn39_gcp_snapshot_publisher.py provision \
  --signing-key-file /absolute/owner-only/validator-access.seed \
  --keys-file /absolute/public/validator-access-keys.json \
  --image ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99 \
  --acknowledge CREATE_TWO_UID124_TDX_GUESTS_FOR_FOUR_HOURS
```

Each command refuses while a selected fixed VM name already exists, a selected
static address remains in use, shared network policy differs, an artifact pin is
invalid, or finalized UID30 no longer has a permit. In two-machine mode, if one
create succeeds and the other fails, it performs no destructive rollback. Every
created guest retains its four-hour automatic deletion bound.

## Public snapshot refresh

For one-machine-first operation, start this refresher immediately after
provisioning and keep the process in the foreground:

```bash
python scripts/sn39_gcp_snapshot_publisher.py publish-loop-primary-only \
  --signing-key-file /absolute/owner-only/validator-access.seed \
  --keys-file /absolute/public/validator-access-keys.json \
  --image ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99 \
  --acknowledge PUBLISH_PUBLIC_UID30_PERMIT_SNAPSHOT_ONLY_TO_UID124_PRIMARY_35_222_166_235
```

This mode verifies and updates only the UID124 primary. The retained two-machine
refresher is:

```bash
python scripts/sn39_gcp_snapshot_publisher.py publish-loop \
  --signing-key-file /absolute/owner-only/validator-access.seed \
  --keys-file /absolute/public/validator-access-keys.json \
  --image ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99 \
  --acknowledge PUBLISH_PUBLIC_UID30_PERMIT_SNAPSHOT_TO_TWO_GUESTS
```

Each cycle rechecks every selected live instance contract, captures one finalized
chain view, verifies the signature locally, and updates only the public signed
snapshot metadata value on the selected instance or instances. A refused refresh
is reported as structured JSON and the next bounded cycle retries it. The loop
schedules at most 48 cycles, five minutes apart. It reads the selected instance
creation timestamps and exits with `INSTANCE_WINDOW_COMPLETE` before another
refresh would reach the earliest four-hour deletion deadline. A guest polls every
15 seconds and stops its miner when its last accepted snapshot becomes stale.

Snapshot rollback and same-height equivocation are refused durably. Both the
metadata installer and the worker's in-process provider accept a fresh
same-height re-sign only when the finalized block hash and complete validator
authorization digest remain identical. The fresh copy replaces the expiring
signed envelope and advances its durable document digest. A refused installed
snapshot is never assigned as active during guest restart. If the launcher
ignores graceful shutdown, the poller kills its bounded launcher process and
force-removes the fixed named container before a restart.

The publisher needs no Cathedral wallet password. The later
`cathedral-uid30-fleet-preview` opens `cathedral/default` locally to sign the
short-lived worker requests. If its hotkey file is encrypted, enter the password
only at the local interactive prompt. Never pass it in an environment variable
or command-line option.

## Required live proof

Primary-only provisioning and snapshot publication are not live compute proof.
They establish one bounded delivery target, not the two-machine result below.

For the retained two-machine path, use validator `main` and the pinned QVL binary
to run the exact no-write command documented in the validator repo:

```bash
cathedral-uid30-fleet-preview \
  --qvl /absolute/path/to/cathedral-tdx-verifier \
  --output /absolute/owner-only/two-machine-proof.json
```

Activation remains blocked unless the artifact reports all of these together:

- `PROVEN_TWO_MACHINE_NO_WRITE_PREVIEW`;
- exactly two UID124 endpoints;
- two distinct TLS SPKIs and QVL-verified stable platform identities;
- 20 independently replayed SAT units from each machine;
- raw UID124 score 40;
- non-authorizing target row `[[124, 65535]]` and zero burn;
- an unchanged signed fleet and finalized chain recheck;
- `authorized_for_chain_write: false` and `chain_write_submitted: false`.

This proves the no-write compute target only. It does not change the current
UID30 row, prove subnet emission, or prove TAO earnings.

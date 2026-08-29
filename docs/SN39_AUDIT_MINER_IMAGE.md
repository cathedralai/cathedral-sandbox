# SN39 independent audit-miner image

This source change defines the hardened signed-fleet worker image for SN39. It
serves fresh Intel TDX evidence, signed fleet discovery, and signed validation
work over native TLS on `0.0.0.0:8081`. The fixed staged bridge also keeps
public evidence and canonical audit SAT available to the current UID30
collector. Customer SAT stays disabled.

This is a source and runtime-contract description. It is not evidence of a
published activation digest, a deployment, or a live two-machine result.

Use [SN39_AUDIT_MINER_OPERATIONS.md](SN39_AUDIT_MINER_OPERATIONS.md) for the
canonical bounded launch order, one-hotkey-per-listed-machine invariant, dated
UID124 proof, and stop conditions.

## Fixed runtime contract

The default entrypoint accepts no command arguments and exactly three public
Cathedral environment inputs:

```text
CATHEDRAL_MINER_HOTKEY=<public Bittensor SS58 hotkey>
CATHEDRAL_PUBLIC_ENDPOINT=https://<public-ip>:8081
CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST=sha256:<64-lowercase-hex>
```

These values are public identity and integrity pins, not wallet material. The
entrypoint requires a canonical AccountId32 SS58 hotkey in Bittensor format
`42`, a globally routable canonical HTTPS IP-literal origin, and an exact
lowercase SHA-256 key-file digest. It rejects every other `CATHEDRAL_*` input,
including wallet material, a worker bearer, an artifact signing seed, chain RPC
configuration, and evidence-collector overrides.

Relative to the legacy image, the public endpoint and public-key digest are the
only new scalar deployment inputs. The hotkey and immutable image digest were
already required. Config and state locations, network, subnet, stake floor,
port, TEE, migration behavior, and limits are fixed.

Everything else is fixed:

```text
Snapshot: /etc/cathedral/validator-access/validator-access.json
Public keys: /etc/cathedral/validator-access/snapshot-keys.json
Fleet manifest: /etc/cathedral/validator-access/fleet.json
Replay and snapshot high-water state:
  /var/lib/cathedral/validator-access/validator-access.sqlite
Network and subnet: finney, SN39
Validator stake floor: 0 Rao
Migration behavior: public evidence and canonical audit SAT only
```

The signed snapshot still requires `validator_permit: true`. A zero stake
floor therefore means permit-only access. It does not mean open access. The
snapshot producer and its private Ed25519 seed stay outside the guest. The
read-only guest config contains only the signed public snapshot, public keys,
and fleet candidates. The persistent state mount contains replay and
finalized-block high-water state. The worker has no Bittensor wallet or RPC
client.

At every start, the entrypoint creates a fresh Ed25519 TLS key and self-signed
leaf certificate under `/run/cathedral-audit-miner`. The directory is owner-only
mode `0700`. The key and certificate are owner-only mode `0600`. The worker
derives its TLS SPKI channel binding from this certificate. The certificate is
transport identity for attestation binding, not public-CA identity.

The generated leaf has the DNS SAN `cathedral-sn39-audit-miner`. The intended
UID30 launch path advertises an IP-literal axon and does not use this SAN as its
peer identity. Its independent `HttpsEvidenceTransport` observes the
self-signed leaf's SPKI, asks the guest to bind that SPKI with the nonce and
hotkey in REPORT_DATA, verifies the quote with QVL, and requires the SAT POST
to present the same SPKI. The ordinary production `RemoteMiner` and prober use
CA and hostname verification and are not compatible with this static SAN. Do
not substitute that client for the reviewed UID30 attested-SPKI transport.

The fixed command selects `--tee tdx`. Docker mounts its own read-only sysfs
over the image's `/sys` tree, so an image-layer
`/sys/kernel/config/tsm/report` directory is not a usable bind target. The
sanitized child environment therefore fixes the collector root at
`/opt/cathedral-audit-miner/tsm-report`. The operator bind-mounts only the
guest's host `/sys/kernel/config/tsm/report` subtree at that target. The path is
not a deployment input. This narrow bind is read-write because quote collection
creates one report directory, writes `inblob`, and reads `outblob`. Making it
read-only breaks evidence collection. No broader sysfs tree or TDX device is
mounted. The image exposes one listener, native TLS on TCP `8081`. It does not
configure a plaintext listener. The worker uses the kernel configfs TSM path
through this bounded read-write exception.

The fixed entrypoint always configures the signed validator-access and bounded
fleet-discovery role in [WORK_REQUEST_V2.md](WORK_REQUEST_V2.md). It also always
enables the narrow legacy-audit bridge during staged migration. There is no
environment flag or command override for signed-only, bearer, customer-SAT,
SNP, GPU, development, wallet, or RPC modes. Removing the bridge requires a
later reviewed image change after the signed collector and rollback path are
live-proven.

An operator with control of the container runtime can replace the entrypoint,
mount different files, or publish another port. The deployment policy must use
the reviewed digest and the fixed command described here.

## Base and dependency pins

The Dockerfile is restricted to Linux amd64 because the launch TDX supply is
x86-64. Its base is the Docker Hub amd64 manifest:

```text
python:3.12-slim-bookworm@sha256:4427763a1ba36f5aa8f656a03e5d00f3b8d61f5dd950c73df6c14f8c7640f8ab
```

`docker buildx imagetools inspect` resolved this digest from the registry on
2026-08-26. The manifest identified Python `3.12.14-slim-bookworm` and Docker
Library revision `f2c5d1b8a6adecb5b00b3c9331d4f863beade6b3`.
Runtime Python dependencies are exact-version, wheel-only, and hash checked in
`requirements/sn39-audit-miner.txt`. The Linux amd64 CPython 3.12
`py-sr25519-bindings==0.2.2` wheel has SHA-256
`849f77ab12210e8549e58d444e9199d9aba83a988e99ca8bef04dd53e81f9561`.
The Docker build runs the fixed sr25519 known-answer test and its corrupted
negative control after installing the wheel. The built image declares runtime
contract label `org.cathedral.sn39.runtime-contract=signed-validator-fleet-v1`.

## Reviewed GHCR publication

`.github/workflows/publish-sn39-audit-miner.yml` runs only after a reviewed
change reaches `main` in one of the image inputs. The publisher:

- grants the publishing job only `contents: read`, `packages: write`,
  `id-token: write`, `attestations: write`, and `artifact-metadata: write`;
- checks out the exact event commit without retaining Git credentials;
- pins the Buildx client and BuildKit builder image used for the build;
- builds only `linux/amd64` from `Dockerfile.sn39-audit-miner`;
- publishes one full-commit tag, `sha-<40-lowercase-hex-commit>`, and refuses to
  overwrite it or continue when the registry lookup is inconclusive;
- enables maximum BuildKit provenance and records a GitHub build-provenance
  attestation against the resulting digest; and
- writes the launch pin to the job summary as
  `ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:<64-hex>`.

The workflow publishes no `latest`, branch, or other mutable convenience tag.
The commit tag is for source lookup. The `image@sha256:...` reference is the
only launch identity accepted by the validator and Polaris deployment records.
Runs for the same source commit are serialized. If a run pushes its tag but
fails before provenance completes, do not overwrite or promote the partial
publication. Repair through a new reviewed source commit or an explicit package
version recovery, then capture and verify the new digest.

New GitHub Container Registry packages are private by default. A package admin
must make the package public in GitHub package settings after its first
publication. GitHub documents this as an irreversible visibility change. The
workflow performs an unauthenticated digest inspection in a separate job. That
job stays red until the package is public. After the visibility change, run the
workflow's `verify-existing-public-digest` manual path with the captured
`sha256:...` digest. The manual verification job has no repository or package
permissions.

Do not promote a digest until all of these are true:

1. The publishing job succeeded.
2. The provenance attestation succeeded for the same digest.
3. Anonymous digest inspection succeeded.
4. The validator and Polaris configuration both name the exact same digest.

GitHub references:

- [Container registry authentication and image publication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Package access control and public visibility](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility)
- [Build provenance attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)

## Run inside the TDX guest

Prepare the fixed host directories. The snapshot producer atomically refreshes
`validator-access.json` with `minimum_stake_rao: 0`. The fleet file uses the
schema in [WORK_REQUEST_V2.md](WORK_REQUEST_V2.md), including an empty
`endpoints` list for a one-machine UID. The private snapshot signing seed stays
outside these directories.

```bash
install -d -o root -g root -m 0700 /etc/cathedral/validator-access
install -d -o root -g root -m 0700 /var/lib/cathedral/validator-access
install -o root -g root -m 0644 validator-access.json \
  /etc/cathedral/validator-access/validator-access.json
install -o root -g root -m 0644 snapshot-keys.json \
  /etc/cathedral/validator-access/snapshot-keys.json
install -o root -g root -m 0644 fleet.json \
  /etc/cathedral/validator-access/fleet.json
```

Set the reviewed public values and exact unpublished or published activation
digest. The script requires the digest suffix to match
`sha256:[0-9a-f]{64}`. Then run the reviewed host script as root:

```bash
export SN39_AUDIT_MINER_IMAGE='ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:<64-hex>'
export CATHEDRAL_MINER_HOTKEY='<public-miner-hotkey>'
export CATHEDRAL_PUBLIC_ENDPOINT='https://<public-ip>:8081'
export CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST='sha256:<snapshot-keys-json-digest>'

sudo --preserve-env=SN39_AUDIT_MINER_IMAGE,CATHEDRAL_MINER_HOTKEY,CATHEDRAL_PUBLIC_ENDPOINT,CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST \
  scripts/run_sn39_signed_fleet_miner.sh
```

The script refuses tags, checks the pulled image's exact RepoDigest,
`linux/amd64` platform, and runtime-contract label, and then starts Docker with
the host network. The container root filesystem and config mount are read-only.
The TLS directory is a bounded tmpfs. Replay state uses the persistent writable
state mount. Capabilities are dropped, privilege escalation is disabled, and
process, memory, swap, file-descriptor, and stop-time limits are fixed.

Docker's fixed init process forwards termination to the worker and reaps any
orphaned descendants. The host keeps the Docker client in the background and
waits through Bash's signal-aware builtin, so `TERM`, `HUP`, and `INT` run the
same container and edge-table cleanup before the startup lock is released.

The only write exception outside the state and TLS mounts is the bounded
configfs path
`src=/sys/kernel/config/tsm/report,dst=/opt/cathedral-audit-miner/tsm-report`.
It must remain read-write for the kernel TSM quote protocol. The script does
not mount `/dev/tdx_guest` or a broader sysfs path.

Before Docker starts, the script syntax-checks and atomically installs the
dedicated `inet cathedral_sn39` nftables table. It affects only TCP destination
port `8081`. For IPv4 it permits at most two tracked connections per source and
limits new SYN packets to four per second with a burst of eight. IPv6 traffic
to this fixed IPv4 launch listener is dropped. Named accept and drop counters
are visible with `nft list table inet cathedral_sn39`. Accepted TCP is passed
through unchanged, so TLS still terminates inside the container. Other host
traffic retains the existing default behavior.

A nonblocking host lock at `/run/cathedral-sn39-startup.lock` serializes the
container name, nftables installation, and cleanup for the process lifetime.
A second start fails before its first Docker or nftables action. Signal and
failure cleanup retain the lock until this process's container and dedicated
table are gone. This prevents a failed contender from deleting the active
worker's edge table.

These limits are bounded functional protection for the source finding about
pre-header stalls. They are not distributed-DDoS proof. The cloud firewall
still limits ingress to the intended validator path. Monitoring must alert on
the named drop counter, container exit, stale snapshot, replay-state failure,
and quote or SAT failure.

On normal exit or failed startup, the script removes only its dedicated
`inet cathedral_sn39` table. If the process is killed without cleanup, the
manual network-edge rollback is exactly:

```bash
sudo nft delete table inet cathedral_sn39
```

Do not flush another nftables table. Do not pass a wallet seed, wallet JSON,
validator private key, snapshot signing seed, bearer, RPC URL, or TDX collector
override. Registration and the signed Bittensor axon advertisement happen
outside this image.

Do not copy `worker.key` out of the guest. The leaf certificate is public, but
UID30 does not treat it as a pre-shared trust anchor. The entrypoint rotates the
key and certificate on every container start, so the validator must observe the
new SPKI and verify a fresh quote before sending audit work. Cross-repository
tests cover the IP-literal TLS context and SPKI checks. The bounded UID124 test
on 2026-08-28 completed one live container, public axon, configfs quote, QVL
verdict, and same-SPKI SAT round trip. That dated result does not prove a new
deployment or ongoing availability. See
[SN39_AUDIT_MINER_OPERATIONS.md](SN39_AUDIT_MINER_OPERATIONS.md#2026-08-28-bounded-proof).

## Measurement and pin boundary

The fresh TDX quote binds the validator nonce, public hotkey, and runtime TLS
SPKI. It proves the verified guest produced that binding under the admitted TDX
policy. It does not place the post-boot OCI image digest into MRTD, an RTMR, or
another TDX launch measurement automatically.

The OCI digest is therefore an operator-enforced supply-chain pin. The
validator and Polaris deployment configuration must record and compare it
separately. Build provenance connects the digest to source and build metadata.
It does not convert the digest into TDX measurement evidence. A measured image
loader or an explicit in-guest measurement extension remains a separate
assurance gate.

## Rollback and remaining launch gates

The fixed startup script accepts only a digest carrying
`signed-validator-fleet-v1`. It cannot launch the reviewed legacy digest, which
has a different entrypoint, environment, and mount contract. Do not substitute
the legacy digest into this script.

After one signed-fleet digest has passed live proof, rollback means restoring
that previously proven signed-fleet `image@sha256:...` value in validator and
Polaris configuration, restarting through the same fixed script, and repeating
anonymous pull and live TDX/SAT validation. Do not retag, overwrite, or delete
a published launch digest as a rollback mechanism.

For the first signed-fleet activation, no previously proven signed-fleet digest
exists. A full legacy-runtime restore is a different command and configuration
transition and is not specified or tested by this source change. First
activation stays blocked until the operator captures and exercises that exact
legacy restore or proves a signed-fleet fallback digest. A digest-only swap is
not a rollback plan.

Stop the signed-fleet container before changing its config. The startup script
removes only `inet cathedral_sn39`; remove that exact table manually if an
unclean stop left it behind. Never flush the host firewall.

Source and publication alone do not:

- register a hotkey on SN39;
- publish the guest IP and port as an axon;
- create a cloud firewall rule;
- make the Workers platform publish container ports or configfs;
- prove a new deployment's anonymous pull, quote, SAT result, validator ingest,
  weight write, or emission;
- prove the intended UID30 IP-literal attested-SPKI transport for any endpoint
  other than the dated bounded proof; or
- prove the application image is included in the admitted TDX measurement.

The source change is ready for review only after its image tests, startup-script
contract tests, full repository suite, and independent security review pass.
Deployment remains blocked until a merge publishes a new immutable digest,
provenance and anonymous pull pass for that digest, the matching validator
source is merged, the fixed nftables boundary and monitoring are exercised, and
two distinct TDX machines for one UID pass fresh signed access, fleet discovery,
QVL, same-SPKI SAT, hardware deduplication, and no-write weight preview.

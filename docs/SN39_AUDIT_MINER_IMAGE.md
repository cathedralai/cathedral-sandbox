# SN39 independent audit-miner image

This image runs the hardened worker protocol needed by the independent SN39
validator. It serves fresh Intel TDX evidence and credential-free canonical SAT
over native TLS on `0.0.0.0:8081`.

Use [SN39_AUDIT_MINER_OPERATIONS.md](SN39_AUDIT_MINER_OPERATIONS.md) for the
canonical bounded launch order, one-hotkey-per-listed-machine invariant, dated
UID124 proof, and stop conditions.

## Fixed runtime contract

The default entrypoint accepts no command arguments and one Cathedral
environment input:

```text
CATHEDRAL_MINER_HOTKEY=<public Bittensor SS58 hotkey>
```

The value is public identity data, not wallet material. The entrypoint accepts
only an AccountId32 SS58 address with Bittensor format `42` and a valid SS58
checksum. It rejects every other `CATHEDRAL_*` input, including wallet material,
a supplied worker bearer, and evidence-collector overrides.

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
not a deployment input. The worker still uses the kernel configfs TSM path
through that narrow host bind. The image exposes one listener, native TLS on
TCP `8081`. It does not configure a plaintext listener.

The general worker CLI requires a bearer for non-audit routes. The entrypoint
creates one random, unprinted, process-local guard value before `exec`. It is
not an image secret or deployment input. Customer SAT and noncanonical SAT stay
disabled. The independent validator sends no bearer to the public evidence and
canonical SAT routes.

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
`requirements/sn39-audit-miner.txt`.

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

Set the captured digest reference in operator configuration. Refuse a tag-only
or malformed value before pulling:

```bash
SN39_AUDIT_MINER_IMAGE='ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:<64-hex>'

if [[ ! "$SN39_AUDIT_MINER_IMAGE" =~ ^ghcr\.io/cathedralai/cathedral-sn39-audit-miner@sha256:[0-9a-f]{64}$ ]]; then
  echo "refusing non-digest audit-miner image reference" >&2
  exit 1
fi

docker pull --platform linux/amd64 "$SN39_AUDIT_MINER_IMAGE"
```

The guest must expose Linux configfs TSM and admit inbound TCP `8081`. Run with
the host network only when the on-chain axon port is the same TLS listener. Keep
the container filesystem read only except for the private runtime tmpfs:

```bash
test -d /sys/kernel/config/tsm/report

docker run --rm \
  --name cathedral-sn39-audit-miner \
  --network host \
  --read-only \
  --tmpfs /run/cathedral-audit-miner:rw,noexec,nosuid,nodev,mode=0700 \
  --mount type=bind,src=/sys/kernel/config/tsm/report,dst=/opt/cathedral-audit-miner/tsm-report \
  --env CATHEDRAL_MINER_HOTKEY="$MINER_HOTKEY" \
  "$SN39_AUDIT_MINER_IMAGE"
```

Do not pass a wallet seed, wallet JSON, validator key, bearer, or TDX collector
override. Registration and the signed Bittensor axon advertisement happen
outside this image. The guest firewall and cloud firewall must admit only the
required TLS port from the intended validator path.

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

Rollback means restoring the previous reviewed `image@sha256:...` value in both
validator and Polaris configuration, restarting the guest workload, and
repeating anonymous pull and live TDX/SAT validation. Do not retag, overwrite,
or delete a published launch digest as a rollback mechanism.

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

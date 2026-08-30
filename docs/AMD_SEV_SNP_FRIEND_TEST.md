# AMD SEV-SNP miner

AMD SEV-SNP is a source-ready SN39 CPU path. It becomes scored only after the
separate Cathedral validator releases a pin to this exact contract and its SNP
admission policy accepts the machine. This repository serves the evidence and
work but does not write SN39 weights. The validator still requires fresh
vendor-verified evidence, the live TLS key bound into the report, a distinct
hardware identity, and canonical SAT. Registration and a local probe do not
earn weight by themselves.

The current TDX audit-miner image is not an SNP image. Use only the separate
immutable SNP image and launcher described in
[SN39 SNP miner image](SN39_SNP_MINER_IMAGE.md) after a published digest is
available.

## Supported hardware

The guest must expose native SEV-SNP attestation through `/dev/sev-guest`.
Plain AMD SEV and Azure vTPM attestation are not supported.

The reviewed verifier accepts:

- AMD attestation report versions 3, 4, and 5.
- The Milan, Genoa-family, and Turin paths recognized by `snpguest` 0.10.0.
- `snpguest` 0.10.0 with SHA-256
  `70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0`.

Report version 2, report version 6, an unknown processor family, a changed AMD
root, or a different `snpguest` binary fails closed. Supporting any of them
requires a reviewed source update.

## Requirements and first hardware proof

- An x86-64 Linux SEV-SNP guest where root can read and write the native
  `/dev/sev-guest` character device.
- Python 3.11 or newer.
- Outbound HTTPS to AMD KDS, GitHub, and PyPI during setup.
- A fresh observed run before the validator policy is published for that
  machine measurement and TCB.

No coldkey, cloud credential, API key, or private hotkey is required for this
first hardware check.

## Install the reviewed source and verifier

Run inside the SEV-SNP guest. The reviewer must supply the exact 40-character
Compute commit to test.

```bash
git clone https://github.com/cathedralai/cathedral-sandbox.git
cd cathedral-sandbox
REVIEWED_COMMIT='<40-character commit supplied by the reviewer>'
git checkout --detach "$REVIEWED_COMMIT"
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
git diff --exit-code
git diff --cached --exit-code

set -euo pipefail
SNP_GUEST_DOWNLOAD="$(mktemp /tmp/cathedral-snpguest-download.XXXXXXXX)"
curl --fail --location \
  https://github.com/virtee/snpguest/releases/download/v0.10.0/snpguest \
  --output "$SNP_GUEST_DOWNLOAD"
printf '%s  %s\n' \
  70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0 \
  "$SNP_GUEST_DOWNLOAD" | sha256sum --check -
chmod 0500 "$SNP_GUEST_DOWNLOAD"
test -r /dev/sev-guest -a -w /dev/sev-guest
```

Stop if either digest check fails. Do not run tests repeatedly or in parallel.
They contact AMD KDS and rapid retries risk rate limiting.

## Run the observed HTTPS and SAT test

The reviewer sends a fresh, nonzero 32-byte challenge as 64 lowercase hex
characters. Choose a new transcript path for every run.

```bash
TRANSCRIPT_PATH="/tmp/amd-sev-snp-transcript-$(date -u +%Y%m%dT%H%M%SZ).json"
REVIEW_CHALLENGE='<64 hex characters supplied by the observing reviewer>'
git status --porcelain=v1 --untracked-files=all
CATHEDRAL_SNPGUEST="$SNP_GUEST_DOWNLOAD" \
  .venv/bin/cathedral-snp-friend-probe \
  --challenge "$REVIEW_CHALLENGE" \
  --output "$TRANSCRIPT_PATH"
```

The first command must print nothing. The probe refuses a dirty source tree,
records the exact commit, and creates a new owner-only JSON file. It never
overwrites an existing transcript.

`LOCAL_PASS` means this observed run completed all of the following:

- AMD VCEK-chain and pinned-root verification.
- Fresh nonce, miner hotkey, measurement, TCB, and TLS SPKI binding.
- VMPL 0, debug disabled, and migration-agent disabled policy checks.
- Rejection of the wrong nonce, hotkey, TLS key, measurement, and a tampered
  signature.
- One canonical SAT round trip.
- A second report after hotkey and TLS-key rotation with a matching,
  review-scoped platform pseudonym.

The transcript omits the raw report, raw CHIP_ID, and TLS private key. It is a
redacted local record, not independently replayable evidence. Sending the file
without the reviewer observing the native-guest run does not prove live
hardware. A matching CHIP_ID-derived pseudonym does not prove durable
machine deduplication on a multi-socket host.

For a lower-level collector check, run:

```bash
CATHEDRAL_RUN_SNP_HW=1 \
  CATHEDRAL_SNPGUEST="$SNP_GUEST_DOWNLOAD" \
  .venv/bin/python -m pytest tests/test_attest_snp_hw.py -q
```

All six hardware tests must pass with no skip.

## Production worker

A public SNP worker uses HTTPS and the complete signed-validator access bundle
in [Validator access and fleet protocol](WORK_REQUEST_V2.md). It starts only
through the fixed `worker serve-snp` command. It has no `--tee`, development,
customer-SAT, composite-evidence, migration, public-evidence, or bearer-only
option.

The separate root-owned launcher mounts only `/dev/sev-guest` as hardware
access. It keeps the container filesystem read-only, drops capabilities, blocks
privilege escalation, and fixes its image repository, image digest, and runtime
contract. It does not mount a wallet, coldkey, chain RPC credential, or
snapshot-signing seed.

The validator's SNP policy remains a strict allowlist. Before a friend's
machine is registered, capture the observed transcript above and add the exact
measurement, processor generation, and minimum reported TCB to the reviewed
validator policy. The same component-wise floor applies to current, reported,
committed, and launch TCB. Do not use a wildcard policy to make a new machine
pass.

### Start the miner

Do not install a launcher from a different source revision. Start with the
published immutable image reference:

```bash
SNP_IMAGE='ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:REPLACE_WITH_PUBLISHED_DIGEST'
docker pull --platform linux/amd64 "$SNP_IMAGE"
SOURCE_COMMIT="$(docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
  "$SNP_IMAGE")"
printf '%s\n' "$SOURCE_COMMIT" | grep -Eq '^[0-9a-f]{40}$'

git clone https://github.com/cathedralai/cathedral-sandbox.git cathedral-snp-runtime
git -C cathedral-snp-runtime checkout --detach "$SOURCE_COMMIT"
test "$(git -C cathedral-snp-runtime rev-parse HEAD)" = "$SOURCE_COMMIT"
test -z "$(git -C cathedral-snp-runtime status --porcelain)"
```

On the separate miner-controlled host, use this same `SOURCE_COMMIT` with only
the [Refresh validator access from a control host](../README.md#2-refresh-validator-access-from-a-control-host)
procedure. Replace the revision shown in that TDX example with
`$SOURCE_COMMIT`. Do not run its TDX host or image steps. Keep the snapshot
signing seed on the control host. Transfer only `snapshot-keys.json` and the
fresh `validator-access.json` to the SNP guest.

On the guest, create both private destinations first. The launcher refuses
linked, non-root-owned, or group/world-accessible access state:

```bash
sudo install -d -o root -g root -m 0700 \
  /etc/cathedral/validator-access \
  /var/lib/cathedral/validator-access
```

Then save this as
`/etc/cathedral/validator-access/fleet.json`, owner `root`, group `root`, mode
`0644`:

```json
{
  "schema": "cathedral_worker_fleet_v1",
  "worker_hotkey": "YOUR_PUBLIC_HOTKEY",
  "endpoints": []
}
```

Install the two transferred access files at the same location and permissions
shown in that access procedure. Then install the fixed launcher from the exact
image-labelled source revision:

On the SNP guest:

```bash
sudo install -o root -g root -m 0700 \
  cathedral-snp-runtime/scripts/run_sn39_snp_miner.sh \
  /usr/local/sbin/cathedral-run-sn39-snp-miner
sudo install -o root -g root -m 0644 \
  cathedral-snp-runtime/examples/systemd/cathedral-sn39-snp-miner.service \
  /etc/systemd/system/cathedral-sn39-snp-miner.service
sudo install -d -o root -g root -m 0700 /etc/cathedral
sudo install -o root -g root -m 0600 \
  cathedral-snp-runtime/examples/systemd/sn39-snp-miner.env.example \
  /etc/cathedral/sn39-snp-miner.env
```

Edit `/etc/cathedral/sn39-snp-miner.env`. Set the published immutable image
reference to the same value as `SNP_IMAGE`, public miner hotkey, public HTTPS
endpoint, and SHA-256 of
`/etc/cathedral/validator-access/snapshot-keys.json`. A mutable image tag is
refused.

Then start and inspect the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cathedral-sn39-snp-miner.service
sudo systemctl status cathedral-sn39-snp-miner.service
sudo journalctl -u cathedral-sn39-snp-miner.service -n 100 --no-pager
```

Do not register or announce the hotkey yet. Give the validator operator the
hardware-proof transcript. Registration follows only after the released
validator policy contains the exact observed generation, measurement, and TCB
floor and a fresh signed validator request passes end to end.

## What the two checks prove

A successful observed run proves fresh vendor-backed SNP evidence and one SAT
round trip for the tested guest, verifier, and challenge. The recorded source
commit and image digest are local audit context. They are not fields in the SNP
report. A successful validator round additionally proves that its policy
admitted the machine and that its endpoint, TLS key, and hardware identity did
not collide.

Neither check proves SN39 registration, a finalized UID30 weight row, subnet
emission, or TAO earnings. Those require the separate live chain test.
Neither check remotely proves the OCI image digest or continuous runtime
integrity after boot.

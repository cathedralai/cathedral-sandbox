# AMD SEV-SNP miner

AMD SEV-SNP is a scored SN39 CPU path in the current direct validator source.
Each validator owns its SNP admission policy and accepts a machine only after
adding its observed measurement, processor generation, and minimum TCB. This
repository serves the evidence and work but does not write SN39 weights. The
validator still requires fresh vendor-verified evidence, the live TLS key bound
into the report, a distinct hardware identity, and canonical SAT. Registration,
policy admission, and a local probe do not earn weight by themselves.

The current TDX audit-miner image is not an SNP image. Use only the separate
immutable SNP image and launcher described in
[SN39 SNP miner image](SN39_SNP_MINER_IMAGE.md). The current published pin is
fixed below. The image digest does not receive weight. A machine started from
that image contributes to its UID only after the scoring validator admits its
live measurement and TCB and verifies fresh evidence and SAT.

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

### Socket policy and hardware identity

Two separate rules are easy to confuse. One is a validator option. The other is
not optional and is now confirmed on real hardware.

**The socket bit is the validator owner's choice.** The guest launch policy bit
`SINGLE_SOCKET` (bit 20, `POLICY.SINGLE_SOCKET` in AMD publication 56860) gates
whether the validator will use the report's CHIP_ID as the machine identity.
Since cathedral-validator #235 that gate is an owner policy field,
`require_single_socket`, which defaults to `true`. A validator that leaves the
default refuses a report without the bit as `snp_single_socket_required`,
whatever the measurement and TCB.

Why the default matters on a multi-socket host: AMD firmware refuses to activate
a `SINGLE_SOCKET` guest through `SNP_ACTIVATE`, and only `SNP_ACTIVATE_EX` can
pin a guest to one socket (56860 section 4.4). Upstream Linux KVM issues
`SNP_ACTIVATE` only. So on a host with two or more populated sockets you cannot
launch a guest that satisfies the default, and your validator's operator must
decide whether to set `require_single_socket` to `false`. The flag is
policy-wide: it applies to every admitted processor generation, not to one
(cathedral-validator `cathedral_thin/independent_runtime/snp_production.py`
lines 55-59 and 101-110).

`cathedral-validator-setup` accepts the key on current cathedral-validator
main. Since cathedral-validator #266 (merged 2026-09-29), its `_validate_policy`
allows `require_single_socket` beside `schema` and `generations` and refuses a
value that is not a JSON boolean, as the runtime does
(`deploy/validator-update/cathedral-validator-setup` lines 291-302). Setup is
installed from the signed updater bootstrap
(`deploy/validator-update/install_updater_bundle.py` lines 95-100), and the
published bootstrap, sequence 3, was signed on 2026-09-27, before #266
(`cathedral-validator/docs/AUTO_UPDATE.md` line 121). So a host installed with
bootstrap sequence 3 or earlier still refuses any policy that contains the key,
whatever its value, with "SNP policy has an unsupported production shape",
until its next bootstrap. That includes the `require_single_socket: true`
that this repository's #222 policy entry carries for a guest with the bit.

On SN39, by operator report (unverified in-repo), UID30 set
`require_single_socket` to `false` on 2026-09-08 and admitted a two-socket
`milan` host that same day. Setup refused the key then, so that would have
needed a manual policy install. The date matches the merge of
cathedral-validator #235, which added the flag. That is one validator's
decision. Ask your target validator's operator rather than assuming.

**Hardware identity dedup is not optional.** Linux routes every SNP command,
including the guest's attestation request, through one PSP on the host. On
2026-09-08 we ran the direct test: two guests on one confirmed shared physical
host both verified against the AMD chain and returned the identical chip
pseudonym `5a8e82885be3a995`, identical measurement, and identical reported TCB.

The validator scores every machine that shares a CHIP_ID with another machine in
the same fleet as zero, under `duplicate_hardware_indexes`. Two guests on one
host therefore cancel each other out rather than doubling anything. Run one SNP
guest per physical host for scoring purposes.

That experiment used one host and did not establish the socket placement of the
two guests, so it confirms same-host CHIP_ID collision and does not by itself
prove the general cross-socket case.

Customer capacity offered from one host is not a second scoring machine. The
direct validator pays one unit per surviving verified machine row per UID. In
cathedral-validator, `cathedral_thin/independent_runtime/fleet_score.py` lines
1064-1092 set every claimant of a repeated hardware identity to zero (the
repeats are found by `duplicate_hardware_indexes`,
`cathedral_thin/independent_runtime/multicompute.py` lines 165-187), and
`cathedral_thin/independent_runtime/direct_validator.py` lines 515-519 then
count the rows that remain per UID. So adding customer slots cannot multiply
reward claims for one chip. The weight computation in those three files never
reads customer capacity. Since cathedral-validator #257, `direct_validator.py`
can also score SN94 prober capacity receipts, but only as a shadow record made
after the weight write, which never reaches the weight plan
(`direct_validator.py` lines 1131-1162 and 1426-1429,
`cathedral_thin/independent_runtime/capacity_shadow.py` lines 35-37). So this
document makes no claim about how customer capacity itself is accounted.

## Requirements and first hardware proof

- An x86-64 Linux SEV-SNP guest where root can read and write the native
  `/dev/sev-guest` character device.
- Python 3.11 or newer.
- Outbound HTTPS to AMD KDS, GitHub, and PyPI during setup.
- A fresh observed run before the scoring validator adds that machine's
  measurement and TCB to its policy.

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
SNP_IMAGE='ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:0dc8db081dc35a993e8d59936c3ad036b39e68da84751282d9bba4ef16db2255'
docker pull --platform linux/amd64 "$SNP_IMAGE"
test "$(docker image inspect "$SNP_IMAGE" \
  --format '{{.Os}}/{{.Architecture}}')" = linux/amd64
test "$(docker image inspect "$SNP_IMAGE" \
  --format '{{index .Config.Labels "org.cathedral.sn39.runtime-contract"}}')" = \
  snp-signed-validator-fleet-v1
SOURCE_COMMIT="$(docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
  "$SNP_IMAGE")"
test "$SOURCE_COMMIT" = 8dde6eaca27116eed53386a1fa33ec70b74a01fb

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
hardware-proof transcript. Registration follows only after the scoring
validator's owner-controlled policy contains the exact observed generation,
measurement, and TCB floor and a fresh signed validator request passes end to
end.

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

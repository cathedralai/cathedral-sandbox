# AMD SEV-SNP friend test

Status: friend testing only. Intel TDX is the production CPU path.

The recurring SN39 validator does not admit AMD SEV-SNP machines or assign
them weight. These checks create local development evidence only. They never
publish a score, issue a receipt, write weights, assign burn, or prove subnet
emissions.

The current audit-miner image at
`sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99`
is an Intel TDX compatibility bridge. It cannot be used for this AMD test.

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

## Requirements

- An x86-64 Linux SEV-SNP guest where the unprivileged test account can read
  and write the `/dev/sev-guest` character device.
- Python 3.11 or newer.
- Outbound HTTPS to AMD KDS, GitHub, and PyPI during setup.
- A reviewer who supplies a new challenge and watches the command run inside
  the native guest.

No Cathedral wallet, cloud credential, API key, or private hotkey is required
for the local test.

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

## Remote friend review

A public SNP worker must use HTTPS and the complete signed-validator access
bundle described in [Validator access and fleet protocol](WORK_REQUEST_V2.md).
Bearer authentication alone is not sufficient. The worker refuses non-loopback
SNP service without a fresh signed snapshot, pinned snapshot keys and digest,
owner-only replay state, a validator stake floor, and its canonical public
endpoint. SNP also refuses both public compatibility modes.

The worker development selector is `cathedral worker develop --tee snp`.
Unauthenticated development is restricted to loopback. The reviewing validator
uses
[`cathedral-amd-sev-snp-dev-preview`](https://github.com/cathedralai/cathedral-validator/blob/main/docs/AMD_SEV_SNP_DEV_PREVIEW.md).
That command signs protected requests with the validator hotkey and remains a
local, no-write preview.

The Compute repository also exposes `runtime develop-audit-attestation` and
`runtime develop-canary` with `--cpu-tee snp` for local development. Production
runtime commands do not expose the SNP selector. SNP development refuses
publishing, receipts, the production policy registry, GPU composition, and
every chain-write path.

## Proof boundary

A successful observed run proves fresh vendor-backed SNP evidence and one SAT
round trip for the tested guest, source commit, verifier, and challenge.

It does not prove production eligibility, durable physical-machine identity,
customer receipt support, SN39 registration or weight, subnet emission, or TAO
earnings. Those gates remain closed until the production validator explicitly
adds AMD SEV-SNP admission.

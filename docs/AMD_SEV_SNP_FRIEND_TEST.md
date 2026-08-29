# AMD SEV-SNP friend hardware self-test

Status: source-ready, not live-proven on the current release.

This procedure exercises one friend-owned AMD SEV-SNP machine against
Cathedral's collector, HTTPS worker, verifier, and canonical SAT path. It does
not turn on production validator weights.

Plain AMD SEV is outside this self-test. The guest must expose native SEV-SNP
attestation through `/dev/sev-guest`.

The initial compatibility profile accepts AMD attestation report versions 3,
4, and 5. It uses the processor-family detection in pinned `snpguest` v0.10.0,
which covers its reviewed Milan, Genoa-family, and Turin paths. The probe fails
closed on report version 2, version 6, or a processor family the pinned verifier
does not recognize. Supporting a newer report or processor requires a reviewed
verifier update first.

## Requirements

- An x86-64 Linux guest launched with AMD SEV-SNP.
- `/dev/sev-guest` present as a character device.
- Outbound HTTPS access to AMD KDS, GitHub, and PyPI during setup.
- Python 3.11 or newer.
- No Cathedral wallet, cloud credential, API key, or private hotkey.

Azure's vTPM attestation path is not included. The current collector requires
the native Linux guest device.

## Install the reviewed source and verifier

Run inside the SEV-SNP guest. Keep the checkout on the exact reviewed commit.

```bash
git clone https://github.com/cathedralai/cathedral-sandbox.git
cd cathedral-sandbox
REVIEWED_COMMIT='<40-character commit supplied by the reviewer>'
git checkout --detach "$REVIEWED_COMMIT"
python3.11 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
git diff --exit-code
git diff --cached --exit-code
set -euo pipefail
SNP_GUEST_DOWNLOAD="$(mktemp /tmp/cathedral-snpguest-download.XXXXXXXX)"
curl --fail --location \
  https://github.com/virtee/snpguest/releases/download/v0.10.0/snpguest \
  --output "$SNP_GUEST_DOWNLOAD"
echo "70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0  $SNP_GUEST_DOWNLOAD" \
  | sha256sum --check
ROOT_SNP_GUEST_DIR="$(sudo mktemp -d /var/tmp/cathedral-snpguest.XXXXXXXX)"
ROOT_SNP_GUEST_BIN="$ROOT_SNP_GUEST_DIR/snpguest"
sudo install -o root -g root -m 0500 "$SNP_GUEST_DOWNLOAD" "$ROOT_SNP_GUEST_BIN"
echo "70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0  $ROOT_SNP_GUEST_BIN" \
  | sudo sha256sum --check
```

The digest pins the official virtee `snpguest` v0.10.0 release. Stop if the
digest check fails.

Do not run the self-test repeatedly or in parallel. Collection and verification
contact AMD KDS several times, and rapid reruns risk service rate limits.
The self-test limits each verifier subprocess to 15 seconds. The shared
collector also caps any operator override at 300 seconds.

## Run the source-level hardware contract

```bash
sudo --preserve-env=PATH \
  CATHEDRAL_RUN_SNP_HW=1 \
  CATHEDRAL_SNPGUEST="$ROOT_SNP_GUEST_BIN" \
  "$PWD/.venv/bin/python" -m pytest tests/test_attest_snp_hw.py -q
```

Expected result: six tests pass. No hardware test is skipped.

## Run the observed end-to-end HTTPS and SAT self-test

The reviewer generates a fresh 32-byte challenge and sends its 64 hex
characters to the friend. The reviewer must observe the terminal on the native
guest for the run to count as live proof. Choose a new output filename for
every run:

```bash
TRANSCRIPT_PATH="/tmp/amd-sev-snp-transcript-$(date -u +%Y%m%dT%H%M%SZ).json"
REVIEW_CHALLENGE='<64 hex characters supplied by the observing reviewer>'
git status --porcelain=v1 --untracked-files=all
sudo --preserve-env=PATH \
  CATHEDRAL_SNPGUEST="$ROOT_SNP_GUEST_BIN" \
  "$PWD/.venv/bin/cathedral-snp-friend-probe" \
  --challenge "$REVIEW_CHALLENGE" \
  --output "$TRANSCRIPT_PATH"
sudo chown "$(id -u):$(id -g)" "$TRANSCRIPT_PATH"
```

The `git status` command must print nothing. The self-test also enforces this
clean-tree check and records the actual 40-character commit it executed.

A local pass writes one owner-only JSON file and prints only its path, status,
and source commit. The file records the reviewer challenge and contains:

- AMD VCEK chain verification.
- Fresh nonce, hotkey, and TLS SPKI binding through REPORT_DATA v2.
- VMPL 0, debug disabled, and migration-agent disabled checks.
- Rejection of the wrong nonce, hotkey, channel key, measurement, and a
  tampered report signature.
- Matching hardware pseudonyms in two observed reports across a second hotkey
  and fresh TLS key on the same guest.
- One canonical SAT challenge verified end to end.
- A reviewer-challenge-scoped HMAC-SHA-256 platform pseudonym, not the raw AMD
  CHIP_ID. A fresh challenge prevents global linkage across review sessions.

The file omits the raw quote, TLS private key, and raw CHIP_ID. It is a redacted
local transcript. It is not independently replayable evidence. Sending the JSON
without a reviewer observing the native-guest run does not prove live hardware.
Two matching CHIP_ID-derived pseudonyms also do not prove durable machine
deduplication. A guest policy with `SINGLE_SOCKET=0` permits multi-socket
activation, where different sockets have different CHIP_ID values. Production
deduplication needs a separate single-socket admission rule or platform design.

## Local pass boundary

`LOCAL_PASS`, plus reviewer observation on the native guest, means the
friend-owned machine completed the source contract and one local HTTPS work
round trip with a vendor-verified SEV-SNP report.

`LOCAL_PASS` does not mean:

- The SN39 production validator accepts AMD evidence.
- UID30 assigns weights to an AMD machine.
- Cathedral issues an AMD customer receipt.
- Cathedral provisions AMD machines.
- The subnet pays emissions.

Those remain separate release gates.

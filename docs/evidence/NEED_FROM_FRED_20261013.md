# Need from Fred — SNP staging pilot (2026-10-13)

Context: isolated API + PR [#1449](https://github.com/bigailabs/polariscomputer/pull/1449) tip integrated; corrected image recorded; **not** booted. Public caller already sent.

## Blockers (must have before boot / install / canary)

### 1. Exact launch cmdline
- [ ] Full kernel **APPEND** string (immutable)
- [ ] Verity **roothash** (part of APPEND or explicit)
- [ ] Confirmed firmware / OVMF path + any other public launch args not already in `boot_new_guest.sh`

Fred already said these are owner inputs and must not be inferred.  
HOST_DATA and corrected raw/efi/initrd/vmlinuz hashes are already published.

### 2. Policy / measurement acceptance
- [ ] Signed acceptance of corrected image as measured SNP candidate (not just raw SHA)
- [ ] Signed policy / measurement-list release + **verifier pins**
- [ ] Durable **checkpoint** / registry state path Toby can pin in `CATHEDRAL_SNP_STARTUP_FILE`
- [ ] Explicit go-ahead that `a7ad573b` stays blocked and `ef0ab84e…` is the candidate under acceptance

### 3. Root-signed 900s grant
- [ ] Fresh central delegation signed by root holder
- [ ] Names **Toby’s** caller (already published):
  - `central:3c44952eb0f9f083976691809073357e1d9cd1a18326cbaacfefd08a7f07ecc7`
  - pubkey b64 `PESVLrD58IOXZpGAkHM1fh2c0aGDJsuqz+/Qin8H7Mc=`
- [ ] Network / netuid: `finney` / `94`
- [ ] Eight scopes: `tee-box:box`, `lease`, `revocations`, `image-import`, `create`, `get`, `exec`, `delete`
- [ ] TTL **900 seconds** (pilot bootstrap bound)
- [ ] Confirmed **sequence** floors + any required revocations bundle
- [ ] Delivered on secure / review channel (not assistants holding root seed)

Railway caller pubkey must **not** be substituted.

### 4. Independent observer (cleanup path)
- [ ] Confirm Toby may use a locally retained observer keypair (public half only shared)
- [ ] Or publish the pinned observer public key / key id Fred expects
- [ ] Clarify absence-receipt shape / inbox expectations for evidence-only cleanup

## Nice-to-have (unblocks smoother install, not boot itself)

### 5. Startup / artifact packaging
- [ ] Push or attach the local API recipe commits noted in the 18:04 PR comment (`Dockerfile.snp-staging`, `ops/cathedral_snp/native_artifact_probe.py`, `docs/SNP_API_ARTIFACT.md`) if Toby should consume them from GitHub
- [ ] Share nonsecret `launch-inputs-public.json` contents (or gist) so Toby can diff against `scripts/snp_staging/boot_new_guest.sh`
- [ ] Any example `cathedral_snp_staging_startup_v1` JSON with **placeholders only** (no secrets)

### 6. Process clarity
- [ ] Who is image/policy owner vs root signer vs validator-access holder for the remaining accepts
- [ ] Confirm ports `:2226` / `:8444` remain the approved pilot forwards after Toby verifies they are free
- [ ] Confirm no merge/deploy of #1449 is required before the bounded pilot (draft source handoff only)

## Already have (do not re-ask)

| Item | Value / source |
|------|----------------|
| Backend PR | #1449 @ `30769ea2` |
| Corrected raw SHA | `ef0ab84e57dd6e4c38fec60ee0c06e297cb963afbb47206277eacd6742a95689` |
| HOST_DATA_B64 | `VR35Ls6k4fpnvRDD0rCX13XEvq+LaOxOAF/2bXHJiF4=` |
| Image stem | `…/images-rootfix/cathedral-staging-snp-rootfix-20261013` |
| Blocked old raw | `a7ad573b…` |
| Pilot bounds | 4 vCPU / 8 GiB / 45 min guest; customer 180s / $1 deny-all |
| Toby caller (public) | sent in Discord reply |
| Isolated API | bore / local staging (not Railway `acaa2961`) |

## Toby sequence after Fred delivers

1. Verify ports free → boot corrected image with exact APPEND + HOST_DATA (still no `a7ad573b`)
2. Pin TLS / fill Binding + startup JSON (`docs/SNP_STAGING_STARTUP.md`)
3. Install via `CATHEDRAL_SNP_STARTUP_FILE` (official path)
4. Apply signed grant → run canary inside the 900s window
5. Cleanup with independent absence receipt

## Discord one-liner (optional ping)

> Still blocked on: (1) exact APPEND+roothash, (2) signed policy/measurement accept + pins/checkpoint, (3) root-signed 900s grant to my published caller, (4) observer public pin / absence shape. Image hashes + HOST_DATA already in hand; not booting until those land.

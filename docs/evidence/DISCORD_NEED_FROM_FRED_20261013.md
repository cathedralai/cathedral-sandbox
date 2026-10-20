# Discord → Fred (need list — copy/paste as normal message)

@wallscaler Still blocked on the following before I boot / install / canary. Corrected image + HOST_DATA already recorded; public caller already sent. Not booting `a7ad573b`. Treating `ef0ab84e…` as `UNQUALIFIED_CORRECTED_IMAGE_CANDIDATE` only.

**Need from you / owners:**

**1) Exact launch cmdline**
- Full kernel APPEND (immutable)
- Verity roothash (in APPEND or explicit)
- Any other public launch args not already in `scripts/snp_staging/boot_new_guest.sh`
- (HOST_DATA + raw/efi/initrd/vmlinuz hashes already in hand — please don’t re-derive APPEND)

**2) Policy / measurement acceptance**
- Signed accept of the corrected image as measured SNP candidate
- Signed policy / measurement-list release + verifier pins
- Durable checkpoint / registry state I can pin in `CATHEDRAL_SNP_STARTUP_FILE`

**3) Root-signed 900s grant** to **my** caller (not Railway):
- caller_id: `central:3c44952eb0f9f083976691809073357e1d9cd1a18326cbaacfefd08a7f07ecc7`
- pubkey b64: `PESVLrD58IOXZpGAkHM1fh2c0aGDJsuqz+/Qin8H7Mc=`
- network/netuid: `finney` / `94`
- scopes: `tee-box:box`, `lease`, `revocations`, `image-import`, `create`, `get`, `exec`, `delete`
- TTL 900s + confirmed sequence floors / revocations as required
- Secure channel only for the signed packet

**4) Independent observer**
- Confirm my locally retained observer pubkey is OK, **or** publish the pinned observer pubkey / key id you expect
- Absence-receipt shape / inbox expectations for evidence-only cleanup

**Optional (helps, not boot itself):**
- Push/attach the 18:04 API recipe files to #1449 if I should consume them from GitHub
- Share nonsecret `launch-inputs-public.json` so I can diff against my boot draft
- Placeholder-only `cathedral_snp_staging_startup_v1` JSON (no secrets)

**Already have:** PR #1449 @ `30769ea2`, raw `ef0ab84e57dd6e4c38fec60ee0c06e297cb963afbb47206277eacd6742a95689`, HOST_DATA_B64 `VR35Ls6k4fpnvRDD0rCX13XEvq+LaOxOAF/2bXHJiF4=`, stem `…/images-rootfix/cathedral-staging-snp-rootfix-20261013`, ports `:2226`/`:8444`, pilot bounds 4vCPU/8GiB/45min + customer 180s/$1 deny-all.

No merge / deploy / boot / signing from my side until 1–3 land (and 4 for clean closeout).

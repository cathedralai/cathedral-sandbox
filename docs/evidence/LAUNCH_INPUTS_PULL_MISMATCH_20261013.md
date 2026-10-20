# Launch-input pull vs boot draft — 2026-10-13

Source: PR #1449 comments [6154001968](https://github.com/bigailabs/polariscomputer/pull/1449#issuecomment-6154001968) / [6154008740](https://github.com/bigailabs/polariscomputer/pull/1449#issuecomment-6154008740)  
Saved JSON: `VERIFIED_DIAGNOSTIC_LAUNCH_INPUTS_20261013.json`

## Pulled into boot prep
| Field | Value |
|---|---|
| status | `BUILT_VERIFIED_NOT_BOOTED_NOT_CUSTOMER_QUALIFIED` |
| img dir | `…/images-verity` |
| raw SHA256 | `8296f243fef954bfc4b5152fb3cc564625d9ff94042762253485200c2a271394` |
| vmlinuz / initrd SHA | `9f55ef72…` / `18275f1c…` (unchanged from prior companion set) |
| fresh roothash | `5607dede48e109b93a7cfc116640621c24e422ae4c6722e66a7e3fb79b676f7f` |
| APPEND (UKI-selected) | `roothash=5607dede… console=ttyS0 systemd.volatile=overlay rw panic=-1` |
| HOST_DATA_B64 | `VR35Ls6k4fpnvRDD0rCX13XEvq+LaOxOAF/2bXHJiF4=` (unchanged) |
| firmware | `/usr/share/ovmf/OVMF.amdsev.fd` / `ac27e626…` |
| shape | 4 vCPU / 8 GiB / EPYC-v4 / policy 0x30000 / kernel-hashes=on |

`scripts/snp_staging/boot_new_guest.sh` defaults updated; still refuses `--execute` without `SNP_STAGING_REVIEWED_LAUNCHER=yes` + policy accept.

## Mismatches / flags (no silent invent)
1. **Prior boot draft** pointed at `images-rootfix` / `ef0ab84e` — **corrected** to `images-verity` / `8296f243…`.
2. **`reviewed_quarantine_launcher`: null** — historical `launch-tee-box.sh` is provenance only; not approved for execute. Boot remains held.
3. **`actual_new_guest_append`: null** — we pin `expected_append_if_reviewed_launcher_selects_this_uki` only; will not invent a different APPEND.
4. **Do not use** historical roothash `e1a3ce4f…` or old filenames — boot script fatal if APPEND contains it.
5. **Customer blockers still open** (overlay rw, admin paths, key custody) — diagnostic ≠ customer-qualified.
6. **Nulls remain intentional:** expected SNP measurement, guest endpoint, allocation, accepted policy/checkpoint, grant.

## SN94 policy bundle on Toby staging? (public)
- **No** accepted SN94 / `cathedral_policy_registry_v1` bundle installed for this pilot.
- Qual dir `policy_release.json` is empty (0 bytes).
- Local drafts exist only for the **older official guest** on `:2225` (`measurement-list-*-2225.json`) — different image/measurement; **not** this verity diagnostic.
- Named signer for measurement-list / image policy: historically **image owner `@skyrocket2026`** (see `SKYROCKET_MEASUREMENT_LIST_CHASE.md`). Fred/`cathedral-root-1` is central-access, not that registry key. No staging record of who currently holds the SN94 policy signing key for the new candidate.

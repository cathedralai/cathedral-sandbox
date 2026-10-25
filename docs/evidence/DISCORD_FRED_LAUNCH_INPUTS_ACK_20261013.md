# Discord → Fred (launch inputs pulled + policy answer)

@wallscaler Pulled the verified diagnostic launch inputs from #1449 comments into boot prep (`VERIFIED_DIAGNOSTIC_LAUNCH_INPUTS_20261013.json`). Observer/#1451 work not repeated.

**Pinned from your JSON**
- raw `8296f243fef954bfc4b5152fb3cc564625d9ff94042762253485200c2a271394`
- dir `…/images-verity` / stem `cathedral-staging-snp-verity-20261013`
- fresh roothash `5607dede48e109b93a7cfc116640621c24e422ae4c6722e66a7e3fb79b676f7f`
- APPEND `roothash=5607dede… console=ttyS0 systemd.volatile=overlay rw panic=-1`
- HOST_DATA_B64 unchanged `VR35Ls6k4fpnvRDD0rCX13XEvq+LaOxOAF/2bXHJiF4=`
- firmware `OVMF.amdsev.fd` / `ac27e626…`
- status `BUILT_VERIFIED_NOT_BOOTED_NOT_CUSTOMER_QUALIFIED`

**Mismatches / flags**
1. My earlier draft still pointed at `images-rootfix` / `ef0ab84e` — **corrected** to verity paths/hashes above.
2. `reviewed_quarantine_launcher` is still **null** (historical `launch-tee-box.sh` provenance only) — boot stays held; I will not treat historical shape as execute approval.
3. `actual_new_guest_append` is null — using only your `expected_append_if_reviewed_launcher_selects_this_uki`; not inventing another cmdline.
4. Refusing historical roothash `e1a3ce4f…` / old filenames.
5. Customer blockers in the JSON (overlay rw, admin paths, key custody) noted — diagnostic ≠ customer-qualified.

**SN94 policy bundle on my staging? (public only)**
- **No** accepted SN94 / `cathedral_policy_registry_v1` bundle for this pilot (qual `policy_release.json` empty).
- Only local drafts are for the **older official `:2225` guest** measurement-list — different image; not this verity candidate.
- Named signer historically for measurement-list/image policy: image owner **`@skyrocket2026`**. I do **not** hold that key; `cathedral-root-1` / Fred central-access is a different trust root. No staging record of a current SN94 policy signing-key holder for the new candidate.

Boot + customer canary remain held until reviewed launcher + acceptance requirements clear. Grant after HTTPS + accepted policy — acknowledged. Ready for your reviewed launch script / Astra / signed policy when they land.

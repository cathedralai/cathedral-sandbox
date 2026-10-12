# Chase — @skyrocket2026 measurement-list publish

**Status (2026-10-12):** draft pins live-reconfirmed on `:2225`; profile
shape **PASS** via throwaway-key `accept_release` (not production-signed).
Needs image-owner **signed registry** publish — **not Toby, not Fred**.

Fred’s `cathedral-root-1` central-access batch signs delegations/revocations
only. The measurement list is the pinned **policy registry** owner key
(@skyrocket2026 / image owner).

## Urgent paste (launch today)

```text
@skyrocket2026 — ASAP for launch: please publish signed measurement-list
registry entry for tee-box-snp-cherry-official-2026-10-09.

Live reconfirmed today on :2225 (snpguest):
- MEASUREMENT 0132f65b23fc8776dcd248b47224301be8d7f66a6c612b00c7b9780c16101291948e5c3df9fac140a0048971fa3ea3db
- host_data 551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e
  (= sha256(central-root-keys.json); matches snpguest Host Data)

Publish-ready profile (validated throwaway accept_release):
docs/evidence/measurement-list-publish-ready-tee-box-snp-2225.json
Also: docs/evidence/measurement-list-draft-tee-box-snp-official-2225.json

Embed profile into next cathedral_policy_registry_v1 release and sign with
the pinned image-owner key. panic-on-corruption stays HOLD until after
publish. Toby cannot sign this; Fred central-access keys are a different trust root.
```

## Pins

- `measurement`: `0132f65b23fc8776dcd248b47224301be8d7f66a6c612b00c7b9780c16101291948e5c3df9fac140a0048971fa3ea3db`
- `host_data`: `551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e`
- `root_digest_from_host_data`: `sha256:551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e`
- `image_id`: `tee-box-snp-cherry-official-2026-10-09`
- `profile_id`: `tee-box-snp-cherry-official-v1`

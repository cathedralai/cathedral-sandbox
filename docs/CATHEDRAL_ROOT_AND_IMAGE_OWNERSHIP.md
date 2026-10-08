# Cathedral root and measured image ownership

Status: **ownership contract + ceremony checklist**. Blocks honest HOST_DATA /
MRCONFIGID binding and #274 sealed SNP PASS until seats are filled and the
first ceremony completes.

Related: `SNP_HOST_DATA_LAUNCH.md`, `COMPUTE_POOL_INTEGRITY.md`.

## Seats (fill names)

| Seat | Authority | Name |
| --- | --- | --- |
| **Root owner** | Mints / holds offline Cathedral root; publishes official `central-root-keys.json` | ________ |
| **Image owner** | Approves measured tee-box guest image + measurement-list entries | ________ |
| **Launch owner** | Sets VMM `host-data` / MRCONFIGID from the published root digest | ________ |

Until names are filled, treat production bind as **BLOCKED**.

## What “official” means

| Artifact | Official when | Example |
| --- | --- | --- |
| Root key file | Root owner publishes path + sha256; ceremony log exists | `/secure/cathedral/central-root-keys.json` hash `sha256:…` |
| Guest image | Image owner records image id + measurement list digest | `tee-box-snp-2026-10-07` + `measurement-list@rev3` |
| Launch bind | Launch owner boots with HOST_DATA = `sha256(root file bytes)` | Report dump posted on #274 |

## Ceremony checklist (first production bind)

1. Root owner generates or retrieves the offline root; never commit private key material to git.
2. Export the **public** `central-root-keys.json` the guest will serve at  
   `/usr/share/cathedral/central-root-keys.json`.
3. Record: date, participants, file sha256, storage location (HSM / offline).
4. Image owner builds or selects the guest image that installs that exact file.
5. Image owner appends measurement-list entries; signs/approves in the team log.
6. Compute HOST_DATA:
   ```bash
   python -m cathedral.tee_box.host_data_cli --root-keys /path/to/central-root-keys.json
   ```
7. Launch owner passes that hex to the SNP VMM `host-data` (see `SNP_HOST_DATA_LAUNCH.md`).
8. Boot cathedral-1 (or -2); dump SNP report; confirm `host_data` matches CLI output.
9. Post evidence pack on issue #274 (template in `SNP_HOST_DATA_LAUNCH.md` § Evidence pack).

## Examples

| Situation | Green? |
| --- | --- |
| Eng uses a laptop test root + `E2E_HOST_DATA_HEX` inject | **No** — test-only |
| Root owner published hash; launch used a different file | **No** — bind mismatch |
| Ceremony complete; report `host_data` equals CLI hex | **Yes** for the HOST_DATA bolt |

## Forbidden

- Relabeling harness injects as sealed PASS
- Miner- or partner-supplied “root” without Root owner publication
- Shipping a guest image that embeds a different root than the launch stamp

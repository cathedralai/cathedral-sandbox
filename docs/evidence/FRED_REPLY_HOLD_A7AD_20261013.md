# Fred reply — hold `a7ad573b` boot (2026-10-13)

## What he said

- Approved **rebuilding** the staging image
- **Hold off booting** raw `a7ad573b` — root-digest formatting mismatch between bootstrap and adapter (fix reviewed; corrected image **not built yet**)
- Has **newer startup/recovery fixes** beyond our `66deb72e` bundle; confirming shared branch for us to pull
- Keep going: isolated API, install scaffold, canary
- **Toby owns guest launch** — but only after he sends corrected image details + verified boot inputs
- He will review the **15-min grant** packet once HTTPS is up

## Our posture

| Item | Action |
|------|--------|
| Boot `a7ad573b` | **Blocked** — boot script now requires `SNP_STAGING_EXPECTED_RAW_SHA256` ≠ a7ad573b |
| Isolated API / install scaffold / canary | Continue |
| Pull newer code | Wait for Fred’s shared branch name, then pull/merge |
| Guest launch | Ready, owned by us — execute only after corrected image + boot inputs |
| 15-min grant | Prepare packet after HTTPS; Fred signs |

## Optional ack to Fred

Fred — understood. Holding boot of a7ad573b. Continuing isolated API + install scaffold + canary. Send corrected image SHA + verified boot inputs when ready, and the shared branch for the newer startup/recovery fixes; we’ll pull, then launch the new guest and send the 15-min grant packet once HTTPS is up.

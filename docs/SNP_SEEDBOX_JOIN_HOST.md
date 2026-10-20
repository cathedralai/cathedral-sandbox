# SNP seed-box host recipe (#1469 join)

**Status:** host-side recipe for phase-1 join. API roster/seal stays on polaris (#1469 steps 1–7).  
**Working decisions:** `Cathedral/docs/PR1469_DECISIONS_WORKING_2026-10-16.md`  
**Issue:** https://github.com/bigailabs/polariscomputer/issues/1469

## Goal

On one SNP host: miner keeps earning; a **warm** customer guest is already wiped and listening on `:8444` so a listed chip seals in about **one minute** after the first sealed create (not ~29 min wipe + 15 min admission).

## Layout

| Slot | Guest | Port | Notes |
|---|---|---|---|
| A | Miner (existing SN94 SNP miner image) | `:8081` | Always on; `scripts/run_sn94_snp_miner.sh` |
| B | Customer (customer-only image) | `:8444` | Warm unadmitted **or** sealed one tenant |
| Spare | Pre-wiped `scratch.raw` on disk | — | Contabo: **not** a second live QEMU (no RAM/CPU headroom with 4/8 + 40/96) |

**Join key:** customer guest CHIP_ID == miner's `machine_id` on the same socket.  
**Identity:** customer public-input hotkey **=** miner hotkey.

## Warm guest + 24h admission

1. Boot customer guest (owner-reviewed start script; digest-pinned image — **no invented pins**).
2. In-guest scratch wipe (~29 min) unless spare scratch already installed.
3. Admission listener waits up to **`MAX_WAIT = 86400`** (`customer_admission.py`; needs image rebuild on b7144296 + **policy release 13**).
4. API discovers from validator roster and seals on first create (Fred lane).
5. On **lease end** or **unadmitted exit**, host supervisor relaunches.

## Supervisor (step 8)

Source: `scripts/snp_seedbox/supervise_customer_guest.py`

```bash
# Dry: prepare next run dir (optional spare scratch move)
python3 scripts/snp_seedbox/supervise_customer_guest.py prepare-next \
  --run-base /var/lib/cathedral/snp-seedbox/runs \
  --spare-scratch /var/lib/cathedral/snp-seedbox/spare/scratch.raw

# Watch current guest until exit
python3 scripts/snp_seedbox/supervise_customer_guest.py watch-once \
  --run-dir /var/lib/cathedral/snp-seedbox/runs/customer-run-CURRENT

# Live supervise (gated): wait → archive → prepare-next → pinned start script
CATHEDRAL_SEEDBOX_LIVE_OK=yes python3 scripts/snp_seedbox/supervise_customer_guest.py supervise \
  --run-base /var/lib/cathedral/snp-seedbox/runs \
  --current-run /var/lib/cathedral/snp-seedbox/runs/customer-run-CURRENT \
  --archive-root /var/lib/cathedral/snp-seedbox/archive \
  --start-script /root/inbox/cathedral-customer-guest-start.py \
  --start-script-sha256 <64-hex> \
  --spare-scratch /var/lib/cathedral/snp-seedbox/spare/scratch.raw \
  --max-cycles 1
```

Rules:

- Does **not** invent QEMU argv or image digests.
- Start script path must match `--start-script-sha256`.
- Live path requires `CATHEDRAL_SEEDBOX_LIVE_OK=yes`.
- Contabo: leave sealed Ditto alone until **2026-10-23** (decision #5).

## Contabo proof sequence (after Ditto ends)

1. Relaunch customer guest with identity hotkey = UID 3 miner hotkey.  
2. Wipe (~29 min) or use spare.  
3. Wait for API discovery (Fred).  
4. Test org sealed create → auto admission.  
5. `ditto_full_test.py` against that org.  
6. Acceptance: no Railway vars, no redeploy, no operator admission script between boot and first sandbox.

## Still Fred / API

Steps 1–7 (fault isolation, migration, roster, discover, seal, reconcile), canary 8, staging deploy, **policy release 13** signature.

## Step 9 later

Publish digest-pinned customer image + miner-facing launcher shaped like `run_sn94_snp_miner.sh`. Until then Contabo/INBOX start script remains the only executable start path; this supervisor only re-invokes it.

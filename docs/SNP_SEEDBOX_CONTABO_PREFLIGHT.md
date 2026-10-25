# Contabo seed-box preflight (offline — no live guest contact)

Do **not** set `CATHEDRAL_SEEDBOX_LIVE_OK=yes` or touch Ditto `:8444` until seal end **2026-10-23** (or Fred frees the slot).

**Fill-in sheet:** `SNP_SEEDBOX_CONTABO_OFFLINE_PREP.md`  
**Proof evidence:** `SNP_SEEDBOX_JOIN_PROOF_EVIDENCE.md`  
**Step 9 stub:** `scripts/snp_seedbox/run_customer_guest_beside_miner.sh`

## Before live proof

- [ ] Offline prep sheet filled (hotkey, start-script sha256, run dirs).
- [ ] Miner guest still healthy on `:8081` (UID 3 / hotkey known).
- [ ] INBOX `cathedral-customer-guest-start.py` located; record **sha256**.
- [ ] Customer image digests for policy **release 13** image recorded (Fred publishes).
- [ ] `MAX_WAIT=86400` image rebuilt and measurement signed as **policy release 13**.
- [ ] Run dirs ready: `runs/` + `archive/` mode `0700`, owner-only.
- [ ] Spare `scratch.raw` pre-wiped offline (optional; Contabo has no second live QEMU).
- [ ] Customer identity hotkey **=** miner hotkey on this chip.
- [ ] API join flag + roster path live on staging (Fred steps 1–7).
- [ ] Dual-guest validator cycle checked (Fred/validator) before treating co-residence as reward-safe.

## Live prove (after gates)

1. Relaunch warm customer guest via pinned start script / step 9 stub (EXECUTE gates on).  
2. Wait wipe / spare.  
3. API discovers → test org sealed create → auto admit.  
4. `ditto_full_test.py`.  
5. Fill `SNP_SEEDBOX_JOIN_PROOF_EVIDENCE.md`.  
6. Acceptance: no Railway vars, no redeploy, no operator admission script.

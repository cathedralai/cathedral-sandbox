# SNP seed-box host tools (#1469)

Host-only. Does **not** invent QEMU argv, image digests, or policy pins.

| File | Role |
|---|---|
| `supervise_customer_guest.py` | Wait for guest exit → archive → next run dir → optional spare scratch → pinned start script |
| `run_customer_guest_beside_miner.sh` | Step 9 stub: pin env + sha256; dry-run by default; exec INBOX start script only when LIVE+EXECUTE |
| `seedbox.example.env` | Env template (fill on Contabo; leave `LIVE_OK` unset until authorized) |
| `../../docs/SNP_SEEDBOX_JOIN_HOST.md` | Full recipe |
| `../../docs/SNP_SEEDBOX_CONTABO_OFFLINE_PREP.md` | Fill-in Contabo prep sheet |
| `../../docs/SNP_SEEDBOX_CONTABO_PREFLIGHT.md` | Short checklist before live proof |
| `../../docs/SNP_SEEDBOX_JOIN_PROOF_EVIDENCE.md` | Evidence template for Contabo §10 proof |

```bash
python3 -m pytest tests/test_snp_seedbox_supervise.py -q
bash -n scripts/snp_seedbox/run_customer_guest_beside_miner.sh
```

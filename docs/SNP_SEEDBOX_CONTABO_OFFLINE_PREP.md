# Contabo offline prep sheet (#1469 join — host)

**Fence:** no Gate 3 work · no Ditto `:8444` contact · no `CATHEDRAL_SEEDBOX_LIVE_OK=yes` until Fred greenlights (Ditto seal end **2026-10-23** or he frees the slot).

Fill this on the Contabo host (or from notes). Leave blank what only Fred publishes.

---

## 1. Host identity

| Field | Value |
| --- | --- |
| Hostname / box | |
| CHIP_ID / machine_id (miner) | |
| Miner UID (testnet 584) | `3` (confirm) |
| Miner hotkey | |
| Miner public endpoint | `…:8081` |
| Customer HTTPS endpoint (planned) | `…:8444` |
| Free RAM / vCPU with miner+Ditto | ~18 GiB / 4 threads (confirm) — **no third live QEMU** |

---

## 2. Miner guest (leave running)

| Check | Done |
| --- | --- |
| Miner answers on `:8081` | [ ] |
| `run_sn94_snp_miner.sh` digests still pinned as deployed | [ ] |
| Will **not** restart miner for join proof unless Fred asks | [ ] |

---

## 3. INBOX customer start script (do not invent)

| Field | Value |
| --- | --- |
| Absolute path | `/root/…/cathedral-customer-guest-start.py` (fill) |
| `sha256sum` (64 hex) | |
| Mode (not group/other writable) | |
| Notes | Contabo INBOX only until step 9 publishes |

```bash
# On Contabo (read-only):
sha256sum -- /path/to/cathedral-customer-guest-start.py
stat -c '%a %U:%G %n' -- /path/to/cathedral-customer-guest-start.py
```

---

## 4. Digests Fred must publish (leave empty until then)

| Pin | Value |
| --- | --- |
| Customer image (repo@sha256) | |
| Policy release **12** id / digest | |
| Measurement (customer guest) | |
| Public input / identity template hotkey | **= miner hotkey** |

---

## 5. Seed-box directories (create offline, empty, 0700)

Suggested layout (adjust to host):

```text
/var/lib/cathedral/snp-seedbox/
  runs/          # current + next customer-run-*
  archive/       # finished runs
  spare/         # optional pre-wiped scratch.raw
```

| Path | Created 0700 | Notes |
| --- | --- | --- |
| `…/runs` | [ ] | |
| `…/archive` | [ ] | |
| `…/spare` | [ ] | optional |
| `…/spare/scratch.raw` | [ ] | optional; Contabo = disk spare only |

---

## 6. Env draft (local file on host — do not export LIVE_OK yet)

Copy from `scripts/snp_seedbox/seedbox.example.env` and fill:

| Var | Filled |
| --- | --- |
| `CATHEDRAL_CUSTOMER_START_SCRIPT` | [ ] |
| `CATHEDRAL_CUSTOMER_START_SCRIPT_SHA256` | [ ] |
| `CATHEDRAL_MINER_HOTKEY` | [ ] |
| `CATHEDRAL_CUSTOMER_HTTPS_ENDPOINT` | [ ] |
| `CATHEDRAL_SEEDBOX_RUN_BASE` | [ ] |
| `CATHEDRAL_SEEDBOX_ARCHIVE_ROOT` | [ ] |
| `CATHEDRAL_SEEDBOX_SPARE_SCRATCH` | [ ] optional |
| `CATHEDRAL_SEEDBOX_LIVE_OK` | **leave unset** |

---

## 7. Fred gates before live

| Gate | Owner | Ready |
| --- | --- | --- |
| §11 confirm | Fred | [ ] |
| API 1–7 + `CATHEDRAL_SNP_JOIN_ENABLED` on staging | Fred | [ ] |
| Canary 8 / roster | Fred | [ ] |
| Policy release 13 | Fred | [ ] |
| Ditto slot free / seal ended | Fred / calendar | [ ] |
| Contabo go | Fred | [ ] |

When all checked → use `SNP_SEEDBOX_JOIN_PROOF_EVIDENCE.md` and launcher/supervise path.

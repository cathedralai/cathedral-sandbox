# Contabo join proof — evidence template (#1469 §10)

**Fill during / after the live proof.** Acceptance: no Railway variable change, no redeploy, no operator admission script between guest boot and first sandbox.

**Fence:** only after Fred greenlight · policy release 13 installed · Ditto slot free.

---

## Meta

| Field | Value |
| --- | --- |
| Date (UTC) | |
| Operator | |
| Contabo host | |
| Miner hotkey / UID | |
| Customer endpoint | `IP:8444` |
| Policy release | `12` |
| Staging join flag | `CATHEDRAL_SNP_JOIN_ENABLED=` |
| Start script path | |
| Start script sha256 | |
| Customer image pin | |
| Run dir | |

---

## Sequence checklist

| Step | Result | Evidence (path / paste) |
| --- | --- | --- |
| 1. Miner still up `:8081` | PASS / FAIL | |
| 2. Customer guest relaunched (identity hotkey = miner hotkey) | PASS / FAIL | |
| 3. Wipe complete or spare scratch used (~29 min or skip) | PASS / FAIL | |
| 4. Identity visible / API discovers from roster | PASS / FAIL | |
| 5. Test org **one** sealed create | PASS / FAIL | |
| 6. API auto-admits (no operator `run_admission`) | PASS / FAIL | |
| 7. `ditto_full_test.py` (or agreed suite) | PASS / FAIL | |
| 8. No Railway var change | PASS / FAIL | |
| 9. No staging redeploy mid-proof | PASS / FAIL | |
| 10. Supervise relaunch after exit (optional max-cycles 1) | PASS / FAIL / SKIP | |

---

## Acceptance (must all be PASS)

- [ ] First sandbox after boot with **no** human admission script  
- [ ] **No** Railway variable edits  
- [ ] **No** redeploy between boot and first sandbox  
- [ ] Offer path: roster → waiting → sealed  

**Overall:** PASS / FAIL  

**Blockers / notes:**

```
(paste)
```

---

## Attachments to keep

| Artifact | Path |
| --- | --- |
| Guest serial / public log | |
| Identity JSON (redact secrets) | |
| Sealed create response | |
| ditto_full_test output | |
| Supervisor cycle JSON (if used) | |

---

## Post-proof

- [ ] Comment evidence summary on https://github.com/bigailabs/polariscomputer/issues/1469  
- [ ] Update local workboard  
- [ ] Replenish spare `scratch.raw` offline if consumed  

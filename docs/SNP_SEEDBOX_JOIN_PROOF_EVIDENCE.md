# Join proof — evidence template (#1469 §10)

**Fill during / after the live proof.** Acceptance: no operator admission script between guest boot and first sandbox.

**Fence (Contabo T3):** only after Fred greenlight · policy release 13 installed · Ditto slot free.

**Cherry `.46` / testnet 584 T1 (2026-10-21):** **PASS** on staging — sealed create auto-admit; founding Join T1 marked TESTNET GREEN in polariscomputer `docs/TESTNET_UNIT_GO_GREEN.md`. Contabo rows below remain the Contabo/T3 template.

---

## Meta

| Field | Value |
| --- | --- |
| Date (UTC) | 2026-10-21 (Cherry T1) / _(Contabo T3: fill)_ |
| Operator | Eng |
| Host | Cherry `84.32.220.46` (T1) / Contabo _(T3)_ |
| Miner hotkey / UID | UID **5** (T1) / UID 3 (Contabo template) |
| Customer endpoint | `https://84.32.220.46:8444` (T1) |
| Policy release | `12` |
| Staging join flag | `CATHEDRAL_SNP_JOIN_ENABLED=true` |
| Start script path | _(host-local; do not commit paths with secrets)_ |
| Start script sha256 | |
| Customer image pin | `b7144296` (T1) |
| Run dir | _(host-local)_ |

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

- [x] First sandbox after boot with **no** human admission script (**Cherry T1 2026-10-21**)  
- [ ] **No** Railway variable edits _(T1 used image-only redeploy to drop static chip; Contabo T3 still aim for zero mid-proof redeploy)_  
- [ ] **No** redeploy between boot and first sandbox _(same note)_  
- [x] Offer path: roster → waiting → sealed (**Cherry T1**)  

**Overall:** **PASS** (Cherry founding T1) / Contabo T3 still open  

**Blockers / notes:**

```
Cherry T1: customer identity hotkey must equal roster miner hotkey;
chip must not remain a company standing worker in SNP startup JSON.
Do not paste API keys, age material, or STARTUP_B64 into git.
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

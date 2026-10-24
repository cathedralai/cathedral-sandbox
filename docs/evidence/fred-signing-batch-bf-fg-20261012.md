# Fred signing batch — finish B.f.2 / B.g on measured SNP `:2225`

Prepared by Toby · 2026-10-12  
Purpose: ready-made offline signing batch. **Fred reviews and runs locally**;
Toby keeps all test private seeds. Root seed never leaves Fred.

Measured root / `central-root-keys.json` on `:2225` **unchanged**.

## Context Fred already has

| Item | Value |
| --- | --- |
| Last delegation sequence | **1** (Toby A full, now **expired** `2026-10-11T20:49:17Z`) |
| Last revocations sequence | **1** (empty list; likely **stale** by >24h — need fresh list) |
| Network / netuid | `finney` / `94` |
| Root key id | `cathedral-root-1` |
| Previous revocations file | Toby’s `revocations.json` (seq 1) — use as `--previous` |

No new FIRST ceremony. No sequence reset. Continue ledger from seq **2**.

## Test identities (Toby holds seeds)

| Role | Key id (label) | Public key (base64) | Seed (Toby only) |
| --- | --- | --- | --- |
| **A** (customer A, full) | `toby-snp-2225-a` | `wgyQxlR1GNnuVDnextSRonGLkB4geLh3bw4P6DIqoIA=` | `toby-snp-2225-bf.seed` (existing) |
| **B** (customer B, full) | `toby-snp-2225-b` | `LmIlQv2lDW8JAZc4Nfgh8TOPYSjRVuhfCecFJBseDAM=` | `toby-snp-2225-b.seed` **new** |
| **Box-only** (least-privilege + revoke target) | `toby-snp-2225-box` | `emZAvtFBPcTr+EvSzwq/vQtePuUmO5nM9pefHTAHtZQ=` | `toby-snp-2225-box.seed` **new** |
| **Sibling** (unrevoked partner) | `toby-snp-2225-sibling` | `EtqqmeCBtBQAw+B+AojE490oBfa0Xm2Z8QLxIJ1eTqw=` | `toby-snp-2225-sibling.seed` **new** |

## Exact permissions

**Full scopes** (A and B) — all `TEE_BOX_CENTRAL_SCOPES`:

```text
tee-box:box
tee-box:lease
tee-box:revocations
tee-box:image-import
tee-box:create
tee-box:list
tee-box:get
tee-box:lifetime
tee-box:delete
tee-box:exec
tee-box:files
```

**Box-only** (Box-only + Sibling):

```text
tee-box:box
```

## Validity window

`--valid-hours 24` on every delegation (max).  
Toby will run the matrix immediately after files return. If that slips past 24h, ask Fred for a one-shot renewal of A/B only (same pubs, next sequences).

## Why two revocation lists in one batch

1. Rev list **seq 1 is >24h** → box will report `revocations_stale` until a **fresh** list is pushed.
2. We must run **least-privilege tests with Box-only while it is still unrevoked**.
3. Only **after** those tests do we push a list that **revokes Box-only**.

So the batch includes:
- **Revocations seq 2** — empty carry-forward (freshness only; `--previous` seq 1).
- **Revocations seq 3** — same carry-forward **plus** revoke Box-only’s digest (from delegate stdout).

## Delegation sequencing (high-water)

Accepting a **newer** delegation sequence raises the box high-water; an **older**
sequence is then refused (`central delegation is older than one already accepted`).
Wrong-scope / revoked refusals happen **before** high-water moves; a successful
auth (including a later `409 relaunch_required`) **does** move it.

Therefore:
- Sign **two** A-full delegations (seq 2 and seq 6): seq 6 is used only after B
  has been accepted so A can still act for f.3-style checks if needed.
- Ordered **test** plan below never expects an old sequence to work after a
  newer one was successfully authorized.

## Ordered signing commands (Fred, local)

Assume:
- `ROOT_SEED` / `ROOT_KEYS` / digest already on Fred’s machine  
- `LEDGER` = existing issuance ledger (last sequence **1**)  
- `PREV_REV` = copy of Toby’s `revocations.json` (seq 1)  
- Tool: `scripts/cathedral_central_access.py`

### Step 1 — Delegations (ledger sequences 2 → 6)

```bash
# seq 2 — A full (renewal; original expired)
python scripts/cathedral_central_access.py delegate \
  --root-key-file "$ROOT_SEED" --root-key-id cathedral-root-1 \
  --root-keys "$ROOT_KEYS" --root-keys-digest "$ROOT_DIGEST" \
  --central-public-key 'wgyQxlR1GNnuVDnextSRonGLkB4geLh3bw4P6DIqoIA=' \
  --network finney --netuid 94 --sequence 2 --valid-hours 24 \
  --ledger "$LEDGER" --out delegation-a-full-seq2.json \
  --route tee-box:box --route tee-box:lease --route tee-box:revocations \
  --route tee-box:image-import --route tee-box:create --route tee-box:list \
  --route tee-box:get --route tee-box:lifetime --route tee-box:delete \
  --route tee-box:exec --route tee-box:files
# record: A_SEQ2_DIGEST=...

# seq 3 — B full (different-customer)
python scripts/cathedral_central_access.py delegate \
  --root-key-file "$ROOT_SEED" --root-key-id cathedral-root-1 \
  --root-keys "$ROOT_KEYS" --root-keys-digest "$ROOT_DIGEST" \
  --central-public-key 'LmIlQv2lDW8JAZc4Nfgh8TOPYSjRVuhfCecFJBseDAM=' \
  --network finney --netuid 94 --sequence 3 --valid-hours 24 \
  --ledger "$LEDGER" --out delegation-b-full-seq3.json \
  --route tee-box:box --route tee-box:lease --route tee-box:revocations \
  --route tee-box:image-import --route tee-box:create --route tee-box:list \
  --route tee-box:get --route tee-box:lifetime --route tee-box:delete \
  --route tee-box:exec --route tee-box:files

# seq 4 — Box-only (least-privilege + later revoke target)
python scripts/cathedral_central_access.py delegate \
  --root-key-file "$ROOT_SEED" --root-key-id cathedral-root-1 \
  --root-keys "$ROOT_KEYS" --root-keys-digest "$ROOT_DIGEST" \
  --central-public-key 'emZAvtFBPcTr+EvSzwq/vQtePuUmO5nM9pefHTAHtZQ=' \
  --network finney --netuid 94 --sequence 4 --valid-hours 24 \
  --ledger "$LEDGER" --out delegation-box-only-seq4.json \
  --route tee-box:box
# record: BOX_DIGEST=...   ← this is what rev list seq 3 revokes

# seq 5 — Sibling box-only (stays unrevoked)
python scripts/cathedral_central_access.py delegate \
  --root-key-file "$ROOT_SEED" --root-key-id cathedral-root-1 \
  --root-keys "$ROOT_KEYS" --root-keys-digest "$ROOT_DIGEST" \
  --central-public-key 'EtqqmeCBtBQAw+B+AojE490oBfa0Xm2Z8QLxIJ1eTqw=' \
  --network finney --netuid 94 --sequence 5 --valid-hours 24 \
  --ledger "$LEDGER" --out delegation-sibling-box-seq5.json \
  --route tee-box:box

# seq 6 — A full again (post–high-water renewal after B is authorized)
python scripts/cathedral_central_access.py delegate \
  --root-key-file "$ROOT_SEED" --root-key-id cathedral-root-1 \
  --root-keys "$ROOT_KEYS" --root-keys-digest "$ROOT_DIGEST" \
  --central-public-key 'wgyQxlR1GNnuVDnextSRonGLkB4geLh3bw4P6DIqoIA=' \
  --network finney --netuid 94 --sequence 6 --valid-hours 24 \
  --ledger "$LEDGER" --out delegation-a-full-seq6.json \
  --route tee-box:box --route tee-box:lease --route tee-box:revocations \
  --route tee-box:image-import --route tee-box:create --route tee-box:list \
  --route tee-box:get --route tee-box:lifetime --route tee-box:delete \
  --route tee-box:exec --route tee-box:files
```

### Step 2 — Revocations seq 2 (fresh empty; not FIRST)

```bash
python scripts/cathedral_central_access.py revoke \
  --root-key-file "$ROOT_SEED" --root-key-id cathedral-root-1 \
  --root-keys "$ROOT_KEYS" --root-keys-digest "$ROOT_DIGEST" \
  --sequence 2 --previous "$PREV_REV" --allow-empty \
  --out revocations-seq2-fresh-empty.json
```

### Step 3 — Revocations seq 3 (revoke Box-only only)

Use `BOX_DIGEST` printed at seq 4 (`delegation_digest sha256:…`):

```bash
python scripts/cathedral_central_access.py revoke \
  --root-key-file "$ROOT_SEED" --root-key-id cathedral-root-1 \
  --root-keys "$ROOT_KEYS" --root-keys-digest "$ROOT_DIGEST" \
  --sequence 3 --previous revocations-seq2-fresh-empty.json \
  --revoke "$BOX_DIGEST" \
  --out revocations-seq3-revoke-box-only.json
```

**This list revokes:** delegation **seq 4 / Box-only** (`toby-snp-2225-box`), digest `$BOX_DIGEST`.  
Sibling seq 5 and A/B are **not** revoked.

### Files to send Toby

```text
delegation-a-full-seq2.json
delegation-b-full-seq3.json
delegation-box-only-seq4.json
delegation-sibling-box-seq5.json
delegation-a-full-seq6.json
revocations-seq2-fresh-empty.json
revocations-seq3-revoke-box-only.json
```

Plus one line: `BOX_DIGEST=sha256:…` (must match seq 4).

## Ordered test plan (Toby, after files land)

Goal: each refusal is for the **intended** reason (scope / relaunch / revoke), not
expiry or stale high-water.

| Step | Actor / credential | Action | Expected | Proves |
| --- | --- | --- | --- | --- |
| T0 | A seq2 + rev seq2 | Push **revocations-seq2**; `GET /v1/box` | 200; `revocations.fresh=true`, sequence 2 | Freshness (not stale seq1) |
| T1 | Box-only seq4 | `GET /v1/box` | 200 | Box-only can inspect |
| T2 | Box-only seq4 | `POST /v1/lease`, `GET /v1/sandboxes` | **401** (scope) | Least-privilege deny management |
| T3 | A seq2 | Lease → create/import as needed → **release** | 200; `needs_relaunch=true` | Boot consumed + released |
| T4 | B seq3 | `POST /v1/lease` (and/or list) | **409** `relaunch_required` | **Different customer refused on used boot** |
| T5 | A seq6 | `POST /v1/lease` | 200 (same customer A) | Not blocked by high-water; same-key still allowed |
| T6 | — | Push **revocations-seq3** (revokes Box-only) | 200; sequence 3 | List update |
| T7 | Box-only seq4 | `GET /v1/box` | **401** (revoked) | Revoked access rejected |
| T8 | Sibling seq5 | `GET /v1/box` | **200** | Unrevoked identity still works |

**Explicitly not claimed by this run:** B.d fresh-boot HW, C receipts, E customer
formats, staging soak, job-pay / weights / capacity broker. Those stay separate.

## Milestone framing

| Complete after this batch | Still outstanding (separate) |
| --- | --- |
| Measured-box B.b + B.e + B.f.2 + B.g least-privilege + revoke sibling | B.d HW fresh-boot |
| Evidence JSON + results doc update | C receipts / Polaris-prober |
| | E customer formats |
| | Staging unit soak (private channel for URL/key) |

**PARTIAL ≠ full security pass.** This batch finishes the **measured-box central-access
matrix** for f.2/g, not the full #274 acceptance run.

## Toby after sign-off

1. Place files under `central_access_materials/` (gitignored).  
2. Run extended client / matrix; wipe seeds from guest after.  
3. Record the three outcomes Fred listed.  
4. Update `TEE_BOX_SNP_E2E_RESULTS.md` + evidence JSON.  
5. Keep production, job-pay, weights, capacity broker untouched.

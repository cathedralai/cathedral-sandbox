# SN94 status report — for leadership (plain language)

**Date:** 2026-10-07  
**Who this is for:** Team lead and anyone who needs the story without reading code.  
**Diagram:** [sn94-unit-architecture-status-2026-10-08.jpg](sn94-unit-architecture-status-2026-10-08.jpg) (Gittensor SN74 scaffold on Sealed/CVMHost; also synced to […-2026-10-07.jpg](sn94-unit-architecture-status-2026-10-07.jpg))

A technical appendix (PRs, flags, API recipes, test commands) is at the end.

---

## 1. The one-minute picture

Think of SN94 as a **marketplace of trusted computers**.

| What customers / miners see today | Status |
| --- | --- |
| Buy a **sealed** computer pack on cathedral.computer and run work | **Working now** |
| Miners prove “this is a real secure chip” and pass a **speed/capacity test (SAT)** → earn subnet rewards | **Working now** |
| Put **private customer jobs** on outside miners’ machines and **pay those miners for that job** | **Not ready yet** |
| Honest claim: “full sealed acceptance on our own AMD SNP machines” (#274) | **Not ready yet** |

We are building so that **every machine—ours or a miner’s—faces the same three checks** before it gets certain kinds of work. Two of those checks are largely in place. The third (custody), plus a few real-world seals and proofs, still block the private miner path.

**Important:** “Blocked” does **not** mean the subnet is dead. Mining and sealed sales continue. It means we will **not** pretend private miner customer work or job-pay is live until the missing pieces exist.

---

## 2. The diagram in everyday words

```text
Customer (Affine, Ditto, Reliquary, Agent, CVM)
    → Website / API
    → Scheduler (“broker”)
    → Three checks: Security | Performance | Custody
    → Pool of machines: Cathedral’s cloud  OR  founding miners
    → Run the job in the right kind of sandbox
    → Receipts (proof of what ran)
    → Validators: pay for SAT (live) / pay for jobs (later)
```

| Box on the diagram | Plain meaning | Today |
| --- | --- | --- |
| **Customer** | Someone buying compute for Affine rollouts, Ditto scoring, Reliquary graders, Agent IDE, or confidential VMs | Sealed packs **for sale**. Older “standard sandbox” create is **closed** to new public orders. |
| **Broker** | One fair queue: “this job needs this kind of machine”—no brand favoritism | Built as **watch mode** (shadow). Not yet the only scheduler in production. |
| **Security** | Is this a real sealed chip with software we trust? | **Working** for mining + sealed cloud. |
| **Performance** | Is the machine healthy and capable (SAT / capacity)? | **Working** for mining; unit checks also built (mostly off until staging soak). |
| **Custody** | Who is allowed to physically touch the hardware? (Contracts, approved sites, deposits, audits.) Attestation cannot answer this. | **Blocked** — see §3. |
| **Cathedral cloud** | Machines we operate (e.g. Google TDX sealed packs) | **Working**; lab test of dense “many sandboxes in one sealed VM” **passed** on a GCP box. |
| **Founding miner** | Outside miner machines that could run **private** customer work | **Blocked** for that product — see §3. Miners can still SAT-mine. |
| **SAT reward** | Pay miners for proving secure hardware + capacity test | **Live** |
| **Job reward** | Pay miners for finishing a customer job after we re-check | **Not built for pay yet** — needs teardown proof first |

---

## 3. Blockers explained — and how to unblock them

### Blocker A — Custody (third check)

**What it is.**  
Security says “trusted chip.” Performance says “strong enough machine.” **Custody** says “this operator and site are allowed to handle private customer data on hardware we don’t fully control.”

**Why it matters.**  
A sealed chip does not stop someone with keys to the building from touching the box. Private customer work on miner hardware needs human/legal/ops trust, not only cryptography.

**What “blocked” means in practice.**  
If a job is marked private, our software **refuses** it until custody is configured (`custody_policy_not_configured`). We fail closed on purpose.

**To unblock Custody**

| # | Action | Who | Artifact |
| --- | --- | --- | --- |
| 1 | Fill / approve checklist C1–C6 (site, agreement, deposit, audit, revoke) | Product + legal + ops | `polariscomputer/docs/CUSTODY_ENROLLMENT.md` **created** |
| 2 | Enroll providers via ops-only registry (`enroll` / `deny`) | Ops (+ eng for DB later) | `cathedral_custody_enrollment.py` **created** |
| 3 | Broker / adapters use `custody_approved` from registry on private jobs | Eng | Wired into `facts_from_capacity_provider` |
| 4 | Revoke on failed audit | Ops | `deny(...)` |

**Rough readiness:** eng wiring is in; policy fill-in + first real enrollments remain.

---

### Blocker B — Founding miner (private customer path)

**What it is.**  
The diagram’s right-hand pool: miners who might run **private** jobs. That path needs **all three** checks, plus a few seals and proofs we do not have yet.

**What it is *not*.**  
It is not “turn off SN94.” Miners can still earn **SAT rewards** today.

**Why it is blocked (four separate bolts)**

| Bolt | Plain meaning | To unblock |
| --- | --- | --- |
| **1. Stamp our seal at boot (HOST_DATA)** | Our software can *read* the seal. The person who **starts** the AMD SNP machine has not yet stamped our Cathedral key into launch on cathedral-1/2. | Launch owner runs the paste-ready ask in `SNP_HOST_DATA_LAUNCH.md` / issue #274 |
| **2. Who owns the master key / official image** | Someone must mint the Cathedral root and approve the measured guest image. | Leadership names those roles |
| **3. Custody** | Same as Blocker A | Checklist + enrollment flag |
| **4. Proof the workspace is really gone** | A miner cannot be trusted to say “I deleted the customer’s data.” Cathedral must observe and sign that. Without it we must not pay for customer jobs. | Issuer **created** (`cathedral_miner_lifecycle_issuer.py`); still need live observation hook → shadow → pay policy |

Also needed for dense sealed use: **reboot between customers** on a real machine (design + lab exist; production driver not finished).

**Rough readiness**

| Milestone | Depends on | Earliest realistic once owners act |
| --- | --- | --- |
| Real SNP seal on cathedral-1/2 | Launch owner + root file | Days to ~2 weeks after ask is answered |
| Private jobs *scheduled* to approved miners (still no job-pay) | Custody + seal + relaunch | Weeks after checklist + seal |
| **Pay miners for customer jobs** | All above + receipt issuer + validator shadow + explicit policy | Longer; do **not** date this until receipts are issuing in staging |

---

### Blocker C — Other items (shorter)

| Item | Plain meaning | Unblock |
| --- | --- | --- |
| Staging soak | New checks are built but **off** in production | Ops turns flags on in staging in order (watch → Ditto → Reliquary) |
| Affline Docker-in-Docker on sealed tee-box | Affline often needs full Docker inside; sealed v1 does not | Leadership keeps Affline on normal sandbox hosts **or** explicitly asks for DinD later |
| Agent IDE on the public site | Code exists as reference; site does not sell it | Product decision + edge work |
| Job reward on chain | Pay for jobs, not only SAT | Only after teardown receipts + policy |

---

## 4. When will the subnet be “ready”?

Answer depends what “ready” means. Use this scorecard:

| Definition of “ready” | Are we there? | What finishes it |
| --- | --- | --- |
| **A. Mining subnet live** (TEE + SAT → weights) | **Yes — now** | Keep running; don’t break SAT path |
| **B. Selling sealed compute** on cathedral.computer | **Yes — now** | Keep sale green; denser “many sandboxes per sealed VM” is improvement, not a sale blocker |
| **C. One shared bar watching all products** (shadow) | **Code ready; prod flags off** | Staging soak, then careful enable |
| **D. Private customer work on founding miners** | **No** | Unblock Custody + HOST_DATA + root + relaunch |
| **E. Pay miners for customer jobs** | **No** | Everything in D + lifecycle receipts issuing + policy activation |
| **F. Honest #274 “full SNP sealed on our guests”** | **No** | HOST_DATA + measured image + e2e on cathedral-1/2 |

**Recommendation for the team lead**

1. Treat **A + B as already ready** for business continuity.  
2. Treat **C** as “ready to soak this month” if staging is available.  
3. Treat **D / E / F as readiness only after named owners close Host-data, root, and custody**—those are calendar-driven by people, not by more silent coding.  
4. Do **not** announce miner job-pay or #274 sealed PASS until the unblock table above is checked off.

There is **no honest single calendar date** for E/F until the launch owner and custody owners commit. Engineering for D–F is largely sequenced and partially built; **waiting on people is the critical path**.

---

## 5. What we already finished (plain list)

- Sealed packs customers can buy today.  
- Miners earning SAT rewards for real TEE + capacity tests.  
- Lab proof that a sealed VM can host many sandboxes (Google TDX test passed).  
- Software that *can* check our seal on AMD SNP (reader + tools)—waiting for the launcher to stamp it.  
- Shared “job ticket” + machine checks + watch-only hooks for Affline/Ditto/Reliquary (turned **off** until staging).  
- Optional hard stop for bad machines on Ditto / Reliquary (also **off** until soak).  
- Draft tools so Cathedral—not the miner—can later sign “workspace really deleted.”  
- Written asks for the launch owner and root owner.

---

## 6. Products: how someone uses them (simple)

| Product | What it’s for | How you get it today |
| --- | --- | --- |
| **Sealed / CVM-shaped** | Attested sealed machines | Buy pack or worker on cathedral.computer |
| **Affline** | Many short Linux sandboxes (Harbor / verifiers) | Public create closed; operator capacity / existing sandboxes; **not** sold as TEE Affline |
| **Ditto** | Small isolated scoring slots | Operator project key; same sandbox family; deny-all; 2–8 concurrent |
| **Reliquary** | Short grader batches on dedicated pool | Arranged Workers trial (email); not a self-serve SKU |
| **Agent IDE** | Freeze/thaw/desktop-style sessions | Reference only; public substitute = sealed sandboxes |

**Site path (all public):** browser or agent → cathedral.computer → Polaris API → right machine type.

---

## 7. Asks for leadership (this week)

1. Confirm we publicly describe readiness as **A+B live; D/E/F not yet**.  
2. Assign **who answers the HOST_DATA launch ask** (AMD boot stamp).  
3. Name **who mints Cathedral root / approves the official image**.  
4. Schedule **custody checklist** owners (legal + ops).  
5. Approve **staging soak** of the new watch/gates (PRs below).  
6. Reconfirm Affline stays on normal sandbox hosts (no DinD on sealed v1) unless you overturn that.

---

## 8. Real work breakdown — so other teammates can help

Use this as a **pickup board**. Each row is a job someone else can take without reading the whole stack. Fill the **Owner** cell with a real name; until then the work is still unowned.

**How to help:** take one row, read **You need**, deliver **Done when**, then ping the **Depends on** owners if stuck. Do **not** invent custody approval or claim #274 PASS from injects.

### 8a. Name these seats first (leadership / PM — 15 minutes)

| Seat | Job in one line | Name (fill in) |
| --- | --- | --- |
| **Launch owner** | Can change SNP boot flags on cathedral-1/2 (or production SNP VMM) | ________ |
| **Root owner** | Mints / holds Cathedral offline root; says which root file is official | ________ |
| **Image owner** | Approves measured tee-box guest image + measurement-list entries | ________ |
| **Custody product** | Writes what “approved site” means (checklist text) | ________ |
| **Custody legal** | Agreement / deposit language | ________ |
| **Custody ops** | Enrolls sites, sets flag, runs audits / revoke | ________ |
| **Polaris eng** | Flags, broker, receipts ingest, staging | ________ |
| **Sandbox eng** | Tee-box, HOST_DATA reader, relaunch driver, e2e | ________ |
| **Validator eng** | Job-reward / supply-boundary only after receipts | ________ |
| **Staging ops** | Turns feature flags on soak order | ________ |

Without those names, teammates cannot parallelize — they do not know who to ask for keys, boxes, or policy.

### 8b. Parallel work packages (pick any whose Depends on is ready)

| ID | Work package | Role | You need (inputs) | You do | Done when (acceptance) | Depends on | Parallel with |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **W1** | Stamp HOST_DATA on cathedral-1 (or -2) | Launch owner | Official root from W2; `SNP_HOST_DATA_LAUNCH.md` + evidence pack template | Install root; `host_data_cli`; set VMM `host-data`; boot; dump report | Evidence pack on #274: CLI hex == report; Inject=NO | Root file exists (W2) | W3, W4, W5, W6 |
| **W2** | Publish official root + say who holds it | Root owner | `CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md` ceremony | Complete ceremony checklist; publish path + sha256 | Seats named; hash published; launch can run W1 | Leadership names seat | W3, W4, W5 |
| **W3** | Approve measured guest image | Image owner | Same ownership doc + candidate build | Approve image id + measurement-list rev | Written approval; e2e can target it | Build artifact | W1 after stamp |
| **W4** | Custody checklist v0 | Custody product + legal | **`polariscomputer/docs/CUSTODY_ENROLLMENT.md`** (created) | Fill C1–C6 policy specifics; lead approves | Doc signed off; ops can enroll | Leadership schedule | W1–W3, W5–W7 |
| **W5** | Custody flag in Polaris | Polaris eng | **`cathedral_custody_enrollment.py`** (created) | Ops `enroll` / `deny`; adapters fill `custody_approved`; never miner self-serve | Tests green; staging private reject/approve | W4 policy text (or enroll against v0) | W1–W3, W6 |
| **W6** | Staging soak of shadow/gates | Staging ops + Polaris eng | **`UNIT_CAPACITY_STAGING_SOAK.md`** (created) | Run soak order; paste notes template | Notes: no sealed/SAT regression | Staging deploy | W1–W5 |
| **W7** | Wire lifecycle receipt **issuer** | Sandbox + Polaris eng | **Issuer created** (`cathedral_miner_lifecycle_issuer.py`); needs live observation hook | Call `issue_after_observation` after real reclaim; persist later | Staging: one real teardown → ingested receipt | Observation hook | After W5 OK |
| **W8** | Relaunch driver on real SNP box | Sandbox eng | W1 stamp; VMM reboot API or operator script | Drive `relaunch.py` SM: drain → stop → reboot → health → admit | One full cycle on cathedral-1/2 with logs | W1 | W5–W7 |
| **W9** | #274 phase claim (honest) | Sandbox eng + Launch | W1 + W3 | Run sealed SNP e2e **without** inject; attach report | Issue #274 updated: real HOST_DATA PASS or still blocked with evidence | W1, W3 | — |
| **W10** | Job-reward shadow (no pay) | Validator + Polaris | Receipts from W7 | Score/annotate only; **do not** enable pay weights | Shadow report for N jobs; policy still off | W7 | — |
| **W11** | Affline host decision | Product lead | DinD vs SandboxHost note | Confirm Affline stays SandboxHost (default) or open DinD epic | Written decision in channel / issue | None | Everything |

### 8c. What each role should **not** do (avoids thrash)

| Role | Do not |
| --- | --- |
| Launch owner | Relabel `E2E_HOST_DATA_HEX` inject as sealed PASS |
| Miner / partner | Self-attest custody or teardown |
| Eng | Turn on job-pay or prod gates without soak notes + lead OK |
| Anyone | Date “job rewards live” before W7 issuing in staging |

### 8d. Suggested order if you have three people this week

1. **Person A (launch + root chase):** fill seats → W2 → W1 → dump on #274.  
2. **Person B (product/legal):** W4 checklist draft; W11 Affline confirmation.  
3. **Person C (eng):** merge/review PRs → W6 staging soak → start W5 flag stub + W7 design note.

Everything else waits on those three tracks.

### 8e. Copy-paste “I can help” message (for Slack)

```text
I can take work package W__ from SN94_UNIT_CAPACITY_TEAM_REPORT §8.
Owner seat: ________
Blockers I need from others: ________
ETA for Done-when: ________
```

---

# Appendix — technical detail (engineers / ops)

## A1. Architecture → code map

| Diagram box | Implementation |
| --- | --- |
| Broker / JobIntent | `polariscomputer` `cathedral_job_intent.py`, `cathedral_capacity_router.py` |
| Gittensor SN74 challenges (additive) | JobIntent `gittensor_challenge` → CVMHost; `POST/GET /v1/challenges/runs` (flag off); docs `GITTENSOR_CHALLENGE_PATH.md` + sandbox `#276` receipt |
| Three checks | `cathedral_machine_eligibility.py` |
| Custody enrollment | `cathedral_custody_enrollment.py`, `docs/CUSTODY_ENROLLMENT.md` |
| Shadow / gates | `cathedral_unit_adapters.py`; flags in config (default off) |
| Staging soak | `docs/UNIT_CAPACITY_STAGING_SOAK.md` |
| SAT cache | `cathedral_sat_pass_cache.py` |
| Lifecycle receipt issuer | `cathedral_miner_lifecycle_issuer.py`, `docs/MINER_LIFECYCLE_RECEIPT_ISSUER.md` |
| Tee-box / SNP | `cathedral-sandbox` `cathedral/tee_box/`, `SNP_HOST_DATA_LAUNCH.md` |
| TEE honesty (TDX+SNP) | `TEE_HONESTY_STACK.md`, `capacity/tee_honesty.py`, `admit(expected_root_digest=)` |
| Root / image ownership | `CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md` |
| Relaunch SM | `cathedral/tee_box/relaunch.py` |
| Teardown receipt helpers | `cathedral/miner_lifecycle_receipt.py` |
| Supply boundary | `cathedral-validator` `CUSTOMER_EXECUTION_SUPPLY_BOUNDARY.md` |

## A2. Repos, branches, PRs, commits

| Repo | Branch | Tip | PR |
| --- | --- | --- | --- |
| polariscomputer | `feat/unit-capacity-eligibility-shadow` | `383d4ad7` | [#1445](https://github.com/bigailabs/polariscomputer/pull/1445) |
| cathedral-sandbox | `feat/tee-box-snp-startup-gates` | `ecf1feb` | [#275](https://github.com/cathedralai/cathedral-sandbox/pull/275) |
| cathedral-validator | `docs/miner-teardown-evidence-link` | `da67e31` | [#301](https://github.com/cathedralai/cathedral-validator/pull/301) |
| Issue #274 | — | — | [SNP acceptance](https://github.com/cathedralai/cathedral-sandbox/issues/274) |

**Polaris commits:** `383d4ad7` Reliquary gate + SAT health sync · `a30eacd1` SAT cache + Ditto gate · `6ace0ce7` adapter shadow · `1d301355` JobIntent + eligibility  

**Sandbox commits:** `ecf1feb` lifecycle receipt + relaunch SM · `c68473f` HOST_DATA ask · `203709f` TDX e2e results · `d162591` SNP gates  

### Flags (all default off)

| Flag | Effect when on |
| --- | --- |
| `cathedral_unit_eligibility_shadow_enabled` | Annotate routing audits |
| `cathedral_unit_adapter_shadow_enabled` | Log agree/disagree on placements |
| `cathedral_unit_ditto_eligibility_gate_enabled` | 503 if Ditto machine fails bar |
| `cathedral_unit_reliquary_eligibility_gate_enabled` | Block/skip Workers if bar fails |
| `cathedral_capacity_broker_enabled` | Existing broker claims |
| `cathedral_gittensor_challenges_enabled` | Admit `POST/GET /v1/challenges/runs` (else 503) |
| `cathedral_unit_tee_honesty_gate_enabled` | Fail Security on bad TEE honesty obs |

## A3. Site → endpoints (per service)

**Edge:** Client → cathedral.computer Worker → Polaris → host.

| Product | Main calls |
| --- | --- |
| Sealed | `POST /v1/console/box-groups` or `POST /v1/workers`; `GET /v1/receipts`, `GET /v1/usage` |
| Affline | `POST/GET/DELETE /v1/sandboxes`, `…/exec` (operator; public create closed) |
| Ditto | Same sandboxes + `labels.customer=ditto`, deny-all, short TTL, cap 2–8 |
| Reliquary | `POST /v1/workers/run`, `GET /v1/workers/result?request_id=` |
| Agent IDE | Not on site edge; reference freeze/thaw/terminals on sandbox binary; sold substitute = sealed |
| Gittensor SN74 | `POST/GET /v1/challenges/runs` (flag off); precursor `POST /v1/benchmarks/gittensor/run` unchanged |

## A4. How to test the unit

```bash
# Polaris (expect 53+ passed)
cd polariscomputer && pytest tests/test_cathedral_job_intent.py \
  tests/test_cathedral_machine_eligibility.py \
  tests/test_cathedral_unit_eligibility_shadow.py \
  tests/test_cathedral_unit_adapters.py \
  tests/test_cathedral_sat_pass_cache.py \
  tests/test_cathedral_custody_enrollment.py \
  tests/test_cathedral_miner_lifecycle_issuer.py -q --noconftest

# Sandbox helpers (expect 7 passed)
cd cathedral-sandbox && pytest tests/test_miner_lifecycle_receipt.py \
  tests/test_tee_box_relaunch.py -q
```

**Staging soak:** all flags false → smoke sealed → adapter shadow on → optional Ditto then Reliquary gates.  
**Hardware:** TDX e2e already PASS on GCP; SNP e2e after real `host-data` on cathedral-1/2.

## A5. Full unit “definition of done”

Shadow+gates green in staging · real SNP HOST_DATA · measured image · relaunch driven · lifecycle receipts issuing · job-reward only after explicit policy — **and** sealed sale + SAT never regress.

---

*Rewritten 2026-10-07 for non-technical readability; technical appendix retained for implementers.*

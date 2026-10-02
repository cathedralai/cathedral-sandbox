# Runtime conformance plan

Draft, 2026-10-02. Owner: Fred.

## Goal

Let outside developers (Gittensor SN74) improve the sandbox runtime against
the conformance suite, on one rented box, without access to the private
service layer. A merged runtime improvement then reaches every Cathedral box
at the next runtime rollout.

## Where things live

| Layer | Repo | Role |
|---|---|---|
| Site | `cathedralai/cathedral-site` (private) | Signup, keys, credits, console |
| Service layer | `bigailabs/polariscomputer` (private) | `/v1/sandboxes`: customers, keys, teams, routing to boxes, quota, billing, the Affine-shaped API |
| Runtime | `cathedralai/runtime` (Apache-2.0, E2B) | On each box: E2B's `/sandboxes` API, orchestrator, the in-VM agent (envd), templates, snapshots, Firecracker |

A create flows: customer → `cathedral.computer/v1/sandboxes` → service layer
picks a box → that box's runtime `/sandboxes` → Firecracker VM. The client is
`polaris/providers/e2b_product.py`.

Apache-2.0 does not require publishing our changes. If we distribute runtime
images to miners we must ship the license, keep upstream NOTICE text, and mark
changed files.

## The three steps

### 1. Runtime driver for the suite

Today the suite speaks only the Cathedral `/v1/sandboxes` API. Developers will
run the runtime alone, so the suite needs a second driver.

- Drive a bare runtime through the E2B Python SDK pointed at the install
  (`Sandbox.create`, `commands.run`, `files.write/read`, snapshots), as an
  optional dependency. No hand-written envd protocol client.
- Each check declares which layer it tests. Checks that only exist in the
  service layer (`quota.minimum`, `usage.by_label`, `create.idempotent`,
  `lifecycle.labels`) report `skip: service layer` under the runtime driver,
  never a pass.
- `--driver cathedral|runtime`, default `cathedral`.

Done when: the same check ids run against an Embed install and against
cathedral.computer, and the report records which driver produced it.

### 2. Sandboxes-per-box check

The number that sets our price per sandbox-hour, and the first thing a runtime
developer can move (memory overcommit, ballooning, smaller guest images).

- Start sandboxes at 1 vCPU / 4 GB, each running a fixed workload that touches
  a realistic amount of memory, until a create fails or the host passes a
  memory threshold.
- Report: stable concurrent sandboxes, host memory per sandbox, and, given a
  box price, cost per sandbox-hour against the $0.07 target.
- Tier `later`, runtime driver only (it needs the whole host).

### 3. Baseline on `cathedral-1`

- Install the runtime with Embed's Docker Compose shape on `cathedral-1`
  (8 vCPU EPYC 7763, 31 GB, 96 GB, `/dev/kvm` present).
- Run the full suite with the runtime driver, plus the density check. Publish
  the report on this repo. This is the baseline every bounty improves from.
- Run the cathedral driver against production in the same session, so the two
  reports show what the service layer adds or costs.

## Caveats, each with a next action

| Caveat | Next action |
|---|---|
| Rollout is not automatic: merged runtime code reaches boxes only through a release, image build, canary and roll | Find how runtime versions reach boxes today; write it down before promising "merge and it's live" |
| The `/v1/cathedral/*` endpoints the service layer calls on each box (capabilities, operations, identity, lifecycle) are not in `cathedralai/runtime` | Find which repo serves them; that code is part of the runtime surface developers would touch |
| Contract changes (new endpoint or field) also need the private service layer updated | Keep bounties to behavior behind the existing contract; contract changes are ours |
| The sealed lane is gVisor in a confidential VM, not Firecracker, so runtime speedups do not reach it | Decide whether the runtime gets a gVisor backend (below) |
| Other Polaris products may not use this runtime | Confirm before claiming fleet-wide gains |
| Upstream drift from E2B grows with every local change | Keep Cathedral changes in separate modules; record what diverges |

## Open question: gVisor as a second runtime backend

E2B is the whole platform (API, orchestrator, envd, templates); Firecracker is
its isolation backend. gVisor is an alternative isolation backend, not an
alternative to E2B. A gVisor backend under the same API and envd would let
sealed and fast lanes share one contract, one agent and one image pipeline,
so most runtime improvements would reach both.

The E2B orchestrator is built around Firecracker's snapshot and memory model,
so this is real work. A cheaper first step is to make the suite the shared
contract: the existing gVisor pool (`cathedral-pool`) and the E2B runtime both
pass the same check ids, and the router treats them as two backends.

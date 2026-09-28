# TEE sandbox box design

Status: design proposal, 2026-09-28. Nothing in this page has run on live
hardware. Each section separates **Existing** (code on `main`, or an open PR
named by number) from **Proposal** (not built). Citations are `file:line`.
Paths without a repository name are in this repository.

## Owner decisions this design keeps

- Intel TDX and AMD SEV-SNP boxes are admitted and paid first. Bare-metal vCPU
  supply is deferred, not dropped.
- A TEE box is a confidential VM that runs customer sandboxes under gVisor
  (`runsc`, `systrap` platform, no `/dev/kvm`).
- The Firecracker runtime (cathedralai/runtime) stays the bare-metal path. Its
  installer refuses a host without `/dev/kvm`
  (runtime `deploy/cathedral/install-runtime-host.sh:418`), and TDX and SNP
  guests do not offer it.
- Weights follow a signed market price table with separate TEE rates. The
  minimum box shape comes from SN120/Affine and SN81. The SN94 owner runs the
  prober; validators on SN39 and SN94 verify receipts. No netuid is hard-coded.

## 1. What a TEE box is

**Existing.** A TDX or SNP miner today is a confidential VM that runs one
Cathedral container:

- The TDX image runs `worker migrate` on TCP 8081
  (`cathedral/audit_miner_entrypoint.py:243-288`). The SNP image runs
  `worker serve-snp` (`cathedral/snp_miner_entrypoint.py:41-81`).
- At each start the entrypoint makes a fresh Ed25519 TLS key and a self-signed
  certificate inside the guest (`cathedral/audit_miner_entrypoint.py:193-240`).
  The SNP entrypoint reuses the same function
  (`cathedral/snp_miner_entrypoint.py:106`).
- The worker serves `/v1/evidence`, `/v1/sat-work`, `/v1/fleet` and GPU
  routes (`cathedral/worker.py:85-86`). The launcher runs it read-only, with no
  capabilities, 128 PIDs and 1 GiB (`scripts/run_sn94_signed_fleet_miner.sh:190-200`).
- The guest itself is a general-purpose Linux VM. In historical testing,
  upgrading packages and installing Docker in it changed the launch
  measurement (`docs/MRTD.md:30-34`).

**Proposal.** A TEE box is the same confidential VM plus a sandbox executor
in the same guest:

| Part | Stays | Added |
|---|---|---|
| Evidence (`/v1/evidence`, REPORT_DATA v2) | yes | nothing |
| In-guest TLS key, fresh at each start | yes | also carries the sandbox API |
| Validator-access signed requests | yes | a control-plane caller key set |
| SAT work route | yes, for now (open question 7) | none |
| Sandbox executor | none | `runsc` with `systrap`, one sandbox per customer request |
| Guest image | miner-administered VM | locked, measured appliance image (section 3) |

The executor is modeled on the Reliquary exclusive executor. Its deployment
already selects `runsc` with `systrap` on hosts without a usable `/dev/kvm`
(`deploy/reliquary-workers/README.md:11`,
`deploy/reliquary-workers/prepare.py:32`).

## 2. The sandbox API a TEE box serves

Customers, Affine and the adapters reach boxes only through the central API.
The box serves an internal API to the central API and to the prober. It never
serves customers directly.

**Existing: what the adapters call on the central API.**

cathedral-harbor (`src/cathedral_harbor/environment.py`):

- catalog: `GET /v1/sandboxes/catalog` (line 193);
- image: `POST /v1/images/import` or `/v1/images/build`, then
  `GET /v1/images/{id}` (lines 319-342);
- create: `POST /v1/sandboxes` with `image_id`, `network`
  (`internet` or `deny_all`), `lifetime_seconds`, `max_spend_usd` and `labels`
  (lines 78, 209-215, 248);
- status and list: `GET /v1/sandboxes/{id}` and `GET /v1/sandboxes`
  (lines 390, 444);
- exec: synchronous `POST .../exec` up to 45 s, otherwise
  `POST .../execs`, poll `GET .../execs/{exec_id}`, stop with `DELETE`
  (lines 48, 465-484, 497-558);
- files: `PUT`/`GET .../files`, `PUT`/`GET .../tar`, `GET .../stat`
  (lines 567-630);
- delete: `DELETE /v1/sandboxes/{id}` (line 425).

It refuses docker-compose tasks, since sandboxes offer no Docker-in-Docker
(lines 166-167).

cathedral-verifiers (`src/cathedral_verifiers/_runtime.py:5-15`) uses the same
catalog, image import, create, `execs`, `files` and delete calls. It adds
`POST .../processes` for background processes. It raises `CathedralUnsupported`
for `open_process`, `expose` and a runtime network policy
(`src/cathedral_verifiers/_runtime.py:168-172`).

The runtime's E2B-compatible front door allows more
(runtime `deploy/cathedral/ingress-proxy.go:40-62`, `:71-100`, `:170-182`):
sandbox create, get, list and timeout; lifecycle and identity reads; template
builds; snapshots; and envd `process.Process` and `filesystem.Filesystem`
Connect RPCs plus `/files`. Its guest listener forwards only the envd port
49983 (runtime `deploy/cathedral/ingress-proxy.go:656`), so it exposes no
customer port either.

**Proposal: the box API subset and how it maps to gVisor.**

| Call | gVisor mapping | Difficulty |
|---|---|---|
| create (image, shape, network, lifetime) | OCI bundle, `runsc run`, own cgroup | easy |
| status, list | executor state | easy |
| exec (sync and background), processes, stop | `runsc exec`, `runsc kill` | easy |
| files, tar, stat | exec in the sandbox, or the host-side rootfs overlay | easy |
| timeout, lifetime, delete | executor timer, `runsc kill` and `runsc delete` | easy |
| network `deny_all` | `--network=none`, as Reliquary does (`deploy/reliquary-workers/README.md:56`) | easy |
| network `internet` | gVisor netstack with guest NAT; block the worker port and guest-local services | medium |
| image import by digest | pull and unpack a centrally built image | medium |
| image build on the box | needs a builder in the guest | hard; build centrally instead |
| snapshot, fork | `runsc checkpoint` exists but is tied to a runsc version and one box | hard; defer |
| port exposure | needs netstack forwarding plus central routing | hard; defer (no adapter uses it) |
| Docker-in-Docker | needs extra runsc privileges | hard; defer (Harbor already refuses it) |

The first version serves only the "easy" rows plus image import by digest.
That covers every call Harbor and verifiers make today.

## 3. Binding the sandbox API to the attestation

**Existing.** The worker's evidence already binds its TLS channel:

- REPORT_DATA v2 is SHA-512 over a domain tag, version, nonce, hotkey, binding
  type and binding digest (`cathedral/common.py:260-295`). The binding type is
  `tls_spki_sha256` or `application_key_sha256` (`cathedral/common.py:151-155`).
- The TLS binding is SHA-256 of the served certificate's SPKI
  (`cathedral/channel.py:78-82`). The worker takes it from the certificate it
  serves and refuses a different configured value (`cathedral/cli.py:1507-1512`).
- A TLS worker must have its binding, and validator access must bind the same
  key (`cathedral/worker.py:1094-1095`, `:1116-1117`). An evidence request for
  another binding gets 403 (`cathedral/worker.py:603-623`).
- The validator records the peer SPKI from its own handshake
  (cathedral-validator `cathedral_thin/independent_runtime/https.py:273-274`).
  It sends that binding with a fresh nonce and checks that the response echoes
  it (cathedral-validator `cathedral_thin/independent/collect.py:368-433`).
  The caller supplies the binding it observed (same file, lines 31-32).
- It refuses the round if the SPKI changes between the binding and the
  evidence POST. Later SAT calls pin that SPKI
  (cathedral-validator
  `cathedral_thin/independent_runtime/fleet_score.py:183-190`, `:227-247`).

**Proposal: one key, one listener.** The sandbox API is served on the worker's
existing attested TLS listener, with the same in-guest key. The executor sits
behind the worker on a guest-local socket and has no network listener of its
own. The central API and the prober follow the validator's pattern:

1. Open TLS to the box and record the peer SPKI.
2. `POST /v1/evidence` with a fresh nonce. Verify the quote with the pinned
   verifier against the REPORT_DATA they compute.
3. Check the measurement against the allowlist, and the platform identity.
4. Send every sandbox call over a connection whose SPKI equals the attested
   one. On any mismatch, or a restart that rotates the key, stop routing and
   attest again.

One key is simpler than a second key. REPORT_DATA v2 has exactly one binding
field (`cathedral/common.py:286-291`), so a separate executor key would need a
second quote or a signed key hierarchy.

Callers must also be authenticated. The worker already requires signed
validator requests on protected routes (docs/WORK_REQUEST_V2.md, "Signed
request"). The sandbox routes would accept only requests signed by a
control-plane key set, supplied the same way.

**Why this closes the co-location hole.** The attack: a miner has a genuine
TDX machine A and a cheaper machine B. It shows A's quote but runs customer
sandboxes, or the capacity challenge, on B.

- The TLS private key is made inside A's guest and never leaves it. A quote
  binds that key's SPKI. Every sandbox call is pinned to that SPKI, so it ends
  inside A's guest. A quote from A cannot vouch for a TLS endpoint on B.
- Channel binding alone proves where TLS ends, not where work runs. A modified
  guest on A could hold the key and forward sandboxes to B. The measurement
  closes this: the admitted image runs sandboxes only locally.
- The capacity challenge runs through the same pinned channel, inside a probe
  sandbox, so it measures A. A's hardware identity comes from A's quote.
  B has no quote and earns nothing.

**Measurement must cover the executor.** Today it does not:

- The Cathedral TDX value hashes TD attributes, XFAM, MRTD, MRCONFIGID,
  MROWNER, MROWNERCONFIG and RTMR0-3 (`docs/MRTD.md:12-18`). A match does not
  prove a particular OCI image (`docs/MRTD.md:40-42`). The SNP report does not
  contain the OCI digest either (`docs/SN94_SNP_MINER_IMAGE.md:45-49`).
- The direct validator does not use the TDX measurement as a gate
  (`docs/MRTD.md:51-54`). Open PR cathedral-validator #256 adds an optional
  owner allowlist, `CATHEDRAL_TDX_MEASUREMENT_POLICY`, with `shadow` and
  `enforce` modes (its `tdx_measurement.py:39-41`). The SNP preview already
  loads `allowed_measurements` (cathedral-validator
  `cathedral_thin/independent_runtime/amd_snp_dev_preview.py:304-319`).

Proposal: ship the box as a measured appliance image:

- The kernel, initrd and command line are measured (RTMR1 and RTMR2 on TDX,
  measured direct boot on SNP). The command line pins a dm-verity root hash
  for a read-only root holding the worker, `runsc` and the executor.
- There is no SSH, no miner shell, no Docker socket and no debug mode.
- Customer images are data. They run inside gVisor and are not measured.

Then the allowlist entry names the executor. RTMR0 can vary with VM shape
(PR #256), so one image may need one entry per shape.

## 4. Isolation and overhead

**Proposal.** Sandboxes share one confidential VM:

- **Sandbox from sandbox:** each sandbox has its own gVisor Sentry (a
  user-space kernel), cgroup, rootfs overlay and network namespace, or no
  network. A tenant must escape gVisor and then attack the guest kernel.
- **All sandboxes from the host:** the TEE encrypts and integrity-protects
  guest memory. The host still controls scheduling, I/O and availability.
  Guest egress is visible to the host, so customers must encrypt their own
  traffic.
- **Residual risk:** a gVisor escape reaches the guest kernel. That kernel
  holds the TLS key and quote access, and it is shared with the other tenants.
  An escaped tenant could impersonate the box. The design does not remove this
  risk (open question 1).

**Overhead.** Systrap intercepts system calls through seccomp traps and needs
no virtualization extensions. Compute and memory-bound code, such as the
capacity lanes, should run near native. System-call-heavy code, such as builds
and small-file I/O, pays more. TDX and SNP add their own cost. None of this
has been measured for Cathedral. Qualification must measure it before TEE
prices are set.

**Existing: the Reliquary limits and admission pattern.**

- 50 `runsc` sandboxes, retired after every batch, reuse disabled
  (`deploy/reliquary-workers/README.md:5`, `deploy/reliquary-workers/prepare.py:86-88`).
- One executor-wide CPU quota; a 256 MiB address-space limit per sandbox,
  which is not resident-memory sizing (`deploy/reliquary-workers/README.md:13`).
- Read-only root, private PID and IPC namespaces, 8192 PIDs, 2 GiB `/tmp`,
  `--network=none` (`deploy/reliquary-workers/prepare.py:97-120`; README line 56).
- Grants start disabled, overlapping owner grants are refused, and enabling is
  a separate step (`deploy/reliquary-workers/admission.py:147-161`, `:177-181`).

**Proposal.**

Each sandbox gets its own cgroup with a CPU quota, memory and swap limit,
PID cap and disk quota. The executor admits a sandbox only while the sum of
admitted shapes fits the box's proven capacity minus a fixed guest reserve.
Every sandbox is retired at delete or lifetime end. Box enable, disable and
image upgrades keep Reliquary's disabled-first grant and drain pattern.

## 5. Capacity and receipts

**Existing (open PR cathedral-sandbox #217, `cathedral.capacity`).**

- One scrypt-like lane per claimed vCPU, holding 80% of the claimed memory.
  The box commits to all outputs first. Then the prober samples lanes with a
  fresh nonce (its `capacity/challenge.py:104-223`).
- The receipt names a hardware identity by kind: `ppid` for TDX, `chip_id` for
  SNP, `probe_fingerprint` for bare metal. An all-zero id is refused (its
  `capacity/receipt.py:58-66`, `:169-185`).
- The price table has separate `tee` and `bare_metal` rates and per-consumer
  minimum profiles (its CAPACITY.md, "Pricing").
- The receipt body has no evidence field (its `capacity/receipt.py:75-89`).

This repository already extracts the needed identities:

- the TDX stable platform id, when the quote-bound claims are verified
  (`cathedral/verify/__init__.py:200-208`);
- the SNP `CHIP_ID`, with a masked or zero chip id refused
  (`cathedral/verify/snp.py:163`, `:482-484`).

**Proposal.**

1. Each round, the prober attests the box as in section 3. It takes the
   PPID or CHIP_ID from the quote it verified itself, never from a box field.
2. Over the pinned channel it creates a probe sandbox of the claimed shape,
   with no network. It runs the challenge there, samples, then deletes the
   sandbox.
3. The challenge still runs because a quote proves neither vCPU count nor
   memory size.
4. Queue item T4 bumps the receipt schema to add an `evidence` object:
   `evidence_kind` (`tdx` or `sev_snp`), `evidence_sha256` over the raw quote
   or report the prober verified, the `measurement`, the verifier digest, and
   the attested `tls_spki_sha256`. A validator can then check that the
   hardware id and measurement come from one verified quote, and audit it
   later.

## 6. Admission (queue item T3)

**Proposal.** The control plane admits a TEE box only when all of these hold,
on one connection:

- the quote verifies with the pinned verifier (TDX QVL or the SNP chain);
- REPORT_DATA v2 binds the nonce, the miner hotkey and the SPKI of the TLS
  key serving the sandbox API;
- the measurement is on the owner allowlist (the PR #256 policy for TDX, the
  SNP `allowed_measurements`);
- the hardware id is not already registered to another box;
- a first capacity challenge passes.

Reuse, do not rebuild: validator-access signed requests and the fleet
manifest (docs/WORK_REQUEST_V2.md), the validator's evidence collection and
SPKI pinning (section 3), and the disabled-first grant pattern (section 4).

**Dedupe by hardware id.** The validator already zeroes every claimant that
shares a hardware identity
(cathedral-validator
`cathedral_thin/independent_runtime/fleet_score.py:1063-1066`). The PPID names
the physical platform, not the guest. Co-resident TDs on one cloud host
therefore collide (`cathedral/runtime.py:1177-1179`). So one physical host is
one TEE box. A miner runs one large TD per host, not several small ones.

## 7. What changes where

- **cathedral-sandbox:** a `runsc` executor serving the section 2 subset
  behind the worker's TLS listener; signed control-plane caller keys on the
  sandbox routes; measured appliance image builds for TDX and SNP; receipt
  schema v2 with the evidence object (T4), on top of PR #217.
- **cathedral-validator:** land #256, run it in shadow on the new image, then
  enforce; promote the SNP measurement allowlist; verify capacity receipts,
  including the evidence object, and dedupe across receipts by hardware id.
- **Private control plane:** registration and admission (T3); routing that
  pins each box's attested SPKI, attests again on change, and drains before
  an image upgrade; the SN94 owner's prober, with TEE rates in the signed
  price table.

**Ordered plan**

1. Agree this design.
2. Build the TDX appliance image with worker, `runsc` and the executor. It is
   not paid yet.
3. Serve the executor subset behind the worker's TLS. Test it with the
   Harbor and verifiers adapters through a staging central API.
4. Run #256 in shadow and record the new image's measurements.
5. Receipt v2 (T4) and the prober's TEE path.
6. Control-plane admission (T3) and routing, disabled by default.
7. Enforce the measurement allowlist and enable paid TDX boxes. SNP follows
   with the same image layout.
8. Later: port exposure, snapshots, Docker-in-Docker, and bare-metal supply.

## Open questions for the owner

1. **Shared-guest risk.** Is one shared TD per box acceptable, given that a
   gVisor escape exposes the box key and other tenants? Or do some customers
   need one TD per tenant?
2. **Caller keys.** Should control-plane keys be pinned in the measured image,
   or delivered as a signed snapshot like validator access?
3. **Cloud TDs.** Co-resident cloud TDs share a PPID and score zero. Do we
   admit only whole-host boxes, or cloud TDs as well?
4. **Measurement approval.** Who builds and signs the appliance image? Should
   the allowlist be the #256 policy file, or the signed registry flow
   (`docs/MRTD.md:70-86`)?
5. **Consumer needs.** Do SN120/Affine or SN81 need snapshots, fork, port
   exposure or Docker-in-Docker in the first version?
6. **Paid shape.** Is the paid shape the proven shape minus the guest and
   gVisor reserve? How large is that reserve?
7. **SAT.** Does SAT work continue on TEE boxes, or do capacity receipts
   replace it for box pay?
8. **Egress.** What egress policy applies to `internet` sandboxes leaving a
   TD, such as blocked ranges and rate limits?

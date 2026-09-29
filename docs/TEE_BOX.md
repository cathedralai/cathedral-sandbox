# TEE sandbox box design

Status: design proposal, 2026-09-28, revised 2026-09-29. Nothing in this page
has run on live hardware. Each section separates **Existing** (code on `main`,
or an open PR named by number) from **Proposal** (not built). Citations are
`file:line`. Paths without a repository name are in this repository. Files
that exist only in an open PR are named with that PR's number.

## Owner decisions this design keeps

- Intel TDX and AMD SEV-SNP boxes are admitted and paid first. Bare-metal vCPU
  supply is deferred, not dropped.
- A TEE box is a confidential VM that runs customer sandboxes under gVisor
  (`runsc`, `systrap` platform, no `/dev/kvm`).
- The Firecracker runtime (cathedralai/runtime) stays the bare-metal path. Its
  installer refuses a host without `/dev/kvm`, and TDX and SNP guests do not
  offer it. (Runtime `deploy/cathedral/` is not on runtime `main`. Runtime
  citations here are from open runtime PR #33; on its base, PR #1, this check
  is `install-runtime-host.sh:422`.)
- Weights follow a signed market price table with separate TEE rates. The
  minimum box shape comes from SN120/Affine and SN81. The SN94 owner runs the
  prober; validators on SN39 and SN94 verify receipts. No netuid is hard-coded.

The v1 decisions on this design itself are at the end of the page, in "Owner
decisions for v1".

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
| Validator-access signed requests | yes, for validators | central access for the control plane, with its root digest in measured state (section 3) |
| SAT work route | yes, for now ("SAT" under "Still open") | none |
| Sandbox executor | none | `runsc` with `systrap`, serving one customer allocation at a time |
| Guest image | miner-administered VM | locked, measured appliance image (section 3), relaunched between customers |
| Writable storage | host-backed disk | guest memory, or dm-crypt with integrity keyed inside the TD (section 4) |

The executor is modeled on the Reliquary exclusive executor. That deployment
does not choose `systrap` itself. The operator passes `--platform kvm` or
`systrap` (`deploy/reliquary-workers/prepare.py:32`). The README advises
`systrap` without a usable `/dev/kvm` (`deploy/reliquary-workers/README.md:11`),
but its example uses `kvm` (line 47). Qualification has not run (lines 3
and 21).

The network exposure differs from Reliquary's. The Reliquary executor listens
on the host network with its own mTLS identity
(`deploy/reliquary-workers/prepare.py:90-92`, `:106`). The TEE box executor
has no listener at all. It sits behind the worker's attested TLS listener
(section 3).

## 2. The sandbox API a TEE box serves

Customers, Affine and the adapters reach boxes only through the central API.
The box serves an internal API to the central API and to the prober. It never
serves customers directly.

**Existing: what the adapters call on the central API.**

cathedral-harbor (`src/cathedral_harbor/environment.py`, `main` at 9435023):

- catalog: `GET /v1/sandboxes/catalog` (line 432);
- image: `POST /v1/images/import` or `/v1/images/build`, then
  `GET /v1/images/{id}` (lines 602, 607-630);
- create: `POST /v1/sandboxes` with `image_id`, `network`
  (`internet` or `deny_all`), `lifetime_seconds`, `max_spend_usd` and `labels`
  (lines 98, 445-457, 520);
- status and list: `GET /v1/sandboxes/{id}` and `GET /v1/sandboxes`
  (lines 675, 740);
- exec: synchronous `POST .../exec` up to 45 s, otherwise
  `POST .../execs`, poll `GET .../execs/{exec_id}`, stop with `DELETE`
  (lines 68, 781-800, 813-822, 867-879);
- processes: `POST .../processes`, to start `dockerd` for a compose task
  (lines 488-497);
- files: `PUT`/`GET .../files`, `PUT`/`GET .../tar`, `GET .../stat`
  (lines 883-968);
- delete: `DELETE /v1/sandboxes/{id}`, then poll until cleanup is confirmed
  (lines 711-718).

Since Harbor PRs #13 and #15 (2026-09-28), Harbor runs docker-compose tasks
in Docker-in-Docker. Every compose sandbox is created from the published
`ghcr.io/cathedralai/cathedral-dind` image, imported once per job by digest
(lines 100-113). The sandbox itself is the DinD host: `dockerd` runs inside
it, and the compose services run under that `dockerd` (lines 131-141,
480-482). A compose task always needs `internet`, since it pulls and builds
inside the sandbox (lines 434-437).

cathedral-verifiers (`src/cathedral_verifiers/_runtime.py`, `main`) uses the
same catalog, image import, create, `execs`, `files` and delete calls. It also
calls:

- `POST .../processes` for background processes;
- `POST .../lifetime` to extend a sandbox (line 387);
- `GET /v1/sandboxes/{id}` (line 351) and `GET /v1/sandboxes` (line 584).

The module docstring (lines 5-15) lists only some of these, so it is stale.
The runtime raises `CathedralUnsupported` for `open_process` (lines 161-166),
`expose` (lines 168-172) and a runtime network policy (lines 174-176).

The runtime's E2B-compatible front door allows more. Per open runtime PR #33
(`deploy/cathedral/ingress-proxy.go:40-62`, `:71-100`, `:170-182`; on base
PR #1, lines 37-66, 68-101 and 167-179), it allows:

- sandbox create, get, list and timeout;
- lifecycle and identity reads;
- template builds and snapshots;
- envd `process.Process` and `filesystem.Filesystem` Connect RPCs, plus
  `/files`.

Its guest listener forwards only the envd port 49983 (PR #33 line 656; PR #1
line 274), so today it exposes no customer port either. Open runtime PR #30
(`-allow-guest-ports`) would change that.

**Proposal: the box API subset and how it maps to gVisor.**

| Call | gVisor mapping | Difficulty |
|---|---|---|
| create (image, shape, network, lifetime) | OCI bundle, `runsc run`, own cgroup | easy |
| status, list | executor state | easy |
| exec (sync and background), processes, stop | `runsc exec`, `runsc kill` | easy |
| files, tar, stat | exec in the sandbox, or the rootfs overlay on protected storage (section 4) | easy |
| timeout, lifetime, delete | executor timer, `runsc kill` and `runsc delete` | easy |
| network `deny_all` | `--network=none`, as Reliquary does (`deploy/reliquary-workers/README.md:56`) | easy |
| network `internet` | gVisor netstack with guest NAT; the deny list is enforced by nftables on the sandbox link, outside the Sentry (section 4, "Egress") | medium |
| image import by digest | a centrally built image, stored with a dm-verity hash tree and verified on every read (section 4, "Storage") | medium |
| image build on the box | needs a builder in the guest | hard; build centrally instead |
| snapshot, fork | `runsc checkpoint` exists but is tied to a runsc version and one box | hard; defer |
| port exposure | needs netstack forwarding plus central routing | hard; defer (no adapter uses it) |
| Docker-in-Docker | `dockerd` inside the sandbox; needs extra runsc privileges | hard; not in v1 (decision 5), though Harbor's compose tasks now use it ("Still open") |

The first version serves the "easy" rows plus image import by digest. Two
more things are needed before it covers Harbor's single-container tasks:

- Harbor's `POST /v1/images/build` (`src/cathedral_harbor/environment.py:627`)
  needs a central builder and a way to deliver the built image into the TD.
- Harbor deletes any sandbox whose `hardware` is not `standard`
  (`src/cathedral_harbor/environment.py:473-478`). The box must present as a
  Standard box: exec `env`, `user` and `cwd` (lines 786-793), and execs up to
  14,400 s (line 64).

Harbor's compose tasks need Docker-in-Docker, which decision 5 leaves out of
v1. A v1 TEE box therefore does not serve them.

**Churn and cold start.** The target is thousands of short-lived sandboxes a
day, so create and delete sit on the hot path.

- **Existing load.** verifiers imports each image once per run and shape,
  then creates one sandbox per rollout, optionally paced per minute. Teardown
  polls until cleanup is confirmed (`_runtime.py:5-11`, `:120`). Harbor
  creates one sandbox per trial (`src/cathedral_harbor/environment.py:451-460`).
- **Proposed targets**, to confirm in qualification. With the image already
  on the box, create to `running` within 2 s at p50 and 5 s at p99. Delete to
  confirmed cleanup within 5 s at p99. The box sustains at least 60 creates a
  minute at full occupancy. A relaunch between customers (decision 1), from
  drain to a new admitted attestation, completes within 5 minutes. The box
  takes no allocation during a relaunch.
- **Image cache.** The cache is keyed by image digest and shared by the
  sandboxes of one allocation. Customer images live on the TD's protected
  storage (section 4), whose key is made at boot, so they do not survive the
  relaunch between customers. Only public catalog base images may be cached
  across relaunches. They sit on host disk as dm-verity images, verified on
  every read against the root hash the control plane names, and they need no
  confidentiality.
- **Warm pool.** Reliquary pre-starts 50 sandboxes and retires each after
  one use (`deploy/reliquary-workers/prepare.py:86-88`). The TEE box may keep
  a warm pool of pre-started `runsc` sandboxes for the allocation's most-used
  image. Each is used once and retired, and pool slots count against the
  allocation's admitted shape. The pool is off until qualification shows cold
  creates miss the target.
- **Retire and cleanup.** Delete returns after `runsc kill`. `runsc delete`,
  overlay and cgroup removal run from a bounded queue. A sandbox's resources
  count as used until its cleanup is confirmed. The drain before a relaunch
  waits for that queue to empty.
- **Qualification measures** these alongside the systrap overhead: create
  latency (cold image, cached image, warm slot), delete-to-cleanup latency,
  sustained creates a minute at full occupancy, image import throughput,
  dm-crypt and dm-verity I/O cost, and relaunch-to-admission time.

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
3. Check the measurement against the owner's published measurement list
   (decision 5), and the platform identity.
4. Send every sandbox call over a connection whose SPKI equals the attested
   one. On any mismatch, or a restart that rotates the key, stop routing and
   attest again.

One key is simpler than a second key. REPORT_DATA v2 has exactly one binding
field (`cathedral/common.py:291-292`), so a separate executor key would need a
second quote or a signed key hierarchy.

**Callers: central access, with its root in measured state (decision 2).**

Existing, in open PRs:

- #225 adds `central_access.py`. An offline Ed25519 root signs a short-lived
  delegation naming one online central key and the routes it may call. The
  central key signs each request over the route, the body hash, a nonce and
  the worker's TLS channel binding. The worker keeps its own replay state and
  a delegation high-water mark, apart from validator access (#241
  `central_access.py:3-10`, `:143-147`).
- A delegation lasts at most 24 hours (#241 `central_access.py:65`, `:436`).
  It may name only routes in `CENTRAL_ROUTES`, which today holds only
  `/v1/capabilities` (#241 `central_access.py:73`, `:423`).
- #228 serves central requests from the worker, off by default. #241 adds a
  root-signed revocation list. The worker persists it, re-reads a local list
  file, and refuses central requests while the list is missing or unusable
  (#241 `central_access.py:494-526`, `cli.py:4433-4436`). #239 adds the
  offline root tool.
- The worker takes the root keys and their digest from miner flags,
  `--central-root-keys` and `--central-root-keys-digest` (#241
  `central_access.py:12-16`, `cli.py:4421-4426`).

Proposal:

- The sandbox routes are added to `CENTRAL_ROUTES`. There is no second caller
  key set.
- The root key digest is never a miner flag or a miner-supplied file. In the
  appliance it comes from measured state, in one of two ways:
  - MRCONFIGID on TDX. The Cathedral TDX value already covers it
    (`docs/MRTD.md:12-18`). At boot the appliance reads its own MRCONFIGID
    from a TD report. It serves no sandbox route unless the root key file
    hashes to that value.
  - A root key file inside the dm-verity root, on either TEE kind. SNP needs
    this form: its `MEASUREMENT` does not cover `HOST_DATA`, the launch field
    closest to MRCONFIGID.
- Delegations of at most 24 h rotate under the root without re-measuring.
  Replacing the root means a new entry on the published measurement list.
- Admission checks this (section 6).

**Why the replaced decision 2 was unsafe.** It had the control-plane caller
keys arrive as a signed snapshot "like validator access". The validator-access
snapshot is signed by the operator's artifact key outside the guest, that is,
by the miner (`cathedral/validator_access.py:3-5`). The miner also chooses the
trusted key file and its digest (`cathedral/audit_miner_entrypoint.py:266-270`,
`inputs.validator_access_keys_digest`). That is sound for validator access,
because each validator re-verifies everything itself. On the sandbox routes it
would let the miner mint its own caller key. It could then exec into, and read
or change files in, the current customer's sandboxes through the front door.
Section 4's protection from the host would be gone.

Open PRs #242 and #243 implement the replaced decision. #242, a library,
authorizes callers with a signed control-plane snapshot through the
validator-access code (its `tee_box/service.py:151`, and its
TEE_BOX_SERVICE.md, "Caller authorization"). #243 adds the worker flags that
feed it from the miner: `--tee-box-caller-snapshot`, `--tee-box-caller-keys`,
`--tee-box-caller-keys-digest` and `--tee-box-caller-state` (its
`tee_box/configure.py:40-43`, `:85-88`). Both have to move to central
access.

**Central state across a relaunch.** Central state lives in guest memory
(section 4), and the guest is relaunched between customers (decision 1), so
each boot starts empty. A replayed request still fails, because it is bound to
the previous boot's TLS key. But the delegation high-water resets, and the
host could offer an older revocation list: #241 compares a list's sequence
only with the stored one (`central_access.py:506-510`). Withholding a newer
list works today too, since the miner delivers the list file. Proposal: after
each relaunch, and whenever the list changes, the control plane installs the
current revocation list over the attested channel, on a central route. The
appliance serves no sandbox route until it has one. A revoked delegation then
stops working as soon as the control plane has pushed the list, not only at
its expiry.

**The co-location hole, and what closes it.** The attack: a miner has a
genuine TDX machine A and a cheaper machine B. It shows A's quote but runs
customer sandboxes, or the capacity challenge, on B.

- **What channel binding gives today.** An honest guest makes the TLS key
  inside itself, and REPORT_DATA binds its SPKI. A plain relay, or a MITM
  without that key, gains nothing: the pinned SPKI will not match.
- **What it does not give today.** In a miner-run TD, guest root can write any
  REPORT_DATA to configfs-tsm, including the SPKI of a key on B. The launcher
  mounts the TSM report tree into the container
  (`scripts/run_sn94_signed_fleet_miner.sh:194`). The worker's 403 on a
  mismatched binding (`cathedral/worker.py:622-623`) is software the miner
  controls. So A can act as a quote oracle for B, and B's endpoint then passes
  the SPKI check.
- **What closes it.** Only an enforced measurement (plan step 7) closes this.
  The admitted image gives no one root, never writes a foreign REPORT_DATA, and
  runs sandboxes only locally. Until then, a quote from A *can* vouch for a TLS
  endpoint on B.
- With the measurement enforced, the capacity challenge runs through the
  pinned channel inside a probe sandbox, so it measures A. A's hardware id
  comes from A's quote, and B earns nothing.

**Measurement must cover the executor.** Today it does not:

- The Cathedral TDX value hashes TD attributes, XFAM, MRTD, MRCONFIGID,
  MROWNER, MROWNERCONFIG and RTMR0-3 (`docs/MRTD.md:12-18`). A match does not
  prove a particular OCI image (`docs/MRTD.md:40-42`). The SNP report does not
  contain the OCI digest either (`docs/SN94_SNP_MINER_IMAGE.md:45-49`).
- The direct validator does not use the TDX measurement as a gate
  (`docs/MRTD.md:51-54`). Open PR cathedral-validator #256 (at 14e2370) adds
  an optional allowlist: a local, unsigned file each validator names with
  `CATHEDRAL_TDX_MEASUREMENT_POLICY`, with `shadow` and `enforce` modes. It is
  TDX-only (its `tdx_measurement.py:10-18`, `:33`, `:48-51`). The SNP
  preview already loads `allowed_measurements` (cathedral-validator
  `cathedral_thin/independent_runtime/amd_snp_dev_preview.py:304-319`).

Proposal: ship the box as a measured appliance image:

- The kernel, initrd and command line are measured (RTMR1 and RTMR2 on TDX,
  measured direct boot on SNP). The command line pins a dm-verity root hash
  for a read-only root holding the worker, `runsc` and the executor.
- The central-access root key digest is in MRCONFIGID or the dm-verity root,
  as above.
- **RTMR3.** The owner asked for the RTMR3 extends to be defined; proposed
  answer: none. *Proposal:* the appliance extends nothing into RTMR3, and
  enables nothing that extends it at runtime. The kernel, initrd, command
  line and dm-verity root are already in RTMR1 and RTMR2, and customer images
  are data, not extended. RTMR3 therefore keeps its initial all-zero value.
  #256 notes that RTMR3 follows what the guest extends at runtime (its
  `tdx_measurement.py:24-25`), so this keeps one entry per image and VM
  shape. An image that later extends RTMR3 needs entries for the values it
  produces.
- **Provider-dependent assumption, to verify:** this needs a provider that lets
  the miner supply the kernel and command line, and measures them into the
  RTMRs or the SNP launch digest. Clouds that boot through a paravisor or vTPM
  measure elsewhere, so this layout may not apply there.
- There is no SSH, no miner shell, no Docker socket and no debug mode.
- Customer images are data. They run inside gVisor and are not measured.

Then the published list entry names the executor. RTMR0 can vary with VM shape
(#256 `tdx_measurement.py:20-21`), so one image may need one entry per shape.

## 4. Isolation, storage and overhead

**Proposal.** One confidential VM per box serves one customer allocation at a
time (decision 1):

- **Sandbox from sandbox,** within one customer's allocation: each sandbox has
  its own gVisor Sentry (a user-space kernel), cgroup, rootfs overlay and
  network namespace, or no network.
- **Customer from customer:** the VM is relaunched and re-attested between
  allocations (decision 1). The relaunch gives a fresh TLS key, a clean
  dm-verity root, a fresh storage key and fresh evidence. The control plane
  routes the next customer only after admission (section 6) passes on the new
  SPKI. So a gVisor escape during one allocation does not persist into the
  next.
- **All sandboxes from the host:** the TEE encrypts and integrity-protects
  guest memory. The host still controls scheduling, I/O and availability.
  Guest egress is visible to the host, so customers must encrypt their own
  traffic. Host-backed disk is covered under "Storage" below.
- **Residual risk:** a gVisor escape reaches the guest kernel for the rest of
  that allocation. That kernel holds the TLS key, quote access and the central
  state. The escaped tenant can reach only its own sandboxes, since no other
  customer and no probe shares the guest, but it could impersonate the box
  until the relaunch.

**Storage.** The host controls the disk, so the design treats host-backed
storage like host-visible traffic:

- **All writable storage** is in guest memory, or on dm-crypt with integrity
  (AEAD, dm-integrity) under a key the TD makes at boot and never writes out
  (decision 7). *Proposal*, per kind: imported images are read through
  dm-verity (below) and, when private, encrypted under the boot key; rootfs
  overlays, `files` and `tar` uploads and bulk scratch space are on dm-crypt
  with integrity; the replay, high-water and revocation state is in guest
  memory only.
- **Images are verified on read.** The central builder emits each image as a
  read-only filesystem with a dm-verity hash tree, and the image id binds its
  root hash. The box opens the image with dm-verity against the root hash the
  control plane named, so every block is checked when `runsc` reads it. There
  is no time-of-check gap between import and `runsc run`. A customer's
  private image is also encrypted under the boot key.
- **State files cannot be rolled back.** *Proposal:* they live in guest
  memory only, never on dm-crypt. AEAD sector tags detect a changed sector,
  but not the replay of an older version of the same sector written under
  the same key. So dm-crypt alone would not stop the host rolling a state
  file back within one boot. State does not need to outlive a boot (section 3, "Central state across a
  relaunch").
- **Residual risk:** on dm-crypt, the host can still replay an older version
  of an overlay or scratch sector within one allocation. That can revert the
  customer's own data. It cannot forge data or read it. A customer who needs
  more puts its scratch space in memory.
- Open PR #242's `RunscExecutor` drives `docker run --runtime=runsc` (its
  TEE_BOX_SERVICE.md, "What T6a adds"). Docker's image and container store
  must then sit on the protected storage too, with images verified on read as
  above.
- Guest memory used for storage comes out of the box's reserve ("Paid shape"
  under "Still open").

**Egress (decision 6; where it is enforced is a proposal, not an owner
decision).** The `internet` deny list is enforced outside the Sentry,
never in the sandbox's own netstack, where a root tenant could change it:

- nftables in the guest, on the sandbox link. The forward hook drops packets
  to denied ranges. The input hook drops everything from the sandbox link
  addressed to the box itself: the worker port, the executor and guest
  services.
- The rules match each packet's destination address, so they apply after DNS
  resolution. A name that resolves, or rebinds, to a denied address is
  dropped.
- The denied ranges include `100.64.0.0/10`, the IPv4 private, link-local and
  reserved ranges, the IPv6 ranges `fc00::/7`, `fe80::/10`, `::ffff:0:0/96`
  and `64:ff9b::/96`, and each cloud metadata address. The public internet is
  allowed, with a per-sandbox bandwidth cap.
- Open PR #243 implements this. The ranges are its `tee_box/egress.py:30-72`,
  and the nft rules on the sandbox bridge are `:102-137`. Its
  `tee_box/enforce.py:1-25` applies them, reads them back before every
  `internet` create, and fails closed. The bandwidth cap is `tc` on each
  sandbox's host-side veth (`tee_box/egress.py:139`). Because the input hook
  drops guest-local DNS, sandboxes use public resolvers (its
  `tee_box/executor.py:47`).

**Overhead.** Systrap intercepts system calls through seccomp traps and needs
no virtualization extensions. Compute and memory-bound code, such as the
capacity lanes, should run near native. System-call-heavy code, such as builds
and small-file I/O, pays more. TDX and SNP add their own cost, and so do
dm-crypt and dm-verity. None of this has been measured for Cathedral.
Qualification must measure it before TEE prices are set.

The capacity probe needs its own calibration. #217 budgets 5 s of startup and
a per-step deadline set from native runs on development VMs (#217
CAPACITY.md, "Timing", lines 93-164 at 7812b15). A probe inside `runsc` inside
a TD must be calibrated there. The deadline timer must start after the probe
sandbox is running. #217 already bounds only the exec and times the create
separately (`timings_ms.create`, same section), and the TEE prober keeps that.

**Existing: the Reliquary limits and admission pattern.**

- 50 `runsc` sandboxes, retired after every batch, reuse disabled
  (`deploy/reliquary-workers/README.md:5`, `deploy/reliquary-workers/prepare.py:86-88`).
- One executor-wide CPU quota shared by all 50 slots. Each slot has a 256 MiB
  address-space limit, which is not resident-memory sizing
  (`deploy/reliquary-workers/README.md:13`).
- For the whole executor container, not each sandbox: read-only root, private
  PID and IPC namespaces, 8192 PIDs and a 2 GiB `/tmp`
  (`deploy/reliquary-workers/prepare.py:97-120`). The inner `runsc` uses
  `--network=none` (README line 56).
- The executor container runs `privileged: true` with `cgroup: host`
  (`deploy/reliquary-workers/prepare.py:102-103`). Inside a TD this makes the
  executor effectively guest root, sharing the guest's cgroup tree. An escape
  from the executor reaches the key and quote access that section 3 relies
  on. The TEE box should keep the executor privileged only as far as `runsc`
  needs.
- Grants start disabled, overlapping owner grants are refused, and enabling is
  a separate step (`deploy/reliquary-workers/admission.py:147-161`, `:177-181`).

**Proposal.**

Each sandbox gets its own cgroup with a CPU quota, memory and swap limit,
PID cap and disk quota. The executor admits a sandbox only while the sum of
admitted shapes fits the box's proven capacity minus a fixed guest reserve.
Every sandbox is retired at delete or lifetime end. Box enable, disable and
image upgrades keep Reliquary's disabled-first grant and drain pattern. Every
allocation ends with a drain and a relaunch.

## 5. Capacity and receipts

**Existing (open PR cathedral-sandbox #217 at 7812b15, `cathedral.capacity`).**

- One scrypt-like lane per claimed vCPU, holding 80% of the claimed memory
  (its `capacity/challenge.py:51`). The prober sends a spec with a fresh
  seed, and the box returns every lane's output, which commits it. Only then
  does the prober draw a fresh nonce and recompute the lanes it picks (its
  `capacity/challenge.py:13-22`; the commitment and sampling are
  `:226-252`).
- The receipt names a hardware identity by kind: `tdx_platform` for TDX,
  `chip_id` for SNP, `probe_fingerprint` for bare metal (its
  `capacity/receipt.py:61-65`). The TDX id comes from the strict verifier's
  `stable_platform_id`, not the PPID: "No TDX verifier outputs the raw PPID"
  (its CAPACITY.md:224, "Hardware identity"). An all-zero id is refused (its
  `capacity/receipt.py:173-190`).
- A receipt answers one validator's nonce in one round, and is valid for at
  most 2 hours (its `capacity/receipt.py:71`, `:297-328`).
- The price table has separate `tee` and `bare_metal` rates and per-consumer
  minimum profiles (its CAPACITY.md, "Pricing").
- The v1 receipt body has no evidence field (its `capacity/receipt.py:79-92`).

**Existing (open PR #237 at 92d79ed, stacked on #217): receipt v2 with
evidence.** It
adds a signed `evidence` object, required for a TEE box and `null` for bare
metal, with seven fields: `evidence_kind`, `evidence_sha256` over the raw
quote or report, `measurement`, `verifier_digest`, `tls_spki_sha256`,
`attestation_nonce` and `attested_at`. `expected_report_data` recomputes the
quote's REPORT_DATA v2 from the nonce, the miner hotkey and the SPKI, for
audit. `verify_receipt(..., max_evidence_age=)` lets a validator refuse
evidence older than it accepts. The evidence comes from admission and is
reused for later receipts (its CAPACITY.md:211-260, "Evidence").

What it does not prove: the receipt carries the quote's hash, not the quote.
A validator cannot re-verify the quote, or check that the hardware id came
from it, from the receipt alone. It trusts the prober for that, as it does for
the challenge. With the quote, from the prober's archive or the box, anyone
can audit the receipt end to end: hash the quote, verify it, recompute the
hardware id and measurement, and compare its REPORT_DATA with
`expected_report_data` (same section).

This repository already extracts the needed identities:

- the TDX stable platform id, when the quote-bound claims are verified
  (`cathedral/verify/__init__.py:200-208`);
- the SNP `CHIP_ID`, with a masked or zero chip id refused
  (`cathedral/verify/snp.py:163`, `:482-484`).

**Proposal.**

1. **Probe only when idle (decision 4).** The prober probes a box only
   between allocations, with the box drained: no customer sandbox, and no
   cleanup pending. So the probe never shares the guest with a customer, and
   the prober is never a second tenant. The natural slot is right after the
   relaunch between customers, before the next allocation. That relaunch's
   fresh attestation is then the receipt's evidence.
2. The prober attests the box as in section 3. It takes the TDX
   `stable_platform_id` or the SNP CHIP_ID from the quote it verified itself,
   never from a box field.
3. Over the pinned channel it creates a probe sandbox of the full claimed
   shape, with no network. It runs the challenge there, samples, then deletes
   the sandbox. The challenge still runs because a quote proves neither vCPU
   count nor memory size.
4. **An allocated box keeps its last good receipt for the round** (decision
   8). How it is scored is a *proposal*, and it needs a change to #237.
   #237's prober rule requires a fresh challenge over the attested TLS key
   each round, and says the prober "must not sign a receipt otherwise" (#237
   CAPACITY.md:256-260, and the rules list at `:90-91`). #217 also binds each
   receipt to one round and one validator nonce, valid for at most 2 hours
   (#217 `capacity/receipt.py:71`, `:297-328`). So the prober cannot simply
   sign this round's receipt for a box it did not probe. Two ways to change
   #237:
   - **Validator-side carry.** The prober signs nothing new. For a box the
     control plane lists as allocated in a signed allocation record, a
     validator pays the box's last receipt that it verified, up to a bounded
     age. `verify_receipt` then needs a mode that accepts a receipt from an
     earlier round, within that bound.
   - **A new receipt kind.** The prober signs a "carried" receipt for the
     round. It names the round of the last passing probe and repeats that
     probe's capacity and evidence. #237's rule would then allow exactly this
     kind without a fresh challenge.

   Either way, the proposed scoring:
   - A carried receipt is paid like a fresh one, so a box does not lose pay
     for serving a customer.
   - It may be carried for at most 24 hours after its probe. The control
     plane schedules a drain and probe before that. Past the bound, the box
     scores zero until it is probed again.
   - Only a box the control plane lists as allocated is carried. An idle box
     that refuses or fails a probe scores zero for the round.
   - Dedupe by hardware id is unchanged, and carried receipts count in it.
5. **Receipt evidence (T4)** follows #237 as implemented. The design does not
   claim more than it does: a validator trusts the prober for the link between
   the quote and the hardware id. The prober keeps an archive of the quotes it
   relied on, so any receipt can be audited with `expected_report_data`.
   Carrying the quote in the receipt stays a possible later change.

## 6. Admission (queue item T3)

**Proposal.** The control plane admits a TEE box, and again after every
relaunch, only when all of these hold, on one connection:

- the quote verifies with the pinned verifier (TDX QVL or the SNP chain);
- REPORT_DATA v2 binds a fresh nonce, the miner hotkey and the SPKI of the TLS
  key serving the sandbox API;
- the measurement is on the owner's published measurement list (decision 5);
- the central-access root digest is in measured state. On TDX the list entry
  fixes MRCONFIGID, which the appliance has checked against its root key
  file. Otherwise the root key file is inside the listed dm-verity root. A
  box whose root keys come from a miner flag or file outside measured state
  is not admitted. Its measurement cannot match a listed entry;
- the hardware id is not already registered to another box;
- a first capacity challenge passes, with the box drained.

Open PR #240 (at 796144c) implements the REPORT_DATA, hardware-id and
measurement checks as a library. It reads #256's policy file format for TDX
(its `capacity/admission.py:1-51`). Under decision 5 it would read the published
list instead.

Reuse, do not rebuild: central access (#225, #228, #241) for control-plane
calls; validator-access signed requests and the fleet manifest for validators
(docs/WORK_REQUEST_V2.md); the validator's evidence collection and SPKI
pinning (section 3); and the disabled-first grant pattern (section 4).

**Dedupe by hardware id.** The validator already zeroes every claimant that
shares a hardware identity
(cathedral-validator
`cathedral_thin/independent_runtime/fleet_score.py:1063-1066`). The TDX
platform id derives from the PPID, which names the physical platform, not the
guest. Co-resident TDs on one cloud host therefore collide
(`cathedral/runtime.py:1177-1179`). SNP is the same: CHIP_ID is per processor
(`cathedral/verify/snp.py:163`), so co-resident SNP guests share it. So one
physical host is one TEE box. A miner runs one large TD or SNP guest per host,
not several small ones.

## 7. What changes where

- **cathedral-sandbox:** a `runsc` executor serving the section 2 subset
  behind the worker's TLS listener; the sandbox routes in `CENTRAL_ROUTES`,
  with the root digest taken from measured state, and the caller snapshot
  of #242 and #243 replaced by central access; revocation-list install over
  the attested channel; all writable storage in guest memory or dm-crypt with integrity,
  images verified on read with dm-verity; Standard-box behavior (exec env,
  user, cwd, 14,400 s execs); image import into the TD by digest; the egress
  enforcer (#243); measured appliance image builds for TDX and SNP, with
  no RTMR3 extends (proposal, section 3); receipt v2 with the evidence
  object (#237), on top of #217, plus the change to #237 that a carried
  receipt needs (section 5, step 4).
- **cathedral-validator:** land #256, with its local file mirroring the
  published measurement list during rollout; run it in shadow on the new
  image, then enforce; take the SNP allowlist from the same list; verify
  capacity receipts, including the evidence object and its age, and dedupe
  across receipts by hardware id. If the carry is validator-side (section 5,
  step 4), validators also carry an allocated box's last receipt.
- **Private control plane:** the owner's signed measurement list, which
  validators, admission, routing and the prober all consume; a central image
  builder serving `POST /v1/images/build` that emits dm-verity images, plus
  image delivery to boxes; registration and admission (T3); routing that pins
  each box's attested SPKI, attests again on change, drains before an image
  upgrade, and relaunches and re-admits the box between customers; the SN94
  owner's prober, probing only drained boxes, with TEE rates in the signed
  price table.

**Ordered plan**

1. Agree this design.
2. Build the TDX appliance image with worker, `runsc`, the executor and
   protected storage. It is not paid yet.
3. Serve the executor subset behind the worker's TLS on central access,
   presenting as a Standard box. Add the central image builder and image
   delivery into the TD. Test with the Harbor and verifiers adapters through a
   staging central API, and measure the churn targets (section 2).
4. Publish the signed measurement list with the new image's measurements. Run
   #256 in shadow with its local file mirroring the list.
5. Receipt v2 (#237) and the prober's TEE path, probing only drained boxes.
6. Control-plane admission (T3), relaunch between customers, and routing,
   disabled by default.
7. Enforce the measurement list and enable paid TDX boxes. SNP follows with
   the same image layout.
8. Later: port exposure, snapshots, Docker-in-Docker, and bare-metal supply.

## Owner decisions for v1 (2026-09-28, amended 2026-09-29)

The owner gave these answers to the author on 2026-09-28 and 2026-09-29;
this section is the record. The 2026-09-29 answers respond to the third
review round. Decisions 1, 2 and 4 changed; 7 and 8 are new.

1. **One customer at a time, relaunched between customers.** One confidential
   VM per box serves one customer allocation at a time, as the Reliquary
   exclusive executor does. *Amended 2026-09-29:* the VM is relaunched and
   re-attested between customer allocations, so a gVisor escape cannot
   persist into the next customer's allocation (section 4). One VM per tenant
   can come later for customers who need it.
2. **Caller keys: central access.** *Replaced 2026-09-29.* Control-plane
   callers use central access (`central_access.py` from #225, #228 and #241).
   An offline Cathedral root key signs short-lived, route-scoped delegations
   of at most 24 h, with a signed revocation list. The root key's digest is in
   measured state: MRCONFIGID, already covered by the Cathedral TDX value
   (`docs/MRTD.md:12-18`), or the dm-verity root. It is never a miner flag or
   file. The sandbox routes are added to `CENTRAL_ROUTES`. Admission checks
   this (section 6). The replaced decision (a signed snapshot like validator
   access) was unsafe: the miner signs that snapshot and chooses its trusted
   keys (`cathedral/validator_access.py:3-5`,
   `cathedral/audit_miner_entrypoint.py:266-270`), so it could authorize
   itself on the sandbox routes (section 3).
3. **Cloud guests.** Whole-host boxes only. One physical host is one box, and
   a miner runs one large confidential VM per host. Cloud guests that share a
   TDX platform id or CHIP_ID with a co-tenant are not admitted in v1.
4. **One published measurement list.** *Replaced 2026-09-29.* The owner
   publishes one signed measurement list. Validators, admission, routing and
   the prober all consume it. It replaces per-validator local #256 files as
   the source of truth. During rollout, #256's local file can mirror it. The
   existing signed registry format and approval flow
   (`cathedral/policy_registry.py`, `docs/MRTD.md:70-86`) are candidates for
   it. The owner asked for the RTMR3 extends to be defined; proposed answer:
   none (section 3). Who builds and approves the image is still open.
5. **Consumer needs.** No snapshots, fork, port exposure or Docker-in-Docker
   in v1. When this was decided, the adapters used none of them. Since
   2026-09-28, Harbor runs its docker-compose tasks in Docker-in-Docker
   (Harbor PRs #13 and #15, section 2), so this decision now excludes those
   tasks ("Still open").
6. **Egress.** `internet` sandboxes may not reach private, link-local or
   cloud metadata ranges, or the box's own addresses. The public internet is
   allowed, with a per-sandbox bandwidth cap. *Proposal (section 4), not an
   owner decision:* enforcement by nftables on the sandbox link, outside the
   Sentry, after DNS resolution, covering the IPv6 ranges and
   `100.64.0.0/10`, as open PR #243 does.
7. **Encrypted storage.** *New 2026-09-29.* All writable storage (imported
   images, rootfs overlays, `files` and `tar` uploads and scratch, and replay
   and high-water state) lives in guest memory, or on dm-crypt with integrity
   (AEAD) under a key made inside the TD at boot. Images are verified on read,
   with no time-of-check gap between import and `runsc run`. State files
   cannot be rolled back by the host. *Proposal (section 4), which is which:*
   images are read through dm-verity; overlays, uploads and bulk scratch are
   on dm-crypt with integrity; the replay, high-water and revocation state
   stays in guest memory only, because dm-crypt with integrity does not stop
   the host replaying an older sector.
8. **Probe only when idle.** *New 2026-09-29.* The capacity probe runs only
   between allocations, with the box drained. An allocated box keeps its last
   good receipt for the round. How that is scored is a proposal that needs a
   change to #237 (section 5, step 4).

Still open:

- **Docker-in-Docker for Harbor's compose tasks.** Decision 5 (no
  Docker-in-Docker in v1) now excludes Harbor's docker-compose tasks, which
  run `dockerd` inside the sandbox (section 2). Does the owner want
  Docker-in-Docker under gVisor in a later version?

- **Image build and approval.** Who builds and approves the appliance image
  and its measurement list entries? This was the original question 4.
- **Paid shape.** Is the paid shape the proven shape minus the guest and
  gVisor reserve, now including memory used for storage? How large is that
  reserve?
- **SAT.** Does SAT work continue on TEE boxes, or do capacity receipts
  replace it for box pay?

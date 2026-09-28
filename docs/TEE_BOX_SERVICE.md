# TEE box sandbox service (T6a, T6b1)

Status: **off by default**. T6a added the library, and T6b1 adds the worker
flags, the egress enforcer, in-sandbox exec kills, disk quotas and an opt-in
runsc image layer. Nothing here has run on TDX or SEV-SNP hardware yet; that
is T6b2 (see "Not done" below). The design is `TEE_BOX.md` on PR #236, branch
`docs/tee-box-design` (sections 2 to 4 and "Owner decisions for v1").
Citations are `file:line` in this repository.

## What T6a adds

`cathedral/tee_box/` holds four parts.

- **Executor protocol** (`cathedral/tee_box/executor.py:179-202`): image
  import by digest, create from an image with a shape, get, list, expiry,
  delete, sync exec, background exec with poll and stop, and file read,
  write, stat and tar.
  - `FakeExecutor` (`cathedral/tee_box/executor.py:273`) keeps everything in
    memory for tests.
  - `RunscExecutor` (`cathedral/tee_box/executor.py:567`) drives
    `docker run --runtime=runsc`. It builds argv lists only, with no host
    shell (`_check_argv`, `cathedral/tee_box/executor.py:416`), and caps every
    captured output. The Docker daemon must register runsc with
    `--platform=systrap` (`cathedral/tee_box/executor.py:682-692`).
  - Each sandbox is one container that runs `sleep infinity`
    (`cathedral/tee_box/executor.py:733`). Exec, files and tar run inside it
    through `/bin/sh` scripts that take paths as positional arguments
    (`cathedral/tee_box/executor.py:535-542`). They run inside because
    gVisor's in-sandbox overlay hides writes from the host. Images therefore
    need `sh`, `sleep`, `cat`, `stat` and `tar`, as Harbor's own upload
    fallback already assumes.
  - **Orphan cleanup by label.** Before `docker run`, every container gets
    a deterministic name (`cathsbx-<sandbox id>`), the box label
    `org.cathedral.tee-box.box=<box id>` and its sandbox label
    (`cathedral/tee_box/executor.py:39-41`).
    - A create that fails is removed by name. A create that times out is
      also kept pending cleanup for 300 s, since the daemon may still start
      it (`cathedral/tee_box/executor.py:921`).
    - `sweep` (`cathedral/tee_box/executor.py:1129`) lists the box's
      containers with `docker ps --filter label=...`. It removes every one
      the table does not track, except creates still in flight, and
      reports what it could not confirm gone.
    - The drain and the reaper both sweep. No new customer is leased the
      box until a sweep confirms that none of the box's containers remain
      and none are pending cleanup. This holds after a worker restart too
      (see the drain guarantee below).
  - **Background exec bounds.** Background exec records, running or
    finished, are capped at 16 per sandbox and 32 per box
    (`cathedral/tee_box/executor.py:34-38`). With at most 1 MiB kept per
    output stream, the box retains at most 64 MiB of exec output.
    - The cap check and the slot reservation are one step under the lock.
    - A finished record is evicted 60 s after its result is first read, or
      600 s after it finished if never read. At a cap, the oldest finished
      record goes first (`cathedral/tee_box/executor.py:1209`).
  - **Uploads.** An upload's stdin is written from its own thread
    (`cathedral/tee_box/executor.py:438`). A target that never reads, such
    as a FIFO, times out and is killed under the transfer timeout. The
    write script also refuses an existing target that is not a regular file
    with `409` (`cathedral/tee_box/executor.py:1313`).
- **Egress policy** (`cathedral/tee_box/egress.py`). `build_egress_policy`
  (`cathedral/tee_box/egress.py:208`) returns the deny list and a
  per-sandbox bandwidth cap (default 100 Mbit/s). The deny list has three
  parts:
  - IPv4 (`cathedral/tee_box/egress.py:30`): "this network", RFC 1918, CGNAT
    100.64/10, loopback, link-local 169.254/16, the IETF, TEST-NET and
    benchmarking blocks, the 6to4 relay block, multicast and 240/4;
  - IPv6 (`cathedral/tee_box/egress.py:47`): unspecified, loopback,
    IPv4-mapped, NAT64, discard, Teredo, documentation, 6to4, ULA,
    link-local, site-local and multicast;
  - cloud metadata, listed on its own (`cathedral/tee_box/egress.py:65`):
    169.254.169.254, 169.254.170.2, 100.100.100.200, Azure WireServer
    168.63.129.16, 192.0.0.192 and fd00:ec2::254.

  The box's own addresses are required and are added to the deny list
  (`cathedral/tee_box/egress.py:240`).

  The policy renders two things as text, which the T6b1 enforcer applies
  (see "Egress enforcement" below):
  - an `nft` ruleset (`cathedral/tee_box/egress.py:102`) that drops
    forwarded packets from the sandbox bridge to denied ranges, and every
    packet from the bridge to the box itself;
  - `tc` argv lists for one sandbox's veth (`cathedral/tee_box/egress.py:139`).

  `deny_all` maps to `--network none`, and `internet` maps to the sandbox
  bridge.
- **Customer lease** (`cathedral/tee_box/lease.py:57`). One control-plane
  caller key holds the box at a time.
  - A lease lasts 60 s to 24 h and can be renewed.
  - Every other caller gets `409` with reason `box_busy`. A caller with no
    lease gets `409` with reason `lease_required`.
  - **Drain guarantee.** Release or expiry
    (`cathedral/tee_box/lease.py:95`) ends the lease and drains it
    (`cathedral/tee_box/service.py:342`). The drain deletes the customer's
    sandboxes and then sweeps every untracked box container. It succeeds
    only when none of the customer's sandboxes is still listed and the sweep
    reports nothing left.
  - Until the drain succeeds, the box is **draining**. Every lease request
    and every sandbox call, from the old customer or a new one, gets `409`
    with reason `box_draining` (`cathedral/tee_box/lease.py:159`).
  - The drain runs outside the lease lock, because the box is already
    marked draining (`cathedral/tee_box/lease.py:102`). A slow container
    daemon therefore holds up only the call that runs the drain.
  - Ordinary calls retry the drain at most every 2 s. The reaper retries it
    on every tick (`cathedral/tee_box/service.py:383`).
  - **A worker starts draining** (`cathedral/tee_box/lease.py:91`). A new
    process does not know what an earlier one left running. So no customer
    is leased the box until the first sweep reports that none of the box's
    labelled containers remain and none are pending cleanup. A restart
    therefore cannot skip a stuck drain.
  - **Stuck draining.** While the container daemon is down, or a container
    cannot be removed, the sweep never comes back clean. The box stays
    draining and refuses every caller. The operator should:
    1. list the leftovers with
       `docker ps --all --filter label=org.cathedral.tee-box.box=<box id>`;
    2. fix the daemon, or remove the container by hand with
       `docker rm --force <name>`.

    The box clears on the next sweep, within about 5 s.
  - A delete in `RunscExecutor` runs `docker rm --force`, then
    `docker kill --signal KILL`, then `rm` again. It counts as done only
    when `rm` succeeds or the daemon reports the container missing
    (`cathedral/tee_box/executor.py:905`).
  - A create holds the lease lock, so a drain cannot miss it
    (`cathedral/tee_box/service.py:638-639`).
  - A worker thread runs every 5 s, and once at start
    (`cathedral/worker.py:1342`). It checks expiry, retries the drain, and
    sweeps orphans.
- **API** (`cathedral/tee_box/service.py:308`). The routes are listed in
  `cathedral/tee_box/service.py:77`. Only `GET /v1/box` and the lease routes
  run without a lease (`cathedral/tee_box/service.py:448`).

| Call | Route |
|---|---|
| Box contract | `GET /v1/box` |
| Lease | `GET`, `POST` (`ttl_seconds`), `DELETE /v1/lease` |
| Image import | `POST /v1/images/import` (`digest`, `reference`), `GET /v1/images/{digest}` |
| Create, list | `POST /v1/sandboxes` (`image_id`, `network`, `lifetime_seconds`, optional `shape`, `labels`, `env`), `GET /v1/sandboxes?label=k=v` |
| Get, delete | `GET`, `DELETE /v1/sandboxes/{id}` |
| Lifetime | `POST .../lifetime` (`extend_by_seconds` or `lifetime_seconds`) |
| Exec | `POST .../exec` (up to 45 s); `POST .../execs` or `.../processes`, then `GET .../execs/{exec_id}?wait=N` and `DELETE` |
| Files | `PUT`/`GET .../files?path=&mode=`, `PUT`/`GET .../tar?path=&exclude=`, `GET .../stat?path=` |

v1 has no snapshot, fork, port or Docker-in-Docker routes.

Every sandbox reports `"hardware": "standard"`
(`cathedral/tee_box/service.py:418`). Exec takes `env`, `user`, `cwd` and
`timeout_seconds`. Background execs may run up to 14,400 s
(`cathedral/tee_box/service.py:60-61`).

A create is admitted only while the sum of sandbox shapes fits the configured
capacity. Otherwise it gets `409` with reason `box_capacity_full`
(`cathedral/tee_box/service.py:644`), the reason Harbor already waits on.

`GET /v1/box` lists the network modes the box offers now, and its `egress`
object says whether the egress rules are enforced, with the last error
(`cathedral/tee_box/service.py:509`).

## Caller authorization

Callers use the validator-access code, with no new cryptography.

- **Snapshot.** The caller snapshot is a signed
  `cathedral_validator_access_snapshot_v1`. Its rows are the control-plane
  hotkeys, with permit `true` and stake 0. It carries the network label
  `cathedral-control-plane` and a zero stake floor. It is loaded by
  `caller_snapshot_provider` (`cathedral/tee_box/service.py:152`) through
  `SignedValidatorSnapshotProvider`. A validator snapshot cannot stand in for
  it, and the reverse holds too: the authorizer refuses any other network
  label (`cathedral/tee_box/service.py:196`).
- **Requests.** Requests carry the validator request envelope in
  `X-Cathedral-Validator-Request`.
  - `ValidatorRequestAuthorizer` and `build_validator_request_header` gained
    a `target_allowed` check (`cathedral/validator_access.py:164`, `:1609`).
    It defaults to the validator routes.
  - The sandbox API passes `sandbox_target_allowed`
    (`cathedral/tee_box/service.py:133`). The signed `path` is the full
    target, query included, so the signature covers file paths.
- **Worker.** The worker verifies the envelope before it reserves a slot or
  reads the body (`cathedral/worker.py:442`). After the body is read, it
  checks the body digest and replay (`cathedral/worker.py:458`).
- **Refusals.** Each of these gets `401`: a request with no header, a key not
  in the snapshot, a stale snapshot, an expired or replayed request, another
  network label, a signature over a different target or body, and an unknown
  route.

## How to enable it (T6b1)

`cathedral worker serve` (TDX) and `cathedral worker serve-snp` take the TEE
box flags (`cathedral/tee_box/configure.py:80`, registered at
`cathedral/cli.py:4410` and `:4434`). The development, migration and GPU
commands do not offer them.

| Flag | Required | Meaning |
|---|---|---|
| `--tee-box-caller-snapshot` | yes | signed caller snapshot (label `cathedral-control-plane`) |
| `--tee-box-caller-keys`, `--tee-box-caller-keys-digest` | yes | trusted Ed25519 keys and their sha256 pin |
| `--tee-box-caller-state` | yes | owner-only SQLite replay state, separate from validator access |
| `--tee-box-executor runsc` | yes | the only executor |
| `--tee-box-capacity V,M,D` | yes | vCPUs, memory MiB and disk MiB for all sandboxes together |
| `--tee-box-default-shape V,M,D` | yes | shape of a sandbox created without one; must fit the capacity |
| `--tee-box-address IP` (repeat) or `--tee-box-detect-addresses` | exactly one | the box's own addresses, denied to sandboxes |
| `--tee-box-bandwidth-mbit` | no (100) | per-sandbox cap |
| `--tee-box-docker-path` | no (`/usr/bin/docker`) | docker CLI in the guest |
| `--tee-box-runtime`, `--tee-box-runtime-path` | no (`runsc`, `/usr/local/bin/runsc`) | the daemon's runtime entry |
| `--tee-box-caller-max-age-seconds` | no (3600) | caller snapshot freshness |
| `--tee-box-id` | no (`default`) | container label for this box |
| `--tee-box-no-disk-quota` | no | run without per-sandbox disk quotas |

- **All or nothing.** With no TEE box flag, the worker passes no API and
  serves no sandbox routes. Giving any flag, even an optional one, requires
  every required flag and one address source, or the worker refuses to
  start (`cathedral/tee_box/configure.py:167`, called at
  `cathedral/cli.py:1382`).
- **Attested TLS only.** The flags need `--tls-certificate` and
  `--tls-private-key` (`cathedral/cli.py:1388`). The API then binds the
  worker's TLS key and hotkey, the key REPORT_DATA binds (design section 3);
  `WorkerServer` checks this again (`cathedral/worker.py:1249-1261`).
- **Detected addresses** are every address in `ip -json address show`,
  plus the `--public-endpoint` host when it is an IP literal. On a cloud
  guest behind 1:1 NAT the public address is not on an interface, so pass
  it with `--tee-box-address` instead.
- **Startup refuses** (`cathedral/tee_box/configure.py:245`) when the caller
  snapshot is absent or stale (`:288`), when the daemon does not register
  the runtime at the runtime path with `--platform=systrap` (`:314`), or
  when disk quotas are unsupported without `--tee-box-no-disk-quota`
  (`:317`).
- **Startup does not refuse** when the egress rules fail to apply
  (`:326`). The box then serves `deny_all` only, and the startup line's
  `tee_box.egress` field reports the error. The egress thread re-applies
  every 60 s, and reads an applied table back every 5 s.

The guest must also provide: a Docker daemon with the runsc runtime entry
(`daemon_runtime_config`, `cathedral/tee_box/executor.py:682`), the docker
CLI, `nft`, `tc`, `ip` and `nsenter` at `/usr/sbin/nft`, `/usr/sbin/tc`,
`/usr/sbin/ip` and `/usr/bin/nsenter`, and the privileges to use them. No
shipped image provides all of that yet (see "Packaging").

The sandbox routes have their own request pool of 8
(`cathedral/worker.py:80`). Request bodies may be up to 8 MiB, under the
worker's request deadline.

## Egress enforcement (T6b1)

`EgressEnforcer` (`cathedral/tee_box/enforce.py:302`) applies the policy
inside the confidential VM. Every command is an argv list with no shell and
a 15 s timeout.

- **Attachment point.** Every `internet` sandbox joins one dedicated Docker
  bridge network. The network and its Linux bridge share one name,
  `cathsbx0`, so `docker run --network cathsbx0` and the nft `iifname` match
  name the same thing. The enforcer creates it with
  `com.docker.network.bridge.name=cathsbx0` and
  `com.docker.network.bridge.enable_icc=false`, and refuses an existing
  network with other settings (`cathedral/tee_box/enforce.py:474`).
- **The table.** `apply` (`cathedral/tee_box/enforce.py:498`) replaces
  `inet cathedral_tee_box_egress` in one `nft -f -` transaction. `verify`
  (`cathedral/tee_box/enforce.py:529`) reads it back with
  `nft --json list table` and compares the parsed sets, chains and rules
  with the policy: the same collapsed deny ranges, hooks, priorities and
  rules, and nothing else (`table_matches`,
  `cathedral/tee_box/enforce.py:224`). The executor verifies again before
  every `internet` create (`cathedral/tee_box/executor.py:934`).
- **Per-sandbox cap.** `attach` (`cathedral/tee_box/enforce.py:698`) finds
  the sandbox's host-side veth from its network namespace: Docker's
  `SandboxKey`, then `eth0@ifN` inside it through `nsenter`, then the
  `cathsbx0` port with index N (`find_veth`,
  `cathedral/tee_box/enforce.py:632`). It applies the `tc` commands and
  reads them back: the root `tbf` rate, the ingress qdisc, and the matchall
  policer's rate and drop action. `detach`
  (`cathedral/tee_box/enforce.py:717`) deletes both qdiscs, and runs only
  after `docker rm` has confirmed the container gone
  (`cathedral/tee_box/executor.py:995`). A remove that fails or times out
  leaves the sandbox running with its cap in place; the orphan sweep also
  detaches only what it confirmed removed. It treats a veth already gone as
  removed.
- **Re-checked on its own thread.** The worker runs the egress check on a
  thread of its own (`cathedral/worker.py:1356`), apart from the reaper, whose
  expiry deletes and drain wait on docker. It starts a check every 5 s
  (`cathedral/worker.py:84`), or at once if the last one overran. Each
  check runs `check_egress` (`cathedral/tee_box/executor.py:1002`), which
  calls `maintain` (`cathedral/tee_box/enforce.py:548`): one
  `nft --json list table` read-back while the table is active, bounded by
  the enforcer's 15 s command timeout, with no docker call.
- **A lapse ends running internet sandboxes.** When a read-back fails (for
  example after `nft flush ruleset` from an nftables reload), enforcement
  turns off at once and the enforcer counts a lapse. A lapse can be found
  by the egress check, by a create's read-back before `docker run`, or by
  `attach`'s read-back after it. In every case `end_lapsed_sandboxes`
  (`cathedral/tee_box/executor.py:1021`) runs before any re-apply (which
  calls docker): the egress check calls it first on every tick
  (`cathedral/tee_box/executor.py:1002`), and both create paths call it
  when they refuse. It marks every `internet` sandbox that was running,
  cuts the bridge off, and starts removing those sandboxes, as a delete
  does, even when the re-apply then succeeds: they ran unprotected for an
  unknown time.
  - **Calls refused.** From that moment every call on a marked sandbox
    (exec, processes, files, tar, stat, lifetime) gets `409` with reason
    `sandbox_network_lapsed` (`cathedral/tee_box/executor.py:1108`). Get,
    list and delete still work.
  - **Bridge quarantined.** `quarantine`
    (`cathedral/tee_box/enforce.py:592`) installs a separate nft table,
    `inet cathedral_tee_box_lapse`, that drops every packet to or from
    `cathsbx0`. It is one `nft -f` call (15 s timeout) with no docker, and
    it does not depend on the egress table that just lapsed. It is
    re-installed on every check while any marked sandbox remains, in case it
    was flushed too, and removed once none is left. While it is in place
    the box offers no `internet` mode and refuses `internet` creates.
    `/v1/box` reports a quarantine that fails to install. Marking a
    sandbox, deciding to install or lift the quarantine, and the nft call
    itself run under one lock, so a lapse found by a create cannot be
    undone by a lift the egress thread had already decided on.
  - **Left by an earlier run.** If the worker stops during a lapse, the
    quarantine table stays in the kernel. `apply` (at startup and on every
    re-apply) adopts it: the box reports not enforced, with the reason, and
    offers no `internet` mode. It is lifted only after the orphan sweep
    comes back clean, since the earlier run's sandboxes may still be
    running until then.
  - **Removal.** Removals run on their own threads, at most 4 at once.
    Each docker call has a 15 s timeout, so one removal takes at most about
    60 s (four docker calls) plus 30 s for the two `tc` deletes. With up to
    64 sandboxes and docker hanging on every call, the last removal can end
    about 16 x 90 s, some 24 minutes, after detection. A removal that
    fails is retried on the next check, and `/v1/box` reports it as the
    egress error.
  - Removal was chosen over `docker network disconnect` because it does
    not depend on how runsc treats an interface that disappears under it.
    A successful re-apply lets new `internet` sandboxes start only after
    the quarantine is lifted; it never brings back the removed ones, whose
    callers then get `404`.
  - **Bound.** A change to the table is detected within one check interval
    plus two read-back timeouts (5 s + 2 x 15 s = 35 s) when nft hangs; when
    nft answers promptly, within about 5 s. From detection, calls on the
    affected sandboxes are refused (`409`), and the quarantine cuts their
    traffic within one more nft call (at most 15 s). Only if nft itself
    fails do processes already running in them keep the network until
    their containers are removed (the removal bound above). So an
    `internet` sandbox serves calls only while its cap verified at create
    and every read-back of the table since has matched.
- **Fail closed.** Until apply and verify succeed, and after any later
  verify fails, `active` is false and `status()` carries the error.
  `RunscExecutor` then offers `deny_all` only
  (`cathedral/tee_box/executor.py:656`) and refuses `internet` with `409`
  before `docker run`. After `docker run`, a sandbox whose cap fails to
  apply or verify is removed at once (`cathedral/tee_box/executor.py:955`).
- **Injection safety.** Box addresses reach nft only as `ipaddress`
  objects. Detection parses every value with `ipaddress` and refuses the
  whole listing on any other value (`cathedral/tee_box/enforce.py:108`).
  The enforcer refuses a policy holding anything else
  (`cathedral/tee_box/enforce.py:90`). Interface names must match a strict
  pattern.
- **Tests.** `tests/test_tee_box_enforce.py` mocks every command for apply,
  verify, failure and teardown. When the host allows unprivileged user and
  network namespaces, it also runs the real `nft`, `tc`, `ip` and `nsenter`
  against a bridge and veth, so the read-back parsers are checked against
  real output.

## Exec timeouts (T6b1)

A customer exec runs through a wrapper that writes its pid to
`/tmp/.cathedral-exec-<random>.pid` inside the sandbox and then execs the
command in place (`cathedral/tee_box/executor.py:546`). When a sync or
background exec times out, or a background exec is stopped, the executor
first runs a kill script as root in the sandbox
(`cathedral/tee_box/executor.py:551`, `:1175`). The script stops the
recorded process and every descendant it finds in `/proc`, repeating until
no new one appears, and then kills them all. Only then is the host-side
`docker exec` client killed. The kill has its own 30 s timeout.

Limits: a command run as a user who cannot write `/tmp` has no pid file,
so only its client is killed. A process that leaves the tree (a daemon that
double-forks) survives until the sandbox is deleted.

## Disk quota (T6b1)

Each container gets `--storage-opt size=<disk_mib>m`
(`cathedral/tee_box/executor.py:722`). Docker supports this on btrfs, zfs,
devicemapper, and overlay2 on xfs mounted with `pquota`. At startup the
worker reads the storage driver from `docker info`
(`cathedral/tee_box/executor.py:862`) and refuses to start on any other
driver unless the operator passes `--tee-box-no-disk-quota`. Docker checks
`pquota` only when a container starts, so on xfs without it every create
fails; creates never run unbounded.

## Packaging (T6b1)

`Dockerfile.tee-box-runsc` is a separate, opt-in build. It takes an SN39
TDX or SNP miner image pinned by digest (`MINER_IMAGE`, no default) and adds
gVisor `runsc` from release `20260817.0`, the last weekly release that
publishes runsc as a single binary. The build fetches it from Google's
release bucket and refuses any file whose sha256 differs from the pinned
one. `tests/test_tee_box_packaging.py` checks the pins.

The production `Dockerfile.sn39-audit-miner` and `Dockerfile.sn39-snp-miner`,
their publishers and their runtime contracts are unchanged. Adding runsc to
them before T6b2 qualification would change every miner's measured image for
a feature no miner can use yet. The runtime also has to sit with the Docker
daemon that runs it, which the miner container does not hold, so the layer
does not yet make a miner container a working box. The measured appliance
image (design plan step 2) is where runsc, the daemon and the host tools
belong.

## Not done (T6b2 and later)

- **Hardware qualification.** Nothing has run on real TDX or SNP guests:
  not runsc with systrap under a TD or an SNP guest, not gVisor's
  overhead (system-call-heavy work pays most), capacity sizing, or the
  guest reserve.
- **Live egress check.** The enforcer has run against real `nft` and `tc`
  in a network namespace, but not on a box: T6b2 must show from inside a
  runsc sandbox that denied ranges, metadata and the box's own addresses
  are unreachable, that the public internet works, and that the cap holds.
  It must also show that Docker's `SandboxKey` and `eth0` hold for runsc
  with `--network=sandbox`, and qualify DNS from inside gVisor on the
  user-defined bridge.
- **Lapse drill.** On a box, flush the ruleset under a running `internet`
  sandbox and show the lapse path end to end: detection within the bound,
  `409` on calls, the quarantine cutting the sandbox's traffic at once, and
  the removal.
- **Image measurement.** No measured image ships runsc, the daemon runtime
  entry, the host tools and the worker together. The opt-in layer is not
  measured or published. Measurement approval follows the design's plan
  steps 2 to 7.
- **Disk quota under runsc.** Confirm that runsc's root overlay counts
  against the `--storage-opt` quota on the qualified storage driver.
- **State across restarts.** The executor tables live in memory. A
  restarted worker forgets its sandboxes and leases, and starts draining.
  Its sweep removes every container with the box label, so an earlier
  customer's sandboxes end rather than being adopted. The box is leasable
  only once that sweep comes back clean.

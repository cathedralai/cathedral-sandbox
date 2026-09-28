# TEE box sandbox service (T6a)

Status: library code and tests only, **off by default**. Nothing here has run
on TDX or SEV-SNP hardware, and no operator command enables it yet. The
design is `TEE_BOX.md` on PR #236, branch `docs/tee-box-design` (sections 2
to 4 and "Owner decisions for v1"). Citations are `file:line` in this repository.

## What T6a adds

`cathedral/tee_box/` holds four parts.

- **Executor protocol** (`cathedral/tee_box/executor.py:161-184`): image
  import by digest, create from an image with a shape, get, list, expiry,
  delete, sync exec, background exec with poll and stop, and file read,
  write, stat and tar.
  - `FakeExecutor` (`cathedral/tee_box/executor.py:234`) keeps everything in
    memory for tests.
  - `RunscExecutor` (`cathedral/tee_box/executor.py:502`) drives
    `docker run --runtime=runsc`. It builds argv lists only, with no host
    shell (`_check_argv`, `cathedral/tee_box/executor.py:374`), and caps every
    captured output. The Docker daemon must register runsc with
    `--platform=systrap` (`cathedral/tee_box/executor.py:570-580`).
  - Each sandbox is one container that runs `sleep infinity`
    (`cathedral/tee_box/executor.py:617`). Exec, files and tar run inside it
    through `/bin/sh` scripts that take paths as positional arguments
    (`cathedral/tee_box/executor.py:492-499`). They run inside because
    gVisor's in-sandbox overlay hides writes from the host. Images therefore
    need `sh`, `sleep`, `cat`, `stat` and `tar`, as Harbor's own upload
    fallback already assumes.
  - **Orphan cleanup by label.** Before `docker run`, every container gets
    a deterministic name (`cathsbx-<sandbox id>`), the box label
    `org.cathedral.tee-box.box=<box id>` and its sandbox label
    (`cathedral/tee_box/executor.py:39`).
    - A create that fails is removed by name. A create that times out is
      also kept pending cleanup for 300 s, since the daemon may still start
      it (`cathedral/tee_box/executor.py:731`).
    - `sweep` (`cathedral/tee_box/executor.py:784`) lists the box's
      containers with `docker ps --filter label=...`. It removes every one
      the table does not track, except creates still in flight, and
      reports what it could not confirm gone.
    - The drain and the reaper both sweep, so no container survives a
      hand-over or a worker restart.
  - **Background exec bounds.** Background exec records, running or
    finished, are capped at 16 per sandbox and 32 per box
    (`cathedral/tee_box/executor.py:33-37`). With at most 1 MiB kept per
    output stream, the box retains at most 64 MiB of exec output.
    - The cap check and the slot reservation are one step under the lock.
    - A finished record is evicted 60 s after its result is first read, or
      600 s after it finished if never read. At a cap, the oldest finished
      record goes first (`cathedral/tee_box/executor.py:833`).
  - **Uploads.** An upload's stdin is written from its own thread
    (`cathedral/tee_box/executor.py:396`). A target that never reads, such
    as a FIFO, times out and is killed under the transfer timeout. The
    write script also refuses an existing target that is not a regular file
    with `409` (`cathedral/tee_box/executor.py:935`).
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

  The policy renders two things as text. Nothing applies them:
  - an `nft` ruleset (`cathedral/tee_box/egress.py:102`) that drops
    forwarded packets from the sandbox bridge to denied ranges, and every
    packet from the bridge to the box itself;
  - `tc` argv lists for one sandbox's veth (`cathedral/tee_box/egress.py:139`).

  `deny_all` maps to `--network none`, and `internet` maps to the sandbox
  bridge.
- **Customer lease** (`cathedral/tee_box/lease.py:51`). One control-plane
  caller key holds the box at a time.
  - A lease lasts 60 s to 24 h and can be renewed.
  - Every other caller gets `409` with reason `box_busy`. A caller with no
    lease gets `409` with reason `lease_required`.
  - **Drain guarantee.** Release or expiry
    (`cathedral/tee_box/lease.py:82`) ends the lease and drains it
    (`cathedral/tee_box/service.py:341`). The drain deletes the customer's
    sandboxes and then sweeps every untracked box container. It succeeds
    only when none of the customer's sandboxes is still listed and the sweep
    reports nothing left.
  - Until the drain succeeds, the box is **draining**. Every lease request
    and every sandbox call, from the old customer or a new one, gets `409`
    with reason `box_draining` (`cathedral/tee_box/lease.py:115`). The drain
    is retried on every call and by the reaper.
  - A delete in `RunscExecutor` runs `docker rm --force`, then
    `docker kill --signal KILL`, then `rm` again. It counts as done only
    when `rm` succeeds or the daemon reports the container missing
    (`cathedral/tee_box/executor.py:719`).
  - A create holds the lease lock, so a drain cannot miss it
    (`cathedral/tee_box/service.py:604-605`).
  - A worker thread runs every 5 s, and once at start
    (`cathedral/worker.py:1339`). It checks expiry, retries the drain, and
    sweeps orphans.
- **API** (`cathedral/tee_box/service.py:307`). The routes are listed in
  `cathedral/tee_box/service.py:76`. Only `GET /v1/box` and the lease routes
  run without a lease (`cathedral/tee_box/service.py:432`).

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
(`cathedral/tee_box/service.py:401`). Exec takes `env`, `user`, `cwd` and
`timeout_seconds`. Background execs may run up to 14,400 s
(`cathedral/tee_box/service.py:59-60`).

A create is admitted only while the sum of sandbox shapes fits the configured
capacity. Otherwise it gets `409` with reason `box_capacity_full`
(`cathedral/tee_box/service.py:610`), the reason Harbor already waits on.

## Caller authorization

Callers use the validator-access code, with no new cryptography.

- **Snapshot.** The caller snapshot is a signed
  `cathedral_validator_access_snapshot_v1`. Its rows are the control-plane
  hotkeys, with permit `true` and stake 0. It carries the network label
  `cathedral-control-plane` and a zero stake floor. It is loaded by
  `caller_snapshot_provider` (`cathedral/tee_box/service.py:151`) through
  `SignedValidatorSnapshotProvider`. A validator snapshot cannot stand in for
  it, and the reverse holds too: the authorizer refuses any other network
  label (`cathedral/tee_box/service.py:195`).
- **Requests.** Requests carry the validator request envelope in
  `X-Cathedral-Validator-Request`.
  - `ValidatorRequestAuthorizer` and `build_validator_request_header` gained
    a `target_allowed` check (`cathedral/validator_access.py:164`, `:1609`).
    It defaults to the validator routes.
  - The sandbox API passes `sandbox_target_allowed`
    (`cathedral/tee_box/service.py:132`). The signed `path` is the full
    target, query included, so the signature covers file paths.
- **Worker.** The worker verifies the envelope before it reserves a slot or
  reads the body (`cathedral/worker.py:439`). After the body is read, it
  checks the body digest and replay (`cathedral/worker.py:455`).
- **Refusals.** Each of these gets `401`: a request with no header, a key not
  in the snapshot, a stale snapshot, an expired or replayed request, another
  network label, a signature over a different target or body, and an unknown
  route.

## How to enable it (library only)

Pass a `TeeBoxSandboxApi` as `WorkerServer(tee_box_api=...)`. Without it, the
worker has no sandbox routes and no `GET`, `PUT` or `DELETE` handlers
(`cathedral/worker.py:919-923`). The API needs the worker's native TLS, and
its caller authorizer must bind the same TLS key and hotkey
(`cathedral/worker.py:1246-1258`). That makes the sandbox API's key the one
REPORT_DATA binds (design section 3).

```python
state = ValidatorAccessState("/var/lib/cathedral/tee-box-callers.sqlite")
provider = caller_snapshot_provider(snapshot_path, trusted_keys, netuid=netuid, state=state)
authorizer = caller_authorizer(provider, worker_hotkey=hotkey,
                               channel_binding=channel_binding, state=state)
egress = build_egress_policy([public_ip])
api = TeeBoxSandboxApi(executor=RunscExecutor(egress), authorizer=authorizer, egress=egress,
                       capacity=Shape(60, 480_000, 2_000_000), default_shape=Shape(2, 4096, 10240))
WorkerServer(host, port, configured_hotkey=hotkey, channel_binding=channel_binding,
             tls_context=tls_context, tee_box_api=api, ...)
```

The sandbox routes have their own request pool of 8
(`cathedral/worker.py:80`). Request bodies may be up to 8 MiB, under the
worker's request deadline.

## Not done (T6b and later)

- **No operator flag yet.** `cathedral worker` has no flag for this, and no
  entrypoint builds the API. T6b adds the flags (caller snapshot, keys,
  state, box addresses, capacity).
- **Image packaging.** No image ships `runsc`, the Docker daemon runtime
  entry, or the executor. The measured appliance image is design plan step 2.
- **Hardware qualification.** Nothing has run on real TDX or SNP guests:
  not systrap under a TD, gVisor overhead, capacity sizing, or the guest
  reserve.
- **Live egress enforcement.** The nft ruleset and `tc` commands are
  rendered, never applied. `RunscExecutor` therefore refuses `internet`
  sandboxes (`cathedral/tee_box/executor.py:741`) unless it is given an
  `egress_enforcer` that applies both for each new container. T6b writes
  that enforcer and qualifies DNS from inside gVisor.
- **Exec timeouts.** A sync exec that times out kills the `docker exec`
  client, but the process in the sandbox keeps running until the sandbox is
  deleted (`cathedral/tee_box/executor.py:816`). T6b should use
  `runsc exec` and `runsc kill`.
- **Disk quota.** It is not enforced. The disk shape counts only toward
  admission.
- **State across restarts.** The executor tables live in memory. A
  restarted worker forgets its sandboxes and leases. Its first sweep removes
  every container with the box label, so an earlier customer's sandboxes
  end rather than being adopted.

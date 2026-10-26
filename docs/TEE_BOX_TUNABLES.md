# TEE box start-up tunables

`--tee-box-tunables PATH` names a JSON settings file that changes how fast a sandbox
starts and nothing about what a sandbox may do. No file, or `{"schema": 1}`, is today's
behaviour exactly (a test compares the daemon config and the `docker run` argv).

Machine-readable schema: [`tee_box_tunables.schema.json`](tee_box_tunables.schema.json),
generated from `cathedral/tee_box/tunables.py` and checked by a test. The file is
at most 4096 bytes; unknown keys, wrong types, out-of-range values, duplicate keys and
floats are refused when the worker starts.

| key | values | default | applied by |
|---|---|---|---|
| `runsc.directfs` | true, false | true | daemon `runtimeArgs` `--directfs=` (only when not the default) |
| `runsc.overlay2` | `root:self`, `all:self` | `root:self` | daemon `runtimeArgs` `--overlay2=` |
| `runsc.net_channels` | 1 to 4 | 1 | daemon `runtimeArgs` `--num-network-channels=` |
| `docker.log_driver` | `json-file`, `local`, `none` | `json-file` | `docker run --log-driver` |
| `image.prime` | `none`, `page_cache` | `none` | after `import_image`: `docker save --output /dev/null <image id>` (best effort) |
| `pool.warm_size` | 0 to 16 | 0 | warm pool size for the most recently imported image |
| `pool.refill_parallelism` | 1 to 4 | 1 | warm containers started at once per refill |
| `pool.idle_seconds` | 30 to 900 | 300 | an unclaimed warm container is removed and replaced after this |
| `boot.create_concurrency` | 1 to 16 | 1 | creates that run at the same time |

runsc flag names and values were checked against gVisor release-20260817.0
(`runsc/config/flags.go`, `runsc/config/config.go`): `--directfs` (bool, default true),
`--overlay2={root|all}:{self|memory}` (default `root:self`), `--num-network-channels`
(int, default 1). `root:memory` is not offered because it would move sandbox writes out
of the per-sandbox disk cap.

## Verbs

Both need the scope `tee-box:tunables`. Errors are `{"error": ..., "reason": ...}`.

### `tunables.get`: `GET /v1/box/tunables`

No lease needed. Answer 200:

```json
{"sha256": "<64 hex>", "source": "default", "applied_at": null,
 "values": {"schema": 1, "runsc": {...}, "docker": {...}, "image": {...}, "pool": {...}, "boot": {...}},
 "daemon_reload": false, "daemon_confirmed": true}
```

- `sha256` is `Tunables.sha256`: sha256 of the canonical JSON of the normalised document
  (every key, defaults filled in, sorted keys, no spaces). Two documents that mean the
  same tunables have the same sha, however they are spelled. The challenge package
  computes it with the same code.
- `source`: `default` (no `--tee-box-tunables`), `file` (the start-up file) or `applied`
  (the last `tunables.apply`). A worker restart goes back to the start-up file.
- `daemon_reload`: the worker has `--tee-box-daemon-json`, so a runsc change can apply.
- `daemon_confirmed`: false only after a failed reload whose rollback also failed; the
  daemon's runsc flags are then unknown until the next confirmed reload or restart.

### `tunables.apply`: `POST /v1/box/tunables`

Needs the lease. The body is a tunables document, the same JSON as the start-up file
(at most 4096 bytes). It is validated by the same code: unknown keys, pinned settings,
wrong types, out-of-range values, duplicate keys and floats are `400`. Answer 200: the
`tunables.get` view plus `previous_sha256`, `changed` and `reloaded`.

What it does:

- Running sandboxes are never touched. Every tunable acts only when a container starts
  or an image is imported, so a change reaches the next create.
- Applying the document already in force changes nothing (`changed: false`).
- `docker.log_driver`, `image.prime`, `pool.*` and `boot.create_concurrency` apply in
  memory: about 0.06 ms per apply through the service on the fake executor, one-off
  measurement of 100 applies (the test applies king and challenger
  50 times each with a sandbox live in under 5 s total). When the start arguments change,
  warm containers are removed so a warm start never differs from a cold one; the reaper
  refills the pool on its next tick. A smaller pool drops its extras at once.
- `runsc.*` flags are Docker daemon `runtimeArgs`, not `docker run` flags. Changing them
  rewrites the runsc entry of `daemon.json` (every other key kept) and runs
  `systemctl reload docker` (SIGHUP: dockerd re-reads `runtimes`, it does not restart).
  The new flags must then show in `docker info`, or the old file is put back and
  reloaded. This needs `--tee-box-daemon-json PATH`; without it the change is `409
  runsc_change_needs_restart`. Because a reload must never meet a live room, it is
  `409 sandboxes_live` while any sandbox exists (warm containers are removed first). A
  failed reload is `503 daemon_reload_failed` and the box keeps its previous tunables.
- `409 creates_in_flight` while a create is past admission. Apply between bursts.
- With `--tee-box-daemon-json`, a worker start whose daemon flags differ from the
  start-up file (for example after an apply and a restart) writes the file's flags back
  before the runtime check.

For the capacity executor this means: alternate king and challenger freely while rooms
are live when the two documents differ only outside `runsc.*`. When they differ in
`runsc.*`, delete the burst's rooms before each apply.

## The runtime flags must match the daemon

The runsc flags live in the Docker daemon's `daemon.json`, which the operator owns. The
worker renders the expected entry (`RunscExecutor.daemon_runtime_config`) and
`runtime_check` refuses to start unless the daemon's tunable flags (`--directfs`,
`--overlay2`, `--num-network-channels`) are exactly those the settings file asks for.
A daemon edited by hand cannot silently disagree with what was approved.

## Warm pool

- Containers are started like any `deny_all` sandbox of the default shape, from the
  verified image id, with no env, and labelled `org.cathedral.tee-box.warm`.
- A create may take one only if it would be started identically: same imported image, the
  default shape, `deny_all`, no env. The container is renamed to `cathsbx-<sandbox id>`;
  if the rename fails it is removed and the create starts cold.
- The pool exists only while a customer holds the lease. It is emptied at every
  hand-over (the drain) and never refilled during one, so no container outlives its lease.
- Warm and starting containers count against `--tee-box-capacity` and `MAX_SANDBOXES`.
  A create that would not fit evicts the oldest warm container first.
- `sweep` leaves warm containers alone and still removes every other untracked
  box-labelled container.

## Create concurrency

`service._create` used to hold the lease lock around `executor.create`. It now admits
and reserves under the lock (count and capacity, including warm and in-flight creates),
releases it, and runs the create under a semaphore of `boot.create_concurrency`. The
reservation is released only after the executor has recorded the sandbox. A drain waits
for every in-flight create before deleting, so none lands after a hand-over. With 1 the
creates still run one at a time.

## Not tunable

These are fixed in `executor.py` and a file that names any of them is refused as an
unknown key:

- runsc `--platform=systrap` and `--network=sandbox` (`RunscExecutor.runtime_check` refuses anything else)
- sandbox shape: `--cpus`, `--memory`, `--memory-swap`, `--pids-limit`, `--storage-opt size`
- `--security-opt no-new-privileges`, the network mode, DNS and the egress rules
- the image: imported by digest, started by local image id with `--pull never`
- the entrypoint (`sleep infinity`), labels, container naming and cleanup
- `MAX_SANDBOXES`, the lease, receipts, and the measured boot of the confidential VM (RTMR3)

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

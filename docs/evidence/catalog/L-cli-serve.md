# Catalog L: the hotel's `sandbox serve` path

Artifact: cathedral-sandbox PR #312 head, commit 887ed40, branch
fix/review-round-6, worktree ~/Documents/projects.nosync/cathedral-sandbox-pr308.
Scope: cathedral/cli.py `sandbox serve` only (cmd_sandbox_serve and what it
calls), cathedral/sandbox_runtime.py, cathedral/sandbox_fleet.py, the
serve-path parts of cathedral/sandbox_server.py, sandbox_provider.py,
sandbox_guest.py and sandbox_egress.py that the start, reaper and stop paths
run, room-kit/profiles/v1.sh, room-kit/room_api.py, and the systemd units
install.sh writes from the profile. Every other CLI command is out of scope.
Known items B1 to B132 are not repeated.

Probes (scratch files, all passed; superseded by tests/test_cli_serve_hardening.py):
probe_cli_serve_keystore (15), probe_cli_serve_startup (5), probe_cli_serve_stop (5).
Run from the worktree with .venv/bin/python -m pytest -q -p no:cacheprovider.

## 1. How a hotel runs it

Unit `$ROOM_ID.service` (install.sh 320-341): User=poolroom,
EnvironmentFile=api.env then secret.env, ExecStart from `profile_exec`:

    $ROOM_OPT/venv/bin/python $ROOM_OPT/bin/room_api.py sandbox serve
        --host 127.0.0.1 --port $ROOM_API_PORT --runtime docker

Restart=on-failure, no RestartSec (100 ms), no StartLimit*, no
TimeoutStopSec, no KillMode (control-group). systemd defaults apply: stop
budget 90 s, then SIGKILL; 5 restarts in 10 s then the unit fails.
Requires/After `$ROOM_ID-docker.service` (Type=notify, so dockerd is ready).
Caddy (443) and the receipts front (18092) forward to this port. A second
unit (`$ROOM_ID-reaper.timer`, 60 s) curls GET /v1/sandboxes with the key.

## 2. Start-up order (what runs before the listener binds)

1. room_api.py main (15-27): reads ROOM_CREATES_PER_MINUTE, patches
   `InMemorySandboxProvider.__init__.__kwdefaults__["creates_per_minute"]`,
   then imports cathedral.cli (heavy import: crypto, attest, lanes).
2. cli.main (6058-6068): parse args, call cmd_sandbox_serve; any Exception
   is printed sanitized as {"error": ...} on stderr, exit 2.
3. cmd_sandbox_serve (1714-1760), in order:
   a. build_sandbox_provider(runtime, allow_insecure_dev) (runtime 117-209):
      detect_runtime; fleet env; DockerGuestProvider.__init__ (guest
      1096-1180): DockerClient (DindConfig.from_env, may raise ValueError),
      RoomNetworkPool.from_env (no docker call), EgressClient.from_env (no
      socket check), _load_auth_pulled (HOME file), `docker info` (15 s
      timeout) via info_ok, kata probe (5 s) only for kata, `docker info`
      again for default_runtime (15 s), inner provider from
      provider_from_environment (keys, quota).
   b. SandboxApplication(provider, require_auth=True): route table.
   c. start_reaper(interval): a daemon thread that waits `interval` then
      calls provider.sweep(); the interval comes from --reaper-interval or
      CATHEDRAL_SANDBOX_REAPER_SECONDS (default 30).
   d. run(app, host, port) (server 1086-1100): ThreadingHTTPServer bind +
      listen(5). getfqdn(host) on bind (loopback: fast).
   e. print {"status":"serving", ..., "capabilities": status()}.
   f. install_stop_signal(): SIGTERM handler raises KeyboardInterrupt.
   g. serve_forever() until KeyboardInterrupt.
   h. finally: stop_reaper(join 10 s), httpd.shutdown(), httpd.server_close(),
      provider.close().
   Probe: test_successful_start_order_and_stop_order records exactly this.
   Before (f) a SIGTERM is the default action: the process dies with nothing
   to clean. A failure in (d) (port taken) escapes before any try/finally:
   the reaper thread is left running and provider.close() never runs
   (probe test_startup_order_and_what_a_bind_failure_leaves).

## 3. Second instance on the same port

ThreadingHTTPServer sets SO_REUSEADDR only (allow_reuse_port False). The
second bind raises OSError EADDRINUSE out of run(); main prints the error
and exits 2; the first instance is untouched. Before the bind the second
instance ran two `docker info` and started its reaper thread (daemon, dies
with the process). It leaves one empty `cathedral-sandbox-*` dir in TMPDIR
(provider.close() not reached). Under systemd this loops 5 times in 10 s
and the unit fails. Probe: test_second_instance_on_the_same_port_...

## 4. Environment variables the serve path reads

Legend for "wrong value": start = crash at start (exit 2, systemd restart
loop, unit failed after 5 tries); silent = ignored or default with no log;
runtime = a wrong limit or wrong behaviour while serving.

| Variable | Read at | Default | Kit value (v1.sh / install.sh) | Wrong value |
|---|---|---|---|---|
| ROOM_CREATES_PER_MINUTE | room_api.py 18 | unset: API default 100 | `${ROOM_CREATES_PER_MINUTE:-100}` | not an int: ValueError traceback, start. 0 or less: SystemExit, start. |
| CATHEDRAL_SANDBOX_RUNTIME | runtime 69 | required | `docker` (and --runtime docker wins) | missing or unknown: ValueError, start. |
| CATHEDRAL_ALLOW_MEMORY_RUNTIME | runtime 133 | off | unset | only "1" counts; memory runtime refused otherwise (start). |
| CATHEDRAL_SANDBOX_FLEET | runtime 143 | off | unset | malformed entry or non-int: ValueError, start. Negative: ValueError, start. |
| CATHEDRAL_SANDBOX_QUOTA | runtime 155 (fleet only), provider 1650 | 500:1000:3000 | `$SIZE_QUOTA` from size.py (`slots:vcpu:mem`) | provider path: != 3 parts, non-int, negative (SandboxContractError is a ValueError): silent fallback to 500/1000/3000. Fleet path: non-int is start. Probe: test_malformed_project_quota_... |
| CATHEDRAL_SANDBOX_KEYS | runtime 184/203, guest 1170, provider 1659 | none | `$KEY:$ROOM_CUSTOMER:$SIZE_SLOTS` (secret.env) | blank or whitespace on docker/kata: permissive provider, any bearer accepted (runtime, open). Entry with no project (empty ROOM_CUSTOMER): no keys, every bearer 401 (runtime, closed). Comma in ROOM_CUSTOMER: a second key. Colon: slot cap lost. Probes in probe_cli_serve_keystore.py. |
| CATHEDRAL_SANDBOX_REVOKED_KEYS | provider 1611 | none | unset | unknown names ignored (silent). |
| CATHEDRAL_KEY_QUOTAS / FACADE_KEY_QUOTAS | api 47 per create | none | unset | non-int values skipped (silent). |
| CATHEDRAL_SANDBOX_REGION | provider 223 | None | `${ROOM_REGION:-}` | any string is shown at /v1/status (silent). |
| CATHEDRAL_API_URL | api 35 at import | https://cathedral.computer | `http://127.0.0.1:$ROOM_API_PORT` | any string; used in document links (silent). |
| CATHEDRAL_SANDBOX_REAPER_SECONDS | server 54 | 30 | unset | not a float: 30 (silent). Negative: 0, reaper off (silent); the 60 s curl timer then does full sweeps inline on the request thread. |
| CATHEDRAL_SANDBOX_OWNER | guest 1114 | "default" | `$ROOM_ID` | blank: "default" (silent). Owner label decides which containers reconcile may remove. |
| CATHEDRAL_SANDBOX_GC_PARALLELISM | guest 1129 | 8 | `${ROOM_GC_PARALLELISM:-16}` | non-int: 8, not 16 (silent). 0: 1. |
| CATHEDRAL_SANDBOX_RM_TIMEOUT | guest 1130 | 60 s | unset | non-float: 60 (silent). Floor 0.1. |
| CATHEDRAL_SANDBOX_RECONCILE_SECONDS | guest 1131 | 60 s | unset | non-float: 60 (silent). 0: reconcile every sweep. |
| CATHEDRAL_SANDBOX_PULL_POLICY | guest 1135 | missing | `missing` | anything but "always" behaves as missing (silent). |
| CATHEDRAL_SANDBOX_REGISTRY_MIRROR | guest 1136 | none | unset | any string (silent until a pull). |
| CATHEDRAL_SANDBOX_AUTH_PULLED_FILE, HOME | guest 387 | $HOME/.cathedral-auth-pulled.json | HOME=/var/lib/pool-room | unreadable or bad JSON: empty set, credentialed-pull memory lost (silent; B81 guard weakened). |
| CATHEDRAL_KATA_RUNTIME | guest 412 | kata-runtime | unset | kata only. |
| CATHEDRAL_DOCKER_RUNTIME | guest 415 | daemon default | unset | a runtime the daemon lacks: every docker run fails (runtime). |
| CATHEDRAL_DIND_DOCKERD_ARGS | guest 135 | built-in list | `$ROOM_DIND_DOCKERD_ARGS` | unbalanced quotes: shlex ValueError, start. |
| CATHEDRAL_DIND_ENV | guest 137 | none | `$ROOM_DIND_ENV` | a word without "=": ValueError, start. |
| CATHEDRAL_DIND_RUNTIME | guest 143 | none | unset | silent. |
| CATHEDRAL_ALLOW_PRIVILEGED_DIND | guest 664 per create | off | `${ROOM_ALLOW_DIND:-0}` | only "1" enables; "yes"/"true" keep DinD refused (runtime, closed). |
| CATHEDRAL_ROOM_NETWORKS | guest 214 | 0 (pool off) | count of ROOM_NETS | non-int: 0, pool off, every room on the main bridge (silent). |
| CATHEDRAL_ROOM_NETWORK_SIZE | guest 220 | 1000 | `${ROOM_NET_SIZE:-1000}` | non-int: 1000 (silent). Clamped 1..1023. |
| CATHEDRAL_ROOM_NETWORK_SUBNETS | guest 217 | none | ROOM_NETS comma-joined | count != networks: ValueError, start. Bad CIDR: docker network create fails at the first create, 502 (runtime). |
| CATHEDRAL_ROOM_NETWORK_PREFIX / _BRIDGE_PREFIX | guest 221/223 | cathedral-room / none | `$ROOM_ID-net` / `rmnet` | silent. |
| CATHEDRAL_ROOM_NETWORK_DNS | guest 224 | none | `"$ROOM_DNS"` (quoted; systemd strips) | empty: guests on room networks get Docker's 127.0.0.11, unreachable under gVisor; DNS dead (silent). |
| CATHEDRAL_ROOM_EGRESS_SOCKET | egress 50 | none (no daemon) | `/run/pool-room-egress/control.sock` when ROOM_EGRESS=1 | wrong path: never checked at start; /v1/status says allowlist enforced; every attached create is 503 egress_unavailable (runtime, closed). |
| CATHEDRAL_SANDBOX_IMAGE_ALLOWLIST | provider 434 per create | none | unset | runtime. |
| CATHEDRAL_SANDBOX_ACCESS_LOG | server 883 | off | unset | only "1". |
| CATHEDRAL_AGENT_DESKTOP | server 1000, provider 1349 | off | unset | only "1". |
| CATHEDRAL_SANDBOX_EXEC_TIMEOUT_MAX | api 641 | 14400 | unset | runtime. |
| DOCKER_HOST | docker CLI | host daemon | `unix://$SOCK` (api.env) | wrong: info_ok false, runtime_unavailable, start. |
| TMPDIR | tempfile | /tmp | `$ROOM_DATA_DIR/work` | missing or unwritable: tempfile falls back to /tmp (PrivateTmp) with no log; room work dirs leave the data volume and the room daemon sees a different /tmp (silent). |
| PYTHONPATH | interpreter | | `$ROOM_OPT/src` | wrong: ImportError, start. |

## 5. Functions and units

### cathedral/cli.py

- `cmd_sandbox_serve(args)` 1714-1760. Purpose: build the provider, start
  the reaper, bind, install SIGTERM, serve, clean up. Trusts: args.host,
  args.port, args.runtime, args.reaper_interval, the whole environment.
  Side effects: docker info x2 (plus kata probe), a TCP listener, a thread,
  stdout JSON, SIGTERM handler, and at stop: docker rm -f of every guest,
  rmtree of every work dir. Locks: none of its own. Callers: argparse
  default (6053), room_api.py via cli.main. Invariant assumed: the bind
  succeeds (no try around run); serve_forever is entered before any
  KeyboardInterrupt (else httpd.shutdown waits forever on an unset Event);
  one process per port.
- `build_parser()` sandbox part 6012-6053. --host 127.0.0.1, --port 8080,
  --allow-insecure-dev, --runtime {memory,docker,kata} or env,
  --reaper-interval float or env. No validation beyond argparse types.
- `main(argv)` 6058-6068. Catches Exception (not BaseException): a
  KeyboardInterrupt that escapes the cleanup gives a traceback, exit 1.

### room-kit/room_api.py

- `main()` 15-27. Patches a dunder default on InMemorySandboxProvider so
  every provider built later (also the docker provider's inner) gets the
  pace; then runs cli.main(argv[1:]). Trusts ROOM_CREATES_PER_MINUTE. No
  side effects beyond the patch. Invariant: `creates_per_minute` stays a
  keyword-only parameter of InMemorySandboxProvider.__init__ (a rename
  silently drops the pace, no error). Probe: test_room_api_launcher_...

### room-kit/profiles/v1.sh

- `profile_exec` 13-15: the ExecStart line. Trusts ROOM_OPT, ROOM_API_PORT
  (empty: argparse error, start).
- `profile_env` 17-48: api.env lines. Trusts SIZE_QUOTA, ROOM_ID, ROOM_DNS,
  ROOM_NETS (word-split into CATHEDRAL_ROOM_NETWORKS and _SUBNETS).
  Writes `CATHEDRAL_ROOM_NETWORK_DNS="$ROOM_DNS"` with literal quotes
  (systemd EnvironmentFile strips matching quotes).
- `profile_keys_env KEY` 51-53: `CATHEDRAL_SANDBOX_KEYS=$1:$ROOM_CUSTOMER:$SIZE_SLOTS`
  into secret.env (0600 root). Trusts ROOM_CUSTOMER to contain no ":" or
  "," and to be non-empty; install.sh checks neither. Invariant: one key,
  one project, max_running = slots.

### systemd units written from the profile (install.sh)

- `$ROOM_ID.service` 320-341: see section 1. Stop: SIGTERM to the whole
  cgroup (docker CLI children in flight die too), SIGKILL at 90 s.
- `$ROOM_ID-reaper.service` + `.timer` 365-381: `curl -fsS` GET
  /v1/sandboxes with the key every 60 s (OnBootSec 120). Trusts the API's
  inline sweep. With the in-process reaper on, this GET only marks.
- install.sh final check 508-509: waits up to 30 s for any HTTP code other
  than 000, then logs it. 000 (never came up) and 401 (key store broken)
  both end in "done".

### cathedral/sandbox_runtime.py

- `kata_host_ready()` 57-65: which() of kata binaries + docker_daemon_ready
  (`docker info`, 2 s). Callers: build_sandbox_provider (kata only).
- `detect_runtime(explicit)` 68-77: explicit or env; ValueError otherwise.
- `FleetGuardedProvider` 80-114: wraps a provider; `create` calls
  require_fleet_admission first, everything else via __getattr__; `status`,
  `authorize`, `close` explicit. Locks: none. Invariant assumed: the fleet
  is live capacity. It is not: NodeCapacity is static and never
  decremented, so `fits` is a per-request shape check against total
  registered capacity (probe test_fleet_guard_is_a_per_request_shape_check).
  Off on hotels (CATHEDRAL_SANDBOX_FLEET unset).
- `build_sandbox_provider(...)` 117-209: the only constructor the serve
  path uses. Trusts env. Docker/kata branch: inner from
  provider_from_environment only when CATHEDRAL_SANDBOX_KEYS is non-blank;
  otherwise None, and DockerGuestProvider builds a permissive inner.
  Memory branch always strict. Fleet quota parse uses bare int() (start on
  junk) and silently skips a quota that is not 3 parts.
- `capabilities_document(provider)` 212-228: status() to a dict for the
  "serving" line. docker says kernel_isolation from the daemon's default
  runtime name; the kit README notes /v1/status cannot see runsc.

### cathedral/sandbox_fleet.py

- `NodeCapacity` 28-60, `fits` 50-60: total >= request. No usage.
- `FleetRegistry` 63-114: dict of nodes, "thread-hostile" by its own
  docstring; FleetGuardedProvider never locks it (static after start, so
  no writer).
- `customer_mvp_quota` 117-123, `assert_quota_fits_fleet` 126-148 (503 at
  start if quota > fleet), `require_fleet_admission` 151-168 (503 fleet
  empty, 429 no node fits), `fleet_from_env_lines` 171-197 (ValueError on
  shape, int() on fields), `usage_fits_remaining` 200-206 (unused by the
  serve path).

### cathedral/sandbox_server.py (serve-path parts)

- `reaper_interval_from_env()` 52-60: float or 30; max(.., 0).
- `install_stop_signal()` 156-170: SIGTERM -> KeyboardInterrupt in the main
  thread. Not restored. A second SIGTERM during the cleanup raises again
  inside the finally block: the cleanup stops where it is.
- `SandboxApplication.__init__` 182-188: provider, routes, reaper state.
- `start_reaper(interval)` 191-209: daemon thread "cathedral-sandbox-reaper";
  `Event.wait(interval)` loop; `except Exception` logs and continues (a
  BaseException would end the thread; none is raised in a non-main thread
  by the code). Returns silently for interval <= 0 or if already started.
- `stop_reaper(timeout=10)` 211-217: set event, join up to 10 s, drop the
  handle. A sweep inside docker rm (up to 60 s per container) outlives the
  join; the thread keeps running concurrently with provider.close().
- `reaper_running` 219-221; `_sweep_inline` 223-233: reads (list 362, get
  374, quota 631) call mark_expired when the reaper runs, else a full
  sweep on the request thread.
- `_Handler._run` 840-853: Content-Length parse, 413 over 256 MiB,
  dispatch. `_send` 855-862. `log_message` 882-884: silent unless
  CATHEDRAL_SANDBOX_ACCESS_LOG=1 (also silences http.server error lines).
  Protocol HTTP/1.0: one TCP connection per request, listen backlog 5.
- `serve(app, host, port)` 1086-1090: subclass of _Handler bound to app,
  ThreadingHTTPServer (daemon_threads True: request threads are not joined
  at server_close). `run` 1093-1100 returns (httpd, address).

### cathedral/sandbox_provider.py (serve-path parts)

- `parse_sandbox_keys(raw)` 1601-1629: split on ",", then ":"; entries with
  fewer than 2 fields or blank key/project are skipped silently; a non-int
  third field becomes max_running None silently. Revoked set from env.
- `provider_from_environment(...)` 1632-1667: quota (silent default) and
  keys, require_known_keys=True.
- `InMemorySandboxProvider.__init__` 179-234: mkdtemp base under TMPDIR,
  limits default 500/1000/3000, keys dict, region from env, RLock.
- `authorize/_auth` 298-317: None -> 401; revoked -> 403; unknown -> 401
  only when require_known_keys. Sets thread-local caller key.
- `sweep` 948-971 (memory provider: collect under the lock, rmtree roots),
  `sweep_tombstones` 973-979, `collectable_ids` 1005-1009, `begin_delete`
  1011-1023 (terminates background processes), `finish_delete` 1025-1034
  (rmtree root), `has_record` 1036-1039.
- `close()` 1513-1523: under the lock; rmtree every root and the base;
  idempotent via `_closed`.

### cathedral/sandbox_guest.py (serve-path parts)

- `docker_daemon_ready` 69-82 (2 s), `_env_int/_env_float` 91-108 (silent
  defaults), `DindConfig.from_env` 133-146 (ValueError at start),
  `RoomNetworkPool.from_env/__init__` 191-225 (ValueError at start on
  subnet count), `ensure` 231-257 (lazy: first create runs docker network
  inspect/create; failure is a 502 per create, not a start failure).
- `_auth_pulled_path/_load_auth_pulled/_save_auth_pulled` 386-405.
- `DockerClient.__init__` 411-416, `default_runtime` 418-424, `info_ok`
  468-476, `remove_confirmed` 829-841 (False on timeout or error; "no such
  container" is gone), `list_labeled` 843-870 (raises on a failed ps).
- `DockerGuestProvider.__init__` 1096-1180: see section 2a. Raises
  SandboxOpError 503 (start) when docker info fails or kata is missing.
  Inner provider choice: given inner, else strict when the keys env is
  non-blank, else permissive.
- `authorize` 1186-1187: forwards to inner.
- `_retire` 1890-1909: begin_delete, pop guest, egress.forget, queue
  container (under _doomed_lock). `_confirm_removed` 1911-1918.
- `mark_expired` 1934-1940: no docker calls. `_remove_many` 1942-1966:
  ThreadPoolExecutor(min(parallelism, n)); each rm has its own timeout;
  `except Exception` per future (a BaseException such as KeyboardInterrupt
  escapes and ends the pass). `_drain_locked` 1968-1996, `_reconcile_locked`
  1998-2024 (removes labeled containers with no record: the previous
  instance's rooms, about 30 s after start; recounts pool ports),
  `sweep` 2036-2062 (mark, drain + reconcile under _drain_lock, tombstones,
  snapshot image GC), `_gc_snapshot_images` 2064-2073,
  `_reconcile_snapshot_images` 2075-2086 (removes every cathedral-snap-*
  image the new instance does not know, i.e. all of them after a restart),
  `status` 2093-2105 (network_allowlist_enforced = egress env set).
- `close()` 2144-2151: refs from `_guests.values()` (no lock) plus doomed;
  `_remove_many(refs)` (all containers, N / parallelism rounds, 60 s cap
  each); `_guests.clear()`; `_inner.close()` (work dirs, base). Does not
  call egress.forget, does not release pool ports, does not touch snapshot
  or built images. Probes in the scratch file probe_cli_serve_stop (superseded by tests/test_cli_serve_hardening.py).

### cathedral/sandbox_egress.py

- `EgressClient.from_env` 48-51: a path string, never opened at start.
  `_call` 53-71: one HTTP request over the unix socket, 30 s; OSError ->
  503 egress_unavailable. `apply` 73-86 (PUT, checks the echoed policy),
  `forget` 88-94 (DELETE, best effort).

## 6. What the stop signal closes and what it leaves (new in #312)

Closes, in order: the reaper (join 10 s), the listener (shutdown returns at
once because serve_forever already left; server_close closes the socket
and does not wait for request threads), every guest container (`docker rm
-f`, parallel), every room work dir and the provider base dir (rmtree),
the in-memory state. Then the process exits; daemon request threads die
with it.

Leaves: in-flight requests with no answer (the connection dies with the
process; an exec's `docker exec` child got SIGTERM from the cgroup kill);
egress policies in the daemon until its 15 s reconcile or until a new room
takes the address (probe test_close_does_not_forget_egress_policies; safe
because an unbound bridge port sends nothing and put() drops the stale
room in the same transaction); snapshot images (removed by the next
instance's first reconcile), built images (kept, by design), the
auth-pulled file (kept, by design), pool-port counts (recounted at the next
reconcile), receipts (another process).

Budget: none set. systemd's default TimeoutStopSec of 90 s then SIGKILL;
the sealed guest's host unit gives the whole VM 60 s. The container pass
runs before the work-dir pass, so a cleanup cut short leaves every work
dir (probe test_an_interrupt_during_the_container_pass_leaves_every_work_dir)
and no later run removes stale `cathedral-sandbox-*` bases.

## 7. Reaper failure modes

- A sweep that raises is logged and the loop continues (tested upstream).
- A sweep that hangs (docker daemon stuck) blocks the thread for up to
  60 s per container per worker; records stay "deleting" and keep counting
  in quota; reads still mark (fast) and the hotel can reach 429 with no
  running room. The kit's 60 s curl timer calls the same inline mark.
- Interval 0 or negative, or an unparsable value that happens to be
  negative: reaper off, no log; reads do full sweeps inline.
- `stop_reaper` returns after 10 s even if the sweep is still inside
  docker rm; close() then races the sweep on the same containers (both
  treat "no such container" as gone; no deadlock: close takes no
  _drain_lock, and _inner._lock is held only briefly by either side).
- `_reconcile_locked` lists `_guests.values()` under _doomed_lock, but
  creates insert into `_guests` without that lock: a size change during
  the list() raises RuntimeError, which the loop logs; the drain of that
  tick is lost until the next interval.

## 8. Hazards (trusts without a check)

1. Key store fail-open: DockerGuestProvider builds a permissive inner when
   CATHEDRAL_SANDBOX_KEYS is blank (runtime 184, guest 1170-1179). The
   only guard is install.sh writing the value. A manual `sandbox serve
   --runtime docker` on the API port behind Caddy is open to any bearer.
2. ROOM_CUSTOMER is never validated (install.sh); v1.sh and
   parse_sandbox_keys trust it to hold no ":" or "," and to be non-empty.
   Empty: a dead hotel (401 to its own key) that install.sh reports as
   done. Comma: a second, guessable key and no slot cap.
3. CATHEDRAL_SANDBOX_QUOTA: any parse failure is the 500/1000/3000 default
   with no log (provider 1650-1658). The per-key max_running still caps
   the room count at slots, but not vCPU or memory.
4. Stop budget: the API unit sets no TimeoutStopSec; the cleanup is
   N / parallelism docker rm rounds, then the work dirs. A large hotel's
   stop can hit the 90 s SIGKILL with the work dirs untouched, and nothing
   later removes stale `cathedral-sandbox-*` bases.
5. close() reads `_guests` without a lock while request threads may insert:
   a size change raises RuntimeError before any container or work dir is
   removed; main prints it and exits 2 (the whole cleanup is skipped).
6. The bind is outside any try: a port conflict leaves the reaper thread
   and the provider base dir; harmless for a docker provider with no rooms.
7. install_stop_signal is installed after the bind and the print; a
   KeyboardInterrupt before serve_forever's own try block leaves
   `__is_shut_down` unset and httpd.shutdown() waits until SIGKILL
   (microsecond window at start, nothing to clean then).
8. EgressClient.from_env never opens the socket: /v1/status claims
   `network_allowlist_enforced` from the env var alone.
9. RoomNetworkPool.ensure is lazy: a bad subnet is found by the first
   customer create (502), not at start or by install.sh's status check.
10. install.sh's final check (508-509) treats 401 and 000 as done.
11. HTTP/1.0 with listen(5): each broker request is a new connection
    into a backlog of five; under a burst with a busy main thread, SYNs
    drop and the client retries after 1 s (not measured here; Linux only).
12. TMPDIR fallback: tempfile silently uses /tmp when $ROOM_DATA_DIR/work
    is unusable; with PrivateTmp the room daemon then mounts a different
    /tmp than the API writes.
13. room_api.py patches a dunder default by name; a signature change in
    InMemorySandboxProvider.__init__ would drop the pace with no error.
14. `_env_int` for GC parallelism falls back to 8, not the kit's 16, on a
    typo; the stop and GC passes run slower than sized.

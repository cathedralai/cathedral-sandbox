# Catalog F: docker guest provider

Artifact: cathedral-sandbox at 22e7824, file cathedral/sandbox_guest.py (1994 lines).
Context read: sandbox_provider.py (the inner record store), sandbox_egress.py,
room-kit/room_egress.py, room-kit/install.sh, room-kit/profiles/v1.sh,
room-kit/lib/room-net.sh, net_plan.py, net_capacity.py, sandbox_server.py,
sandbox_api.py (request types), cli.py cmd_sandbox_serve, broker/main.go
create and room paths, tests/fake_docker_cli.py and the guest test files.

Deployment facts that shape every entry (install.sh, v1.sh):
- One API process per hotel, systemd unit `<room>.service`, user poolroom,
  Restart=on-failure, no MemoryMax, TMPDIR=$ROOM_DATA_DIR/work.
- DOCKER_HOST is the room daemon: default runtime runsc, overlay2 on xfs with
  prjquota, iptables=false, ip6tables=false, own bridge; firewall rules come
  from room-net.sh.
- One API key per hotel (CATHEDRAL_SANDBOX_KEYS=key:customer:slots). Every
  guest of the broker arrives as that one key. Tenant separation on a shared
  hotel is the broker's job; this file sees one caller.
- CATHEDRAL_SANDBOX_PULL_POLICY=missing, GC parallelism 16, egress socket set
  when ROOM_EGRESS=1 (default), room networks from ROOM_NETS.
- The server is ThreadingHTTPServer: one thread per request, no cap. The
  reaper thread calls sweep() every 30 s (CATHEDRAL_SANDBOX_REAPER_SECONDS).
- SIGTERM ends the process without provider.close() (cli.py:1750 catches
  KeyboardInterrupt only).

## Module functions

### _now (61-62)
Purpose: UTC now.
Callers: exec history stamp (1453).

### docker_cli_available (65-66)
Purpose: `docker` on PATH.
Side effects: none.
Callers: docker_daemon_ready; sandbox_runtime.

### docker_daemon_ready (69-82)
Purpose: `docker info --format {{.ServerVersion}}`, 2 s timeout, True on exit 0.
Trusts: PATH, DOCKER_HOST from the environment.
Side effects: one docker process.
Callers: sandbox_runtime.kata_host_ready / detect.
Invariant: a daemon that answers now answers later; checked once.

### _env_int, _env_float (91-108)
Purpose: parse an env var with a floor; bad text gives the default silently.
Callers: RoomNetworkPool.from_env, DockerGuestProvider.__init__.
Hazard: a typo in an operator value is not reported.

### DindConfig.from_env (119-146)
Purpose: DinD runtime, dockerd args, extra env from CATHEDRAL_DIND_*.
Trusts: shlex-splittable operator strings. A bad CATHEDRAL_DIND_ENV raises
at DockerClient() construction (API does not start).
Callers: DockerClient.__init__.

### runtime_has_kernel_isolation (149-156)
Purpose: name starts with "runsc" or contains "kata".
Callers: status().
Invariant: the runtime name describes the runtime. Not checked against the
daemon beyond the name.

### is_dind_image (159-162)
Purpose: "docker:" and "dind" in the lower-cased image name.
Callers: _start_guest (after the pull).

## RoomNetworkPool (165-294)

### __init__ (191-210)
Purpose: names <prefix>-i, per-network size (1..1023), subnets, bridge
prefix, dns, used counters, lock.
Trusts: subnets count equals count (checked); subnet sizes are not checked
against size (net_plan.py cuts blocks that fit, a hand-written ROOM_NETS may not).

### from_env (213-225)
Purpose: build from CATHEDRAL_ROOM_NETWORK*; None when count is 0.
Callers: DockerGuestProvider.__init__.

### ensure (231-257)
Purpose: once per process: `docker network inspect --format {{len .Containers}}
<name>` (30 s); missing networks get `docker network create --driver bridge
[--subnet S] [-o com.docker.network.bridge.name=<bridge_prefix><i>] <name>`
(60 s). Counts attached containers as used ports.
Flags not passed: no --internal, no --ipv6, no icc or masquerade options
(the daemon runs iptables=false; room-net.sh owns MASQUERADE and the nft
bridge rule that drops guest to guest frames).
Trusts: `len .Containers` counts only this API's guests. After a restart it
counts the previous instance's containers until the first reconcile recounts.
Side effects: docker network create.
Locks: self._lock for the whole pass (serial docker calls under the lock).
Callers: _start_guest, set_network.
Invariant: a network that exists has the intended subnet and bridge name.
Not checked: an existing network with another subnet is reused as is.

### acquire (259-273)
Purpose: least used network with a free port; 503 network_capacity_exhausted
with Retry-After 10 when all are full.
Locks: self._lock.
Callers: _start_guest, set_network.
Invariant: size per network is at or under the bridge port cap and under the
subnet's usable addresses. The second half is not checked here.

### release (275-280)
Purpose: decrement, never below 0, unknown names ignored.
Callers: _release_pending, _confirm_removed, set_network.

### recount (282-289)
Purpose: reset counters from the list of networks held by guests, queued
removals and pending starts.
Callers: _reconcile_locked (every CATHEDRAL_SANDBOX_RECONCILE_SECONDS, 60 s).
Invariant: `_guests` has one record per live container. A stale GuestRecord
keeps a port counted forever (see hazards).

### document (291-294)
Purpose: counters for quota() and room_networks().

## GuestRecord (297-314)
One per live guest: ids, image, dind, host /work path, network mode, pool
network, attached flag, applied policy and sha, background process logs,
probed timeout form. Plain dataclass, mutated without a lock.

## DockerClient (317-810)

### __init__ (320-325)
Purpose: kata runtime name, optional guest runtime (CATHEDRAL_DOCKER_RUNTIME,
unset in v1), DindConfig.

### default_runtime (327-333)
Purpose: `docker info --format {{.DefaultRuntime}}` (15 s); "" on any failure.
Callers: DockerGuestProvider.__init__ (once, for status kernel_isolation).

### run (335-371)
Purpose: the one subprocess wrapper. `subprocess.run(argv, capture_output,
text=True, timeout, input=str, env=os.environ+env)`.
Output parsing: text mode with the default strict UTF-8 decoder. Output is
read whole into memory with no bound.
Errors: FileNotFoundError -> 503 runtime_unavailable; OSError -> 503
runtime_unavailable; TimeoutExpired -> 504 docker_timeout (the child is
killed by subprocess). A nonzero exit is NOT an error here; each caller
decides. UnicodeDecodeError is not caught (hazard H1).
Trusts: argv built by callers; stdin text round-trips through UTF-8.
Side effects: one docker process per call.
Callers: every method below.

### info_ok (373-381)
Purpose: daemon answers `docker info` (15 s).
Callers: DockerGuestProvider.__init__ only. Never re-checked.

### _registry_env (383-412)
Purpose: for a pull or push with credentials, write a private DOCKER_CONFIG
dir (mkdtemp under TMPDIR, chmod 700, config.json 0600 with username and
password for _registry_host(image)); remove it after the call.
Trusts: registry_auth has username and password (validated by ImageSource).
Side effects: plaintext credentials on the data volume for the life of the
call; left behind if the process dies mid-pull.
Callers: pull, push.

### pull (414-422)
Purpose: `docker pull <image>` (600 s); nonzero -> 502 image_pull_failed with
the first 300 chars of stderr (the broker reads that text to decide guest
fault vs hotel fault, main.go:1434).
Callers: ensure_image.

### push (424-447)
Purpose: `docker tag <source> <target>` (30 s) then `docker push <target>`
(1800 s) with the one-call config; returns the RepoDigest for target.
Side effects: the target tag stays as a local image name forever (hazard H5).
Callers: push_snapshot.

### image_size (449-454)
Purpose: Size from image inspect, 0 when unknown.
Callers: build_image, _snapshot_sizes.

### ensure_image (456-482)
Purpose: pull policy. Skip when local and not refresh. With a mirror and no
credentials, pull <mirror>/library/<name> first and `docker tag` it as the
original name; on failure pull direct.
Trusts: a local image by that name is the image the caller means (H5).
Callers: DockerGuestProvider._ensure_image.

### image_inspect (484-494)
Purpose: `docker image inspect --format {{json .}}` (30 s), last stdout line
as JSON, {} on any failure.
Callers: push, image_size, _start_guest, prefetch, image_status.

### build (496-506)
Purpose: `docker build -t <tag> -f <dir>/Dockerfile <dir>` (900 s); nonzero ->
502 image_build_failed. Runs on the room daemon with full network (B42).
Callers: build_image, _build_image.

### image_exists (508-513)
Purpose: `docker image inspect --format {{.Id}}` exit 0 (15 s).
Callers: ensure_image, build_image, _build_image, _snapshot_image, image_status.

### create_and_start (515-626)
Purpose: build and run `docker run`. Exact argv in order:
`docker run -d --name cathedral-<sid>`
`--label cathedral.sandbox.owner=<owner> --label cathedral.sandbox.id=<sid>`
`--cpus <vcpu> --memory <memory_gib>g -v <host work dir>:/work -w <workdir or /work>`
`[--user <user>]`
`[--runtime kata | --runtime <dind runtime> | --runtime <CATHEDRAL_DOCKER_RUNTIME>]`
(none of these in v1: the daemon default runsc applies)
`[--privileged -e DOCKER_TLS_CERTDIR= -e <dind env>...]` (DinD only; needs
CATHEDRAL_ALLOW_PRIVILEGED_DIND=1, else 403 privileged_dind_disabled; v1 sets 0)
`[--storage-opt size=<disk_gib>G]` (not with kata)
`--network none` when attach is False, else `[--network <pool net>
[-v <sandbox root>/resolv.conf:/etc/resolv.conf]]` (default bridge when no pool)
`-e K=V` for every request env entry
then `<image> dockerd-entrypoint.sh dockerd <args>` (DinD) or `<image>
<entrypoint...>` or `<image> sleep infinity`.
Not passed: --pids-limit, --memory-swap, --cap-drop, --security-opt,
--read-only, --hostname, --dns (daemon.json dns applies on the default
bridge), --init, --ulimit, --shm-size, --tmpfs, --cgroup-parent, --stop-timeout.
Trusts: workdir, user, env keys and entrypoint words straight from the
request (no validation in CreateSandboxRequest for workdir and user). They
are separate argv items, so they cannot inject flags; a bad value makes
docker run fail and comes back as 502 (H4).
Retry: on a nonzero exit with --storage-opt present, remove the half-made
container by name and run again without --storage-opt, whatever the reason
was. Then nonzero -> remove by name, 502 guest_start_failed with 400 chars of
stderr. Empty stdout -> 502.
Side effects: mkdir of the work dir, container create and start, two docker
runs on retry.
Callers: _start_container.
Invariant: a failed docker run leaves at most a container named
cathedral-<sid>, removed here; the storage driver rejecting size= is the
only reason for the retry (not true, any failure retries).

### _run_guest (628-635)
Purpose: docker run with 180 s; on 504 remove the container by name.
Callers: create_and_start.

### set_network (637-665)
Purpose: without the egress daemon only. Inspect attached networks
(`docker inspect --format {{json .NetworkSettings.Networks}}`); for none or
allowlist disconnect every network (`docker network disconnect -f`); for
public ensure `docker network connect <network>` (default "bridge").
Errors of disconnect are ignored. Connect failure -> 502 network_change_failed.
Callers: DockerGuestProvider.set_network (no egress branches).

### exec (667-705)
Purpose: `docker exec [-d | -i] [-u user] [-w cwd] [-e K=V]... <cid> <argv>`;
stdin as text; timeout from the caller; on 504 return (137, "", "exec timed
out", True) and kill only the client (the guest process goes on, B41).
Output: whole stdout and stderr in memory, no cap here.
Callers: DockerGuestProvider.exec, _timeout_form, start_process,
stop_process, wait_dind_ready.

### remove (707-709)
Purpose: `docker rm -f`, result unchecked. No caller in cathedral/ (dead).

### remove_confirmed (711-723)
Purpose: `docker rm -f <ref>` with timeout; True on exit 0 or "no such
container" in stderr; False on timeout or any other error.
Callers: create_and_start, _run_guest, _start_guest, _remove_many.

### list_labeled (725-755)
Purpose: `docker ps -a --no-trunc --filter label=cathedral.sandbox.owner=<owner>
--format "{{.ID}} {{.Label \"cathedral.sandbox.id\"}}"` (60 s); nonzero ->
502 docker_list_failed (callers must not read a failure as empty).
Callers: _reconcile_locked.

### pause, unpause (757-773)
Purpose: `docker pause|unpause` (30 s); nonzero -> 502.
Callers: freeze, thaw.

### commit (775-787)
Purpose: `docker commit <cid> <image>` (300 s) then `image inspect {{.Id}}`;
nonzero commit -> 502 snapshot_failed. The room is not paused during commit.
Callers: snapshot.

### wait_dind_ready (789-810)
Purpose: poll `docker info` inside the guest for 90 s. DinD only.
Callers: _after_start.

## Module helpers (813-969)

### mirror_ref (813-833)
Purpose: Docker Hub names to <mirror>/library/<name>; other registries and
digest refs are not mirrored.
Callers: ensure_image.

### _registry_host (836-840)
Purpose: first path part when it has a dot, colon or is localhost, else the
Docker Hub v1 index URL.
Callers: _registry_env.

### _public_ip (843-857)
Purpose: not private, loopback, link local, reserved, multicast, unspecified.
Strips a zone suffix. IPv4 mapped and documentation ranges count as private
in Python 3.12+.
Callers: _checked_opener.check, _fetch_context_tar.

### _checked_opener (860-893)
Purpose: urllib opener whose HTTP and HTTPS connections check the peer
address after connect (every hop, redirects included). Built with
build_opener, so the default handlers are present too: ProxyHandler (reads
http_proxy env; the API unit has none), HTTPRedirectHandler, FTPHandler,
FileHandler, DataHandler.
Trusts: a redirect lands on http or https. urllib refuses file: and data:
redirects but allows ftp:, which FTPHandler opens with no peer check (H3).
Callers: _fetch_context_tar.

### _fetch_context_tar (896-941)
Purpose: refuse file:, non http(s), missing host; getaddrinfo pre-check (all
answers public, else 400 build_context_forbidden); then open with the
checked opener, socket timeout 120 s (per operation, not total), and
`resp.read()` the whole body into memory. No size cap (H2). Errors -> 502
build_context_fetch_failed.
Callers: _build_image (create with build.context_tar_url; the broker forwards
that field untouched, main.go:563-600 and images.go:88).

### _in_work (944-953)
Purpose: path is /work or under /work, else 400 path_outside_work.
Callers: write_file, read_file, write_tar, read_tar, stat.

### _read_room_log (956-969)
Purpose: open with O_NOFOLLOW|O_NONBLOCK, regular files only, read whole file.
Trusts: the parent chain (API owned). No size cap on the log (H2).
Callers: process_logs.

## DockerGuestProvider (972-1979)

### __init__ (975-1059)
Purpose: DockerClient, dicts (_guests, _snapshot_images, _snapshot_meta,
_built_images, _build_locks, _doomed, _doomed_nets, _net_pending,
_doomed_attempts, _auth_pulled), owner label from CATHEDRAL_SANDBOX_OWNER,
RoomNetworkPool, EgressClient, GC settings, pull policy, mirror; info_ok()
or 503; kata probe; _oci_runtime for status; inner provider from
CATHEDRAL_SANDBOX_KEYS (strict) or permissive InMemorySandboxProvider.
Everything here is process memory: nothing is persisted (B24 and H6).
Callers: sandbox_runtime.build_sandbox_provider.

### capabilities_dind (1061-1063)
Purpose: True once any DinD guest started this process, or any live guest is
DinD. Iterates _guests without a lock (H9).
Callers: status.

### authorize (1065-1066)
Purpose: pass through to the inner key check (sets thread local caller key).
Callers: server _authenticate on every request.

### build_image (1068-1104)
Purpose: POST /v1/images/build. Tag cathedral-build-<sha256(dockerfile,
context bytes)[:16]>:latest; per-tag lock; extract the inline tar with
filter="data" into a mkdtemp under TMPDIR (no extracted-size bound), write
the Dockerfile, docker build, rmtree. Returns image, content_hash, cached,
size_bytes.
Trusts: the context tar's expanded size (the server caps the compressed
input at 256 MiB). Content-addressed: any tenant gets another tenant's
built image for the same inputs (by design, no secret in the key).
Locks: _build_locks_guard briefly, then the tag lock for the build.
Side effects: temp dir, docker build, image kept forever (never GC'd).
Callers: server build_image route (also the broker's build path).

### _build_image (1106-1134)
Purpose: create path with build. Key is request.build.content_hash =
sha256(dockerfile, context_tar_url string), not the fetched bytes. Tag
cathedral-build-<hash[:16]>:latest. Cache hit when the tag exists. Else
fetch the URL (no size cap), extract with filter="data" (fallback to plain
extractall on TypeError, Python < 3.12), build.
Trusts: the URL's content never changes (B58 class, hotel side); the fetched
tar's size and expansion.
Locks: none (two concurrent creates of the same new build both build).
Callers: _image_for.

### _image_for (1136-1143)
Purpose: image name from image, snapshot or build; default image otherwise
(not reachable: CreateSandboxRequest needs one source).
Callers: _start_guest.

### _resolve_snapshot (1145-1154)
Purpose: snapshot id for an id or a name, from the inner store. No owner.
Locks: inner _lock.
Callers: _snapshot_image, push_snapshot.

### _snapshot_image (1156-1172)
Purpose: committed image of a snapshot; 404 snapshot_not_found when unknown;
409 snapshot_image_missing when the record exists but the image is not local
(after a restart, every snapshot).
Callers: create (pre-check), _image_for, push_snapshot.

### create (1174-1211)
Purpose: fork pre-check; inner create (quota, pacing, idempotency, records
with state running, /work dir, snapshot tar unpacked); then one guest per
record. Any failure deletes every record of the batch and drops the
Idempotency-Key entry.
Trusts: inner create admitted on resident counts; the guest start can still
fail after the record exists (the record then sits in quota for the length
of the start).
Locks: inner _lock in the idempotency cleanup.
Callers: server create route.
Invariant: a record in state running has a container (false for the
duration of _start_guest and after the sweep bypass, H7).

### _enrich_doc (1213-1230)
Purpose: add runtime, guest block (container_id, image, dind, network_mode,
network_name, network_enforced=True always, allowlist_fail_closed,
network_switchable) and the policy document.
Callers: create, _after_start.

### _egress_manages, _policy_doc, _attach_for (1232-1259)
Purpose: policy answers for a guest; interface decision per mode: none ->
no interface; internet -> interface; deny_all and allowlist -> interface
only with the egress daemon (else fail closed to no interface).
Callers: _enrich_doc, set_network, _start_guest.

### _ensure_image (1261-1273)
Purpose: refresh when credentials are given, when the image was pulled with
credentials in this process (_auth_pulled), or pull policy always; then
client.ensure_image; remember credentialed refs.
Trusts: _auth_pulled survives (it does not survive a restart, H5).
Callers: _start_guest, prefetch.

### _start_guest (1275-1352)
Purpose: for one record: refuse if the record is gone or deleting (replay);
resolve image; pull and record image facts; dind check (after the pull);
acquire a pool port when the guest gets an interface (_net_pending holds
it); docker run; then, with the daemon and an interface, PUT the policy to
the egress daemon (on failure: remove the container, forget, release, raise);
if the record vanished meanwhile remove the container and 404; register the
GuestRecord; _after_start.
Order: the container runs before the policy is applied. The daemon denies a
room address with no policy (room_forward drop, DNS REFUSED), so the window
between start and apply is deny by default; a customer entrypoint that
needs network in its first second fails there. A slow daemon (30 s socket
timeout per operation) turns into 503 egress_unavailable and the room is
removed.
Trusts: the egress daemon's `docker inspect` sees the container running
(an entrypoint that exits at once gives 502 from the daemon, 503 here, H4).
Locks: inner _lock briefly; _doomed_lock for _net_pending.
Callers: create.

### _release_pending (1354-1358)
Purpose: drop the pending port of a failed start.
Callers: _start_guest.

### _start_container (1360-1397)
Purpose: write <sandbox root>/resolv.conf from pool dns (mounted rw into the
guest), labels owner and id, then client.create_and_start.
Callers: _start_guest.

### _after_start (1399-1408)
Purpose: DinD readiness wait; touch activity; enrich.
Callers: _start_guest.

### exec (1410-1468)
Purpose: argv[0] "bash" becomes "sh" (argv form included; the broker rejects
string cmd since 2026-10-23, so this is the live path); timeout default 60;
probe the image's timeout form once; wrap as `timeout N argv` (gnu),
`timeout -t N argv` (busybox) or run bare (none); docker exec with client
timeout N+15 (wrapped) or N (bare); exit 124, 137, 143 or a client timeout
set timed_out; append ExecRecord and the FULL stdout and stderr bytes to the
record (kept until delete, then 24 h in the tombstone); then cut the answer
to 16 MiB of characters and set truncated.
Trusts: output fits in memory (H2); output is UTF-8 (H1); the guest honours
SIGTERM (gnu timeout has no -k here, H8); state is running (a frozen guest
gives docker's own exit code, not 409).
Locks: inner _lock for the history append, after the command ran.
Callers: server exec route.
Invariant: the command runs once (true) and stops at its limit (false: B41
and H8).

### _timeout_form (1470-1486)
Purpose: run `timeout 5 true` then `timeout -t 5 true` as the image default
user with no env; first exit 0 wins; "none" otherwise; cached per guest.
Callers: exec.

### start_process (1488-1518)
Purpose: pid proc_<10 hex>; `docker exec -d [-u user] -w cwd -e ... <cid>
sh -c "(<quoted argv>) > /work/.process-<pid>.log 2>&1"`; nonzero -> 502
process_start_failed; remember the host log path; inner record gets
(None, log path). No bash to sh rewrite here (H10). running=True always.
Callers: server start_process route.

### process_logs (1520-1524)
Purpose: _read_room_log of the whole log (no cap, no Range support despite
the OpenAPI note).
Callers: server route.

### stop_process (1526-1538)
Purpose: `sh -c "pkill -f '.process-<pid>.log' || true"` as the default user,
15 s. Matches the wrapper shell only (B44); a missing pkill is hidden by
`|| true` and the route answers 204.
Callers: server route, delete.

### write_file, read_file, write_tar, read_tar, stat (1540-1555)
Purpose: _in_work then the inner host-side implementation (O_NOFOLLOW chain,
B38 fixed). API writes count against disk_gib; room writes do not (B40).
Callers: server routes.

### snapshot (1557-1592)
Purpose: inner snapshot first (tar of host /work into <base>/<snap>.tar.gz
under the inner lock, store cap 1000 per hotel, named get-or-create); if the
snapshot is new and the guest is live, `docker commit` to
cathedral-snap-<snap>:latest (not paused: tar and commit are two instants);
on commit failure delete the inner record; record sizes (image, layer,
archive) into the record and the operation.
Trusts: /work fits on the volume twice (B40 class); the 1000 store is shared
by every tenant of a shared hotel.
Side effects: tar file, docker image (kept until delete_snapshot or forever,
H6).
Callers: server snapshot route.

### _snapshot_sizes, list_snapshots (1594-1618)
Purpose: byte accounting; list from the inner store plus sizes.

### delete_snapshot (1620-1626)
Purpose: inner delete (False when the record is gone), drop meta, `docker
image rm` when this process knows the image. The server answers 404 when the
inner record was gone even though the image was just removed.
Callers: server route.

### push_snapshot (1628-1639)
Purpose: committed image of the snapshot -> client.push(target). The target
name stays as a local image (H5).
Callers: server route.

### set_network (1641-1672)
Purpose: with the daemon: _switch_policy. Without it, pool on: inner record
first, then docker disconnect or connect and pool port moves. Without pool:
inner first, then docker connect "bridge" or disconnect.
Trusts: the docker step succeeds after the record changed (no rollback).
Callers: server route.

### _switch_policy (1674-1693)
Purpose: refuse a guest with no interface (409 network_not_switchable);
none means deny_all; PUT the new policy to the daemon FIRST, update the
GuestRecord, THEN ask the inner provider (which refuses frozen, 409). Order
is wrong for a frozen room (H11).
Callers: set_network.

### freeze, thaw (1695-1706)
Purpose: docker pause then inner freeze; inner thaw then docker unpause. A
failure in the second step leaves the two sides apart.
Callers: server routes.

### delete (1708-1724)
Purpose: stop every background process (one docker exec each, 15 s), then
_retire and one removal attempt. Idempotent.
Callers: server route, create (cleanup), bulk_delete does not use it.

### bulk_delete (1726-1742)
Purpose: label match under the inner lock, _retire each, one parallel
removal attempt. Background processes are not stopped first (container
removal ends them).
Callers: server route.

### _retire (1745-1764)
Purpose: inner begin_delete (state deleting, logs retained, quota kept), pop
the GuestRecord, forget the egress policy at once (best effort), queue the
container and its network in _doomed and _doomed_nets.
Locks: _doomed_lock.
Callers: delete, bulk_delete, mark_expired.
Invariant: every record that leaves running passes here (false, H7).

### _confirm_removed (1766-1773)
Purpose: drop the queue entries, release the port, inner finish_delete
(record gone, rmtree of the sandbox root).
Callers: _remove_queued, _drain_locked.

### _remove_queued, _remove_many (1775-1821)
Purpose: ThreadPoolExecutor of min(16, n) `docker rm -f` with
CATHEDRAL_SANDBOX_RM_TIMEOUT (60 s); on_done per container as it finishes.
Callers: delete, bulk_delete, _drain_locked, _reconcile_locked, close.

### mark_expired (1789-1795)
Purpose: _retire every collectable id (TTL plus 300 s grace, idle window,
revoked key). No docker call. Called inline on list, get and quota when the
reaper runs.
Callers: sweep, server _sweep_inline.

### _drain_locked (1823-1851)
Purpose: one removal attempt for every queued container, in batches, with an
attempt counter and a stderr line per failure. Holds _drain_lock (caller).
Callers: sweep.

### _reconcile_locked (1853-1878)
Purpose: list labeled containers; a container whose sandbox id is not queued
and has no record is an orphan: remove it. Then recount pool ports from
_guests, _doomed_nets and _net_pending. Skipped with a stderr line when the
list fails.
Trusts: `list(self._guests.values())` under _doomed_lock while other threads
mutate _guests without that lock (H9).
Callers: sweep, at most every 60 s, and on the first sweep of a process (so
a restart removes every previous container, B24).

### room_networks, quota (1880-1888)
Purpose: pool counters; quota from the inner provider plus pool counters.

### sweep (1890-1913)
Purpose: mark_expired; if the drain lock is free: drain, then reconcile on
its interval; then inner.sweep() which collects any record that became
collectable in the meantime DIRECTLY (state deleted, rmtree, no container
removal, no egress forget, GuestRecord kept) (H7). Returns the marked count.
Callers: reaper thread every 30 s; server _sweep_inline when no reaper.

### pending_removals (1915-1918)
Purpose: copy of _doomed. Tests only.

### status (1920-1932)
Fields and truth:
- status: inner, always "operational", docker health never re-read.
- create_latency_p50_ms, error_rate: inner create metrics (record creation
  only, not the guest start).
- region: CATHEDRAL_SANDBOX_REGION.
- runtime: "docker" or "kata".
- kernel_isolation: runsc or kata by NAME of the daemon default at start up
  ("" when docker info failed, so False). True on v1 hotels.
- dind: sticky True after any DinD guest in this process (v1 refuses DinD).
- disk_enforced: True. Only API writes to /work are bounded; room writes are
  not (B40). The flag overstates.
- network_allowlist_enforced: the socket path is configured. True even when
  the daemon is down (creates then fail closed, so the claim holds in effect).
Callers: server status route; capabilities_document at start up.

### prefetch (1934-1951)
Purpose: for each image (up to 1000): refresh pull with optional credentials
(600 s each, in the request thread), inspect, record; one operation id.
Callers: server route.

### image_status (1953-1966)
Purpose: inner entry, else image inspect when local.

### __getattr__ (1968-1969)
Purpose: everything else goes to the inner provider as is: get, list, wait,
heartbeat, logs, usage, expose, terminals, tickets, templates, desktop.
Templates published through the inner path name an image the daemon does
not have, so a create from a template pulls a non-existent ref and fails 502.

### close (1971-1978)
Purpose: remove every guest and queued container in parallel, clear, inner
close (rmtree of the base dir). Only runs on KeyboardInterrupt.

### shlex_quote (1981-1982)
Purpose: single-quote a word for the start_process wrapper.

## Hazards (trusted but not checked)

H1. DockerClient.run decodes docker output as strict UTF-8 (345-353). Any
exec, commit or pull whose output has a byte that is not UTF-8 raises
UnicodeDecodeError, which no layer catches (server _Handler._run 806 has no
catch-all). The connection closes with no answer.

H2. No size bound anywhere between a room and API memory: exec stdout and
stderr (693), process logs (969), build context URL body (935), inline build
context expansion (1092). The API unit has no MemoryMax and Restart=on-
failure; an OOM kill restarts the API and the first reconcile removes every
room on the hotel (B24).

H3. _checked_opener trusts urllib's redirect rules; ftp: redirects are
allowed and FTPHandler connects without the peer check (893).

H4. create_and_start maps every docker run failure to 502 guest_start_failed
(616-622) and _start_guest maps an egress apply failure to 503 (1326-1331).
The broker rests a hotel for 10 s on any 5xx that is not a known image fault
(main.go:534). Guest input (entrypoint, user, workdir, an entrypoint that
exits at once) is therefore a hotel fault to the broker.

H5. The local image cache is shared by every tenant and gated on pull
credentials only. push() leaves the target tag local (426); ensure_image
starts any local name without a pull (470); _auth_pulled is process memory
(1018). Snapshot images cathedral-snap-<id>:latest pass the image regex.

H6. Nothing persists across a restart: records, snapshots (tar paths and
ids), _snapshot_images, _built_images, _auth_pulled, _doomed. The base
directory (TMPDIR=$ROOM_DATA_DIR/work) with every /work and snapshot tar
stays on disk; cathedral-snap-* images stay in the daemon with no API path to
remove them; a TTL expiry never removes a snapshot image even without a
restart (inner _sweep_snapshots_locked drops only the tar).

H7. sweep() ends with inner.sweep() (1912), which deletes a record that
became collectable during the drain without the two-phase delete: the
container keeps running until reconcile, its egress policy stays until the
daemon's own reconcile, its GuestRecord and pool port stay for the life of
the process, quota is freed early.

H8. The gnu timeout wrapper has no -k (1427): a command that ignores SIGTERM
runs past its limit; the client gives up at N+15 s and reports 137, the
process goes on in the room (extends B41 to images that have timeout).

H9. _guests is a plain dict read by capabilities_dind (1063), close (1972)
and _reconcile_locked (1875) while request threads add and pop entries.
Python raises RuntimeError when the size changes during iteration; status()
then fails without a JSON answer, reconcile aborts the sweep.

H10. exec rewrites argv[0] "bash" to "sh" for every image (1418-1419);
start_process keeps "bash" (1496). Bash features fail under dash on Debian
based images via exec; bash is required via start_process on Alpine.

H11. _switch_policy applies to the daemon before the inner state check
(1686 before 1689). A frozen room's policy changes while the API answers 409
and keeps the old mode.

H12. Every docker call runs inside the request thread with long timeouts
(pull 600 s, build 900 s, push 1800 s, prefetch 1000 pulls); ThreadingHTTPServer
has no thread cap; Caddy cuts the client at 15 min while the hotel goes on.

H13. _registry_env leaves plaintext registry credentials on the data volume
if the process dies during a pull or push.

H14. The storage-opt retry (600-615) drops the rootfs size limit after any
first failure, not only a driver refusal.

H15. The named-snapshot store (1000) and the create pacing are per hotel,
shared by every guest of a shared hotel; one guest can fill the store.

H16. is_dind_image runs after the pull (1287 then 1302): a docker:dind
create pulls for up to 600 s and then gets 403.

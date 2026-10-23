# Catalog E: sandbox_api.py + sandbox_provider.py (PR #311, commit 22e7824)

Scope: cathedral/sandbox_api.py (1173 lines), cathedral/sandbox_provider.py (1689).
Context read: sandbox_server.py (routing, handlers, listener, ws, openapi),
sandbox_guest.py (DockerGuestProvider, the delegating wrapper over _inner).

Deployment facts that set the blast radius:
- Each hotel (room-kit profiles/v1.sh line 52) is installed with ONE key:
  `CATHEDRAL_SANDBOX_KEYS=<key>:<customer>:<slots>`. So a shipped hotel's
  provider holds a single api_key.
- The broker (broker/hotels.go) stores one hotel key per hotel and forwards
  every broker-guest's request under that single key. So on a SHARED hotel the
  provider cannot tell two broker-guests apart (same bearer); isolation between
  guests on a shared hotel is the broker's job, not the provider's.
- The provider is nonetheless written multi-tenant: `_assert_owner` BOLA guard,
  per-key subquota, list scoping, owner-scoped templates/tickets/logs. The
  "cross-key" hazards below are holes in THAT contract; they bite any provider
  configured with >1 key (supported by parse_sandbox_keys /
  provider_from_environment; exercised by tests/test_tenant_authz.py).

---

## sandbox_api.py — contracts, validation, pure decision functions

Module constants (trusts: process env, read live):
- CATHEDRAL_API_URL/REGISTRY/SANDBOX_API_BASE (35-38). No side effects.
- Resource bounds (65-67): VCPU 1-16, MEMORY_GIB 1-64, DISK_GIB 5-100.
- TTL (70-72): default 3600 s, max 48*3600 s, GC grace 300 s.
- Fork (74-75): FORK_MAX_COUNT 16, FORK_SLO 15 s.
- Snapshot (80-82): default 7 d, max 30 d, MIN_SNAPSHOTS 1000.
- Project minimums (85-91).
- Regexes (94-112): idempotency key `[A-Za-z0-9._:-]{8,128}`; `_NON_PUBLIC_V4`
  reserved nets; label key/value; `_IMAGE_REF_RE`; `_TEMPLATE_UID_RE`.
- EXEC_MAX_TIMEOUT_SECONDS 14400 (636); STDOUT cap 16 MiB, floor 10 MiB (648-649);
  PROCESS_LOG_RETENTION_HOURS 24 (650).

`_configured_key_quotas` 41-56 / `key_quota_for` 59-61
- Purpose: per-key max_running from CATHEDRAL_KEY_QUOTAS / FACADE_KEY_QUOTAS.
- Trusts env string `key:limit,...`; silently skips malformed pairs.
- Invariant: env-set caps override the key store's max_running.

`SandboxContractError` 115-121 / `_require` 124-126
- Stable (code, message) raised on contract violation. `_require` is the guard.

`ImageSource` 131-183
- Trusts caller `image` string. `__post_init__`: template UID short-circuits
  (no further checks); else must match `_IMAGE_REF_RE` (registry?/repo/:tag|@digest,
  each part starts alnum so a leading `-` cannot read as a docker flag, B43);
  rejects `://` scheme; validates resolved_digest and registry_auth shape.
- `tag`/`digest` re-run the regex; `to_document` hides auth (bool only).
- Invariant: a mutable tag is allowed here; digest is pinned later by the mirror.

`BuildSpec` 187-212
- Trusts dockerfile + (context_tar_url xor multipart). `content_hash` = sha256 of
  dockerfile + "\0" + (url or "multipart"). NOTE: multipart contexts all hash to
  the literal "multipart", so two different multipart bodies collide on the build
  cache key (image reuse keyed on content that excludes the actual bytes).

`Resources` 217-241
- Bounds vcpu/memory_gib/disk_gib; bool rejected; gpu optional >=0.

Network grammar 247-365
- `NETWORK_MODES` {public,none,allowlist,internet,deny_all}; `public`->`internet`.
- `canonical_network_mode` 253-255.
- `normalize_allow_entry` 258-321: trusts one allowlist string. Lowercases,
  strips trailing dot. host:port only 80/443 for NAMED hosts (IP:port refused);
  CIDR/IP must be v4 and not overlap `_NON_PUBLIC_V4` (B46); hostname labels via
  `_HOST_LABEL_RE`, numeric TLD refused. Returns canonical form.
- `canonical_network_policy` 324-329: mode + sorted/unique/normalized allow
  (allow emptied for every mode except allowlist).
- `network_policy_sha256` 332-335: sha256 of canonical JSON (sort_keys, no spaces,
  utf-8).
- `_validate_network` 338-350: mode in set; <=256 entries; allowlist needs >=1;
  non-allowlist entries only length-checked (dropped later).
- `NetworkSpec` 354-365 default mode "public".

`_validated_labels` 369-381 — key/value regex, value may be "".

`CreateSandboxRequest` 385-475
- Trusts the whole decoded create body. `__post_init__`: exactly one source
  (image|build|snapshot_id); count 1..16; ttl 1..48 h; idle_timeout 1..48 h;
  env str->str; labels validated; entrypoint a non-empty argv of strings.
- Props: is_fork (snapshot + count>1), total_vcpu/memory (×count).
- `to_document` 451-475 is the admission record: source, resources, network,
  ttl/idle, labels, env_keys (names only, §3.17), entrypoint.

`SnapshotRecord` 480-502 — id, size_bytes>=0, ttl>=1, created_at, name, labels.
  NOTE: carries NO api_key / owner. (Root of hazard H1.)

`ForkPlan` 506-514 — snapshot_id + count 1..16.

Quota 519-593
- `QuotaLimits` 519-534, `QuotaUsage` 538-548 (`within`), `QuotaDecision` 552-560.
- `evaluate_quota` 563-593: projects usage+request; project-wide full -> 429
  retry_after 1 `project_quota_exhausted`; then per-key cap (env first, else
  key_max_running) measured against key-scoped `owned` usage -> 429
  `key_subquota_exhausted`; else admit 202. Pure function.

Lifecycle 597-610
- `is_collectable` 597-605: now>=deadline, OR (if heartbeat given) idle beyond
  TTL_MAX. Provider always passes heartbeat=None.
- `gc_deadline` 608-610: expires_at + 300 s.

Idempotency / ops 614-630
- `validate_idempotency_key` 614-620.
- `operation_id` 623-624: `op_` + 16 hex (64 bits).
- `idempotency_digest` 627-630: stable key from request content; PURE, no tenant
  salt -> identical bodies across tenants produce identical keys (feeds hazard H2).

Exec contracts 636-717
- `exec_max_timeout_seconds` 639-646: env override, floor 1, default 14400.
- `_validated_env` 653-659.
- `_validated_abs_path` 662-668: must start "/" and have no `..` component.
  Does NOT reject trailing slash, embedded NUL, or single-dot segments.
- `ExecRequest` 672-717: cmd shell-string OR argv list; cwd abs; env/user/timeout/
  stdin. `is_shell` 711; `argv` 715-717 maps a shell string to `("bash","-c",cmd)`
  (guest layer rewrites bash->sh). timeout None is allowed (unbounded in the
  in-memory `_run`; the guest defaults to 60 s).
- `ExecResult` 721-741, `ProcessHandle` 745-751, `ExecRecord` 754-770.

Files 775-847
- `FilePut` 775-784 (abs path, octal mode), `FileGet` 788-807 (abs path, max_bytes,
  closed Range), `TarPut` 811-817, `TarGet` 821-834 (exclude wins over include),
  `StatResult` 838-847.

Network patch / expose 852-887
- `NetworkPatch` 852-863 (same validation as NetworkSpec), `ExposeRequest`
  870-878 (port 1..65535), `ExposeResult` 882-887.

Images 892-924
- `PrefetchRequest` 892-911 (<=1000 refs, each `_IMAGE_REF_RE`, auth kept out of
  repr), `ImageStatus` 915-924.

Observability 929-991
- `Metrics` 929-949; `StatusReport` 953-991 (region, runtime, kernel_isolation,
  dind, disk_enforced, network_allowlist_enforced defaults = reference truth).

Auth / pricing / misc 996-1108
- `ApiKey` 996-1013 (key, project, max_running>=0, revoked).
- Pricing constants 1021-1029; `Pricing` 1033-1078 (`cost_usd` rounds to 6,
  `reference_comparisons`).
- `snapshot_gib_months` 1081-1085: bytes/1024^3 × seconds/(720 h). Units consistent.
- `parse_byte_range` 1093-1108: `bytes=a-b` -> closed interval; unsatisfiable ->
  range_not_satisfiable; absent/missing-end tolerated.

---

## sandbox_provider.py — InMemorySandboxProvider (the runnable control plane)

`_now` 73-74 UTC aware. `SandboxOpError` 77-85 (code, http_status, retry_after).
`_Sandbox` 88-115 dataclass: holds api_key (owner), processes, exec_history,
container_stdout/stderr, exposed, idle fields.
`SandboxProvider` Protocol 118-173: the dispatch surface the server calls.

`InMemorySandboxProvider.__init__` 179-231
- Trusts constructor args / env (CATHEDRAL_SANDBOX_REGION). Creates `self._lock`
  (RLock), a tempdir base, and the in-memory maps: _sandboxes, _snapshots,
  _operations, _images, _idempotency, _log_tombstones, tickets/terminals/templates,
  per-key create buckets. `_ctx` is thread-local tenant context.
- Invariant assumed: every mutating method takes `_lock`; caller key comes from
  the thread-local set by authorize()/create().

Helpers 234-347
- `_caller_key` 234-235: thread-local api_key (None in permissive mode).
- `_host` 237-249: `_validated_abs_path` then resolve under root; raises
  path_escape if outside. Used by disk accounting and as a pre-check before
  `_open_beneath`.
- `_assert_owner` 251-261: BOLA guard. If caller set and sandbox.api_key set and
  differ -> 404. Trusts the thread-local. Invariant: a keyed caller only sees its
  own sandboxes. (Snapshots/usage/quota do NOT call this — hazards H1/H3.)
- `_require_active` 263-270: 404 on missing/deleted/deleting; then _assert_owner.
- `_require_running` 272-287: active + not frozen (409) + running/creating.
- `authorize` 289-292 / `_auth` 294-308: revoked -> 403; strict mode unknown ->
  401; sets thread-local. §3.14.
- `_disk_bytes` 310-315: sum of regular-file sizes under root via rglob (follows
  symlinks via is_file; expensive full-tree walk).
- `_assert_disk_room` 317-339: only when enforce_disk. used=_disk_bytes minus the
  replaced file; limit=disk_gib×1024^3; over -> 413. Caller holds _lock.
- `_touch` 341-347: stamp last_activity_at. Caller holds _lock.

create / fork 350-507
- `create` 350-373: holds _lock for the whole op. _auth, set ctx, idempotency
  check (replay on match, 409 on body mismatch), `_create_locked`, record latency,
  store idempotency. Side effects: filesystem (materialize), maps.
- `_create_locked` 374-440: per-key create pacing (trailing 60 s bucket, fork
  counts as N); `evaluate_quota` (project + key subquota); snapshot lookup by id
  OR name; image allowlist env check; materialize N sandboxes; record create
  times. Trusts request + api_key. Holds _lock (via caller). Note: snapshot lookup
  here is NOT owner-checked (hazard H1).
- `_image_id_for` 442-476: build -> content-hash id; template ref -> OWNER-checked
  (404 if not caller's, 409 if not READY) then returns image_ref; plain image ->
  cache setdefault + random img id.
- `_materialize` 478-507: mkdir root/work, unpack snapshot tar into work (UNDER
  _lock), build _Sandbox with api_key=owner, state "running". Side effects: disk.

read / wait 510-558
- `get` 510-512, `wait` 514-526 (polls out of lock, 408 on timeout), `_get_doc`
  528-558 (serialises sandbox + live `_disk_bytes`).

exec / processes 561-662
- `_guest_env` 562-573 (static): PATH/HOME/LANG/TERM + sandbox.env + request.env;
  host CATHEDRAL_* NOT inherited.
- `_run` 575-597: real `subprocess.Popen` argv, cwd root/work (or request.cwd),
  start_new_session, communicate(timeout). On TimeoutExpired kills the process
  GROUP (SIGKILL) and keeps the sandbox. Returns rc/out/err/timed_out/duration.
  Runs OUTSIDE _lock. Trusts argv from ExecRequest; timeout None => unbounded.
- `exec` 599-625: _require_running under lock, run out of lock, cap out/err at
  16 MiB with truncated flag, then under lock update metrics + exec_history +
  container buffers. Side effects: subprocess, disk (child writes), maps.
- `start_process` 627-640: Popen detached, stdout->`.process-<pid>.log` in root
  (NOT disk-checked), under lock. Keeps (Popen, logpath).
- `process_logs` 642-648 / `stop_process` 650-662: owner via _require_active;
  stop SIGTERMs the process group.

files / tar / stat 664-751
- `write_file` 664-676: under lock _require_running + _touch + _assert_disk_room;
  then OUTSIDE lock `_host` pre-check and `_open_beneath` (O_NOFOLLOW per
  component) + fchmod. Disk check and write are NOT atomic (TOCTOU on accounting).
- `read_file` 678-699: owner under lock; `_open_beneath` O_RDONLY; max_bytes over
  size -> 413; inclusive Range slice.
- `write_tar` 701-716: pre-check compressed size; extract via `_safe_extract`;
  post-check extra_bytes=0. On post-check 413 the extracted bytes REMAIN on disk
  (no rollback) — see hazard H5.
- `read_tar` 718-736: gzip a directory, exclude wins over include.
- `stat` 738-751: `_open_beneath`, fstat, mode & 0o7777.

snapshot / fork primitives 754-839
- `snapshot` 754-794: ttl 1..30 d; under lock sweep expired, name get-or-create
  (scans ALL snapshots by name — NOT owner-scoped), store cap 1000 -> 429,
  _require_active (owner of the SOURCE sandbox is enforced), tar root/work to
  base/<snap>.tar.gz UNDER _lock, build SnapshotRecord (no owner), record op.
- `_sweep_snapshots_locked` 796-806: drop snapshots past their own ttl (unlink tar).
- `list_snapshots` 808-826: label filter only; NO owner filter (hazard H1).
- `delete_snapshot` 828-834: pop by id; NO owner check (hazard H1).
- `_unpack_snapshot` 836-838: `_safe_extract` tar into root/work.

lifecycle / GC 841-1013
- `heartbeat` 841-851: owner; ttl 1..48 h; reset expires_at; touch.
- `delete` 853-872: idempotent; terminate processes; state deleted; retain logs;
  rmtree; drop record. Destroys everything but the 24 h log tombstone.
- `_retain_logs` 874-899: tombstone with stdout/stderr/exec_history/metrics/labels/
  resources/created/deleted/api_key/retained_until (deleted_at + 24 h).
- `logs` 901-928: live -> owner-checked; else tombstone, 404 past retention,
  owner-checked via tomb api_key (B12).
- `sweep` 930-953: collect past-TTL/idle/revoked sandboxes (rmtree UNDER lock),
  drop expired tombstones. Returns count.
- `_is_collectable_locked` 955-972: past_ttl OR idle_expired OR owning key revoked.
- two-phase delete for the guest wrapper: `collectable_ids` 979-983,
  `begin_delete` 985-997 (state "deleting", retain logs), `finish_delete`
  999-1008, `has_record` 1010-1013.

list / bulk delete 1016-1048
- `list` 1016-1030: owner-scoped (skips other keys), hides "deleting", state +
  label filter. (This is the scoping that usage/quota omit.)
- `bulk_delete` 1032-1048: requires a label filter (else SandboxContractError);
  owner-scoped target selection; delegates to `delete`.

network / expose 1051-1063
- `set_network` 1051-1056: owner via _require_running; record mode/allow (memory
  runtime does not enforce egress).
- `expose` 1058-1063: url `https://<id>-<port>.<host>`.

freeze / thaw 1066-1118 — SIGSTOP/SIGCONT background processes; state frozen/running.

Agent IDE (tickets/terminals/templates) 1121-1332
- `mint_access_ticket` 1121-1134 owner; `consume_access_ticket` 1136-1140 +
  `_consume_ticket` 1142-1146 bind ticket to its sandbox, single use.
- terminals 1148-1258: create/list/delete/connect/write/read, all gated by
  _require_running/_require_active (owner). `terminal_write` runs exec OUTSIDE the
  lock after buffering lines.
- `publish_template` 1260-1293 stores owner_api_key; `list_templates` 1295-1307 and
  `get_template` 1309-1317 are OWNER-scoped. `desktop` 1319-1332 env-gated.
  (Templates are owner-scoped; snapshots are not — the asymmetry is the tell.)

images / quota / usage / status / ops 1335-1499
- `prefetch` 1335-1341 global `_images` cache; `image_status` 1343-1350 reads the
  global cache (no owner).
- `_usage_now` 1353-1369: resident (running/creating/frozen/deleting), optionally
  key-scoped. Used for quota math.
- `quota` 1371-1394: GLOBAL counts (no caller scope) + snapshot store + pacing.
- `usage` 1396-1454: bills actives + tombstones, grouped by a label; NO caller
  scope (hazard H3). Sweeps snapshots and bills snapshot GiB-months.
- `status` 1456-1470: p50 of the UNBOUNDED `_create_latencies_ms`, error rate.
- `get_operation` 1472-1477: by op id (64-bit random); NO owner scope.
- `close` 1480-1490 / `pricing` 1492-1499.

module helpers 1502-1680
- `_open_beneath` 1502-1534: open root/path one component at a time, every hop
  O_NOFOLLOW below a dirfd; make_dirs creates intermediate dirs; a link anywhere
  -> path_escape. Closes the check-then-open gap (B38). Trusts `path` already
  `_validated_abs_path`. Empty path opens ".".
- `_render_cmd` 1537-1538; `_parse_label_filters` 1541-1549 (`k=v` or bare `k=""`);
  `_host_of` 1552-1553.
- `_child_peak_rss_bytes` 1556-1565: RUSAGE_CHILDREN.ru_maxrss, bytes on darwin,
  ×1024 on linux. NOTE: process-wide across ALL children, so one exec's peak can
  bleed into another sandbox's reported memory_peak.
- `parse_sandbox_keys` 1568-1596: `key:project[:max_running]` CSV; revoked set from
  CATHEDRAL_SANDBOX_REVOKED_KEYS; a non-int max_running silently becomes None
  (unlimited). Colons inside a key/project mis-split.
- `provider_from_environment` 1599-1634: CATHEDRAL_SANDBOX_QUOTA `running:vcpu:mem`
  (3 ints else defaults 500/1000/3000), keys from CATHEDRAL_SANDBOX_KEYS,
  require_known_keys=True, enforce_disk=True. A malformed quota string silently
  grants the large DEFAULT quota.
- `_safe_extract` 1637-1672: reject member/link names that are absolute or contain
  `..`; resolve dest within base; extract with filter="data" (3.12+); on <3.12
  extract file/dir only and refuse links. Fail closed.
- `ImageStatusLike` 1675-1680.

---

## Hazards (code that trusts something it did not check)

H1. Snapshots have no owner (api.SnapshotRecord 480; provider snapshot 754,
    list_snapshots 808, delete_snapshot 828, create fork lookup 408-419). A key
    may fork ANY snapshot by id or by human NAME, list every key's snapshots, and
    delete any snapshot. `_assert_owner` is never consulted on the snapshot path,
    unlike templates. In a >1-key provider this is cross-key filesystem
    exfiltration (fork unpacks the other tenant's /work), enumeration, and
    deletion. Latent on a single-key hotel.

H2. Idempotency store keyed by the Idempotency-Key string ALONE, never scoped by
    api_key and never pruned (provider 199, 354-371; api.idempotency_digest 627
    has no tenant salt). Same key + identical body from a second key replays the
    first key's sandbox document (id, labels, state) and suppresses the second
    key's create. Replay window is unbounded (map grows forever).

H3. quota() 1371 and usage() 1396 are not caller-scoped, though the thread-local
    caller is available and list() 1016 uses it. On a multi-key provider, any key
    reads every key's resident counts (quota) and every key's label values, hours
    and dollar cost (usage). get_operation 1472 and image_status 1343 are likewise
    global (guarded only by unguessable ids / shared cache).

H4. _run 575 trusts ExecRequest.timeout None and blocks forever (no cap) in the
    in-memory provider; only the guest layer defaults to 60 s. Not the shipped
    customer path, but the reference/fallback provider can hang a worker.

H5. Disk enforcement is partial and non-atomic: write_file 664 checks under lock
    then writes out of lock (TOCTOU); write_tar 701 extracts first and only then
    rechecks, leaving the over-quota bytes on disk; exec/start_process child
    writes and the snapshot tars in `self._base` are never counted. `_disk_bytes`
    walks the whole tree under the lock on every write (stall). Extends B40.

H6. Lock-held heavy IO: _materialize 478 (snapshot untar) and snapshot 754 (tar of
    /work) run under the global RLock, so one tenant's large fork/snapshot
    serialises every other tenant's call. sweep 930 rmtrees under the lock too.

H7. Metric bleed: _child_peak_rss_bytes 1556 reads process-wide RUSAGE_CHILDREN,
    so memory_peak_bytes for sandbox A can reflect sandbox B's child.

H8. Operator footguns: parse_sandbox_keys 1568 turns a bad max_running into
    "unlimited"; provider_from_environment 1599 turns a malformed
    CATHEDRAL_SANDBOX_QUOTA into the large default quota; BuildSpec.content_hash
    203 collapses all multipart contexts to the same cache key.

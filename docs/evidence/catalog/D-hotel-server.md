# Catalog D: hotel server surface (sandbox_server, agent_websocket, agent_rfb, agent_interactive)

Commit 22e7824 (PR #311 head), frozen copy /private/tmp/claude-501/r6.
Scope: the Python HTTP control plane a hotel runs (`cathedral sandbox serve`),
its WebSocket terminal/desktop paths, and the Agent IDE value types. Context
read: room-kit/profiles/v1.sh, room-kit/install.sh, cathedral/sandbox_api.py,
and the two providers (sandbox_provider.py in-memory, sandbox_guest.py docker)
plus the broker (Go) and room_receipts.py as the consumers in front.

Deployed shape: Caddy :443 (TLS-ALPN, 15 m read/write) -> room_receipts.py
proxy (signs create/exec/delete) -> this API on 127.0.0.1:ROOM_API_PORT. The
broker holds one hotel key per hotel and dials the hotel's public URL. A
customer never holds a hotel key; the broker and ops do.

## Server model (facts)

- `ThreadingHTTPServer` (stdlib). One OS thread per connection, `daemon_threads=True`, unbounded thread count. `request_queue_size` = socketserver default 128 (listen backlog); not overridden.
- `_Handler` does NOT set `protocol_version`, so it is HTTP/1.0: the connection closes after each response (no server keep-alive). room_receipts.py's own handler sets HTTP/1.1 + `request_queue_size=1024`.
- `_Handler.timeout` = None (stdlib default). No per-connection socket read timeout on the API. Only the two WS loops call `self.connection.settimeout(120.0)`. A slow client on the request path blocks its thread with no timeout (bounded in prod by Caddy's 15 m and the proxy's 1800 s dial timeout).
- Header/line size bounded by stdlib: `http.client._MAXLINE`=65536, `_MAXHEADERS`=100 -> 414/431 before the handler runs.
- Body: `_Handler._run` reads exactly `Content-Length` bytes into memory with no per-route cap (`self.rfile.read(length)`). Negative/junk Content-Length: `int(...,)` either reads to EOF (`-1`) or raises (non-numeric, uncaught). The broker caps room bodies at 256 MiB (create at 1 MiB); the API itself does not. (This is B54's "body limits per route pending".)
- Under 1,000 concurrent execs: 1,000 threads. `exec` runs the child OUTSIDE `provider._lock` (provider.exec takes the lock only to read the record, releases, runs, re-takes to append history), so execs proceed in parallel; every list/get/create/heartbeat serialises on one RLock briefly. No concurrency cap, no admission queue in the API (create pacing is per-key count/min, not in-flight). Thread-per-conn + no cap is the ceiling.
- Auth: `_authenticate` parses `Authorization: Bearer <k>`, case-insensitive header, `startswith("bearer ")`. The key is passed to `provider.authorize`. The in-memory provider compares keys by dict lookup (`self._keys.get`), NOT constant-time; revoked -> 403, unknown -> 401 in strict mode. room_receipts.py (the receipt front) DOES use `hmac.compare_digest`. Multi-key via `parse_sandbox_keys` (`key:project:max_running`, comma-separated). Per-key ownership via `_assert_owner` (BOLA guard: foreign sandbox reads as 404).
- Unauthenticated reach: only `/openapi.json` (GET, in `PUBLIC_PATHS`). Every WS upgrade (`do_GET` + `Upgrade: websocket`) bypasses `_authenticate` but is gated by a single-use access ticket that only the owner can mint. There is no health route on the API itself (health is a separate unit/port fronted by Caddy `/room/health`). No attestation route on the API (that lives in room_receipts.py).

## sandbox_server.py

Module-level
- `reaper_interval_from_env` L52-60: reads CATHEDRAL_SANDBOX_REAPER_SECONDS; 0 disables. Trusts env. No lock. Caller: cli.cmd_sandbox_serve.
- `_json_default` L64-69: json fallback for MappingProxy/datetime. Pure.
- `Response` L72-89 + `.json/.error/.no_content`: response record; `json.dumps(default=_json_default)`. Pure.
- `_body_digest` L92-93: sha256 hex of the raw body; feeds idempotency replay equality.
- `_allow_list` L96-101: coerce allow to tuple; raises SandboxContractError if not list/tuple. Trusts caller list.
- `_network_spec` L104-112: build NetworkSpec from dict|str|None; raises invalid_network_mode otherwise.
- `_create_request` L115-139: **the hazard site.** Builds CreateSandboxRequest from the JSON dict. `Resources(**payload["resources"])`, `ImageSource(**payload["image"])`, `BuildSpec(**payload["build"])`, `tuple(payload["entrypoint"])`. Trusts the client dict shape. Extra/typed-wrong fields raise bare TypeError/ValueError, NOT SandboxContractError. No lock. Caller: `create`.
- `_CODE_STATUS` L143-153: contract-code -> status map (default 400).
- `_require_param` L640-644: required query param or invalid_path 400.

Class `SandboxApplication`
- `__init__` L160-166: provider + require_auth, registers routes, prepares reaper thread handle + stop Event.
- `start_reaper`/`stop_reaper`/`reaper_running` L169-199: daemon thread calling `provider.sweep()` every N s; a failed sweep is logged to stderr and the loop continues. Lock: Event only. Invariant: sweep is thread-safe (provider takes its own lock).
- `_sweep_inline` L201-211: before a read, call `provider.mark_expired()` if present AND the reaper runs, else `provider.sweep()`. In-memory provider has no mark_expired -> always full sweep inline. Docker provider has mark_expired (fast, no docker calls). Callers: list/get/quota.
- `_add`/`_register` L214-271: compile `^pattern$` per route; register all REST verbs. Trusts the route table. `image_lookup` route is `/v1/images/(?P<ref>.+)` -> ref may contain `/` and `..` (dict lookup in-memory; docker image_status shells out but B43 quoting is fixed).
- `dispatch` L273-285: urlparse, parse_qs(keep_blank_values), match method+path, mark public, invoke. Returns 404 route_not_found otherwise. Invariant: a matched handler either returns a Response or raises one of the 4 caught types.
- `_invoke` L287-301: authenticate (unless public), `unquote` path params, call handler. Catches SandboxContractError, SandboxOpError, AfflineRerunError, json.JSONDecodeError ONLY. **Any other exception (TypeError/ValueError/KeyError) propagates out** -> no HTTP response written -> connection drop. This is the error-mapping gap. Does NOT leak tracebacks to the client (they go to stderr via socketserver), but also does not return a 400/500 body.
- `_authenticate` L303-312: Bearer parse; `provider.authorize(api_key)`. Non-constant-time key compare downstream (in-memory). Returns the key (thread-local tenant context set inside `authorize`).
- `_json` L314-316: `json.loads` or {} for empty body. Raises JSONDecodeError (caught).
- Handlers L319-637 (each takes query/headers/body/api_key + path params):
  - `create` L319-323: `_create_request` (hazard) -> provider.create -> 202. Reads Idempotency-Key header. Trusts body shape.
  - `list_sandboxes` L325-330: `_sweep_inline`, provider.list(label,state). Scoped to caller key in the provider.
  - `bulk_delete` L332-337: requires a `label` filter (else invalid_label 400); provider.bulk_delete. Scoped to caller key in provider.
  - `get_sandbox`/`delete_sandbox`/`patch_sandbox` L339-349: sweep-before-read; delete is idempotent 204; patch heartbeats ttl.
  - `wait` L351-354: `int(payload.get("timeout_seconds",120))` — non-int -> uncaught ValueError (room path -> 502 to that guest only).
  - `exec_` L357-371: `cmd` required; `tuple(cmd)` when not str -> `tuple(123)` TypeError uncaught (room path -> 502). Builds ExecRequest (validates timeout/env). provider.exec.
  - `start_process` L373-378, `process_logs` L380-381, `stop_process` L383-385, `attach_unsupported` L387-389 (501).
  - `put_file` L392-397: `int(mode_raw,8)` — bad octal -> uncaught ValueError (room path -> 502). path from query.
  - `get_file` L399-417: `int(max_bytes_raw)` — bad -> uncaught ValueError. Range parsed via api.parse_byte_range (416 on unsatisfiable). 206 on range, 200 else. Content-Length set from len(data).
  - `put_tar`/`get_tar`/`stat` L419-433: path from query; tar extract is in the provider (`_safe_extract`, fail-closed).
  - `snapshot` L436-446, `_store_idempotent_snapshot` L448-450 (no-op), `list_snapshots` L452-453, `push_snapshot` L455-461 (501 if unsupported), `delete_snapshot` L463-465.
  - `heartbeat` L468-470: ttl via provider (validates 1..48h).
  - `set_network` L473-480: **requires `mode` be a str** (B15 fix) else invalid_network_mode 400; NetworkPatch validates allow.
  - `expose` L482-484.
  - `freeze`/`thaw` L487-491.
  - `mint_access_ticket` L494-496: provider mints a single-use ticket bound to the sandbox; owner+running enforced in provider.
  - `create_terminal`/`list_terminals`/`delete_terminal` L498-510.
  - `connect_terminal` L512-517: ticket from body or `?ticket=`; required. provider consumes ticket (sandbox-bound, single-use).
  - `terminal_write` L519-524 / `terminal_read` L526-527: REST PTY; write requires connected, read requires active (owner).
  - `publish_template`/`list_templates`/`get_template` L529-548: templates scoped by owner_api_key.
  - `desktop` L550-551: gated by CATHEDRAL_AGENT_DESKTOP.
  - `logs` L554-555.
  - `prefetch` L558-568, `build_image` L573-590 (`BUILD_CONTEXT_MAX_BYTES`=256 MiB checked AFTER full base64 decode; raw b64 body up to ~342 MiB read first), `image_lookup` L592-593.
  - `quota` L596-598 (sweep-before), `usage` L600-607, `status` L609-610.
  - `affline_validate_rerun` L612-629: reads `provider._keys` to resolve the caller's project; delegates to affline_rerun (own body cap 512 KiB, trigger-secret gate). Bearer + optional X-Cathedral-Affline-Trigger.
  - `get_operation` L631-632, `openapi` L634-637 (public).
- OpenAPI builders L648-799: static doc; pure.

Class `_Handler(BaseHTTPRequestHandler)`
- `_run` L806-816: read Content-Length body (no cap), dispatch, write status+headers+Content-Length+body. Sets no socket timeout. An exception from dispatch propagates (no response). Caller: do_* verbs.
- `do_GET` L818-822: routes `Upgrade: websocket` to `_handle_websocket` BEFORE auth; else `_run("GET")`.
- `do_POST/PUT/DELETE/PATCH` L824-834.
- `log_message` L836-838: access log only when CATHEDRAL_SANDBOX_ACCESS_LOG=1 (address + format). No secrets.
- `_ws_fail` L840-846: JSON error for a failed upgrade.
- `_handle_websocket` L848-878: parse path/query, extract ticket (`ws.extract_access_ticket`), require Sec-WebSocket-Key, dispatch terminal vs desktop regex, else 404. **No Origin check.** No api-key auth (ticket is the credential). Trusts: ticket string, Sec-WebSocket-Key.
- `_ws_terminal` L880-937: consume ticket via `connect_terminal` (sandbox-bound, single-use) in a try/except SandboxOpError -> _ws_fail; send 101 with `Sec-WebSocket-Protocol: cathedral.ticket.<ticket>` (echoes the ticket back in a header); push banner; loop recv(4096) with 120 s socket timeout; decode frames; on TEXT/BINARY newline-terminate and `terminal_write` then `terminal_read`. **The loop body's `terminal_write`/`terminal_read` are NOT wrapped; the outer except catches only (TimeoutError, BrokenPipeError, ConnectionResetError, OSError), so a SandboxOpError (sandbox ended mid-session) propagates and kills the thread.** No per-connection process to clean up (reference PTY runs exec synchronously). Tenant context is NOT set for this thread, so provider owner checks are no-ops here — safe only because the ticket already bound the sandbox.
- `_ws_desktop` L939-1025: require CATHEDRAL_AGENT_DESKTOP=1 (else 404) and ticket; `consume_access_ticket` (full ticket, single-use, sandbox-bound); 101; RFB version/security/VNC-challenge state machine; `verify_vnc_response(challenge, resp, ticket)`. The VNC password is the FULL ticket but DES uses only its first 8 bytes (`sat_`+4 chars) — redundant, since consume already required the full ticket. Same unguarded-exception shape as terminal (though desktop calls only agent_rfb pure helpers after consume, so less exposed). 120 s socket timeout.
- `serve`/`run` L1028-1042: bind ThreadingHTTPServer with a per-app handler subclass; return httpd (+address). Caller drives serve_forever.

## agent_websocket.py (RFC 6455 helpers, stdlib)
- `accept_key` L21-23, `handshake_response` L26-37: Sec-WebSocket-Accept; optional subprotocol. Pure.
- `encode_frame` L40-60: server frames unmasked; length 7/16/64-bit. Pure. No max-frame guard (server trusts its own payloads).
- `decode_frames` L63-99: parse frames from a bytearray; handles 126/127 extended length and client mask. **No max-length guard: a client-advertised 64-bit length (up to 2^64) is used to decide "need more bytes"; it does not pre-allocate, but a client can make the server buffer grow to the advertised size before a frame completes.** Bounded in practice by the 120 s recv timeout and recv(4096) chunking, and only reached post-ticket. Returns (frames, remainder).
- `iter_client_handshake` L102-132: client-side request builder (tests/bridges); ticket in header + subprotocol, query only if explicitly allowed.
- `extract_access_ticket` L135-159: prefer `X-Cathedral-Access-Ticket`, then `cathedral.ticket.*` subprotocol, then `?ticket=` ONLY if CATHEDRAL_WS_ALLOW_TICKET_QUERY=1 (else returns error ticket_query_forbidden, so tickets stay out of URLs/logs). Trusts header/subprotocol strings.
- `read_http_response_headers` L162-177: client helper.

## agent_rfb.py (minimal RFB/VNC, stdlib)
- `server_init` L39-41, `framebuffer_update_solid` L44-51, `handle_client_messages` L53-83: consume client RFB messages (FramebufferUpdateRequest/KeyEvent/PointerEvent/SetEncodings/SetPixelFormat), reply with a solid 8x8. `SetEncodings` reads `n` from the client and needs 4+4n bytes; unknown types drop one byte. Trusts client message framing; bounded by the 120 s timeout. Only reached after a valid ticket.
- `_bit_reverse`/`_vnc_password_key` L86-97: VNC DES key = bit-reversed first 8 bytes of the password (the ticket). **Truncates to 8 bytes.**
- DES tables + `_permute/_des_subkeys/_f/_des_ecb_encrypt` L101-223: textbook DES-ECB. Pure.
- `vnc_encrypt_challenge` L226-231, `new_vnc_challenge` L234-235 (os.urandom(16)).
- `security_offer_vnc`/`security_result_ok/fail` L238-248.
- `verify_vnc_response` L251-260: constant-time-ish compare (OR of XORs) of the DES-encrypted challenge. Correct given the 8-byte key caveat.
- `security_handshake_none` L263-267: raises — SecurityType None is disabled (desktop must prove the ticket at the RFB layer).

## agent_interactive.py (Agent IDE value types)
- `utc_now` L23, id mints `new_ticket_id` L27-28 (`sat_`+token_urlsafe(18), ~144 bits), `new_terminal_id` L31-32 (`term-`+hex8), `new_template_uid` L35-37 (slug+hex6). secrets-based.
- `validate_ticket_ttl` L40-44 (1..300 s), `validate_terminal_size` L47-52 (1..1000), `validate_template_name` L55-58 (regex, 1..64). Raise ValueError (provider maps to 400).
- `AccessTicket` L61-79: ticket/sandbox_id/expires_at/consumed; `alive(now)` = not consumed and now<=expires_at. to_document never emits the ticket string back except via the server's subprotocol echo.
- `TerminalSession` L81-105, `SandboxTemplate` L108-136: records with to_document; template carries owner_api_key for scoping.

## Context: sandbox_api.py (request/contract types the server builds)
- `SandboxContractError` L115-122 + `_require` L124-126: the ONLY exception type the dispatcher maps cleanly. Anything that raises outside this (dataclass `__init__` TypeError, `tuple()`/`int()` ValueError) is the error-mapping gap.
- Validated types: `ImageSource` L130-183 (ref regex, no scheme, registry_auth shape; `tag` is a PROPERTY not an init kwarg), `BuildSpec` L186-213, `Resources` L216-241 (int bounds), `NetworkSpec`/`NetworkPatch` L353-365/851-864, `CreateSandboxRequest` L384-475 (exactly one source; ttl/count/env/labels/entrypoint validated in __post_init__ — but only AFTER `_create_request` has already called the sub-constructors), `ExecRequest` L671-717, file/tar/stat specs L774-847, `ExposeRequest` L869-878, `PrefetchRequest` L891-911, `ApiKey` L995-1013, `parse_byte_range` L1093-1108. Allowlist normalisation `normalize_allow_entry` L258-321 rejects IPv6/private/reserved (B46).

## Context: room-kit/profiles/v1.sh
- `profile_exec` L13-15: ExecStart = room_api.py sandbox serve --host 127.0.0.1 --port $ROOM_API_PORT --runtime docker. API binds loopback only.
- `profile_env` L17-48: PYTHONPATH, runtime=docker, QUOTA, REGION, DIND flags, CATHEDRAL_API_URL (loopback), OWNER=$ROOM_ID, ROOM_CREATES_PER_MINUTE (default 100), egress socket, room-network env. Trusts room.env values.
- `profile_keys_env` L51-53: CATHEDRAL_SANDBOX_KEYS=`<key>:$ROOM_CUSTOMER:$SIZE_SLOTS` (one key per hotel, project=customer, max_running=slots).

## Context: room-kit/install.sh (systemd units + guards)
- `log`/`mark`/`fetch` L28-57: helpers; fetch verifies sha before use.
- `refuse_restart_with_rooms` L34-49: counts `docker ps --filter label=cathedral.sandbox.owner`; refuses an install/restart while live rooms exist unless ROOM_RESTART_WITH_ROOMS=1 (B24 phase-1). Fails closed if the room daemon does not answer.
- `write_room_env`/`size_room`/`net_settings` + steps 0-13: build the data volume (xfs prjquota, no nodev), runsc, venv, Caddy, service user, the room docker daemon (iptables/ip6tables off, runsc default), size, key material (api.key 0640 root:poolroom, secret.env 0600, reaper.headers 0600 Bearer), the API unit (User=poolroom, NoNewPrivileges, ProtectSystem=full, PrivateTmp), health, reaper timer (curls /v1/sandboxes every 60 s to drive TTL GC), egress unit (nftables per room, before the API), receipts unit (Level 1 Ed25519 or sealed SNP), Caddy on 443 (TLS-ALPN only, no port 80), host firewall only if it blocks 443.
- Units created: `$ROOM_ID-data.service`, `-docker.service`, `.service` (API), `-health.service`, `-reaper.{service,timer}`, `-egress.service`, `-receipts.service`, `-caddy.service`.

## Hazards (code trusts something it did not check)

1. `_invoke` L287-301 catches only 4 exception types. `_create_request`/`exec_`/`put_file`/`get_file`/`wait` convert client-controlled JSON/query into dataclass kwargs, `tuple(...)` and `int(...)`. A JSON-valid-but-shape-wrong value (e.g. `image:{image,tag}`, `resources:{...,bogus}`, `entrypoint:123`, `?mode=zz`, `?max_bytes=abc`, `timeout_seconds:"x"`) raises bare TypeError/ValueError -> no HTTP response -> connection drop. On the CREATE path the broker reads the drop as `err != nil` and rests the hotel for all guests (Finding 1). On room paths it is a per-guest 502.
2. `_Handler` has no socket timeout and no body cap; `_run` reads full Content-Length into memory. Bounded in prod by Caddy/proxy timeouts and the broker's 256 MiB/1 MiB caps, but the API trusts the front. (B54 pending part.)
3. `_ws_terminal` loop body L924-933 does not guard SandboxOpError; a sandbox that ends mid-session (TTL reaper is routine) kills the WS thread with a stderr traceback and drops the socket without a close frame (Finding 2).
4. WS paths have no Origin check. Safe only because the credential is a ticket in a custom header/subprotocol (no ambient cookie), so a browser cannot forge it; worth stating explicitly.
5. `decode_frames` trusts a client 64-bit frame length with no max; recv-timeout + post-ticket gate bound it. Observation.
6. agent_rfb VNC uses only the first 8 bytes of the ticket as the DES key; redundant because `consume_access_ticket` already required the full ticket. Observation.
7. In-memory provider key compare is a dict lookup, not constant-time (room_receipts.py uses hmac.compare_digest). Timing-oracle risk is low (keys are high-entropy, the front proxy is constant-time). Observation.
8. `self._idempotency` (provider.create) is keyed by the Idempotency-Key string alone, not by (api_key, key). Latent cross-tenant collision, but NOT reachable in prod: the broker never forwards a guest's Idempotency-Key to the hotel, and each hotel key is single-tenant. Observation (disproof below).

# Catalog C: broker core (guests, hotels, state, receipts, probe, placement)

Artifact: cathedral-sandbox 22e7824 (PR #311 head), frozen at /private/tmp/claude-501/r6.
Files: broker/guests.go, broker/hotels.go, broker/state.go, broker/receipts.go,
broker/probe.go, broker/placement.go. Context read: broker/main.go (config,
hotel calls, sync loop, main), broker/README.md, broker/config.example.json,
the broker tests, compat.go and images.go where they call these files.

No shell function or systemd unit lives in these files. The repo has no unit
for the broker (deploy/ holds miner-update and reliquary units only).

Lock names: `b.mu` (broker state, rooms, counters, guest limits), `b.hotelsMu`
(serialises hotel set changes), `b.compat.mu` (client images, idem, execs,
tombs), `b.hset` (atomic pointer to the immutable hotel set), `h.lastAnswer`
(atomic), `b.dirty` (atomic).

## Config (main.go 43-83, 221-256; context)

- `hotelConfig`: id, name, threads, ram_gib, api, health, key_file, concurrency (0: 16),
  drain, labels, sealed, max_slots.
- `guestConfig`: id, key_sha256 (empty: view only), view_token_sha256, ops, plus
  `guestLimits` (max_rooms 0: 1,000; max_creates_per_minute 0: none;
  default_sealed; hotels absent: all).
- `config`: listen (empty: Go binds ":http" on every interface), state_dir
  (empty: nothing persists, runtime join is 409), hotels, guests,
  insecure_cookie, max_exec_seconds (0: 14,400), max_queue_wait_seconds
  (0: 10 s, <0: never move), operator_key_sha256 (empty: no operator routes).
- `loadBroker` 221-256: `json.Unmarshal` with no DisallowUnknownFields. Refuses:
  unreadable config, bad JSON, hotel id empty or with a dot, unreadable key
  file, duplicate hotel id. Accepts: unknown keys (dropped), duplicate guest
  id (second object replaces the first in `b.guests`, both keys stay in
  `b.byKey`), duplicate key hash (second guest wins, first is locked out),
  empty guest id, guest `hotels` naming unknown hotels, `labels.sealed=true`
  without `sealed: true`.
- Keys: guest key compared as `sha256 hex (lowercase)` map lookup in
  `guestFromKey` (406-412); operator key with `subtle.ConstantTimeCompare` in
  `isOperator`; view token constant time in `viewGuest`. Config hashes are
  lower-cased at load (guests) or at compare time (operator, view).
- Hotel key: file contents trimmed, sent as `Authorization: Bearer` on every
  hotel call (`doBase` 275, `getJSON` 301).

## guests.go

| Function | Lines | Purpose | Trusts | Side effects | Locks | Callers | Invariant |
|---|---|---|---|---|---|---|---|
| `guestLimits.maxRooms` | 45-50 | 0 means 1,000 | config | none | none | admit, guestView, handleQuota | MaxRooms is never negative (PATCH refuses <0) |
| `guestLimits.allows` | 53-63 | empty list: every hotel | config, PATCH | none | caller's | limitsAllow, handleHotels, ensureBuilds | list ids are hotel ids (not checked at load) |
| `broker.activeRooms` | 67-77 | pending + running rooms of g over all hotels | room.guest labels from hotels | none | caller holds b.mu | admit, guestView | sync-discovered rooms carry the right `broker_guest` label |
| `broker.admit` | 81-113 | reserve n rooms against max_rooms and the 60 s window | n from the request (1..10,000) | appends n timestamps to g.admits; g.pending += n | b.mu | handleCreate, compatCreate | caller calls unreserve exactly once per admitted room |
| `broker.unreserve` | 116-120 | pending -= n | caller | none | b.mu | handleCreate, compatCreate | paired with admit |
| `writeLimitErr` | 122-127 | 429 with Retry-After | retry seconds | HTTP | none | handleCreate | none |
| `broker.scope` | 131-148 | apply hotel set and sealed default to a placement | guest limits | mutates pl | b.mu while copying limits | parseSelection, compatCreate, build.go:165 | hotels in the request were already checked by limitsAllow |
| `broker.guestView` | 152-163 | operator view of a guest | none | none | caller holds b.mu | handleGuestAdmin, patchGuest | none |
| `broker.handleGuestAdmin` | 165-185 | GET list, PATCH one | operator key | HTTP | b.mu for the list | ServeHTTP (before guest auth) | isOperator is the only gate |
| `broker.patchGuest` | 187-243 | change limits in memory | operator JSON (64 KiB, unknown fields refused) | guest limits change, not persisted | b.mu for the write; hotel ids checked outside the lock | handleGuestAdmin | hotels named exist now (may leave later) |
| `guestState.limitsAllow` | 246-250 | may g use hotel id | limits | none | takes b.mu (never call with b.mu held) | fanout, handleBulkDelete, handleHotelDoc, parseSelection, compatImport, handleProbe | none |
| `broker.anyHotel` | 253-260 | some hotel matches pl | h.cfg.Labels, Sealed | none | none (reads labels unlocked) | compatCreate | labels change only under b.mu (patchHotel); unlocked read |
| `broker.compatImageByID` | 262-267 | image by id | none | none | compat.mu | compatCreate | none |

Rate window math (`admit` 88-110): admits sorted oldest first; entries aged
>= 60 s are cut. Refuse when len+n > limit. Retry-After: the time until the
(len+n-limit)th oldest entry ages out, ceil to seconds, at least 1; 60 when
n > limit (can never pass) or when the window is empty.

## hotels.go

| Function | Lines | Purpose | Trusts | Side effects | Locks | Callers | Invariant |
|---|---|---|---|---|---|---|---|
| `broker.hotelList` | 37-42 | current hotel list | none | none | none (atomic) | everywhere | list is immutable once stored |
| `broker.hotelByID` | 44-49 | hotel by id | none | none | none (atomic) | everywhere | same |
| `newHotel` | 51-65 | build a hotel: concurrency default 16, sealed label forced, one http.Client | config or join request | allocates transport (MaxIdleConns 1024, MaxIdleConnsPerHost and MaxConnsPerHost concurrency+64, IdleConnTimeout 90 s, no dial or TLS timeouts) | none | loadBroker, joinHotel, loadRuntimeHotels | every call sets a context timeout (`do` per call, `getJSON` 10 s) |
| `broker.addHotel` | 68-89 | copy-on-write add | id shape checked again | replaces hset | hotelsMu | loadBroker, joinHotel, loadRuntimeHotels | id unique |
| `broker.dropHotel` | 91-103 | copy-on-write remove | id | replaces hset | hotelsMu | leaveHotel | caller checked emptiness (separate lock section) |
| `broker.startSync` | 106-110 | start syncLoop with a cancel | ctx | goroutine | none | main, joinHotel | h.stop set once |
| `broker.isOperator` | 114-121 | bearer == operator key | header | none | none | handleHotelAdmin, handleGuestAdmin | operator_key_sha256 set, else always false |
| `validURL` | 131-134 | http(s), host, no userinfo | join body | none | none | joinHotel | none |
| `broker.handleHotelAdmin` | 136-151 | dispatch join, patch, leave | operator key | HTTP | none | ServeHTTP (before guest auth) | none |
| `broker.joinHotel` | 153-217 | add a hotel at runtime | operator JSON (1 MiB); id 1-64 chars no dot; key 32+ [A-Za-z0-9_-]; `sealed`, `drain`, `max_slots` also accepted though undocumented | GET /v1/status on the hotel with the key (verify, default on); mkdir state_dir/hotel-keys 0700; write <id>.key 0600; hotels.json rewrite; sync goroutine | hotelsMu via addHotel; b.mu via saveRuntimeHotels | handleHotelAdmin | state_dir set; key file written before addHotel (a refused add leaves the file) |
| `broker.patchHotel` | 219-248 | set drain, replace labels | operator JSON | hotels.json rewrite for runtime hotels | b.mu for the write | handleHotelAdmin | sealed label stays (not re-applied: broken by a PATCH without it) |
| `broker.leaveHotel` | 250-276 | remove an empty runtime hotel | id | drop from set, cancel sync, hotels.json rewrite, remove key file | b.mu for the count; hotelsMu via dropHotel | handleHotelAdmin | no create picks the hotel between the count and the drop (not enforced: drain first) |
| `hotelDoc` | 278-284 | operator view | none | none | none (unlocked read of cfg) | join, patch | none |
| `broker.saveRuntimeHotels` | 290-308 | write hotels.json (tmp + rename, 0600, no fsync) | none | disk | b.mu while copying cfg | join, patch, leave | state_dir exists (join made hotel-keys under it); writes `null` when no runtime hotel remains |
| `broker.loadRuntimeHotels` | 312-340 | re-add runtime hotels at start | hotels.json and key files in state_dir | reads disk, addHotel | hotelsMu via addHotel | main (after loadCaps and loadCompat, before startSync) | key file present; id not already in config (else skipped with a log) |

What "up" means: `h.ok` (main.go 1028) = health answered within 15 s, or
(a room call answered within 15 s and health answered at least once). `pick`,
`noRoomReason`, `handleHotels`, prefetch and the board all read `h.ok`.
Backoff: `backoffUntil` set to Retry-After (default 2 s) on a hotel 429 and
to 10 s on a failed start, 401 or 403; read by pick and noRoomReason; not
persisted. Draining: `cfg.Drain` excludes the hotel from pick and prefetch;
rooms keep routing; noRoomReason counts a drained hotel as down (503).

`h.do` / `doBase` (main.go 260-291, context): URL = base + path + query; sets
Bearer and `Content-Type: application/json` whenever a body is given (also
for raw file and tar bodies); per-call context timeout; `io.ReadAll` of the
answer with no size cap; marks `lastAnswer` on any answer < 500; returns the
raw transport error (it carries the hotel URL). `getJSON` (293-311): 10 s,
non-200 is an error with path and status only, body streamed into the
decoder with no cap.

## state.go

| Function | Lines | Purpose | Trusts | Side effects | Locks | Callers | Invariant |
|---|---|---|---|---|---|---|---|
| `broker.markDirty` | 49 | flag a change | none | none | atomic | register, release, rememberGuestRoom, compat import/idem/delete, build | none |
| `broker.saveLoop` | 51-70 | every 1 s, save if dirty | none | disk, log line per failed second | none directly | main (goroutine, never ends) | the process gets one more tick before it exits (it does not: no signal handling, no final save) |
| `broker.saveCompat` | 73-140 | snapshot UUIDs, guestRooms, finished idem answers, tombs, images; prune > 48 h; tmp + rename 0600; mkdir state_dir 0700; no fsync | in-memory state | disk; deletes stale idem and tombs from memory | b.mu then compat.mu (json.Marshal runs under compat.mu) | saveLoop, tests | whole file rewritten each dirty second; size grows with history (guestRooms, UUIDs) |
| `broker.saveBuildContext` | 143-161 | write one context tar (tmp + rename) | img | disk | caller holds compat.mu | build.go | none |
| `broker.loadCompat` | 164-235 | read the state file | file in state_dir (0600) | fills savedUUIDs, guestRooms, idem (done), tombs, images, reads context files | b.mu then compat.mu | main (logs and continues on error), tests | a corrupt file is skipped, not kept; the next save replaces it |

Persisted: client UUID -> broker room id, guest -> hotel -> room ids, finished
Idempotency-Key answers (status and body), tombstones, images (and contexts
as files), runtime hotels (hotels.json) and their keys, probe caps (caps.json,
mode 0640, plain write). Not persisted: rooms (rebuilt from hotel lists),
hotel ok/slots/backoff, guest PATCH limits, running or finished compat execs,
prefetch jobs, rate windows, latency samples, savedUUIDs for rooms that are
gone at restart (dropped at the next save).

Startup order (main.go 1386-1404): loadBroker -> loadCaps -> loadCompat ->
go saveLoop -> loadRuntimeHotels -> startSync for every hotel -> serve.
loadCaps runs before runtime hotels exist, so their caps are dropped and
the next saveCaps writes caps.json without them.

## receipts.go

| Function | Lines | Purpose | Trusts | Side effects | Locks | Callers | Invariant |
|---|---|---|---|---|---|---|---|
| `broker.rememberGuestRoom` | 15-34 | record guest -> hotel -> room id for the receipt filter | room guest from create or hotel label | memory grows for ever; markDirty | caller holds b.mu | register (create and sync) | empty guest, hotel or id is ignored |
| `broker.guestRoomIDs` | 38-55 | remembered ids plus live rooms of the guest on a hotel | room.guest | none | b.mu | handleHotelDoc | none |
| `filterHotelReceipts` | 62-64 | filter with no bulk-delete owner | body | none | none | tests | none |
| `filterHotelReceiptsFor` | 70-114 | keep receipts whose statement.sandbox_id is owned or whose bulk_delete target names the guest last; set count, filtered, scanned; receipts kept byte for byte | hotel JSON | none | none | handleHotelDoc | top-level object re-encoded (key order changes); `head` left as the hotel's |
| `receiptSandboxID` | 116-129 | statement.sandbox_id as string | hotel JSON | none | none | filterHotelReceiptsFor | a non-string id fails the whole page (502) |
| `marshalRaw` | 131-139 | encode without HTML escaping | value | none | none | filter | none |
| `bulkDeleteGuest` | 143-169 | owner of a bulk_delete receipt: last `label=broker_guest=<g>` in the signed target query | hotel receipt target | none | none | filterHotelReceiptsFor | the broker appends its label last (handleBulkDelete 909) and the hotel applies every label pair (sandbox_provider.list and bulk_delete use `all(...)`), so a forged earlier label never widens a delete |

Growth: `guestRooms` keeps every room id ever placed (B55); it is written to
the state file on every dirty second, so the write size grows with history,
not with activity.

## probe.go

| Function | Lines | Purpose | Trusts | Side effects | Locks | Callers | Invariant |
|---|---|---|---|---|---|---|---|
| `broker.probeCreate` | 34-49 | start a probe room (image, ttl 900, 1 vCPU, 4 GiB, 10 GiB, labels broker_guest=<ops guest>, kind=probe) | hotel answer | room on the hotel, image pull; bypasses admit, pick, h.sem, queue counters, drain and backoff | none | probeHotel, probeDind | caller deletes the room (defer) |
| `broker.probeExec` | 51-63 | run `sh -c` in the room | hotel answer | exec | none | probeHotel, probeDind | none |
| `broker.probeHotel` | 65-100 | one room per hotel: uname, gVisor count, egress wget to cloudflare, optional dind, sealed attestation | hotel answers | create, 2 execs, delete (background ctx, 2 min); error text stored | none | handleProbe | a cancelled create that succeeded on the hotel is not deleted (TTL 900 s cleans it) |
| `broker.probeSealed` | 104-116 | GET /room/attestation on the health base; report present and 96-char measurement | hotel JSON | none | none | probeHotel | no signature check (documented) |
| `broker.probeDind` | 118-129 | docker:28-dind room, inner `docker run --network host` | hotel | pulls docker:28-dind and alpine on the hotel | none | probeHotel (dind=true) | opt-in |
| `broker.handleProbe` | 131-171 | ops key: probe every hotel in the guest's list in parallel; store results on h.caps; saveCaps | ops flag (config), body 4 KiB | rooms on every allowed hotel (drained and resting ones too); h.caps replaced; caps.json | b.mu for h.caps | serveNative (ops only) | probe errors (with hotel URL) become board data |
| `broker.saveCaps` | 174-188 | write caps.json (0640, plain write) | none | disk | b.mu | handleProbe | none |
| `broker.loadCaps` | 190-207 | read caps.json into h.caps for hotels present now | file | memory | none (startup) | main (before loadRuntimeHotels) | all hotels already in the set (false for runtime hotels) |

## placement.go

| Function | Lines | Purpose | Trusts | Side effects | Locks | Callers | Invariant |
|---|---|---|---|---|---|---|---|
| `broker.maxQueueWait` | 30-39 | config to duration (<0 never, 0 default 10 s) | config | none | none | waitSlot | none |
| `hotel.noteCreate` | 42-49 | EWMA of create time | duration | h.createEWMA | caller holds b.mu | createOne (success only) | none |
| `hotel.expectedWait` | 53-67 | seconds until a create can start | counters | none | caller holds b.mu | waitSlot | cap(h.sem) >= 1 |
| `hotel.weight` | 70-88 | free x headroom / (create x (1 + wait)) | hotel-reported cpu | none | caller holds b.mu | pick | headroom floor 0.05 |
| `broker.waitSlot` | 94-129 | wait for h.sem; after the limit move to a hotel with half the wait; on ctx end release counters | ctx | h.queued, g.queued, h.moved, tried | b.mu for counter moves | createOne | the caller reads `<-h.sem` exactly once after `do` |

## Goroutines

| Started at | Ends |
|---|---|
| main.go 1398 `saveLoop` | never (ctx Background) |
| hotels.go 109 `syncLoop` per hotel | `h.stop()` on leave; config hotels never |
| main.go 607 batch createOne | when createOne returns (ctx, 5 min hotel timeout, sem wait) |
| main.go 802 fanout per hotel | 30 s timeout |
| main.go 918 bulk delete per hotel | 30 min timeout |
| probe.go 151 per hotel | ~5 min create + 60 s execs (+ 4 min dind) |
| compat.go 291 import prefetch per hotel | 10 min, background ctx |
| compat.go 798 compat exec | hotel answer or cancel; entry never removed (B55) |
| images.go 362, 433, 573; build.go 111 | not this catalog |
| main.go 1251 `stream` per board viewer | client disconnect |

## Maps and their guards

| Map or field | Guard | Unlocked readers |
|---|---|---|
| `b.guests`, `b.byKey` | written at load only | all handlers (read only) |
| `g.limits` | b.mu | none found (build.go 89-95 locks) |
| `g.pending`, `admits`, `queued`, `recent`, counters | b.mu | none |
| `b.hset` | atomic; changes under hotelsMu | all (intended) |
| `h.rooms`, `h.grid`, `slots`, counters, `caps`, `lat`, `backoffUntil`, `ok` | b.mu | `h.caps` read by json.Marshal in `stream` after snapshot returns (pointer swap only) |
| `h.cfg.Drain`, `h.cfg.Labels` | written under b.mu (patchHotel) | `selects` from parseSelection (images.go 228), `anyHotel` (guests.go 254), `hotelDoc`, `prefetch` paths |
| `h.cfg.API`, `h.cfg.Health`, `h.key`, `h.client` | immutable after construction | all |
| `h.lastAnswer` | atomic | all |
| `b.byUUID`, `b.savedUUIDs`, `b.guestRooms` | b.mu | none |
| `b.compat.images`, `idem`, `execs`, `tombs` | compat.mu | none |
| `b.dirty` | atomic | none |

## Hazards (trusted without a check)

- `loadBroker` accepts unknown keys, duplicate guest ids, duplicate key hashes,
  empty guest ids, an empty `listen`, and guest `hotels` entries that name
  no hotel. Every one fails open except the unknown-hotel entry.
- `config.example.json` shows hotel-a with `labels: {"sealed": "true"}` and no
  `sealed: true`: such a hotel takes unsealed creates and the board shows it
  unsealed; `probeSealed` does not run for it.
- `patchHotel` replaces the whole label map; the sealed label `newHotel`
  forced is not re-applied.
- `joinHotel` trusts that the hotel's `GET /v1/status` checks the key. It does:
  sandbox_server `PUBLIC_PATHS` is only `/openapi.json`, every other route
  runs `_authenticate` while `require_auth` (default True). A hotel started
  with `require_auth=False` would pass verify with any key.
- `joinHotel` accepts any id characters except a dot; `/` in an id breaks
  room routing and the key path (`hotel-keys/<id>.key`). Operator only.
- `leaveHotel` counts rooms and drops the hotel in two lock sections; a
  create that picks the hotel between them lands on an orphaned hotel object
  and its id answers 404 for ever. Mitigated by draining first (not enforced).
- `probeCreate` ignores drain, backoff, `h.sem` and the hotel's queue; the
  probe room is not in `h.rooms` until the sync loop lists it.
- Probe errors carry the hotel's private URL into `h.caps`, `caps.json` and
  the live board of every guest.
- `saveCompat` and `saveRuntimeHotels` rename without fsync; `saveCaps` writes
  in place. A truncated state file is logged, skipped and replaced.
- No signal handler: the last second of client state is lost at every
  restart; no final save; `log.Fatal` on listen error.
- `saveLoop` logs one line per second while state_dir is unwritable and keeps
  the dirty flag; nothing at startup checks that state_dir is writable.
- `filterHotelReceiptsFor` drops every receipt with no sandbox_id unless it is
  the guest's own bulk delete (B30 for refused creates; any other hotel
  receipt type without a sandbox id is invisible to guests).
- `bulkDeleteGuest` depends on the hotel signing the query string in the order
  received and on the broker label being last.
- `h.do` sets `Content-Type: application/json` on every body, including raw
  file and tar bodies relayed by handleRoom.
- `getJSON` and `doBase` read hotel answers with no size cap.
- `g.recent` is pruned only while a live board is open.
- `admit` records the n timestamps even when the create then fails; a batch
  with count above max_creates_per_minute gets 429 Retry-After 60 for ever.
- `activeRooms` counts a room twice (pending and running) between register
  and unreserve; transient, same outcome as the true count except at the
  limit boundary for microseconds.
- `MaxConnsPerHost = concurrency + 64` is shared by creates, execs, fanout,
  the sync loop and the probe. Execs of one guest can hold every connection;
  when health shares host:port with the API the sync loop starves and the
  hotel goes down for everyone (extends B53). Probe
  `TestReview6LongExecsStarveHealthAndTakeTheHotelDown`: 68 execs of one
  guest, syncHotel took 30.0 s with three `context deadline exceeded`
  errors, `h.ok` false, another guest's create answered 503
  `hotels_unavailable`.
- Unlocked reads of `h.cfg.Labels` (parseSelection, anyHotel, hotelDoc)
  against `patchHotel` writes: `go test -race` over 40 PATCH/create rounds
  (`TestReview6PatchHotelLabelsRaceWithCreates`) reported nothing; a
  pointer-sized swap, no map mutation, so no crash path was found.

## Probe tests written (all in /private/tmp/claude-501/r6/broker/review6_core_test.go)

Failing by design (each is a finding or observation above): ConfigLoaderFailsOpenOnTypos,
EmptyGuestIDOwnsUnlabeledRooms, PatchLabelsDropsTheSealedLabel,
ProbeErrorPutsHotelAddressOnTheLiveView, ProbeStartsARoomOnADrainedHotel,
RuntimeHotelCapsLostAtRestart, RestartWithinASecondLosesClientIDs,
CorruptStateFileIsReplacedNotKept, CompatExecIsForgottenAtRestart.
Passing probes that record behaviour: LongExecsStarveHealthAndTakeTheHotelDown
(30 s, skipped under -short), BatchOverRateLimitRetriesForever,
RecentCreatesPrunedOnlyByTheLiveView, EmptyRuntimeHotelsFileLoads,
JoinKeyFileOutlivesARefusedJoin, PatchHotelLabelsRaceWithCreates (-race).
Every pre-existing broker test still passes with the file present.

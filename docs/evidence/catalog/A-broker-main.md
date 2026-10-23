# Catalog A: broker/main.go and broker/live.html (review round 6)

Artifact: cathedral-sandbox at 22e7824 (PR #311 head), frozen copy at
/private/tmp/claude-501/r6. Files owned by this catalog: broker/main.go
(1450 lines, read in full) and broker/live.html (336 lines, read for what
the live board exposes). Context read: broker/README.md, hotels.go,
guests.go, placement.go, state.go, probe.go, receipts.go, images.go 1-290
and 380-425, compat.go (isCompat, newUUID, roomByUUID, hotelExec,
serveCompat, compatIdem, compatCreate, compatRoom, cleanupState,
writeHotelCompat, flushCompat), the test harness in images_test.go 1-300,
and on the hotel side cathedral/sandbox_server.py (routes, create,
put_file, body read), sandbox_provider.py (create, list, delete, quota),
sandbox_api.py (label and exec limits), sandbox_guest.py (image pull).

Probe tests: /private/tmp/claude-501/r6/broker/review6_main_test.go (new
file, nine tests, results in section 11). No existing file was changed.

Known items B1 to B61 are not repeated. Where a line below sharpens one,
the B number is named.

## 1. Types and constants

| Name | Lines | What it holds | Trusts | Notes |
|---|---|---|---|---|
| hotelConfig | 43-58 | id, name, threads, ram, api and health base URLs, key file, concurrency, drain, labels, sealed, max_slots | the private config file and hotels.json | id must have no dot (room ids split on the first dot) |
| guestConfig | 60-66 | id, key sha256, view token sha256, ops, embedded guestLimits | config | an empty key means view only |
| config | 68-83 | listen, state_dir, hotels, guests, insecure_cookie, max_exec_seconds, max_queue_wait_seconds, operator_key_sha256 | config | no field is validated beyond hotel id and key file |
| room states | 93-100 | '.', 'c', 'r', 'd', 'f', 'o' as bytes | | the live grid is one byte per slot |
| guestLabel | 102 | "broker_guest" | | ownership label on every room the broker creates |
| room | 104-114 | id (hotel.hid), uuid, hid, h, guest, state, slot, since, vanished | | id, uuid, hid, h, guest never change after publish; state, slot, since, vanished change under b.mu |
| latencies | 116 | hotel, queue, overhead samples | | never pruned except by the ops reset (B55) |
| hotel | 118-154 | cfg, key, client, sem, and the b.mu guarded live state | | lastAnswer is atomic; everything from slots down is b.mu |
| guestState | 156-166 | cfg, counters, recent, limits, pending, admits | | recent is pruned only by snapshot(), see hazards |
| broker | 168-188 | cfg, mu, hset (atomic), hotelsMu, guests, byKey, byUUID, compat, prefetch, started, savedUUIDs, dirty, guestRooms | | guests and byKey are written only in loadBroker, so later reads need no lock |
| okWindow | 191 | 15 s | | health or room answers younger than this keep a hotel in placement |
| hotelFailBackoff | 561 | 10 s | | rest after a hotel fault on create |

## 2. Routes

Dispatch is ServeHTTP (1277-1319), then serveNative (1321-1371) for a
native client, or serveCompat (compat.go) when the User-Agent starts with
"cathedral-harbor/" or "ctcli/". Operator routes are matched before the
guest key check. Live routes have no guest key.

| Method, path | Auth | Handler | Hotel calls | Timeout at the hotel | Body limit |
|---|---|---|---|---|---|
| GET /healthz | none | inline 1279 | none | | |
| POST /v1/broker/hotels | operator key | joinHotel (hotels.go) | GET /v1/status on the new hotel unless verify false | 10 s | 1 MiB |
| PATCH /v1/broker/hotels/{id} | operator key | patchHotel | none | | 1 MiB |
| DELETE /v1/broker/hotels/{id} | operator key | leaveHotel | none | | |
| GET /v1/broker/guests | operator key | handleGuestAdmin (guests.go) | none | | |
| PATCH /v1/broker/guests/{id} | operator key | patchGuest | none | | 64 KiB |
| any /v1/* without a known key | | 401 unauthorized (compat envelope for compat UA) | | | |
| POST /v1/sandboxes | guest key | handleCreate 563 | POST /v1/sandboxes on 1 to 3 hotels per room; GET /v1/snapshots fan-out for a fork (images.go) | 5 min per create call | 1 MiB, cut silently, then x count (hazard 5) |
| GET /v1/sandboxes | guest key | handleList 818 | GET /v1/sandboxes?label=broker_guest=g on the guest's hotels | 30 s | none read |
| DELETE /v1/sandboxes?label= | guest key | handleBulkDelete 903 | DELETE /v1/sandboxes?label=...&label=broker_guest=g on the guest's hotels | 30 min | none read |
| any /v1/sandboxes/{hotel}.{hid}[/tail] | guest key, must own the room | handleRoom 663 | one call to the room's hotel at /v1/sandboxes/{hid}/tail with the query | 2 min; 20 min when tail ends in exec or wait; timeout_seconds + 2 min when larger | 256 MiB, cut silently (hazard 2), read for every method (B54) |
| POST /v1/sandboxes/{room}/snapshot | guest key, owner | roomSnapshot (images.go) via handleRoom | POST .../snapshot | 10 min | 256 MiB (read by handleRoom) |
| GET /v1/hotels/{id}/attestation | guest key | handleHotelDoc 754 | GET /room/attestation on the Health base | 1 min | |
| GET /v1/hotels/{id}/receipts | guest key; hotel must be in the guest's list; ops sees all | handleHotelDoc | GET /room/receipts with the query (after, limit) | 1 min | |
| GET /v1/quota | guest key | handleQuota 862 | GET /v1/quota on the guest's hotels | 30 s | |
| GET /v1/usage | guest key | handleUsage 896 | GET /v1/usage?label=broker_guest=g on the guest's hotels | 30 s | |
| POST /v1/images/prefetch | guest key | handlePrefetch (images.go) | POST /v1/images/prefetch on chosen hotels | see images.go | |
| GET /v1/images/prefetch/{id} | guest key | handlePrefetchStatus | none | | |
| GET /v1/snapshots | guest key | handleSnapshotList | GET /v1/snapshots per hotel | see images.go | |
| any /v1/snapshots/{id}[/push] | guest key | handleSnapshot | see images.go | | |
| GET /v1/broker/hotels | guest key | handleHotels (images.go) | none | | |
| GET /v1/broker/stats | guest key | handleStats 945 | none | | |
| POST /v1/broker/stats | ops flag | handleStats, resets counters | none | | |
| POST /v1/broker/probe | ops flag | handleProbe (probe.go) | create, exec, delete one room per hotel in the guest's list | 5 min, 30 s, 240 s, 2 min | 4 KiB |
| GET /v1/status | guest key | inline 1357 | none | | |
| POST /{guest}/live/sign-in | token in the form body | handleSignIn 1140 | none | | 4 KiB (MaxBytesReader, 413) |
| GET /{guest}/live | view cookie or ?token= | handleLive 1167 | none | | |
| GET /{guest}/live/events | view cookie | stream 1251 | none | | |
| anything else | | 404 | | | |

Error codes handleCreate can return: 400 bad_body, invalid_json,
invalid_count, invalid_hotel_selection; 409 unknown_hotel,
no_matching_hotel, snapshot_hotel_excluded, snapshot_ambiguous; 404
snapshot_not_found; 429 room_limit, create_rate_limit (with Retry-After),
no_free_rooms, or the hotel's own 429 body; 499 client_gone; 502
hotel_unreachable; 503 hotels_unavailable, snapshot_hotel_unavailable; any
4xx or 5xx body from a hotel passed through with X-Broker-Hotel. A batch
answers 202 with sandboxes, count and an errors map; when nothing was
made it answers with results[0].status.

## 3. Functions

Format: name (lines). Purpose. Trusts. Side effects. Locks. Callers.
Invariant.

- maxExec (85-90). The longest exec the broker accepts, default 14,400 s.
  Trusts config. No side effects. No lock. Callers: hotelExec, compatRoom
  (compat.go). Invariant: at or below the hotels' exec limit; not checked.
- byBID (194-200). Room by broker id "hotel.hid". Trusts the id split on
  the first dot. No side effects. Caller holds b.mu. Callers: compatCreate,
  tests. Invariant: a hotel id has no dot (loadBroker, addHotel check it).
- register (203-217). Gives a room its client UUID, restores a saved one,
  records the guest to hotel to room mapping, marks state dirty. Trusts
  savedUUIDs from the state file. Side effects: byUUID, guestRooms, dirty
  flag. Caller holds b.mu. Callers: createOne, syncHotel. Invariant: one
  room per UUID; a saved UUID already in use is not reused.
- sha (219). SHA-256 hex of a string. Callers: key and token checks.
- loadBroker (221-256). Reads the config, reads every hotel key file,
  builds hotels and guests. Trusts the config file and key files. Side
  effects: reads files. No lock (start only). Callers: main, tests.
  Invariant: a config error or a missing key file stops the process
  (log.Fatal in main); guest ids and key hashes are unique, not checked.
- hotel.do (260-262). Hotel API call on the API base. Callers: everything
  that talks to a hotel API.
- hotel.doBase (264-291). One HTTP call with the hotel key, a timeout, the
  body as JSON. Reads the whole answer. Any answer below 500 refreshes
  lastAnswer (keeps the hotel "answering" for syncHotel). Trusts the hotel
  to answer with a bounded body (no size limit on the read). Side effects:
  network, lastAnswer. No lock. Callers: do, handleHotelDoc. Invariant: the
  caller's ctx bounds the call; a 401 or 404 still counts as an answer.
- hotel.getJSON (293-311). GET and decode JSON, 10 s, 200 only. Trusts the
  JSON shape. Network. No lock. Callers: syncHotel (three calls), joinHotel,
  probeSealed.
- hotel.resize (315-328). New grid of n slots, keeps rooms whose slot fits,
  others get slot -1. Trusts the hotel's slots value (capped by max_slots).
  Caller holds b.mu. Callers: syncHotel. Invariant: slots > 0 and changed;
  a hotel that reports 0 slots keeps its old grid.
- hotel.place (330-338). First free grid cell for a room, or slot -1.
  Caller holds b.mu. Callers: createOne, syncHotel. Invariant: the grid is
  display only; placement capacity uses used(), not the grid.
- broker.release (340-346). Drops a room's UUID and calls hotel.release.
  Caller holds b.mu. Callers: createOne (an adopted twin), syncHotel.
- hotel.release (348-356). Clears the grid cell and the rooms entry when
  they still point at this room. Caller holds b.mu. Callers: broker.release,
  createOne 429 branch. Invariant: a stale pointer never evicts a newer
  room with the same hid.
- hotel.used (358). Rooms known plus creates in flight plus queued. Caller
  holds b.mu. Callers: pick, noRoomReason, handleHotels, leaveHotel.
- broker.pick (362-392). Weighted random hotel among ok, not draining, not
  resting, not excluded, allowed by the placement, with free rooms. Trusts
  h.ok and h.slots from the sync loop. Caller holds b.mu. Callers:
  createOne, waitSlot. Invariant: never returns a hotel the placement
  forbids; the rounding fallback returns the last eligible hotel.
- writeJSON, writeErr (396-404). JSON answers; encode errors ignored.
- guestFromKey (406-412). Bearer key to guest by hash lookup. Trusts
  nothing. Callers: ServeHTTP, main's counting handler.
- ms (414). Duration to milliseconds.
- createOne (426-558). Places one room: labels it with the guest, drops
  count, marshals once, then up to three attempts: pick, wait for a create
  slot (waitSlot may move it), place a 'c' square, POST to the hotel with a
  5 min timeout, release the slot, then update state. Success (200 or 202
  with an id): the room becomes 'r', replaces a twin the sync loop adopted
  first, gets a UUID, counters and latencies move, the answer carries the
  broker id and X-Broker-* headers. 429: square released, hotel rests for
  Retry-After or 2 s, next hotel. Any other answer: square 'f'; the hotel
  rests 10 s on a transport error, a 5xx that is not the guest's image
  fault, a 401 or a 403; a 4xx or a guest image fault returns at once; a
  transport error or 5xx goes to the next hotel. After three attempts the
  last answer is returned. Trusts: that a transport error means the hotel
  did not make the room (hazard 1); that the hotel's 202 body has an id.
  Side effects: network, grids, rooms, byUUID, guestRooms, counters, dirty
  flag. Locks: b.mu taken and released around each state step, never held
  during the hotel call. Callers: handleCreate (single and batch),
  compatCreate. Invariant: h.queued and g.queued are balanced on every path
  (waitSlot releases them on ctx end); h.creating is balanced; the hotel
  semaphore is released right after the call.
- handleCreate (563-635). Reads up to 1 MiB (silently cut), parses JSON,
  reads count (1 to 10,000), resolves the placement (may call hotels for a
  fork), applies it, admits count rooms against the guest limits, then
  runs createOne once or count times in parallel (each goroutine re-parses
  the raw body). Trusts the body to be small per room (hazard 5). Side
  effects: via createOne. Locks: none directly. Callers: serveNative.
  Invariant: admit and unreserve are balanced per room; no native
  idempotency (the compat path has Idempotency-Key in compatIdem).
- finishCreate (637-659). Copies result headers to the guest, adds
  X-Broker-Overhead-Ms and records it on the hotel, writes doc or raw body.
  Locks: b.mu briefly. Callers: handleCreate. Invariant: a 429 or error
  body from a hotel reaches the guest unchanged.
- handleRoom (663-738). See section 4.
- copyRoomHeaders (742-748). Copies X-Room-* headers (signed receipts) to
  the guest. Callers: createOne, handleRoom.
- handleHotelDoc (754-787). GET attestation or receipts of a hotel from
  its Health base, 1 min. Receipts of a hotel outside the guest's list are
  404; a non-ops guest's receipts are filtered to rooms it has owned
  (guestRoomIDs) plus its own bulk deletes. Trusts the hotel's receipt
  JSON shape (502 receipts_unreadable otherwise). Locks: via limitsAllow
  and guestRoomIDs. Callers: serveNative. Invariant: attestation is public
  to any guest key by design.
- fanout (793-816). Parallel GET to every hotel in the guest's list, 30 s,
  errors become {"error":"unavailable"}. Callers: handleList, handleQuota,
  handleUsage. Invariant: a hotel outside the list is never asked (B56).
- handleList (818-843). Fan-out list with the guest label, ids rewritten
  to hotel.hid, sorted by id, hotel_errors per failed hotel. Trusts the
  hotel to filter by label.
- sumInto (845-860). Recursive sum of numeric fields. Callers: handleQuota.
- handleQuota (862-894). Fan-out quota plus the guest's running rooms from
  broker memory and its limits. Locks: b.mu for the count. Invariant:
  running_sandboxes counts only state 'r' rooms (hazard 3 undercounts).
- handleUsage (896-901). Fan-out usage with the guest label.
- handleBulkDelete (903-931). DELETE with the guest's label appended last
  on every hotel in the guest's list, 30 min each, statuses per hotel.
  Trusts the hotel to apply the last repeated label (receipts.go relies on
  it). Invariant: refuses with no label filter.
- pct (935-943). Percentiles of a sample list. Callers: handleStats.
- handleStats (945-979). GET: chain-wide per hotel counters to any guest
  (B26). POST: ops only, resets counters. Locks: b.mu for the whole
  handler.
- healthDoc (983-992). Shape of the hotel's /room/health.
- syncHotel (994-1088). See section 6.
- syncLoop (1090-1101). syncHotel every 2 s until ctx ends. Callers:
  startSync (hotels.go). Invariant: the ticker is stopped on return; the
  loop ends when leaveHotel cancels.
- viewGuest (1105-1118). Guest from the URL id plus a ?token= or the
  bv_<guest> cookie, constant-time hash compare. Returns the raw token when
  it came in the URL so handleLive can set the cookie. Callers: handleLive.
- writeSignIn (1122-1136). 401 HTML form posting the token to
  /<guest>/live/sign-in. The guest id is path-escaped into the action, the
  note is HTML-escaped. Callers: handleLive, handleSignIn.
- handleSignIn (1140-1157). POST form token, 4 KiB max, constant-time
  compare, sets the cookie, 303 to /<guest>/live. No lockout, no rate
  limit. Callers: ServeHTTP.
- setViewCookie (1159-1165). bv_<guest>, path /<guest>/, 30 days,
  HttpOnly, Secure unless insecure_cookie, Lax. Trusts the token to be a
  legal cookie value (hazard 11). Callers: handleSignIn, handleLive.
- handleLive (1167-1191). no-store, no-referrer, DENY framing; sign-in
  form without a valid cookie; a ?token= link sets the cookie and
  redirects; "live" serves live.html with a CSP that allows inline script
  and style and Google Fonts; "live/events" streams. Callers: ServeHTTP.
- snapshot (1193-1242). See section 7. Locks: b.mu for the whole build.
  Side effect: prunes g.recent to 60 s. Callers: stream. 0% coverage
  before this round; covered by the probe in section 11.
- seenAge (1244-1249). Seconds since a time, -1 for never.
- stream (1251-1273). SSE, one snapshot per second, ends on write error or
  client disconnect. Needs http.Flusher (countingWriter forwards Flush).
  Callers: handleLive.
- ServeHTTP (1277-1319). Dispatch, see section 2. Callers: main, tests.
- serveNative (1321-1371). Native route switch. Callers: ServeHTTP,
  serveCompat default branch (through a capture writer).
- countingWriter (1374-1384). Records the status so main can count 429s on
  creates per guest; forwards Flush. Callers: main.
- main (1386-1421). See section 8.
- errCodeOf (1424-1432), guestImageFault (1436-1450). Read a hotel error
  body; decide whether image_pull_failed is the guest's fault by message
  substrings. Trusts the hotel's message text. Callers: createOne.

## 4. handleRoom (663-738)

- Path split: rest = "<hotel>.<hid>[/tail]". Every tail segment is checked
  for "." and ".." first (400 invalid_path, B59). Then the hotel id is
  looked up in the hotel set (atomic) and the room in h.rooms under b.mu;
  ownership is rm.guest == guest id; a miss of any kind is 404
  sandbox_not_found so a foreign room looks absent.
- Ownership does not look at the state: a room marked 'd' still routes
  (good for exec and delete; it is how the probe in section 11 shows a
  stuck 'd' room answering).
- Body: io.ReadAll(io.LimitReader(r.Body, 256 MiB)) for every method,
  before the method check. The read error is ignored; a disconnect cancels
  r.Context(), so the hotel call then fails fast. A body over 256 MiB is
  cut and the first 256 MiB go to the hotel as a complete request
  (hazard 2, finding F3). GET and DELETE send no body.
- POST .../snapshot is handed to roomSnapshot with the buffered body.
- Hotel path: /v1/sandboxes/<url.PathEscape(hid)>/<tail>, tail appended
  raw (it is the decoded URL path), query passed through.
- Timeout: 2 min; 20 min when the tail ends in "exec" or "wait"; when the
  body's timeout_seconds + 2 min is larger, that. Overflow of a huge
  timeout_seconds leaves 20 min; the hotel rejects the value anyway.
- Transport error: 502 hotel_unreachable; the hotel is not rested here.
- DELETE with no tail answered 204 or 404: the room goes 'r' to 'd' with
  vanished = now under b.mu; release waits for the sync loop (section 6).
  A hotel 204 for an already gone room (its delete is idempotent) is the
  same path. The compat path (compatRoom) calls handleRoom through a
  capture writer and adds a tombstone on 204 or 404.
- Headers to the guest: Content-Type, Content-Range, Content-Length,
  Retry-After, Accept-Ranges, then every X-Room-* header (signed receipts)
  unchanged.
- Body to the guest: for application/json answers except tail "receipts",
  every JSON string equal to the hid becomes the broker id and
  Content-Length is dropped (recomputed). Receipts pass byte for byte so
  signatures hold. Any other JSON that embeds a signed statement with the
  hid would be altered: only the path "receipts" is exempt, not a content
  type or a marker.

## 5. Create path

- Order in handleCreate: read and parse, count, placementFor (hotel
  choice, sealed rule, fork lookup that may call every hotel's
  /v1/snapshots), apply (drops hotels, hotel_labels, exclude_hotel_labels,
  sealed; sets the hotel snapshot id), admit (room limit then rate limit,
  pending += count), create, unreserve per room.
- The rate limit and room limit run after the fork lookup, so a guest over
  its limits still costs a snapshot fan-out per request.
- Label rewrite: labels[broker_guest] = guest id always wins; count is
  removed; the hotel never sees "sealed".
- Sealed default: scope() (guests.go) adds hotel_labels sealed=true when
  the guest has default_sealed and the create names no hotel and no sealed
  field; a fork of an unsealed snapshot drops it (placementFor). A sealed
  hotel takes only creates with the sealed label or its id (selects, B29).
- hotels and hotel_labels: ids outside the hotel set or the guest's list
  are 409 unknown_hotel; a selection that matches no hotel is 409
  no_matching_hotel; a fork whose hotel is excluded is 409
  snapshot_hotel_excluded.
- Hotel rest and backoff: 429 rests Retry-After (min 2 s); transport
  error, 5xx not caused by the guest's image, 401 and 403 rest 10 s
  (hotelFailBackoff) and count h.failed; a 4xx or a guest image fault
  rests nothing, counts g.failed, no retry (B1, B9, B14, B17).
- g.failed: counted on a final 5xx, on a 4xx or guest image fault, and
  when no hotel is left after a 5xx. Not counted on 499 or on a 429.
- Rate limits: max_rooms over state 'r' rooms plus pending; the
  per-minute window counts admitted rooms, failures included. 429 room_limit
  Retry-After 10; 429 create_rate_limit Retry-After computed.
- Batch: up to count goroutines at once, each re-parsing the raw body and
  marshaling its own copy; the hotel semaphores bound the hotel load, not
  the broker memory (hazard 5, finding F5). A batch over max_rooms is
  refused whole.
- Idempotency: none on the native path. The compat path keys on guest,
  path and Idempotency-Key, keeps the answer 48 h in the state file, and
  forgets a 429 or 5xx answer so a retry runs again (compatIdem). The
  hotel itself honours Idempotency-Key on create (sandbox_server.py 321)
  and the broker never sends one.
- Retry on a lost answer: a transport error, including the broker's own
  5 min deadline, makes createOne rest the hotel and try the next one. The
  hotel (ThreadingHTTPServer, one thread per request, synchronous docker
  pull with a 600 s limit inside create) finishes the room anyway. The
  next sync adopts that room as the guest's (section 6). One create, two
  rooms (hazard 1, finding F1).
- A 202 whose body has no id takes the same "hotel fault, next hotel"
  branch without resting the hotel.

## 6. Sync loop (syncHotel 994-1088, every 2 s per hotel)

Three sequential calls with 10 s each, no lock held: /room/health on the
Health base, /v1/quota and /v1/sandboxes on the API base. Then one b.mu
section.

- ok: health answered inside 15 s, or a room call answered inside 15 s
  and health answered at least once ever. healthLate marks the second
  case. A hotel whose health never answered stays out of placement
  (slots unknown).
- Health answer: slots (capped by max_slots) resize the grid; cpu, mem,
  load, containers copied. Quota answer: apiRunning = running + frozen,
  apiDeleting = deleting (the hotel hides "deleting" records from its
  list and counts them in quota, sandbox_provider.py 978-1046).
- List failed: return. No room changes at all: no adoption, no release,
  'f' squares stay, listOK false on the board. This is the hotel outage
  behaviour: rooms stay in memory as they were.
- List ok, states:
  - 'c': only in the grid, never in h.rooms; set by createOne; ends with
    the hotel answer.
  - 'r': set by createOne or by adoption from the list (guest from the
    broker_guest label, UUID restored or new, guestRooms updated). Leaves
    to 'd' when the room is missing from the list and since is older than
    5 s, or when handleRoom's DELETE got 204 or 404.
  - 'd': kept while the list still shows it, or while it is among the
    newest apiDeleting vanished rooms, or for 2 s after it vanished.
    Otherwise released: out of h.rooms, the grid and byUUID; guestRooms
    keeps the id for receipts. There is no transition from 'd' back to
    'r' (hazard 3, finding F4).
  - 'f': grid only, cleared 30 s after since, but only when the list call
    works.
  - vanished: the time the room left the list or the DELETE answered.
- Hotel API restart (B24): every room leaves the list, all go 'd' after
  5 s, then all but apiDeleting are released 2 s later. B24 phase 2
  (adopt rooms on hotel start) would list them again while the broker
  still has them as 'd': with the current code they would never return to
  'r'. The phase 2 design needs the missing transition.
- Dropped from memory: broker.release in syncHotel, and in createOne when
  the sync loop adopted the same hid first (the adopted twin is released,
  the created room keeps a fresh UUID).
- guestRooms: guest to hotel to hid set, written by register, read by
  guestRoomIDs for the receipts filter, persisted in the state file, never
  pruned (by design: deleted rooms keep their receipts readable).
- Races: createOne vs adoption is handled by the "old != rm" replace.
  handleRoom reads the room under b.mu and then uses only fields that never
  change (h, hid, id, uuid). handleRoom's DELETE bookkeeping writes
  rm.state under b.mu; if the sync released the room during the hotel
  call the write lands on a detached object, which is harmless. A late
  list can mark a live room 'd' (section 11, probe 1).
- Lock coverage: rooms, grids, slots, ok, counters, latencies, limits,
  pending, admits, guestRooms, byUUID, savedUUIDs are b.mu. hset and
  lastAnswer are atomic. h.cfg.API and h.cfg.Health are never written
  after start. h.cfg.Drain and h.cfg.Labels are written under b.mu by
  patchHotel; Labels is read without b.mu by placement.selects from
  parseSelection and anyHotel, and hotelDoc reads both after the unlock
  (race detector report in section 11, probe 8).

## 7. Live board (handleLive, snapshot, stream, live.html)

- Sign-in: POST form token to /<guest>/live/sign-in or the older
  ?token= link; both set bv_<guest> (30 days, HttpOnly, Secure unless
  insecure_cookie, Lax, path /<guest>/) and redirect to /<guest>/live. A
  wrong token and an unknown guest both get the same 401 form. No attempt
  limit.
- Every second the stream holds b.mu while it walks every hotel's grid
  (O(total slots)) and marshals outside the lock. One goroutine per open
  viewer; it ends when the viewer disconnects or a write fails. Many
  viewers mean many lock holds per second; nothing bounds the number of
  streams per guest.
- What a view token holder learns (probe 7 output), per hotel: caps
  (probe results, including the sealed note with the measurement prefix
  and the attestation path), containers, cpu, creating, deleting_all,
  drain, grid (own rooms by state, every other guest's room as 'o'),
  health_late, health_ms, id, list_ok, load1, mem_gib, mem_pct, mine, name,
  ok, queued, ram_gib, rooms_all, sealed, seen_age_s, slots, threads.
  Totals: created, creates_per_s, creating, deleting, failed, queued,
  rejected, running. Chain-wide numbers (containers, rooms_all,
  deleting_all, queued, creating, load, memory, other guests' squares) are
  B26. Not exposed: hotel addresses, keys, lastErr, other guests' ids or
  room ids.
- live.html loads Inter and JetBrains Mono from Google Fonts; the CSP
  allows it; the viewer's browser contacts Google. Theme choice is kept in
  localStorage. The page reconnects by itself on error (EventSource).
- snapshot is the only place g.recent is pruned, so without an open
  viewer g.recent grows by one entry per successful create for the life
  of the process (extends B55).

## 8. main (1386-1421): startup and shutdown

Order: parse -config; loadBroker (fatal on a config error or a missing
hotel key); loadCaps (any error silent); loadCompat (error logged, run
continues); saveLoop goroutine on a Background context; loadRuntimeHotels
(error logged, run continues; a runtime hotel whose key file is missing is
skipped with a log line); startSync for every hotel present at that
moment; HTTP server with ReadHeaderTimeout 10 s, IdleTimeout 2 min, no
ReadTimeout, no WriteTimeout; log.Fatal on ListenAndServe.

- Fails loudly: unreadable config, bad JSON config, hotel id with a dot,
  missing hotel key file, listen error.
- Fails silently or by log only: caps.json unreadable or undecodable;
  client-state.json unreadable or undecodable (then the first dirty save
  replaces it, finding F2); hotels.json unreadable or undecodable (the
  runtime hotels are absent until the next join, and the next join writes
  hotels.json with only itself); a runtime hotel key missing.
- Order hazard: loadCaps runs before loadRuntimeHotels, so probe results
  of runtime hotels are never restored (finding F7).
- Shutdown: none. No signal handling, no graceful stop, no final state
  save; saveLoop flushes once a second (finding F6). A kill cuts every
  in-flight exec answer; the hotel keeps running the exec.
- The 429 counter: a wrapper counts 429 answers on POST /v1/sandboxes per
  guest after the handler returns.

## 9. Goroutines, timers, locks, swallowed errors

- Goroutines and timers: syncLoop per hotel (ticker stopped on exit, ends
  on h.stop); stream per viewer (ticker stopped, ends on disconnect);
  fanout, handleBulkDelete, handleProbe goroutines bounded by their hotel
  timeouts (30 s, 30 min, 5 min plus execs) and by r.Context(); waitSlot
  makes a new time.After every queue wait limit while a create waits,
  collected by the GC; saveLoop for the process life. No leak found.
- Lock order: b.mu is never held during a hotel call. b.compat.mu and
  b.mu are not nested in main.go. hotelsMu guards only the hotel set
  swap.
- Map reads outside b.mu: h.cfg.Labels in placement.selects
  (parseSelection, anyHotel) while patchHotel writes it under b.mu
  (probe 8); hotelDoc reads h.cfg after the unlock. b.guests and b.byKey
  are read without a lock but written only at start. Everything else
  checked is under b.mu or atomic.
- Swallowed errors: handleRoom's body read error (the context cancel
  covers it); a hotel 202 without an id (becomes a retry on another
  hotel); writeJSON encode errors; handleProbe's body; syncHotel's
  h.lastErr is set and never shown anywhere; loadCaps swallows every
  error; saveCaps ignores the write error; main logs and continues on
  loadCompat and loadRuntimeHotels errors; leaveHotel ignores the key
  file removal error.

## 10. Hazards (what the code trusts without checking)

1. createOne (534-549) treats a lost answer (transport error, 5 min
   deadline) as "no room was made" and tries the next hotel. The hotel
   finishes the create (synchronous pull up to 600 s, one thread per
   request). The sync loop adopts the orphan as the guest's room.
   Finding F1, probe 2.
2. handleRoom (687) trusts io.LimitReader to hold the whole body. A body
   over 256 MiB is cut and sent as complete; the hotel's put_file has no
   cap and answers 200 with the cut length. Finding F3, probe 9. Extends
   B54.
3. syncHotel (1063-1066) trusts one list without the room as proof it is
   gone, and has no 'd' to 'r' path when a later list shows it again.
   Finding F4, probe 1. Also a precondition for B24 phase 2.
4. main (1395) trusts that an undecodable state file is harmless. The
   first save replaces it and every client room id, idempotency answer and
   guest room set is lost. One field of another type in one record is
   enough since loadCompat uses nothing on an Unmarshal error. Finding F2,
   probe 3.
5. handleCreate (602-612) trusts count to be cheap: the raw body is parsed
   once per room and marshaled once per room before any hotel call;
   measured 109 MiB for 100 rooms with a 0.95 MiB body, so about 1.1 GiB
   at the default max_rooms. Finding F5, probe 5. Extends B54.
6. saveLoop (state.go 51-70) and main trust a one second tick; nothing
   flushes on stop and there is no signal handler. Finding F6, probe 6.
7. main (1394, 1399) trusts that every hotel is present when loadCaps
   runs. Runtime hotels lose their probe results at every restart.
   Finding F7, probe 4.
8. placement.selects (images.go 71) reads h.cfg.Labels without b.mu while
   patchHotel (hotels.go 239) writes it under b.mu. Race detector report,
   probe 8. No corruption shown: the map is replaced, not mutated.
9. handleRoom (732-735) trusts that no JSON answer other than tail
   "receipts" carries a signed statement with the hid in it. The exemption
   is by path only.
10. snapshot (1198-1201) is the only pruner of g.recent; without a viewer
    the slice grows for the process life. Extends B55.
11. setViewCookie (1163) trusts the view token to be a legal cookie value.
    A token with a quote, comma, semicolon, backslash or space is stripped
    by net/http and the sign-in loops forever. Tokens are operator chosen;
    config hazard only.
12. handleSignIn (1140-1157) has no attempt limit; the compare is constant
    time and the token is operator chosen.
13. handleCreate runs placementFor (fork lookup across hotels) before
    admit, so the rate limit does not bound the snapshot fan-out.
14. doBase (285-289) counts any answer below 500 as "the hotel answers",
    so a hotel that rejects the broker's key with 401 keeps ok while its
    health is late; the 401 rest on create (B9) limits the damage.
15. handleStats and snapshot show chain-wide counters to any guest key or
    view token (B26, known).
16. live.html fetches Google Fonts; the viewer's IP reaches Google.
17. CI (.github/workflows/ci.yml) never runs go test in broker/; the
    package's 73% coverage and every test here is local only. The
    -race job covers cmd/cathedral-tdx-verifier only.

## 11. Probes written and results

File: /private/tmp/claude-501/r6/broker/review6_main_test.go. Run with
`cd /private/tmp/claude-501/r6/broker && go test -count=1 -run <Name> .`

| # | Test | Result on 22e7824 | Shows |
|---|---|---|---|
| 1 | TestReview6RoomListedAgainStaysDeleting | FAIL (6.0 s): state 'd' after the late list and after the next list; exec through the broker 200; quota running_sandboxes 0 | F4 |
| 2 | TestReview6LostCreateAnswerLeavesAnOrphanRoom | FAIL: one create answered 202 with c.sbx_1; the guest lists 2 rooms (b.sbx_1 and c.sbx_1, both labelled g1), quota says 2 running | F1 |
| 3 | TestReview6UndecodableClientStateIsReplacedByTheFirstSave | FAIL (1.5 s): loadCompat error "cannot unmarshal string into ... images.x.CPU"; broker ran; first save kept 1 client id; the old room's id is gone | F2 |
| 4 | TestReview6RuntimeHotelCapsAreNotRestoredInMainOrder | FAIL: config hotel caps restored, runtime hotel r1 restored with no caps | F7 |
| 5 | TestReview6BatchCreateMultipliesTheBodyByCount | FAIL (2.1 s): 0.95 MiB body x count 100 grew the heap by 109 MiB at the peak (one run, this Mac) | F5 |
| 6 | TestReview6SaveLoopDoesNotFlushWhenStopped | FAIL: dirty state, loop stopped, no file written | F6 |
| 7 | TestReview6LiveStreamShowsOtherGuestsAndChainCounters | PASS: sign-in by POST, SSE event, own 'r' and other guest 'o' squares, chain-wide keys present, seen_age_s -1, no address or key in the event | positive control; covers snapshot, stream, seenAge |
| 8 | TestReview6LabelsPatchRacesWithHotelSelection (with -race) | FAIL: DATA RACE, write hotels.go:239 via main.go:1284, read images.go:71 via images.go:229, 240, main.go:583 | hazard 8 |
| 9 | TestReview6NativeFilePutOver256MiBIsCutToTheLimit | FAIL: PUT of 268,435,457 bytes answered 200; the hotel received 268,435,456 and reported written 268435456 | F3 |

Not covered by these probes: main() itself (its order is replicated in
probes 3 and 4), real hotel latency (probe 1 simulates a 6 s list with a
proxy), the 5 min create deadline (probe 2 drops the connection instead),
client retry behaviour of Harbor and ctcli after a broker restart (bounds
F6), the hotel's _create_locked lock scope during a pull.

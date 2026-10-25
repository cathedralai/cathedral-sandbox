# Catalog B: broker compat surface

Artifact: cathedral-sandbox at 22e7824 (PR #311 head), frozen copy at
/private/tmp/claude-501/r6. Files read in full: broker/compat.go (999 lines),
broker/build.go (193), broker/images.go (642). Context read: broker/main.go,
state.go, hotels.go, guests.go, placement.go, README.md; the hotel API it
calls (cathedral/sandbox_server.py, sandbox_provider.py, sandbox_guest.py,
sandbox_api.py); the cloud API the clients were written against
(cathedral/tee_box/service.py); room-kit/install.sh (room docker daemon).
cathedral/sandbox_client.py sets no User-Agent and speaks the native hotel
API, so it never reaches this layer.

No systemd unit lives in these files. The broker runs as one process; its
unit is not in the repo.

## How a request enters the layer

- main.go:1291-1306. Every /v1/ path: key hash to guest, else 401. Then
  `isCompat(r)`: User-Agent starts with "cathedral-harbor/" or "ctcli/".
  Yes: serveCompat. No: serveNative. A missing key with a compat UA gets the
  client envelope `{"detail": {...}}`.
- The UA prefix is the only switch. A compat client cannot reach a native
  room id (`<hotel>.<id>`); compatRoom resolves UUIDs only. A native client
  that sends one of the two prefixes is silently moved to the compat rules.
- Room ids: the broker gives each room a random v4 UUID at register
  (main.go:203-217), kept in b.byUUID and in the state file (uuids), so the
  id survives a restart. A released room leaves byUUID (main.go:340-346).

## compat.go

Entry format: lines. Purpose. Trusts. Side effects. Locks. Callers.
Invariant.

compatAgents, consts. 35-40. The two UA prefixes; defaultMaxExecSeconds
14400; fileMaxBytes 64 MiB (PUT file and PUT tar body cap).

isCompat. 42-50. UA prefix test. Trusts the User-Agent header. No side
effects. No locks. Callers: ServeHTTP main.go:1294, 1301. Invariant: only
the published clients send these prefixes.

newUUID. 52-59. Random v4 UUID. Trusts crypto/rand; its error is dropped.
Callers: register main.go:209, compatExecStart 794. Invariant: rand does
not fail (on failure the id is zeros plus version bits and would collide).

compatImage, compatExec, compatTomb, compatState, idemEntry. 61-104.
compatImage: ID, Ref, CPU, MemoryGiB, DiskGiB, Build, Dockerfile are
exported and so land in the state file (state.go:124-126, no json tags);
buildCtx, ctxMissing, builds, failedAt live in memory only. compatExec:
state is running, killed, lost, exited or timed_out; result is the whole
hotel exec document. compatState.mu guards images, idem, execs, tombs.
idemEntry.done is closed when the answer is final.

newCompat. 106-108. Empty maps.

compatErr. 111-118. Writes the client envelope and Retry-After. Callers: 37
in compat.go, 3 in build.go, 1 in main.go.

reEnvelope. 121-143. Hotel or broker error body to the client envelope;
copies Retry-After into retry_after_s. Trusts the body is JSON with an
"error" object or string; anything else passes through unchanged.

capture and methods. 146-154. A buffering ResponseWriter. status defaults
to 200 when the wrapped handler never calls WriteHeader.

roomByUUID. 156-164. UUID to room, owner checked. Locks b.mu. Callers:
compatRoom 588. Invariant: byUUID holds live rooms only.

hotelExec. 167-180. Clamps timeout to maxExec (config, default 14400),
sets body.timeout_seconds, POST /v1/sandboxes/<hid>/exec on the room's
hotel with an HTTP timeout of timeout+60 s, parses the answer (parse error
gives a nil doc). Trusts the hotel's own limit is not lower than the broker
max (else 400 invalid_timeout). Side effects: network; a process in the
room. No locks. Callers: compatRoom exec 644, compatExecStart 800,
runScript 863.

serveCompat. 182-228. Router. GET /v1/account: static document (owner_id,
empty email, scope sandboxes:control, no teams, no key expiry). GET
/v1/sandboxes/catalog: compatCatalog. POST /v1/runs: 201 with url "" (run
reports are dropped). POST /v1/images/import, POST /v1/images/build. GET
/v1/images/<id>: looks the id up in the shared images map (not scoped to
the guest), runs ensureBuilds for a built image with the caller's hotel
list, answers imageView. POST /v1/sandboxes through compatIdem. GET
/v1/sandboxes: compatList. GET /v1/quota: compatQuota. GET /v1/usage:
native handleUsage reshaped. /v1/sandboxes/<uuid>...: compatRoom.
Everything else: serveNative through a capture and flushCompat, so native
routes (snapshots, broker hotels, hotel receipts) answer errors in the
client envelope. GET /v1/images/prefetch/<id> is caught by the /v1/images/
prefix and answers 404 image_not_found under a compat UA.

compatTemplates. 231. room-1x4, room-2x8, room-4x16. All three map to
image alpine:3.20 with disk 10 GiB.

compatCatalog. 233-259. Sums free rooms over every hotel with h.ok,
drained hotels and the guest's hotel list included. Static capabilities:
dynamic_network_policy true; allowlist entry types (hostnames, wildcards,
ipv4, cidrs, no ipv6, ports 80 and 443); max_lifetime_seconds 23 h;
cleanup_margin 0; exec_output_limit_bytes 16 MiB (matches
sandbox_guest.py:1459 cap); max_exec_seconds from config; templates with
hourly_rate_usd "0.05", "0.10", "0.20". Locks b.mu. Callers: serveCompat
189. Invariant: the catalog describes what this guest can get (it does
not: see hazards 6, 23).

compatImport. 261-296. Body up to 1 MiB. image: any string (the hotel
validates the reference, B43). resources cpu, memory_gib,
minimum_free_disk_gib: positive numbers, else 1, 4, 10. id: first 16
bytes of sha256(guest|ref|cpu|mem|disk) shaped as a UUID, so the same
import gives the same id. Stores the image (never removed), markDirty.
Fire-and-forget POST /v1/images/prefetch on every hotel in the guest's
list with context.Background and 10 minutes; results dropped. Answers
state "ready" without any pull. Locks: compat.mu briefly; limitsAllow
takes b.mu per hotel. Callers: serveCompat 193.

compatIdem. 299-337. Reads the body up to 1 MiB (longer bodies are cut,
and then fail as "not JSON" downstream). Without Idempotency-Key runs fn.
Key: guest|path|header value; the body is not part of the key. First
caller runs fn against a capture, stores status and body, deletes the
entry when the status is 429 or 500 and up, closes done, copies the
captured headers. Later callers wait for done or their own context, then
replay status and body with Content-Type json only. saveCompat persists
finished entries (state.go:105-116) and loadCompat restores them closed;
in-flight entries are not saved. A background start (execs) is final at
once and is saved with its exec_id; a synchronous exec stays in flight for
the whole command and is never saved. Pruned after 48 h, only by saveCompat,
which only runs with state_dir. Locks: compat.mu around map operations.
Callers: serveCompat 210 (create), compatRoom 638 (exec), 665 (execs).
Invariant: any answer that is not 429 or 5xx is final for the key.
Broken for 409 image_not_ready, which carries Retry-After (finding F9).

compatCreate. 339-452. Reads image_id, image, template, network,
network_allow, lifetime_seconds (default 3600, cap 48 h), sealed (bool
only), labels (as given; createOne replaces a non-object with an empty
one and adds broker_guest). Ignores env, shape and every other field.
image_id: images map, not scoped to the guest; built image: hotels that
hold it plus tag (409 image_not_ready, retry 5, when none); imported:
ref. Unknown id 404. template outside compatTemplates 404
template_not_found. No source 400 invalid_source. compatNetwork. scope
(guest hotel list, sealed default). Built image held only on hotels this
create may not use: ensureBuilds and 409 (retry 10). admit, createOne,
unreserve. Non-202: code and message through reEnvelope. 202: byBID for
the uuid, 201 compatView. Side effects: a room. Locks: compat.mu;
b.mu through scope, admit, byBID. Callers: serveCompat via compatIdem
210. Invariant: register ran inside createOne, so byBID finds the room;
else the answer's id is "". Also: a 409 from this function is cached by
compatIdem (F9); after a restart the built-image branch never restarts a
build (F3).

compatNetwork. 460-484. mode as a string, or the object {"mode","allow"}.
nil, "", internet, public: internet. deny_all, none: deny_all. allowlist:
needs one or more entries. Else 400 invalid_network_mode. Entries are not
checked here (hotel: B46). Callers: compatCreate 386, compatSetNetwork
505.

compatSetNetwork. 487-525. Body up to 1 MiB. Requires a string mode
(B18). allow, else network_allow. PUT /v1/sandboxes/<hid>/network, 2
minutes. Copies X-Room-* headers (signed receipt). Non-200: reEnvelope.
200: {"id": uuid, "network": doc.network}. Callers: compatRoom 663 for
PUT, POST and PATCH.

compatView. 528-542. Copy of the hotel room document with id = uuid,
hardware "standard", state default "running", lifetime_seconds =
ttl_seconds. The hotel's expires_at (ISO string), hotel, labels, env_keys,
metrics pass through. Callers: compatCreate 451, compatList 561,
compatRoom 622.

compatList. 544-566. Drops limit and offset. Native handleList (guest
hotel list since B56). Each hotel room becomes compatView with the uuid
from byBID; a room not yet in h.rooms is dropped silently; hotel_errors is
dropped. Locks b.mu. Callers: serveCompat 212. Untested.

compatQuota. 568-584. Native handleQuota, then admission_open and
available.rooms summed over every hotel with h.ok (drain and the guest's
list ignored). Locks b.mu. Callers: serveCompat 214. Untested.

compatRoom. 586-707. UUID to room with owner check. Unknown uuid: a
tombstone answers GET and DELETE with state deleted plus cleanupState,
anything else 404 sandbox_not_found. Routes on a live room: GET: hotel GET
(hotel 404 becomes state deleted). DELETE: native handleRoom; 204 or 404
writes a tombstone, markDirty, answers 200 with cleanupState. POST exec:
compatIdem, compatExecBody, hotelExec on the request context, state
exited or timed_out. network: compatSetNetwork. POST execs: compatIdem,
compatExecStart. execs/<id>: compatExecPoll. files, tar, stat: the shell
programs below. lifetime (POST, PATCH): body up to 64 KiB; extend_by_seconds
or ttl_seconds, else 3600; sent as heartbeat ttl_seconds (the hotel sets
expires_at = now + ttl, sandbox_provider.py:849); lifetime_seconds is not
read. Default: native handleRoom with the broker id and flushCompat (id
rewrite). Trusts the tail (handleRoom refuses . and .. since B59). Locks:
b.mu via roomByUUID; compat.mu for tombs.

cleanupState. 709-720. GET the room on its hotel, 15 s. 404 or unknown
hotel: confirmed; else pending. Called on every DELETE answer and every
GET or DELETE of a tombstone. Untested.

writeHotelCompat. 722-731. Error: reEnvelope. Success: byte replace of
"<hid>" by "<uuid>". Callers: lifetime 694. Untested.

flushCompat. 733-747. Copies captured headers. Error: reEnvelope, drops
Content-Length. JSON success on a room: replace "<bid>" by "<uuid>", drops
Content-Length. Callers: serveCompat 226, compatRoom 629, 705. Untested.

compatExecBody. 750-785. command, else cmd: a non-empty list of non-empty
strings (a string gives 400). Copies cwd, env, user, stdin as given (user
root is allowed). timeout_seconds > 0 else maxExec. Callers: compatRoom
639, compatExecStart 788.

compatExecStart. 787-817. New exec with a random id, state running, in
the execs map. Goroutine on context.Background: hotelExec; result: killed
stays killed; transport error: lost; non-200: lost "hotel answered N";
else exited or timed_out with the whole hotel document (stdout and stderr
up to 16 MiB each). Answers 202 {exec_id, state running}; the cloud API
answers 200. Memory: the result is kept until the process ends. Not
persisted. Locks compat.mu. Callers: compatRoom 665 via compatIdem.
Untested.

compatExecPoll. 819-852. The exec must exist and name this room (the
room's owner was checked in compatRoom). DELETE: state killed and cancel
of the broker's HTTP call; the hotel keeps running the process. Other
methods: wait up to 25 s on done, a timer or the request context. Answers
exec_id, state and the result fields flat. Callers: compatRoom 667.
Untested.

shq. 856. POSIX single quotes; ' becomes '"'"'. Covers every byte except
NUL, which JSON carries as \u0000 and the hotel's exec cannot pass to
argv.

runScript. 858-872. hotelExec of ["sh", "-c", script] as root, optional
stdin. Transport error: "hotel <id> did not answer" (B52). Non-200:
"hotel answered N". Callers: the five file functions.

exitCode. 874-879. exit_code or -1.

compatPutFile. 881-908. path must start with "/". Body up to 64 MiB, 413
beyond. mode: decimal integer (cloud API meaning, 420 = 0644) written in
octal, not bounded. Script and stdin below. 900 s. Non-zero: 500
file_write_failed with stderr.

compatGetFile. 910-934. path not checked (a relative path is resolved
against the exec cwd, /work on the hotel). Exit 44: 404 file_not_found.
Non-zero: 500 file_read_failed. truncated or bad base64: 413
file_too_large. Cap: 16 MiB of base64, about 12 MiB of file.

compatPutTar. 936-958. path must start with "/" and not be "/". Body up
to 64 MiB. gzip sniffed from the magic bytes. The pipeline's exit code is
tar's.

compatGetTar. 960-984. Exit 44: 404 path_not_found. The pipeline's exit
code is base64's, so a tar failure is masked. Non-zero, bad base64 or
truncated: 500 tar_failed with stderr (empty on truncation). Cap: about 12
MiB compressed.

compatStat. 986-999. Answers path, exists, is_dir, is_file. No size or
mode (the cloud API gives both).

### Shell programs run as root in the room (sh -c, wrapped by the hotel in
timeout 900, sandbox_guest.py:1421-1431)

- PutFile 898-900: `set -e; mkdir -p '<dir>'; base64 -d > '<p>'[; chmod
  <octal> '<p>']`, stdin = base64 of the body (1.33x). dir = path.Dir(p).
- GetFile 912: `test -f '<p>' || exit 44; base64 '<p>'`.
- PutTar 951: `set -e; mkdir -p '<p>'; base64 -d | tar --no-same-owner
  -x[z]f - -C '<p>'`, stdin = base64 of the body.
- GetTar 966: `test -d '<p>' || exit 44; tar -czf - [--exclude='<e>']...
  -C '<p>' . | base64`.
- Stat 988: `if [ -d '<p>' ]; then echo dir; elif [ -f '<p>' ]; then echo
  file; elif [ -e '<p>' ]; then echo other; else exit 44; fi`.
- Quoting: every guest value goes through shq. A value cannot leave its
  quotes. `--exclude=<e>` is one argv word, so e cannot add options. A
  leading "-" in p reaches test, base64 or tar as an operand after a flag,
  not as a flag. There is no privilege at stake: the guest already has
  root exec in its own room through the exec route with user root.
- Tools assumed in the image: sh, test, mkdir, base64, tar, gzip, chmod.
  A missing sh gives a non-zero exit (500). A missing gzip in GetTar gives
  exit 2 from tar, masked by base64: 200 with an empty body.
- Output cap: the hotel reads the whole output into memory
  (subprocess.run with capture_output, sandbox_guest.py:345), then cuts
  stdout and stderr to 16 MiB each and sets truncated
  (sandbox_guest.py:1459-1467). The compat routes honour truncated.

## build.go

buildContextMaxBytes, buildHotel. 26-32. 256 MiB; state building, ready
or failed with tag or error.

compatBuild. 34-84. MaxBytesReader at 257 MiB (a larger body is a 400
"invalid_build", not 413). ParseMultipartForm(32 MiB): file parts beyond
that go to temp files, which net/http removes after the handler. Non-file
parts (dockerfile) up to 10 MiB more. dockerfile: required, any content,
passed to the hotels verbatim. context: up to 256 MiB, 413 beyond. cpu,
memory_gib, minimum_free_disk_gib as in import. id: first 16 bytes of
sha256("build|guest|dockerfile|sha256(ctx)|cpu|mem|disk"). Same id and a
built image: reuse it; when ctxMissing or the stored bytes differ (B58:
a cut-short context file), replace the context, reset img.builds to an
empty map, save the context. New id: store and save. markDirty,
ensureBuilds, imageView. Disk: state_dir/build-contexts/<id>.tar.gz
(write then rename). Memory: buildCtx stays for the process lifetime
(B55). Locks compat.mu. Callers: serveCompat 195.

ensureBuilds. 88-113. Hotels: not drained and allowed by the guest's
list (b.mu). Under compat.mu: return when ctxMissing; for each hotel with
no state, or failed more than a minute ago, set building and start
buildOn. No cap on retries: a client that polls a failing image restarts
a build on every hotel once a minute. Callers: compatBuild 82, serveCompat
206 (every GET of the image, with the caller's hotel list), compatCreate
415. Invariant: img.builds has an entry for every buildOn in flight.
Broken by the reset in compatBuild (F4).

buildOn. 115-147. Under compat.mu: base64 of the context (1.33x copy).
json.Marshal (second copy). POST /v1/images/build on the hotel, 30
minutes, context.Background. Under compat.mu: st := img.builds[hotel];
200 with image: ready and tag; else failed with the hotel's error;
failedAt. Dereferences st without a nil check. Memory: two transient
copies of 1.33x the context per hotel, concurrently for all hotels of one
build.

builtOn. 150-158. Hotels in state ready and the tag of the last one met
in map order. Caller holds compat.mu. Callers: compatCreate 354,
imageView 171. Invariant: every hotel tags the same content with the same
tag (sandbox_guest.py:1077-1078: sha256 of Dockerfile and context).

imageView. 163-193. scope for a plain create (b.mu, then released).
Under compat.mu: imported image: ready. Built: ready when a ready hotel
is selectable for this guest's plain create; ctxMissing: failed "context
lost"; any hotel building or no entries: pending; else failed with the
first error met in map order. Callers: serveCompat 208, compatBuild 83.

## images.go

placement, selects, allows, apply. 39-97. selects: allowed list (guest),
ids, images (built image holders), the sealed-config rule (a hotel with
Sealed in config takes only creates that ask for sealed or name it),
match labels, exclude labels. allows: only (fork hotel) and selects.
apply: strips hotels, hotel_labels, exclude_hotel_labels, sealed from the
hotel body; sets snapshot_id. Reads h.cfg.Labels and h.cfg.Sealed without
b.mu while patchHotel (hotels.go:234-241) swaps the labels pointer under
b.mu: a data race on the pointer, no map mutation. Callers of selects and
allows: pick main.go:368, noRoomReason 116, parseSelection 229,
placementFor 257, imageView build.go:173, anyHotel guests.go:255,
handlePrefetch 554.

noRoom, noRoomReason. 101-147. 503 snapshot_hotel_unavailable for a fork;
else 409 no_matching_hotel, 429 no_free_rooms, 503 hotels_unavailable.
Locks b.mu in noRoomReason. Callers: createOne main.go:449.

errDoc, apiErr, stringMap. 149-177. Helpers.

parseSelection. 182-234. hotels: each id must exist and be allowed, else
409 unknown_hotel. hotel_labels, sealed (true: match; false: exclude),
exclude_hotel_labels. scope. 409 no_matching_hotel when no hotel selects.
Callers: placementFor 240, handlePrefetch 540.

placementFor. 238-262. parseSelection (a no_matching_hotel is deferred
for a fork). snapshot_id: findSnapshot; a sealed default is dropped when
the snapshot's hotel is unsealed; 409 snapshot_hotel_excluded; pl.only =
the hotel. Callers: handleCreate main.go:583.

handleHotels. 265-284. Guest-scoped hotel list with labels, up, drain,
free rooms. Locks b.mu. Callers: serveNative main.go:1348.

snapshotName, guestSnapshot, hotelSnapshots, matchSnapshot. 290-334.
Hotel name "<guest>:<name>". guestSnapshot rewrites snapshot_id to
"<hotel>.<sid>", strips the name prefix, deletes the guest label, adds
hotel. hotelSnapshots: GET /v1/snapshots?label=broker_guest=<guest> on
one hotel, 30 s. matchSnapshot: by sid or by the prefixed name.

findSnapshot. 339-384. "<hotel>.<rest>": that hotel, any hotel in the
chain, not the guest's list. Bare ref: every hotel in parallel, not the
guest's list; one hit, else 404 or 409 snapshot_ambiguous. Trusts the
hotel to filter by the label exactly (sandbox_provider.py:808-826: equal
per key, the broker's label is the only one sent). Callers: placementFor
247, handleSnapshot 461.

roomSnapshot. 387-417. Adds the guest label, prefixes the name, POST
/snapshot (10 min), rewrites result. Callers: handleRoom main.go:689.

writeRaw. 419-423.

handleSnapshotList. 426-451. Every hotel in parallel, not the guest's
list; hotel_errors names a hotel that failed. Callers: serveNative 1344.

handleSnapshot. 454-488. DELETE /v1/snapshots/<ref>, POST
/v1/snapshots/<ref>/push (body up to 1 MiB passed as given, registry_auth
included, 30 min). findSnapshot first. Callers: serveNative 1346.

prefetch types, prefetchKeep, newID. 492-519. 24 h in memory.

handlePrefetch. 522-576. images: non-empty strings. parseSelection
(guest-scoped). registry_auth passed in the hotel body, not stored, held
in memory until the goroutines end. Job in memory; jobs older than 24 h
are pruned here. One goroutine per selected hotel. Callers: serveNative
1340.

prefetchOn. 580-610. POST /v1/images/prefetch, 30 min,
context.Background. done or failed per hotel.

prefetchView, handlePrefetchStatus. 613-642. Copy for the guest; status
checks job.guest.

## State and lifetimes

| State | Where | Pruned | Survives a restart |
|---|---|---|---|
| images (import, build) | compat.images, state file | never | yes (builds map reset to empty) |
| build contexts | img.buildCtx, state_dir/build-contexts | never | yes (a short file is replaced on resubmit, B58) |
| idempotency answers | compat.idem, state file | 48 h, only with state_dir | finished ones only |
| tombstones | compat.tombs, state file | 48 h, only with state_dir | yes |
| background execs | compat.execs | never | no (poll answers 404) |
| room uuids | b.byUUID, state file | with the room | yes |
| prefetch jobs | b.prefetch.jobs | 24 h on the next prefetch | no |

## What a client is promised, and where it differs

- Account: owner_id = guest id, email "", scopes [sandboxes:control], no
  teams, no key expiry or budget.
- Catalog: 23 h max lifetime (create caps at 48 h; cloud API 24 h); exec
  output 16 MiB (matches the hotel); max_exec_seconds from config; hourly
  rates 0.05, 0.10, 0.20 (the published price is one flat rate);
  free_rooms and available are chain-wide; no max_file_bytes (cloud API 8
  MiB; here PUT 64 MiB, GET about 12 MiB); no max_sync_exec_seconds (cloud
  API 45 s; here a sync exec holds the connection up to max_exec).
- Runs: 201 with url "". Reports are dropped.
- Import: "ready" at once, no pull check.
- Create: 201 with the hotel document and a uuid. env and shape are not
  forwarded. Errors carry retry_after_s.
- Exec: sync exec runs up to max_exec on one connection. Background start
  answers 202 (cloud 200). Poll answers fields flat with "truncated"
  (cloud: stdout_truncated, stderr_truncated).
- Lifetime: extend_by_seconds is sent as the new absolute TTL;
  lifetime_seconds is ignored.
- Delete: 200 {state deleted, cleanup_state}; a tombstone answers for 48
  h with state_dir.
- Files: mode decimal; GET cap about 12 MiB; PUT cap 64 MiB; tar GET cap
  about 12 MiB compressed, over the cap a 500 with an empty message; stat
  without size or mode.

## Hazards (code that trusts what it did not check)

1. compatIdem 316: treats every answer that is not 429 or 5xx as final.
   409 image_not_ready carries Retry-After and is cached for 48 h (F9).
2. compatRoom 679-694: sends extend_by_seconds as the new absolute TTL and
   does not read lifetime_seconds; the hotel sets expires_at = now + ttl
   (F1).
3. compatCreate 345-399: forwards only the fields it knows; env and shape
   are dropped without an error (F2).
4. buildOn 128-139: dereferences img.builds[hotel] without a nil check;
   compatBuild 73 resets that map while builds are in flight (F4).
5. compatCreate 363-366: a built image with an empty builds map (every
   restart) answers 409 and never restarts the build; only GET
   /v1/images/<id> does (F3).
6. compatCatalog 236-242, compatQuota 575-579: sum free rooms over every
   hotel, including drained ones and hotels outside the guest's list (F6).
7. findSnapshot 360, handleSnapshotList 431: ask every hotel in the chain
   for the guest's snapshots; a hotel outside the list is reached and can
   stall the call (F5, extends B56).
8. compatGetTar 966: the pipeline's exit code is base64's; a tar failure
   (missing gzip, a file removed during the walk, an I/O error) answers
   200 with a short or empty archive.
9. compatGetTar 977: over the output cap answers 500 tar_failed with an
   empty message where compatGetFile answers 413 with a reason (F7).
10. compatExecStart 793-816: the exec record lives only in this process;
    a restart answers 404 to the poll while the command runs on, and the
    keyed retry of the start replays an exec_id the new process does not
    know. A synchronous exec in flight at the restart has no saved
    idempotency entry (compatIdem saves finished entries only), so its
    keyed retry runs the command a second time (F8, extends B48).
11. compatExecPoll 827-834: DELETE cancels the broker's call only; the
    process keeps running in the room until its timeout.
12. serveCompat 196-208: the images map is not scoped to the guest; an id
    is a hash of guest and inputs, so only unguessability separates
    guests; a GET by another guest runs ensureBuilds with that guest's
    hotel list.
13. compatImport 287-294: one goroutine per hotel per import, 10 minutes
    each, no bound per guest; the hotel pulls whatever it is given.
14. compatBuild and buildOn: no bound on concurrent builds per guest; one
    256 MiB build makes about 680 MiB of transient copies per hotel, all
    hotels at once, on top of the 256 MiB kept for the process lifetime
    (sharpens B54, B55).
15. ensureBuilds 107: a failed hotel is retried a minute later on every
    GET of the image, without a cap; a client that keeps polling a
    failing build keeps every hotel building.
16. compatBuild 40-44: the Dockerfile is passed unread; the hotel runs
    `docker build` on the room daemon (sandbox_guest.py:496-507) with no
    --network, no resource limits, and BuildKit on by default; whether RUN
    steps run under runsc or runc is not established in this repo
    (observation O1).
17. compatList 557-563: drops rooms the broker has not registered yet and
    drops hotel_errors; a hotel outage looks like fewer rooms.
18. compatIdem, compatCreate, compatSetNetwork, compatImport: a 1 MiB body
    cap that cuts silently and then answers "request body is not JSON"
    (the cloud API allows 8 MiB).
19. compatPutFile 893-897: mode is not bounded; chmod of an out-of-range
    value fails after the file is written, so a 500 leaves the file.
20. runScript assumes sh, base64, tar, gzip, test, mkdir and chmod exist in
    the image.
21. hotelExec 168: clamps to the broker max and trusts the hotel max is
    not lower.
22. selects 67-78: reads hotel labels without b.mu while patchHotel writes
    them under b.mu.
23. compatCatalog 255: counts drained hotels (h.cfg.Drain not checked) as
    free.
24. idem and tombs grow without bound when state_dir is unset
    (saveCompat is the only pruner, state.go:73-75).
25. compatSetNetwork 494-510 and compatCreate 386: allow entries pass
    unchecked to the hotel (B46 holds there).

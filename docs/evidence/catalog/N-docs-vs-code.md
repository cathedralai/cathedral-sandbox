# Docs versus code, PR #312 head (887ed40)

Artifact: cathedral-sandbox at 887ed40 (fix/review-round-6, stacked on #311),
worktree ~/Documents/projects.nosync/cathedral-sandbox-pr308. Read only.
Known items B1 to B132 are not repeated unless a doc sentence still says the
old thing.

Mode: docs-versus-code. Every sentence of the named documents was checked
against the code at this commit. Line numbers are those of 887ed40.

Documents read: docs/CUSTOMER_SANDBOX_ACCESS_2026-10-21.md, broker/README.md,
room-kit/README.md, room-kit/sealed/README.md,
docs/evidence/CUSTOMER_FEEDBACK_FIXES_2026-10-23.md, README.md,
docs/evidence/REVIEW_ROUNDS_2026-10-23.md (deploy plan and "Lands at" column).
docs/DEDICATED_SEALED.md does not exist at this commit.
The top level README.md has no sandbox product section at this commit: it is
the SN94 mining README (lines 1 to 97). Nothing to check there.

Code read in full: broker/*.go (not the tests), room-kit/install.sh,
room-kit/room_receipts.py, room-kit/room_egress.py, room-kit/verify_receipts.py,
room-kit/room_health.py, room-kit/profiles/v1.sh, room-kit/lib/*,
room-kit/room.env.example, room-kit/versions.lock, room-kit/room_api.py,
room-kit/sealed/*, cathedral/sandbox_api.py, cathedral/sandbox_server.py,
cathedral/sandbox_guest.py, the pinned tarball
room-kit/dist/cathedral-6701dda.tar.gz (extracted to the scratchpad and
grepped). Parts of cathedral/sandbox_provider.py, cathedral/sandbox_egress.py
and cathedral/cli.py by grep.

Verdict words: UNSUPPORTED (the code does not do this), CHANGED (#311 or
#312 changed it and the sentence still says the old thing), MISREAD (true as
written, but a customer or operator would take it the wrong way), OK.

---

## 0. Cross cutting: the kit still installs the hotel API at 6701dda

Finding N0. room-kit/versions.lock:18-20 pins CATHEDRAL_COMMIT=6701dda and
CATHEDRAL_TARBALL=dist/cathedral-6701dda.tar.gz (sha256 033e8807...).
install.sh:169-174 installs that tarball; sealed/build-guest.sh:133-141 packs
the same tarball into the measured initrd. Four #312 commits changed
cathedral/ after that pin: 94713c4, 2e41dda, 707062e, 91150c1.

The extracted pinned tarball has none of these markers (HEAD has them all):
DOCKER_BUILDKIT (B62), install_stop_signal (B84), MAX_BODY_BYTES (B65),
"invalid_request" (B63), _GUEST_START_FAULTS (B80), _run_bounded and
EXEC_OUTPUT_CAP (B78, B79), _snapshot_owner (B67), sweep_tombstones (B82),
timeout -k (B87), the on-disk _auth_pulled set (B81, restart part).

So at this commit a stage H reinstall or a stage S rebuild does not deliver
B62, B63, B64, B65, B66, B67, B68, B69, B71, B78, B79, B80, B81 (restart
part), B82, B83, B84, B85, B87. It does deliver the kit-side fixes (B72, B73,
B113 to B127) because those live in room-kit/ files.

Doc sentences this breaks:

- docs/evidence/REVIEW_ROUNDS_2026-10-23.md:95-98 (deploy plan step 3, "Run
  install.sh from the merge checkout") and :193-196 ("#312 adds a fifth check
  to stage H and S: run the build probe and expect the RUN step to report the
  gVisor kernel"). With the pin as it is, that probe fails after the deploy.
- docs/evidence/REVIEW_ROUNDS_2026-10-23.md:121-139, 142-145, 147 ("Lands at
  H, S" for the items above).
- room-kit/README.md:202-203 "Then every guest runs under runsc." Rooms do;
  RUN steps of POST /v1/images/build do not on a hotel installed from this
  kit (BuildKit's runc worker, B62).
- room-kit/sealed/README.md:3-5 "The guest runs the same room kit and the
  same hotel API as an unsealed hotel." True, and both are the 6701dda API.

Corrected sentence (for the deploy plan): "Before stage H or S, run
./make-dist.sh <merge commit> in room-kit, commit the new tarball and
versions.lock, and reinstall from that commit. A reinstall from 887ed40
installs the hotel API at 6701dda, which has none of the #312 hotel fixes,
and the build probe still reports the host kernel."

---

## 1. docs/CUSTOMER_SANDBOX_ACCESS_2026-10-21.md

N1. Line 12. Claim: "hotels": [...] restricts to these ids; an unknown id
returns 409 unknown_hotel.
Code: broker/images.go:184-196 (native path). broker/compat.go:335-341: the
Harbor and ctcli create copies only labels, image, shape, env, network,
lifetime and sealed; "hotels", "hotel_labels" and "exclude_hotel_labels"
are dropped without an error.
Verdict: MISREAD (native only).
Corrected: "On the /v1 API, "hotels", "hotel_labels" and
"exclude_hotel_labels" choose the hotel; an unknown id is 409 unknown_hotel.
Harbor and ctcli creates ignore these three fields; they can send only
"sealed": true or false."

N2. Lines 17-19. Claim: a sealed hotel takes only sealed creates; send
"sealed": true or ask for default_sealed; without it a guest whose only hotel
is sealed gets no_matching_hotel.
Code: broker/images.go:65-69: the sealed-only rule is skipped when the create
names hotels ("hotels": [id]); hotel_labels {"sealed": "true"} also selects
it (images.go:70-73).
Verdict: MISREAD.
Corrected: "A sealed hotel takes a create that says "sealed": true, that
sends hotel_labels {"sealed": "true"}, or that names it in "hotels". A plain
create goes there only when the guest has default_sealed. A guest whose only
hotel is sealed and who sends a plain create gets 409 no_matching_hotel."

N3. Lines 23-31. Capacity errors table and "503 hotels_unavailable always
carries Retry-After: 5".
Code: broker/images.go:111-147 matches the table for a single create.
broker/main.go:738-758: for a batch create (count > 1) with no room placed,
the answer carries Retry-After only when the status is 429.
Also broker/main.go:533-543 and 578-583: when every matching hotel answered
429 itself, the guest gets the hotel's own 429 body (codes
create_rate_exceeded, quota_exhausted, key_subquota_exhausted from
cathedral/sandbox_provider.py:390-412), not no_free_rooms.
Verdict: MISREAD (two gaps).
Corrected: "A single create that finds no hotel gets 503 hotels_unavailable
with Retry-After: 5. A batch create answers 503 with no Retry-After header.
A hotel that is full or paced beyond ROOM_CREATES_PER_MINUTE answers its own
429 (create_rate_exceeded, quota_exhausted or key_subquota_exhausted); the
broker passes that code on after it has tried the other hotels."

N4. Line 41. Claim: hostname entries are reachable on TCP 80 and 443 via the
egress proxy.
Code: room-kit/room_egress.py:240-242, 708-758. OK. The proxy connects to
public IPv4 answers only (line 732).
Verdict: OK.

N5. Line 42. Claim: "pypi.org:443" or ":80" normalized to the bare hostname.
Code: cathedral/sandbox_api.py:275-291, room-kit/room_egress.py:99-116. OK.
Verdict: OK.

N6. Line 43. Claim: "*.pythonhosted.org": all subdomains.
Code: room-kit/room_egress.py:176-182 allows_name: name.endswith("." + w).
The suffix itself (pythonhosted.org) is not allowed.
Verdict: MISREAD.
Corrected: "*.pythonhosted.org allows every name under pythonhosted.org and
not pythonhosted.org itself; add the bare name as a second entry when you
need it."

N7. Lines 44-45. Claim: IPv4 address and IPv4 CIDR, with the example
"10.0.0.0/8".
Code: cathedral/sandbox_api.py:98-101 and 292-300: 10.0.0.0/8 overlaps
_NON_PUBLIC_V4 and is refused with 400 invalid_network_allowlist "private,
host or reserved ranges cannot be allowlisted" (B46, #311).
room-kit/room_egress.py:84-87, 126-127 refuses it again at the enforcement
point.
Verdict: UNSUPPORTED (the example is an entry the code rejects).
Corrected: "IPv4 CIDR, for example "203.0.113.0/24": all addresses in the
range, all ports. Private, loopback, link-local, carrier NAT, multicast and
reserved ranges (10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16,
127/8, 0/8, 224/4, 240/4, 192.0.0/24, 198.18/15) are refused with 400
invalid_network_allowlist."

N8. Lines 48-49. Claim: only ports 80 and 443 for named hosts; other ports
dropped.
Code: room_egress.py:235-250 (prerouting redirect for 80/443/53, forward
drop for the rest). OK.

N9. Lines 50-53. Claim: "hostname:8080" is 400 invalid_network_allowlist with
the message "named hosts only allow TCP 80 and 443"; "1.2.3.4:443" is 400.
Code: sandbox_api.py:311-315 (message: "allowlist entry 'x:8080': named
hosts only allow TCP 80 and 443 (omit the port, or use :80/:443)"),
sandbox_api.py:287-291. OK.

N10. Line 54. Claim: IPv6 is not supported.
Code: sandbox_api.py:297, 306; room_egress.py:123-124; and since #312
(B115) room_egress.py:268 drops IPv6 frames at the bridge guard, lib/room-
net.sh:100-105 drops them at the host.
Verdict: OK. Could add: "Rooms get no IPv6 address and IPv6 frames from a
room are dropped."

N11. Line 55. Claim: "internet" mode gives full egress.
Code: room-kit/lib/room-net.sh:82-85 drops 169.254/16, 10/8, 172.16/12,
192.168/16, 100.64/10 for every room bridge; room-net.sh:89 drops frames
with a source outside the bridge CIDR; room_egress.py:9 comment says the
same.
Verdict: MISREAD.
Corrected: ""internet" mode gives egress to public addresses. Private
ranges, link-local (cloud metadata) and the host itself are always blocked."

N12. Line 56. Claim: a room's policy can be changed live with PUT
/v1/sandboxes/<id>/network.
Code: cathedral/sandbox_guest.py:1820-1826: a room created with network
"none" has no interface, 409 network_not_switchable. sandbox_guest.py:1829-
1830 (#312, B85): a frozen room is 409 sandbox_frozen before the daemon
moves. broker/compat.go:510-516: the change must name a mode (400
invalid_network_mode).
Verdict: MISREAD.
Corrected: "A room created with internet, deny_all or allowlist can switch
live with PUT /v1/sandboxes/<id>/network; the body must name the mode. A
room created with "none" has no interface and answers 409
network_not_switchable. A frozen room answers 409 sandbox_frozen until it is
thawed."

N13. Lines 60-63. Claim: on the compat path a missing "network" defaults to
"internet".
Code: broker/compat.go:484-486 (compat). cathedral/sandbox_server.py:104-111
and sandbox_api.py:357: a native create with no "network" is NetworkSpec()
mode "public", which is "internet" (sandbox_api.py:248). Both paths default
to internet.
Verdict: MISREAD (implies the native path differs).
Corrected: "A create with no "network" field gets internet mode on both the
/v1 API and the Harbor and ctcli path. Send "network": {"mode": "deny_all"}
or an allowlist when the room must not reach the internet."

N14. Lines 69-78. Claim: the exec body field is "cmd" or the alias
"command"; it must be a non-empty JSON array of strings; a string value
returns 400 invalid_exec.
Code: broker/compat.go:772-807 (Harbor and ctcli only): both names, array
only, string is 400 invalid_exec. cathedral/sandbox_server.py:391-405
(native path, same in the pinned tarball at line 357): only "cmd" is read,
"command" alone is 400 invalid_exec "cmd is required"; a string cmd is
accepted (sandbox_api.py:688-689, 717: it runs as bash -c, and
sandbox_guest.py:1551-1552 rewrites bash to sh).
Verdict: UNSUPPORTED for the /v1 API.
Corrected: "Harbor and ctcli: "cmd" or "command", a non-empty array of
strings; a string is 400 invalid_exec. The /v1 API: "cmd" only ("command"
is 400 invalid_exec: cmd is required); an array runs as given, a string
runs through sh -c."

N15. Lines 79-81. Claim: output is truncated by the hotel at
exec_output_limit_bytes (default 16 MiB, shown in GET
/v1/sandboxes/catalog); "truncated": true.
Code: cathedral/sandbox_guest.py:320, 1598-1606 (a constant, not a setting);
broker/compat.go:193-194, 252: the catalog route exists only for requests
whose User-Agent starts with cathedral-harbor/ or ctcli/ (compat.go:36-51).
A native GET /v1/sandboxes/catalog goes to handleRoom (main.go:1469-1470)
and answers 404 sandbox_not_found (main.go:797-801).
Verdict: MISREAD.
Corrected: "Exec output is cut at 16 MiB per stream (a fixed limit) and the
answer then has "truncated": true. Harbor and ctcli see the limit as
exec_output_limit_bytes in GET /v1/sandboxes/catalog; the /v1 API has no
catalog route."

N16. Lines 87-90. Claim: the files API reaches /work only; a path outside
/work returns 400 path_outside_work; move files with an exec.
Code: cathedral/sandbox_guest.py:1065-1074, 1679-1694 (native /v1 files,
tar, stat). broker/compat.go:10-12, 877-1030: the Harbor and ctcli files,
tar and stat routes run through exec plus base64 inside the room, reach any
absolute path, cap PUT bodies at 64 MiB (compat.go:40, 910-913: 413
file_too_large), and a GET larger than the 16 MiB exec output limit (about
12 MiB of file after base64) is 413 file_too_large (compat.go:950-952,
1000-1002). Their errors are invalid_path, file_not_found, path_not_found,
file_write_failed, tar_extract_failed, never path_outside_work.
Verdict: UNSUPPORTED for Harbor and ctcli.
Corrected: "/v1 API: files, tar and stat reach /work only; another path is
400 path_outside_work. Harbor and ctcli: files, tar and stat run as
commands inside the room and reach any path; a PUT body is at most 64 MiB
and a GET of more than about 12 MiB is 413 file_too_large. Both: files
written through the API land in the room as the room's user sees them."

N17. Line 90. Claim: snapshots and forks keep /work and the room's own file
system.
Code: sandbox_guest.py:1733-1751 (image plus /work archive), 1770-1782
(push: root file system only). OK.

N18. Lines 100-101. Claim: standard room, gVisor; sealed room, SEV-SNP; the
host cannot read the guest's memory or disk; the operator still holds the
hotel API key and "each such call gets a signed receipt"; plain HTTP on the
link.
Code: room-kit/room_receipts.py:248-257: only create, exec, process start,
network set (PUT, POST, PATCH), delete and bulk delete are signed. File
read and write, tar, stat, snapshot, fork, wait, process logs, process stop,
freeze, thaw get no receipt. room-kit/sealed/README.md:74-77 (#312) says
this correctly.
Verdict: UNSUPPORTED ("each such call").
Corrected: "The operator still holds the hotel API key, so it can call the
API like the broker does. Create, exec, process start, network change,
delete and bulk delete leave a signed receipt; file read and write, tar,
stat, snapshot, fork, wait, process logs and process stop leave none."

N19. Lines 103-104. Claim: sealed hotels are identified by the sealed: true
label in GET /v1/broker/hotels.
Code: broker/hotels.go:55-62: a hotel with "sealed": true in the config
always carries the label "sealed": "true" (a string). broker/images.go:265-
284: the list shows only the guest's hotels. A bool in hotel_labels is 400
invalid_hotel_selection (images.go:160-177).
Verdict: MISREAD.
Corrected: "GET /v1/broker/hotels lists the hotels your key may use; a
sealed one carries "labels": {"sealed": "true"} (a string). In a create use
"sealed": true (a boolean) or hotel_labels {"sealed": "true"} (a string)."

N20. Lines 104-105. Claim: the operator sets default_sealed with PATCH
/v1/broker/guests/<id>.
Code: broker/guests.go:187-243; guests.go:20-21 and broker/README.md:73: a
runtime change is memory only, a restart returns to the config file.
Verdict: MISREAD (operator).
Corrected: "...via PATCH /v1/broker/guests/<id>; the change lasts until the
broker restarts, so the operator also writes it into the config file."

N21. Lines 110-114 (#312 text). Claim: receipts come from every sealed hotel
and from an unsealed hotel only when its operator turned receipts on; a
hotel without the front answers 404 not_found; rooms there get no
X-Room-Receipt header.
Code: room-kit/lib/receipts_mode.sh:13-15 and install.sh:102-106, 415: a new
unsealed install has ROOM_RECEIPTS=1 unless the operator sets 0. B130 (live
state) says the shared hotels carry none today. The 404 comes from
room_health.py:194-195 when the broker's health URL points at the health
port instead of the receipts front or Caddy.
Verdict: MISREAD (default is on, not off; and see N22 for the header).
Corrected: "Receipts come from hotels that run the receipts front: every
sealed hotel, and an unsealed hotel installed with ROOM_RECEIPTS=1 (the kit
default; the operator can turn it off). Today's shared hotels do not run it.
A hotel without the front answers 404 not_found on GET
/v1/hotels/<id>/receipts and its rooms carry no X-Room-Receipt header."

N22. Line 114 (and sealed/README.md:110, broker/README.md:93). Claim: rooms
on receipted hotels get the X-Room-Receipt header on create, exec and
delete.
Code: /v1 API through the broker: main.go:527-528 and 761-763 (single
create), main.go:860 (room routes). broker/main.go:738-758: a batch create
(count > 1) returns a JSON list with no per-room headers. Harbor and ctcli:
compat.go:437-463 compatCreate writes its own 201 and copies no headers;
compat.go:647-671 exec goes through hotelExec, which returns no headers;
compat.go:628-646 delete answers its own JSON on 204 and copies no headers;
only compat.go:528 (network change) and the pass-through branch
compat.go:717-727 (for example POST .../processes) copy X-Room-* headers.
Verdict: UNSUPPORTED for Harbor, ctcli and batch creates.
Corrected: "/v1 API: a single create, an exec, a process start, a network
change, a delete and a bulk delete return the receipt in X-Room-Receipt. A
batch create (count > 1) returns none; read them from the chain. Harbor and
ctcli receive X-Room-Receipt only on network changes and process starts;
for create, exec and delete read GET /v1/hotels/<id>/receipts or GET
/v1/sandboxes/<id>/receipts."

N23. Line 116. Claim: the receipt chain is per-hotel, per-boot.
Code: room_receipts.py:146-154, 219: the key, binding and chain are made at
each start of <ROOM_ID>-receipts.service, which has Restart=on-failure
(install.sh:424). A restart of the service, not only a boot, starts a new
chain (B22, B76 pending).
Verdict: MISREAD.
Corrected: "The receipt chain is per hotel and per start of the receipts
service; a service restart, including a crash restart, begins a new chain
under a new key."

N24. Lines 116-120. Claim: the guest to room mapping is persisted in
state_dir/client-state.json; without state_dir the filter resets on restart.
Code: broker/state.go:46, 99-113, 230-249; broker/receipts.go:15-55. OK.
Without state_dir, live rooms are learned again from the hotel list
(main.go:1195-1197, 211-226); receipts of rooms deleted before the restart
are no longer visible. Fine as written.

N25. Lines 122-123. Claim: an ops key receives the raw, unfiltered chain.
Code: broker/main.go:891-897: a hotel outside the key's "hotels" list is
404 route_not_found for an ops key too (B12). main.go:903: unfiltered only
when the hotel is in the list.
Verdict: MISREAD (operator).
Corrected: "An ops key receives the unfiltered chain of a hotel in its own
hotel list; a hotel outside that list answers 404 route_not_found to it as
well."

N26. Lines 125-132. Claim: the filtered chain, verify_receipts.py --broker
--key-file, full-chain checks only on an unfiltered chain, --sandbox <id>.
Code: room-kit/verify_receipts.py:318: --hotel defaults to "sealed-1"; with
another hotel id the broker answers 404 route_not_found and urllib raises
an uncaught HTTPError (no FAIL verdict, a traceback). verify_receipts.py:346-
366: without --require-sealed, --expected-measurement, --ark-sha256 or
--product, a level 1 (unsealed) binding passes with "level": "hotel" in the
output (B74 fails it only when a sealed flag is given). --sandbox fetches
GET /v1/sandboxes/<id>/receipts through broker/main.go:803-809, which is 404
sandbox_not_found once the room has left the hotel list (deleted rooms).
Verdict: MISREAD (three traps).
Corrected: "Run verify_receipts.py --broker <url> --key-file <file> --hotel
<hotel id>; without --hotel it asks for a hotel named sealed-1. Add
--require-sealed when the hotel must be a sealed one: a hotel that answers a
level 1 (unsealed) binding otherwise passes. --sandbox <hotel>.<id> works
while the room exists; for a deleted room use the filtered hotel chain."

N27. Lines 136-151. Error codes quick reference.
Code: listed codes match (images.go:103, 132-146, 193, 233, 258;
compat.go:482, 491, 495, 514, 651, 812; guests.go:86, 105;
sandbox_guest.py:1073). Missing codes that a customer meets, several added
by #311 or #312: 413 request_too_large (broker room routes over 256 MiB,
main.go:811-815, B90; hotel bodies over 256 MiB, sandbox_server.py:845-849,
B65), 413 build_context_too_large (build.go:50, sandbox_server.py:622-623),
413 file_too_large (compat files, compat.go:912, 951, 967, 1001), 400
invalid_request (a wrong-shaped field, sandbox_server.py:324-330, B63), 500
internal_error (sandbox_server.py:331-335, B64), 409 sandbox_frozen
(sandbox_provider.py:284-288), 409 network_not_switchable
(sandbox_guest.py:1822), 400 invalid_timeout (timeout above the hotel's
limit, sandbox_api.py:701-708), 400 invalid_entrypoint, invalid_user,
invalid_workdir, entrypoint_exited (sandbox_guest.py:325-334, 717-720,
1460-1463, B80), 429 create_rate_exceeded, quota_exhausted,
key_subquota_exhausted (hotel, see N3), 409 image_not_ready (compat.go:363,
430), 404 snapshot_not_found, 409 snapshot_ambiguous (images.go:340, 388),
400 invalid_count (count over 10,000, main.go:719-721), 400 invalid_path
(a "." or ".." segment, main.go:791-795, B59), 502 hotel_unreachable
(main.go:844, 900), 404 sandbox_not_found (another guest's room or a
deleted room, main.go:800, 808). Also the envelope: Harbor and ctcli get
{"detail": {"error": code, "message": ..., "retry_after_s"}}
(compat.go:116-123), the /v1 API gets {"error": {"code", "message"}}
(main.go:425-427).
Verdict: CHANGED (incomplete after #311 and #312).
Corrected: add the rows above, and one line: "Harbor and ctcli clients see
errors as {"detail": {"error": <code>, "message": ...}}; the /v1 API as
{"error": {"code": <code>, "message": ...}}."

---

## 2. broker/README.md

N28. Line 11. Claim: scatter picks a hotel at random with weight = free
rooms.
Code: main.go:383-415 uses h.weight(f) from placement.go:70-88 (free rooms
times CPU headroom over create time times queue wait). Lines 21-25 of the
same README say this.
Verdict: MISREAD (the two sections disagree).
Corrected (line 11): "Picks a hotel at random, weighted by free rooms, CPU
headroom and queue (see Placement)."

N29. Line 12. Claim: gather asks all hotels in parallel.
Code: main.go:921-946: only hotels in the guest's "hotels" list (B56).
Verdict: CHANGED.
Corrected: "Asks every hotel in the guest's hotel list in parallel and merges
the answers."

N30. Lines 16-17. Claim: the broker adds the label broker_guest=<guest>.
Code: main.go:597-599: it also adds broker_batch=<uuid> on every create
(B88, #312).
Verdict: MISREAD (a customer listing labels sees two broker labels).
Corrected: "The broker adds two labels to each room it creates:
broker_guest=<guest>, which it filters on, and broker_batch=<id>, which it
uses to remove rooms of a request whose answer was lost."

N31. Lines 26-29. Claim: a create that waits longer than max_queue_wait_
seconds moves to another eligible hotel with a free room; if none, it
waits.
Code: placement.go:112-126: it moves only when the other hotel's expected
wait is less than half of the current one.
Verdict: MISREAD (operator).
Corrected: "...moves to another eligible hotel with a free room whose
expected wait is under half of its current one. Otherwise it keeps waiting
and checks again after the same interval."

N32. Lines 38-48. Hotel choice table. Code: images.go:182-234. OK on the
/v1 API; dropped by Harbor and ctcli (see N1).

N33. Lines 56-60. Guest limits. Code: guests.go:36-50, 81-113. max_rooms
counts running rooms plus admitted rooms not yet placed (guests.go:67-77).
OK. Line 58 "names hotels with "hotels"" applies to the /v1 API only (N1).

N34. Lines 65-73. Operator guest routes. Code: guests.go:165-243. OK.
PATCH also answers 409 unknown_hotel for an unknown id in "hotels"
(guests.go:215-221); add it.

N35. Lines 77-78. Claim: GET /v1/hotels/<id>/receipts returns the chain to
an ops key.
Code: main.go:891-897 (B12). See N25.
Verdict: MISREAD.
Corrected: "...returns that chain to an ops key whose hotel list includes
the hotel; a hotel outside the list is 404 route_not_found for every key."

N36. Lines 92-93. Claim: a sealed hotel also signs a receipt for the switch.
Code: room_receipts.py:253-255: any hotel with the receipts front signs
network_set, sealed or not. Harbor and ctcli get the header on this route
(compat.go:528). OK, incomplete.
Corrected: "A hotel with the receipts front (every sealed hotel) also signs
a receipt for the switch (X-Room-Receipt)."

N37. Lines 109, 113. Claim: GET /v1/snapshots lists the guest's snapshots on
all hotels; a guest sees only its own.
Code: images.go:432-460: the guest's hotels only (B108). OK otherwise.
Corrected: "...on every hotel in the guest's hotel list."

N38. Lines 121-123. Claim: prefetch pulls on every hotel, or on the hotels
the hotel choice fields select.
Code: images.go:549-567: parseSelection applies the guest's hotel list and,
for a default_sealed guest, the sealed default (guests.go:131-148). A
default_sealed guest's prefetch with no hotel fields warms sealed hotels
only; its later create with "sealed": false pulls at create time.
Verdict: MISREAD.
Corrected: "...pulls the images on the hotels a plain create of this key
would use (its hotel list, and sealed hotels only when it has
default_sealed), or on the hotels the hotel choice fields select. Send
"sealed": false to warm unsealed hotels for a default_sealed key."

N39. Lines 136-138. Claim: the longest exec is max_exec_seconds (default
14,400); keep it at or below the hotel limit.
Code: compat.go:172-176 clamps a Harbor or ctcli timeout to the broker
maximum without an error. main.go:825-837: the /v1 API forwards
timeout_seconds to the hotel, where a value above
CATHEDRAL_SANDBOX_EXEC_TIMEOUT_MAX is 400 invalid_timeout
(sandbox_api.py:701-708).
Verdict: MISREAD.
Corrected: "Harbor and ctcli: a timeout above max_exec_seconds (default
14,400) is lowered to it. /v1 API: the hotel's limit
CATHEDRAL_SANDBOX_EXEC_TIMEOUT_MAX (default 14,400) applies and a higher
value is 400 invalid_timeout."

N40. Lines 139-143. Exec body. See N14. Same correction, plus: the compat
layer reads "command" before "cmd" when both are present (compat.go:777-
780).

N41. Lines 144-148. Claim: the broker asks each hotel that takes new rooms
to build; the image is ready when one hotel has it; a create goes only to
hotels that have it.
Code: build.go:90-116: hotels that are not draining and are in the guest's
list (down hotels are asked and retried after a minute). build.go:168-184:
"ready" only when a hotel that the guest's plain create may use (hotel list
and sealed default) holds it. compat.go:424-432: a create whose image is
built only on hotels outside its placement is 409 image_not_ready with
Retry-After 10, and the broker starts the build there. build.go:26, 49-51:
a context over 256 MiB is 413 build_context_too_large.
Verdict: MISREAD.
Corrected: "The broker asks every hotel in the guest's list that is not
draining to build it. The image is ready when a hotel the guest's plain
create may use holds it; for a default_sealed key that means a sealed
hotel. A create that needs the image on another hotel gets 409
image_not_ready and the broker builds it there. The context is at most 256
MiB (413 build_context_too_large)."

N42. Lines 149-156. State dir. Code: state.go:23-28, 41-47, 78-157, 192-281;
main.go:1564-1578 (flush at stop, B93). OK.

N43. Line 165. Claim: POST /v1/broker/hotels takes {"id", "api", "key",
"health"?, "name"?, "concurrency"?, "labels"?, "threads"?, "ram_gib"?}.
Code: hotels.go:146-150: joinRequest embeds hotelConfig (main.go:45-60), so
"sealed", "max_slots" and "drain" are read too. hotels.go:55-62 and
images.go:65-69: only "sealed": true makes the hotel refuse plain creates;
a label alone does not (B131 fixed the example config, not this line).
Verdict: UNSUPPORTED (operator, security relevant).
Corrected: "POST /v1/broker/hotels: {"id", "api", "key", "health"?,
"name"?, "concurrency"?, "labels"?, "threads"?, "ram_gib"?, "sealed"?,
"max_slots"?, "drain"?}. A sealed hotel must be joined with "sealed": true;
the broker then adds the label itself. A label alone leaves the hotel open
to unsealed creates."

N44. Lines 171-172. Claim: GET /v1/broker/hotels (guest key) lists all
hotels with labels and free rooms.
Code: images.go:265-284: the guest's hotels only; also "up" and "drain".
Verdict: CHANGED.
Corrected: "GET /v1/broker/hotels (guest key) lists the hotels in the key's
hotel list with name, labels, up, drain and free rooms."

N45. Lines 177-180. Secrets. Code: main.go:10-11, 228, 429-435; hotels.go:
218-227; log.Printf calls name room ids and guest ids only. OK.

N46. Lines 184-192. Live view. Code: main.go:1243-1329, 1389-1411. OK.
Note (B26 pending, known): the page and /v1/broker/stats show every hotel
in the chain, not only the guest's.

---

## 3. room-kit/README.md

N47. Lines 3-5. Claim: one customer per host; gVisor; API on 443 with a
real TLS certificate.
Code: profiles/v1.sh:51-53 (one key); install.sh:218, 295; install.sh:440-
485 (Caddy when ROOM_TLS=on). OK. The sealed guest runs ROOM_TLS=off
(sealed/build-guest.sh:155).

N48. Lines 25-33. Requirements. Claim: outbound HTTPS to Docker Hub, Let's
Encrypt, GitHub (uv, Caddy, Python) and storage.googleapis.com (gVisor).
Code: install.sh:169 installs the API's dependencies with uv pip install
--require-hashes -r files/requirements.lock, which names no index, so the
wheels (cffi, cryptography, pycparser) come from PyPI (pypi.org,
files.pythonhosted.org). room.env.example:22 sets ROOM_REGISTRY_MIRRORS to
https://mirror.gcr.io, so pulls go there first. install.sh:62-89 runs apt
when docker.io, xfsprogs, curl, bzip2, iptables, nftables or conntrack are
missing (the Ubuntu archive). Python comes from uv's managed downloads
(GitHub, astral-sh/python-build-standalone). Ubuntu 24.04 or 26.04 is not
checked by any script.
Verdict: MISREAD (operator; a firewalled host fails the install).
Corrected: "Outbound HTTPS to Docker Hub and mirror.gcr.io (images), PyPI
(pypi.org and files.pythonhosted.org, the API's wheels), GitHub (uv, Caddy,
Python), storage.googleapis.com (gVisor), Let's Encrypt, and the Ubuntu
archive when a host package is missing."

N49. Lines 36-40, 43-82. Bridges and room networks. Code: lib/net_plan.py,
lib/net_capacity.py, lib/room_nets_mode.sh, install.sh:107-122, 267-281,
profiles/v1.sh:36-47, lib/room-net.sh:68-73. OK. "GET /v1/quota shows
room_networks": sandbox_guest.py:2030-2034 (also in the pinned API). OK.

N50. Lines 86-91. Claim: ROOM_RECEIPTS=1 default; the chain covers create,
exec, background process start, delete and network policy changes.
Code: receipts_mode.sh:13-15; room_receipts.py:248-257 also signs bulk
delete (DELETE /v1/sandboxes). OK, add bulk delete.

N51. Lines 92-99. Listener, Caddy routing, ROOM_TLS=off.
Code: receipts_mode.sh:23-39; install.sh:443-467, 488-492. OK. Note: the
receipts front also serves /room/health from a cache on its own listener
(room_receipts.py:358-368); the sealed guest's broker health URL is that
listener.

N52. Lines 101-104. Claim: on a normal host the binding says level hotel;
it does not read /sys/kernel/config/tsm/report; health does not say sealed.
Code: room_receipts.py:96-110: when the configfs directory exists the
service writes one zero report and reads the provider to choose the mode; a
provider other than sev_guest is level 1; a probe error stops the service.
On a host with no configfs-tsm directory nothing is read. room_receipts.py:
471-473: health says sealed only in sealed mode.
Verdict: MISREAD (operator; a TDX or SNP host running the unsealed kit
reads one report, and an SNP guest with sev_guest enters the sealed path,
see N53).
Corrected: "On a host with no /sys/kernel/config/tsm/report the binding
says level hotel (schema cathedral_hotel_binding_v1) and nothing is read
from the TSM. On a host that has one, the service reads one report to learn
the provider: anything but sev_guest is level 1."

N53. Lines 108-114. Claim: sealed receipts stay opt-in; a new unsealed host
does not enter that path.
Code: room_receipts.py:150-151: the mode is chosen by the TSM provider
alone. An unsealed install (install.sh without --sealed) inside any SEV-SNP
guest that exposes sev_guest signs sealed receipts and says sealed: true in
health, with that VM's measurement, although no measured guest was built.
Verdict: MISREAD.
Corrected: "The sealed path is chosen by the TSM provider, not by a
setting: any install inside an SEV-SNP guest with configfs-tsm sev_guest
signs sealed receipts and reports sealed: true, whether or not the guest was
built by install.sh --sealed. A host with no SNP TSM never enters it. The
verifier proves the measurement, not that an operator built it; compare the
measurement with a published build."

N54. Lines 119-156. Egress policy. Code: room_egress.py throughout;
install.sh:384-409; profiles/v1.sh:32-35; sandbox_guest.py:1378-1383,
1817-1838; lib/room-net.sh:80-110. OK, with these notes:
- Line 127: "A room address that has no policy has no egress": OK
  (room_egress.py:244-250); since #312 a bridge port with no policy sends
  nothing (room_egress.py:259-264, B113).
- Lines 128-130: "All DNS from a fenced room goes to the hotel resolver,
  whatever server the room asks": room_egress.py:237-242: the pair rule
  `ip saddr . ip daddr @allow return` comes before the port 53 redirect, so
  an allowlist room that allowlisted a public resolver's address (for
  example 1.1.1.1) can query that resolver directly. It gains DNS answers,
  not connectivity. MISREAD, low. Corrected: "...whatever server the room
  asks, unless the server's address is itself on the room's allowlist."
- Lines 144-148: allowlist entries, at most 256 (room_egress.py:68, 153-154;
  sandbox_api.py:249, 341-342). OK. IPv6: see N10.
- Lines 154-156: ROOM_EGRESS=0 fails closed to network none:
  sandbox_guest.py:1378-1383, 681-684. OK.

N55. Lines 166-177. Install. Code: install.sh:13-23, 298-311. OK (#312 text).

N56. Lines 181-196. What the kit installs. Code: install.sh steps 2 to 11.
OK. Line 195 "does not restart the host Docker daemon": true; install.sh:86-
88 masks docker.service and docker.socket when this install added docker.io.
Add: "If the kit installed docker.io itself, it masks the host Docker
units."

N57. Lines 202-203. Claim: every guest runs under runsc.
Code: install.sh:218, 295 (rooms). cathedral/sandbox_guest.py:591-605 at
HEAD forces DOCKER_BUILDKIT=0 so build RUN steps run under the daemon's
default runtime; the pinned 6701dda API (what install.sh installs) has no
such line, so build steps run under BuildKit's runc worker (B62).
Verdict: CHANGED but not delivered (see N0).
Corrected: "Every room runs under runsc. Image builds (POST
/v1/images/build) run under runsc only once the kit's pinned API includes
the classic-builder change (cathedral at or after 91150c1); at 6701dda a
build's RUN steps run on the host kernel."

N58. Lines 226-231. Claim: a restart of <ROOM_ID>.service forgets the
sandboxes and the first reconcile pass (about 30 s later) removes their
containers; install.sh stops when rooms are live.
Code: cli.py:1735-1739 starts the in-process reaper with
REAPER_INTERVAL_DEFAULT_SECONDS = 30 (sandbox_server.py:49, 191-209);
sandbox_guest.py:2036-2062, 1998-2024: the first sweep runs the reconcile
and removes labeled containers with no record. install.sh:37-52, 291, 500.
OK. Since #312 (B84, HEAD only, not in the pinned API) SIGTERM also removes
the work directories; with the pinned API they stay on the data volume.

N59. Lines 232-234. Claim: GET /v1/status says runtime: docker and
kernel_isolation: false; the API does not know the room daemon uses runsc.
Code: sandbox_guest.py:1163-1167 and 2093-2105 (same in the pinned tarball
at 1042-1045, 1928): _oci_runtime is the room daemon's default runtime,
read with docker info over DOCKER_HOST, which install.sh:295 asserts is
runsc; runtime_has_kernel_isolation("runsc") is True. So /v1/status says
"runtime": "docker", "kernel_isolation": true,
"network_allowlist_enforced": true.
Verdict: UNSUPPORTED.
Corrected: "GET /v1/status says runtime: docker and kernel_isolation: true,
read from the room daemon's default runtime at start. /room/health carries
the proof: a throwaway guest's kernel and dmesg, refreshed every 10 minutes
(room_health.py:47-70)."

---

## 4. room-kit/sealed/README.md

N60. Lines 3-8. Claim: rooms under gVisor (systrap) inside the guest; the
same kit and API; receipts for create, exec, process start, network change
and delete; expired rooms get no receipt.
Code: build-guest.sh:165, 141; room_receipts.py:248-257 (add bulk delete).
OK; the API is the pinned 6701dda (N0).

N61. Lines 18-20. Assess. Code: install-sealed.sh:23-33 also refuses when
free RAM is under SEALED_MEM_GIB + 32 GiB for a first start. OK, add RAM.

N62. Lines 23-29. Build. Code: build-guest.sh. OK. The expected measurement
is computed by install-sealed.sh:58-65, not build-guest.sh. Trivial.

N63. Lines 30-34. Claim: the unit room-sealed-<name>.service runs host-
net.sh up and launch-guest.sh.
Code: install-sealed.sh:74-89, 108 (#312, B124) also installs and enables
room-sealed-<name>-net.timer, which runs host-net.sh check every minute and
re-creates the tap and the iptables rules when they are missing. Unit
Restart=no (install-sealed.sh:102): a crashed guest is not restarted.
Verdict: CHANGED (the timer is not documented).
Corrected: "4. Units room-sealed-<name>.service (host-net.sh up, then QEMU;
no automatic restart) and room-sealed-<name>-net.timer, which checks the
host link rules every minute and puts them back after a firewall reload."

N64. Lines 35-36. Claim: it waits for GET /room/attestation and compares the
measurement with the build.
Code: install-sealed.sh:113-128 (#312, B123): it first refuses to restart a
running guest with live rooms unless SEALED_RESTART_WITH_ROOMS=1;
install-sealed.sh:141-150 (#312, B125): on a mismatch it stops and disables
the unit, points images/current back at the previous image and exits 1.
Verdict: CHANGED (not documented).
Corrected: "5. Check. It refuses to restart a guest that has live rooms
(set SEALED_RESTART_WITH_ROOMS=1 to end them). It waits up to 15 minutes
for GET /room/attestation and compares the measurement with the build. On a
mismatch it stops and disables the guest, makes the previous image current
again and exits 1; nothing is served."

N65. Lines 38-44. Inside the guest. Code: guest-boot.sh:13-26,
build-guest.sh:184-186. OK.

N66. Line 56. Claim: files the kit downloads at boot (gVisor, uv, Python,
Caddy, the wheel set) are pinned by sha256 or sha512 in versions.lock and
requirements.lock.
Code: install.sh:54-60 (gVisor, uv, Caddy by hash), 169 (wheels by hash),
166: `uv python install 3.12` with PYTHON_VERSION=3.12 (versions.lock:8), a
minor version. uv checks the download against its own built-in manifest,
but the kit pins no exact Python build; a later 3.12.x changes the guest
software without changing the measurement.
Verdict: MISREAD (B61 neighbourhood).
Corrected: "...gVisor, uv and Caddy are pinned by hash in versions.lock;
the wheel set by hash in requirements.lock. Python is pinned to the 3.12
line only: uv downloads the newest 3.12.x build and checks it against its
own manifest."

N67. Line 58. Claim: the hotel API key authenticates the broker; the host
can call the API too; each call gets a receipt.
Code: see N18. Only the signed actions do.
Verdict: UNSUPPORTED ("each call").
Corrected: "...the host can call the API too; create, exec, process start,
network change, delete and bulk delete get a receipt, other calls do not
(see below)."

N68. Lines 63-69. What the host cannot do. Code: launch-guest.sh:19
(policy 0x30000), build-guest.sh:191-194, 207-209, 218. OK. B128 (pending,
known): the host can corrupt or replay scratch sectors.

N69. Lines 71-82. What the host can do. Code: room_receipts.py:248-257;
launch-guest.sh (plain HTTP on the tap). OK (#312 text).

N70. Lines 86-104. Receipts. Code: room_receipts.py:155-186, 229-243, 394-
439. OK. Add bulk delete to line 94.

N71. Lines 108-113. Routes table. Line 110: X-Room-Receipt on create, exec
and delete. See N22: also process start, network change and bulk delete on
the /v1 API; not for Harbor and ctcli on create, exec, delete; not on batch
creates. Line 111: GET /v1/sandboxes/<id>/receipts works while the room is
on the hotel list (N26). Line 112: the attestation is served to any guest
key, in or outside the hotel list (main.go:891-893). OK otherwise.

N72. Lines 115-118. result_sha256 versus the broker body. Code:
main.go:862-865; compat.go:744-753, 755-769 (Harbor and ctcli bodies are
rewritten twice). OK.

N73. Lines 122-133. Verify. Code: verify_receipts.py:188-213, 138-166,
216-255. OK. Missing flags a customer needs: --hotel (default sealed-1),
--require-sealed, --save (N26). The offline form shown does fail a level 1
chain when --expected-measurement is given (verify_receipts.py:350-354).

N74. Lines 135-150. Not covered yet. Code matches (room_receipts.py:146-
243; install.sh:424 Restart=on-failure; verify_receipts.py:149-150). OK.
Line 143-144 "Neither do rooms that a bulk delete ... removes one by one":
the bulk delete itself is one signed bulk_delete receipt with no room id
(room_receipts.py:256; broker/receipts.go:141-169 keeps it for the guest).
Fine as written.

N75. Lines 152-160. Remove. Claim: disable the service, remove the unit
file, rm -rf $SEALED_DIR, remove the hotel from the broker.
Code: install-sealed.sh:74-89, 108: room-sealed-<name>-net.timer stays
enabled; host-net.sh:37-47 check runs `up` when the rules are missing, so
one minute after the documented removal the tap device, the FORWARD and
INPUT chains and the MASQUERADE rule are back, and after rm -rf $SEALED_DIR
the timer's service fails every minute because host-net.sh is gone.
Verdict: UNSUPPORTED (operator).
Corrected: "sudo systemctl disable --now room-sealed-<name>-net.timer
room-sealed-<name>.service (stops the guest and the link check; ExecStopPost
removes the host link rules); sudo rm -f /etc/systemd/system/room-sealed-
<name>.service /etc/systemd/system/room-sealed-<name>-net.service
/etc/systemd/system/room-sealed-<name>-net.timer && sudo systemctl
daemon-reload; sudo rm -rf $SEALED_DIR."

---

## 5. docs/evidence/CUSTOMER_FEEDBACK_FIXES_2026-10-23.md

N76. Lines 10-20 (A). Code: broker/images.go:109-147, images_test.go. OK.

N77. Lines 24-30 (B). Code: images.go:192-193 (409). OK.

N78. Lines 34-44 (C). Code: state.go:46, 99-113, 230-249; receipts.go. OK.

N79. Lines 48-64 (D). Code: sandbox_api.py:258-321, room_egress.py:89-136,
tests/test_sandbox_api.py exists. OK. Note: the hotel code that enforces D
is in the pinned 6701dda tarball (the marker "named hosts only allow" is
present there), so D is live on a kit-installed hotel.

N80. Lines 68-79 (E). Code: compat.go:772-807, harbor_test.go. OK. Compat
path only (N14).

N81. Lines 83-102 (F, G). Docs. The sentences they introduced are reviewed
above (N1 to N46).

N82. Lines 108-116. Claim: until green is restored and re-added to the
broker config, a create that names hotels: ["green"] returns 503
hotels_unavailable.
Code: images.go:190-196: a hotel id that is not in the broker's hotel set
(removed from the config) or not in the guest's list is 409 unknown_hotel;
503 needs the hotel to be configured and down.
Verdict: MISREAD (operator).
Corrected: "While green is in the broker config and down, a create that
names hotels: ["green"] gets 503 hotels_unavailable. If green is removed
from the config, the same create gets 409 unknown_hotel."

N83. Lines 120-130. How to test. Code: broker/*_test.go present, CI runs
them since #312 (B102); tests/test_sandbox_api.py present. OK.

---

## 6. docs/evidence/REVIEW_ROUNDS_2026-10-23.md (deploy plan only)

N84. Lines 89-93 (stage B). OK against main.go:1564-1578 and state.go.

N85. Lines 95-98 (stage H) and 193-196 (fifth check). See N0: a reinstall
from this commit installs the hotel API at 6701dda; the build probe reports
the host kernel. UNSUPPORTED until versions.lock is bumped.

N86. Lines 99-101 (stage S). See N0 and N75 (the net timer).

N87. Lines 102-103 (stage T). OK; add the --hotel and --require-sealed
flags to the customer instructions (N26).

---

## 7. Claims the code supports but a customer or operator would misread

Collected from above, shortest form:

- M1. "Hotel selection" fields are /v1 only; Harbor and ctcli drop them
  silently (N1).
- M2. A sealed hotel is also selected by naming it in "hotels" (N2).
- M3. 429 from a create can carry the hotel's own code (create_rate_exceeded,
  quota_exhausted, key_subquota_exhausted); batch 503s carry no Retry-After
  (N3).
- M4. "*.suffix" excludes the suffix itself (N6).
- M5. "internet" still blocks private, link-local and host ranges (N11).
- M6. Live network change: not for rooms created with "none", not for frozen
  rooms, and the body must name the mode (N12).
- M7. Missing "network" is internet on both paths, not only compat (N13).
- M8. The catalog route exists only for Harbor and ctcli user agents (N15).
- M9. Receipts come per receipts-service start, not per boot (N23).
- M10. An ops key is also limited to its hotel list for receipts (N25, N35).
- M11. verify_receipts.py: --hotel defaults to sealed-1; a level 1 chain
  passes without --require-sealed; --sandbox is for live rooms (N26).
- M12. Labels: a sealed hotel's label value is the string "true"; the create
  field is the boolean true (N19).
- M13. PATCH default_sealed is lost at a broker restart (N20).
- M14. Rooms carry broker_batch as well as broker_guest (N30).
- M15. Prefetch and build "ready" follow the key's hotel list and sealed
  default (N38, N41).
- M16. The compat exec timeout is clamped; the /v1 timeout above the hotel
  limit is 400 invalid_timeout (N39).
- M17. GET /v1/broker/hotels, GET /v1/sandboxes, quota, usage and snapshots
  cover the key's hotel list, not the chain (N29, N37, N44).
- M18. Harbor and ctcli errors arrive in the {"detail": ...} envelope (N27).
- M19. The install needs PyPI and mirror.gcr.io as well (N48).
- M20. An unsealed kit inside an SNP guest signs sealed receipts (N53).
- M21. DNS to an allowlisted resolver address bypasses the hotel resolver
  (N54).
- M22. Python is pinned to 3.12.x, not an exact build (N66).
- M23. The sealed unit does not restart a crashed guest (Restart=no) (N63).
- M24. 503 hotels_unavailable for "green" becomes 409 unknown_hotel once
  green leaves the config (N82).

## 8. Coverage limits

- No probes were run (the task said none needed); every claim is from
  reading the code and one extraction of the pinned tarball.
- cathedral/sandbox_provider.py and cathedral/sandbox_egress.py were read by
  grep and short excerpts, not line by line.
- Live hosts were not touched; B130 (which hotels carry receipts today) is
  taken from the review doc.
- The Harbor plugin and ctcli sources are not in this repository; what they
  send is inferred from broker/compat.go.
- The receipts statement's "same core fields as the staging lane" (sealed
  README line 95) was not checked against the staging lane.
- Ubuntu 24.04 or 26.04 (room-kit README line 25) is not checked by any
  script; not verified.

# Review rounds 1 to 5, 2026-10-23

Scope: the broker, the hotel API, the room kit (egress, receipts, install)
and the sealed kit, at PR #311. Each finding was checked against the source.
A fix has a test that failed before it. "Customer path" means the code that a
live customer's requests pass through: the broker, the shared hotels and the
dedicated sealed hotel.

Status:

- **Fixed**: in #310 or #311, lands with the deploy stage named.
- **Pending**: needs a design or an owner decision; not in #311.
- **Doc**: by design; the docs now say so.

Deploy stages (see the plan at the end): **B** broker restart, **H** shared
hotel reinstall, **S** sealed hotel rebuild, **T** client tool (on merge).

## Findings

| # | What breaks, in plain terms | Customer path | Status | Lands at |
|---|---|---|---|---|
| B1 | One guest's bad request rested a hotel for every guest | Yes | Fixed | B |
| B2 | Allowlist `host:443` refused: hotels ran old API code | Yes | Fixed | H, S |
| B3 | Two tests expected the old allowlist rule | No | Fixed | merge |
| B4 | The ops probe could start a room on a dedicated hotel | Yes | Fixed | B |
| B5 | `host:443` also opens port 80 | Yes | Doc | |
| B6 | A bare IP opens every port | Yes | Doc | |
| B7 | Harbor path ignores the hotel choice | No | Pending | |
| B8 | A guest's filtered receipts view cannot be tested from outside | Yes | Logic verified | |
| B9 | B1's fix stopped resting a hotel whose own key was wrong | Yes | Fixed | B |
| B10 | Image import warmed every hotel, dedicated ones too | Yes | Fixed | B |
| B11 | Bulk delete reached every hotel, dedicated ones too | Yes | Fixed | B |
| B12 | An ops key could read a dedicated hotel's receipts | Yes | Fixed | B |
| B13 | A guest's own bulk-delete receipt was hidden from it | Yes | Fixed | B |
| B14 | A fake image name rested a hotel for everyone | Yes | Fixed | B |
| B15 | A network change with no mode opened the internet (hotel) | Yes | Fixed | H, S |
| B16 | A fork of a `deny_all` room gets internet unless `network` is set again | Yes | Pending (design) | |
| B17 | B14's fix also excused the hotel's own registry faults | Yes | Fixed | B |
| B18 | Same as B15, on the Harbor path | Yes | Fixed | B |
| B19 | Narrowing a guest's hotel list leaves its rooms on the old hotels | No | Pending | |
| B20 | A room whose bridge port was not found escaped the network guard | Yes | Fixed (fails closed) | H, S |
| B21 | Expired, bulk-deleted and restart-removed rooms get no delete receipt | Yes | Pending (design); doc states it | |
| B22 | A receipts-service restart starts a new key; the broker then serves only the new binding | Yes | Pending (design); doc states it | |
| B23 | A room could link its process log to the hotel API key and read it | Yes | Fixed | H, S |
| B24 | An API restart forgets every room and removes their containers | Yes | Phase 1 fixed (install refuses while rooms are live); phase 2 pending (adopt rooms on start) | H |
| B25 | Files outside `/work` answered 200 but never reached the room | Yes | Fixed (400 `path_outside_work`) | H, S |
| B26 | Any guest key sees chain-wide hotel counters on `/v1/broker/stats` and the live board | Yes | Pending (low) | |
| B27 | A wrong hotel key shows the guest a 401, as if its own key failed | Yes | Pending (low) | |
| B28 | A guest's filtered receipt chain failed `verify_receipts.py` | Yes | Fixed | B, T |
| B29 | A dedicated sealed hotel takes only `"sealed": true` creates | Yes | Doc | |
| B30 | Refused creates (no room id) are receipted but no guest can see them | Yes | Pending (low) | |
| B31 | Debug sealed builds never started SSH | No | Fixed | S |
| B32 | Guest receipt paging stopped after 10,000 hotel receipts and still said PASS | Yes | Fixed | B, T |
| B33 | `filtered` is a server-set flag; `head` is not signed, so no chain proves nothing is missing | Yes | Doc; verifier output says what it checked | T |
| B34 | The new install guard exited with no message when the room daemon was down | No | Fixed | H |
| B35 | A failed re-install in auto mode could leave room networks without egress rules | Yes | Fixed | H |
| B36 | The verifier passed a debug sealed build (host has root SSH) | Yes | Fixed | T |
| B37 | A sealed install whose measurement differed still said "done" | No | Fixed | S |
| B38 | The files API checked a path, then opened it again: a room could swap in a link and read the hotel API key | Yes | Fixed | H, S |
| B39 | A build context URL could reach cloud metadata or host services by DNS rebinding or redirect | Yes | Fixed | H, S |
| B40 | `disk_gib` is not enforced for writes to `/work` from inside the room; one room can fill the shared volume | Yes | Pending (design: XFS project quota per room) | |
| B41 | In an image with no `timeout` binary, an exec past its limit keeps running | Yes | Pending | |
| B42 | Image builds are not under the room's network policy | Yes | Pending (design) | |
| B43 | An image reference could start with `-` and read as a docker flag | Yes | Fixed | H, S |
| B44 | Stopping a background process can miss its children | Yes | Pending (low) | |
| B45 | Room egress rules are IPv4 only; IPv6 is not disabled on room bridges | Yes | Observation: a live room has no IPv6 address and cannot add one (gVisor). Hardening pending | |
| B46 | Allowlists accepted private, host and reserved ranges (`169.254.169.254`, `0.0.0.0/0`) | Yes | Fixed | H, S |
| B47 | The host holds the sealed hotel's API key, and broker to guest traffic is plain HTTP on the tap | Yes | Doc fixed; pending (design: TLS into the guest, key made in the guest) | |
| B48 | A write whose answer was lost was sent to the API again: an exec could run twice | Yes | Fixed | H, S |
| B49 | A chunked request body was signed as empty | No (broker sends lengths) | Fixed (411) | H, S |
| B50 | Bad `after`/`limit` on the receipts route was a 500 | No | Fixed (400) | H, S |
| B51 | The verifier does not pin the AMD ARK by default and has no TCB floor | Yes | Pending; doc states it | |
| B52 | Harbor file, tar and stat errors showed the hotel's private API URL | Yes | Fixed | B |
| B53 | One guest's long execs can use every broker connection to a shared hotel and stall other guests | Yes | Pending (design: per-guest in-flight limit) | |
| B54 | The broker buffers up to 256 MiB per room request and had no idle timeout | Yes | Idle timeout fixed (B); body limits per route pending | B |
| B55 | Finished background execs, build contexts, guest room ids and latency samples are never pruned | Yes | Pending (weeks-scale) | |
| B56 | List, quota and usage asked hotels outside the guest's list | Yes | Fixed | B |
| B57 | Operator PATCH `hotels: []` or `max_rooms: 0` widened a guest | No | Fixed (400) | B |
| B58 | A build context cut short by a crash was used forever | Yes | Fixed | B |
| B59 | The room route passed `..` segments to the hotel | Yes | Fixed (400) | B |
| B60 | CI: `govulncheck` flags `crypto/x509` in Go 1.26.9 | No | Fixed in CI (1.26.10). The broker is built with Go 1.27.3 (clean). The release workflow still pins 1.26.9 | merge |
| B61 | The measured sealed image is not reproducible from source (unpinned apt) and packs the whole kit dir; rescue units are not masked | No | Pending | |

## Deploy plan

Each stage is a separate go. Stop at the first failed check.

1. **Merge** #310, then #311. No live effect.
2. **B: broker.** Build from the merge commit (Go 1.26.10 or later). Back up the
   binary and config. Swap, restart. Rooms keep running; ownership is rebuilt
   from labels. Check: guest path 200, one ops room create, exec and delete,
   a guest receipts page shows `"filtered": true` and `"scanned"`.
   Rollback: the old binary.
3. **H: shared hotels**, one at a time, least used first. Only when the hotel
   has no live rooms (`install.sh` now refuses otherwise). Run `install.sh`
   from the merge checkout. Check: egress `GET /rooms` shows `port_bound` for
   new rooms, probe passes, one ops room with `deny_all` and one allowlist.
   Rollback: re-run `install.sh` from the previous checkout.
4. **S: dedicated sealed hotel.** A rebuild is a new guest with a new
   measurement, so all its rooms end. Needs the customer told and a window.
   Publish the new expected measurement.
5. **T: client tool.** `verify_receipts.py` ships with the merge; customers
   fetch the new copy.

## Pending, by owner

Engineering design: B16, B21, B22, B24 phase 2, B40, B41, B42, B47, B53.
Small follow-ups: B7, B19, B26, B27, B30, B44, B45 hardening, B51, B54 body
limits, B55, B61, release workflow Go version.

## Round 6 (2026-10-23): eleven line-by-line readers, live state, graphs

Scope: every line of the broker, the hotel API, the room kit and the sealed
kit at #311 head (22e7824), read by eleven independent readers, plus a
read-only check of the live hosts and one live build probe with our own key.
Fixes are on PR #312 (branch fix/review-round-6, stacked on #311). Every fix
has a test that failed first. Graphs: docs/evidence/REVIEW_ROUND6_GRAPHS.html.

| # | What breaks, in plain terms | Customer path | Status | Lands at |
|---|---|---|---|---|
| B62 | Dockerfile RUN steps ran on the host kernel (runc), not under gVisor: BuildKit ignores the daemon's default runtime. Confirmed live through the broker | Yes, builds on shared hotels | Fixed (classic builder) | H, S; re-probe after deploy |
| B63 | A create with a wrong-shaped field (an unknown key in `image`, a number for `entrypoint`, a 5,000-digit integer, deep nesting) raised out of the hotel API, the connection dropped, and the broker rested the hotel for everyone | Yes | Fixed (400) | H, S |
| B64 | Any unexpected error in a hotel handler dropped the connection | Yes | Fixed (500 JSON, logged) | H, S |
| B65 | Hotel API request bodies were unbounded | Yes | Fixed (413 over 256 MiB) | H, S |
| B66 | A terminal WebSocket whose room ended died with a traceback | Yes | Fixed (close frame) | H, S |
| B67 | Snapshots had no owner: a second key on a hotel could fork, list or delete another key's snapshot by name | Latent (one key per hotel) | Fixed | H, S |
| B68 | Idempotency replays crossed keys: a second key with the same key string and body got the first key's room document | Latent | Fixed | H, S |
| B69 | Usage showed every key's labels and cost | Latent | Fixed | H, S |
| B70 | Affine lane: Cathedral signs a caller-supplied verify result as a full re-run. The lane is dormant (no seed configured on any hotel) | No | Pending (design, Toby and Fred) | |
| B71 | Affine lane inputs escaped the 4xx mapping (deep JSON, huge integers, NaN, surrogates, overflow) | No (dormant) | Fixed by B63 and B64 | H, S |
| B72 | The receipts front could fail after the API ran the action (image as an object, a lone-surrogate escape, a slow image inspect): no receipt, connection dropped, hotel rested, an orphan room per hotel tried | Yes | Fixed | S |
| B73 | A refused create with the object image form signed the registry password into the chain | Yes | Fixed | S |
| B74 | The verifier passed a level-1 (unsealed) chain under sealed flags; a sealed guest with no TSM falls back to level 1 | Yes | Fixed | T |
| B75 | The verifier failed a fresh hotel with no receipts | Yes | Fixed | T |
| B76 | A receipts-service restart appends a second chain to the same file; the first segment cannot be verified through the broker (B22 sharpened) | Yes | Pending (design) | |
| B77 | The receipts front runs as root and holds the API key and every body | Yes | Pending (observation) | |
| B78 | Exec output, process logs and the room's log record were unbounded in the API's memory; one room could force an OOM restart, which removes every room | Yes | Fixed (16 MiB caps) | H, S |
| B79 | Exec output that is not UTF-8 killed the request | Yes | Fixed | H, S |
| B80 | A bad entrypoint, user or workdir was a 502, which rested every shared hotel in turn | Yes | Fixed (400) | H, S |
| B81 | The image cache was tenant-blind: a pushed snapshot tag and a credentialed private image could be started by another key by name (after a restart too) | Yes, shared hotels | Fixed | H, S |
| B82 | A TTL that ended during the drain skipped the two-phase delete: record gone, container and policy left | Yes | Fixed | H, S |
| B83 | Snapshot images were never removed on TTL expiry or after a restart | Yes | Fixed | H, S |
| B84 | SIGTERM (a systemd restart) left every room's work directory and snapshot tar on the data volume | Yes | Fixed | H, S |
| B85 | A network change on a frozen room was applied, then refused: the room ran on the new policy while the record said the old | Yes | Fixed | H, S |
| B86 | exec rewrites `bash` to `sh`; start_process does not | Yes | Pending (design) | |
| B87 | GNU timeout without -k let a command that ignores TERM run past its limit | Yes | Fixed | H, S |
| B88 | A create whose answer was lost left an orphan room on the hotel, adopted and billed to the guest | Yes | Fixed (batch label, reaped) | B |
| B89 | A corrupt or undecodable client state file was replaced by the first save: every client room id gone | Yes | Fixed (per-section read, copy kept) | B |
| B90 | A native file PUT over 256 MiB was cut and answered 200 | Yes | Fixed (413) | B |
| B91 | A room marked deleting by a late hotel list stayed deleting forever; quota undercounted it | Yes | Fixed | B |
| B92 | A batch create multiplied a 1 MiB body by count (1 GiB for 1,000 rooms) | Yes | Fixed (marshaled once) | B |
| B93 | No signal handling and no flush at stop: a restart lost the last second of client ids and idempotency answers | Yes | Fixed | B |
| B94 | Probe results of runtime-joined hotels were dropped at every restart | No | Fixed | B |
| B95 | The config loader failed open on a typo: "hotel" for "hotels" gave a dedicated guest every hotel; empty and duplicate guest ids and shared key hashes loaded | Yes | Fixed (refused) | B |
| B96 | One guest's long execs used every broker connection to a hotel, the sync loop timed out, and the hotel left placement for everyone (the sealed hotel's health is on the same port) | Yes | Fixed (own pool); B53 per-guest cap still pending | B |
| B97 | PATCH labels on a sealed hotel dropped its sealed label: no sealed create matched it until a restart | Yes | Fixed | B |
| B98 | A probe error put the hotel's private URL on every guest's live board | Yes | Fixed | B |
| B99 | The probe started rooms on drained and resting hotels | No | Fixed | B |
| B100 | Background execs live in the broker's memory; a restart loses them, and a keyed retry of a synchronous exec runs it twice | Yes | Pending (design) | |
| B101 | Hotel labels and drain were read without the lock PATCH writes under (a real data race) | Yes | Fixed | B |
| B102 | CI never ran the broker's Go tests | No | Fixed (CI job) | merge |
| B103 | A build resubmit reset the build map under a build in flight: a nil pointer took the broker down, or a stale result overwrote the live build | Yes | Fixed | B |
| B104 | A keyed create answered 409 image_not_ready replayed that 409 for 48 hours | Yes | Fixed | B |
| B105 | The lifetime route sent extend_by_seconds as the new absolute TTL: a room with an hour left and a 10 minute extension ended in 10 minutes | Yes | Fixed | B |
| B106 | After a broker restart a create from a built image answered 409 until someone fetched the image | Yes | Fixed | B |
| B107 | The Harbor create dropped env and shape | Yes | Fixed | B |
| B108 | Snapshot list, delete and fork asked hotels outside the guest's list | Yes | Fixed | B |
| B109 | Finished background exec results (up to 32 MiB each) were kept forever | Yes | Fixed (an hour, and with the room) | B |
| B110 | Catalog and quota counted free rooms chain-wide | Yes | Fixed | B |
| B111 | A tar over the output limit was a 500 with no message | Yes | Fixed (413) | B |
| B112 | Builds keep 256 MiB per build plus transient copies, no per-guest cap | Yes | Pending (B54, B55 class) | |
| B113 | A new room's frames passed the bridge guard before its port was bound: with raw sockets it could send as a neighbour on the same bridge for a moment | Yes, shared hotels | Fixed (unbound ports send nothing) | H, S |
| B114 | No per-room cap on egress proxy connections: one room could use every file descriptor of the daemon that serves all rooms | Yes | Fixed (256) | H, S |
| B115 | IPv6 was not dropped on room bridges (B45 hardening) | Yes | Fixed | H, S |
| B116 | DNS forwards over UDP only; a large answer may be truncated for allowlist rooms | Yes | Pending (low) | |
| B117 | The egress control socket is group-only and sandbox_id is unvalidated | No | Pending (low) | |
| B118 | Pinned uv and Caddy archives extracted as uid 1001: a host with a second user owned code that runs as root and the TLS front | No | Fixed | H |
| B119 | Disk sizing differed between a first install and a re-run (volume mounted or not) | Yes | Fixed (assess after mount) | H |
| B120 | The live-rooms guard was a point check minutes before the restarts | Yes | Fixed (re-checked) | H |
| B121 | A re-run rewrote config and restarted the daemon before failing on a missing key file | Yes | Fixed (preflight; README keeps the file) | H |
| B122 | A failed apt left /usr/sbin/policy-rc.d on the host | No | Fixed | H |
| B123 | install-sealed.sh restarted the guest with live rooms: every room ended, no receipts, a new measurement | Yes | Fixed (guard) | S |
| B124 | Host link rules were set once; a firewall reload removed them and every room lost the internet while health stayed green | Yes | Fixed (timer) | S |
| B125 | A measurement mismatch left the guest serving and booting again | Yes | Fixed (disabled, previous image) | S |
| B126 | The measured initrd packed untracked files from the checkout | Yes | Fixed | S |
| B127 | The AmdSev firmware's provenance is not recorded; the ovmf fallback fails late | No | Partly fixed (checked after apt); provenance pending | S |
| B128 | The scratch disk is plain XTS: the host can corrupt or replay sectors without a receipt | Yes | Pending (design, B47 disk side) | |
| B129 | Live: a second service on the broker host is bound on every interface with plain HTTP and runs as a user in the docker group | Yes (shared host) | Pending (Toby and Fred) | |
| B130 | Live: the shared hotels carry no receipts; the doc now says which hotels do | Yes | Doc fixed | merge |
| B131 | The example broker config implied a label alone makes a hotel sealed | No | Fixed | merge |
| B132 | Live: the sealed hotel's health and API share one port, so B96 applied to it | Yes | Fixed by B96 | B |
| B133 | SN94 miner unit: a docker daemon restart (exit 143, counted as success) left the only miner stopped; no page when the start limit left it failed | No (SN94 miner, live on Contabo) | Fixed (Restart=always, OnFailure page); the live unit file must be updated by hand | miner host |
| B134 | Miner updater: an unreadable state file made every hourly check exit 10 (unit success), so a dead miner paged nobody; status refused outright | No (updater not enrolled yet) | Fixed | merge |
| B135 | The updater installer described --minimum-sequence as inclusive; the code refuses a record at the floor | No | Doc fixed | merge |
| B136 | Harbor/ctcli clients got no X-Room-Receipt on create, exec or delete (network changes and process starts only) | Yes, Harbor path | Fixed | B |
| B137 | The hotel pin in versions.lock still named the #311 commit: stage H and S from #312 would not have delivered its hotel API fixes | Yes | Fixed (pin moved to the #312 commit) | H, S |
| B138 | verify_receipts.py defaulted --hotel to a fixed name; the wrong hotel ended in an uncaught error | Yes | Fixed (required with --broker) | T |
| B139 | Removing a sealed hotel left the link-check timer restoring the host link every minute | No | Fixed (condition on sealed.env; README) | S |
| B140 | Customer and operator docs disagreed with the fixed code in 16 places (allowlist example, exec and file contracts per path, receipted calls, verifier flags, error codes, sealed selection, join body, kernel_isolation, network requirements) | Yes | Doc fixed | merge |
| B141 | A hotel API started on the docker or kata runtime with an empty key store accepted any bearer token as its own tenant with the default quota. Latent: the kit always writes a key, but one typo in the unit file would have opened the hotel | Yes (latent) | Fixed (refuses to start, 503; a local override flag exists) | H, S |
| B142 | A malformed key store entry was skipped without a word: an empty project name left the hotel with zero keys (401 for everyone, the broker too), a non-integer slot count meant unlimited | Yes | Fixed (refused at start) | H, S |
| B143 | A malformed hotel quota value fell back to the 500 rooms / 1,000 vCPU / 3,000 GiB default with no log, so a sizing typo oversold the hotel | Yes (capacity) | Fixed (refused at start) | H, S |
| B144 | The installer took the customer name unvalidated: empty closed the API for its own key, a comma or colon minted a second key | Yes (operator input) | Fixed (shape check before anything changes) | H |
| B145 | The hotel API unit had no stop budget: stopping a full hotel removes every room's container and work directory, which outran the 90 s default and ended in SIGKILL mid-pass, leaving work directories on the data volume for good | Yes | Fixed (10 min stop budget; stale work directories swept at the next start) | H, S |
| B146 | The installer's final check accepted any answer: a 401 printed "done" over a hotel that answered nobody | Yes (operator) | Fixed (needs a 200 with the hotel's own key, else the install fails) | H |
| B147 | The B130 updater fix returned "alert" (12) where the fallback shim must pass the current updater's status through; the existing test caught it in CI, not locally (the suite subset run here did not include it) | No | Fixed (pass-through when the status pages, alert when it would be quiet) | miner host |

Deploy stages are as above (B broker, H shared hotel reinstall, S sealed
rebuild, T client tool; "miner host" is the Contabo SN94 miner, updated by
hand). #312 adds a fifth check to stage H and S: run the build probe (`scratchpad/buildkit/run.sh` in the review transcript) and
expect the RUN step to report the gVisor kernel.

# O. Mutation pass over PR #312 (fix/review-round-6, 22e7824..887ed40)

Artifact: the nine commits 94713c4..887ed40 at head 887ed40, in a throwaway
worktree /private/tmp/claude-501/r6mut (removed at the end). Main worktree
untouched. Nothing committed or pushed.

Method: for each fix hunk (git diff -U3 of the commit, non-test, non-doc
files), reverse-apply that hunk alone at head and run the tests the commit
added or changed. Python: .venv pytest -q -p no:cacheprovider. Go:
go test -short -count=1 -run <names> . (CI runs -race -short; the lock-read
hunks were rerun with -race). Hunks that only compile together were also
reverted together (combo runs). Where one hunk bundles several fixes, the
sub-fixes were reverted by hand (sub-hunk runs).

Baseline at head: 148 Python tests pass (26 s); go test -short and
go test -race -short pass (16 s / 20 s).

Verdicts
- DETECTED: at least one of the commit's tests fails with the hunk reverted.
- UNTESTED: every test passes with the hunk reverted. The fix is unguarded.
- DEP: reverting it alone does not compile or import (a field, import or
  helper other hunks use). Not meaningful alone; see the combo row.
- N/A: comment only, example config, CLI/main wiring with no unit seam.

## 94713c4 Hotel API: answer every request (cathedral/sandbox_server.py)

Tests run: tests/test_sandbox_server.py, tests/test_agent_websocket.py

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 153 | MAX_BODY_BYTES constant | DEP (NameError in _run) | real-listener tests fail for the wrong reason |
| 2 | 299 | _invoke maps TypeError/ValueError/KeyError/OverflowError/RecursionError to 400; any other exception to a 500 JSON answer | DETECTED | test_wrong_shaped_create_is_a_400_not_a_dropped_connection x4; 500 branch alone: test_unexpected_handler_error_is_a_500_json_answer |
| 2 sub | 304 | OverflowError and RecursionError in the 400 tuple (the 5,000-digit integer and the deep nesting named in the commit message) | UNTESTED | none; with them removed 43 tests pass |
| 3 | 804 | _Handler._run: invalid or oversized Content-Length is a 413 before the body is read | UNTESTED | none; 49 tests pass |
| 4 | 925 | terminal WebSocket: SandboxOpError sends a close frame | DETECTED | test_terminal_websocket_closes_cleanly_when_the_sandbox_is_gone |

## 2e41dda Hotel API: snapshots, idempotency, usage per key

Tests run: tests/test_provider_key_isolation.py (+ guest hardening/exec for sandbox_guest.py)

cathedral/sandbox_provider.py

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 194 | _snapshot_owner map, idempotency keyed by (key, Idempotency-Key) | DETECTED | fork and list/delete tests |
| 2 | 260 | _snapshot_visible | DETECTED | fork and list/delete tests |
| 3 | 353 | idempotency lookup per key | DETECTED | test_idempotency_keys_are_per_key |
| 4 | 368 | idempotency store per key | DETECTED | test_idempotency_keys_are_per_key |
| 5 | 407 | fork by id or name sees own snapshots only | DETECTED | test_a_snapshot_cannot_be_forked_by_another_key |
| 6 | 764 | get-or-create by name is per key | DETECTED | test_snapshot_list_delete_and_names_are_per_key |
| 7 | 786 | owner recorded at snapshot | DETECTED | fork and list/delete tests |
| 8 | 803 | owner entry dropped at snapshot expiry | UNTESTED | none (bookkeeping; a leaked owner entry per expired snapshot) |
| 9 | 811 | list_snapshots per key | DETECTED | test_snapshot_list_delete_and_names_are_per_key |
| 10 | 827 | delete_snapshot per key | DETECTED | test_snapshot_list_delete_and_names_are_per_key |
| 11 | 877 | tombstone records api_key | UNTESTED | none; sub-hunk run j confirms the usage tombstone filter is dead without it |
| 12 | 1415 | usage: actives and tombstones of the caller only | DETECTED (actives) | test_usage_is_scoped_to_the_caller |
| 12 sub | 1445 | tombstone filter mine(t.get("api_key")) | UNTESTED | none; 4 tests pass with the filter removed |
| 13 | 1436 | usage: snapshot cost of the caller only | UNTESTED | none |

cathedral/sandbox_guest.py

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 1146 | DockerGuestProvider._resolve_snapshot honours visibility (fork image lookup and push_snapshot) | UNTESTED | none; 31 tests pass |
| 2 | 1202 | failed create drops the (key, Idempotency-Key) entry, not the bare key | UNTESTED | none; 31 tests pass |

## fa8d932 Receipts front

Tests run: tests/test_room_kit_receipts_proxy.py, tests/test_room_kit_level1_receipts.py

room-kit/room_receipts.py

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 42 | import traceback | DEP | signing-failure test fails on NameError |
| 2 | 365 | lone-surrogate body refused before the action; signing failure still answers with X-Room-Receipt-Error | DETECTED (both) | test_a_lone_surrogate_in_the_body_is_refused_before_the_api_runs_it; test_a_signing_failure_still_answers_the_caller |
| 3 | 390 | image given as an object: sign the reference only | DETECTED | test_an_image_given_as_an_object_is_signed_by_its_reference |
| 4 | 470 | image_digest swallows docker errors; non-str ref gives None | DETECTED (error path) | test_image_inspect_errors_give_no_digest; the isinstance guard is unreachable from fields() |

room-kit/verify_receipts.py

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 241 | empty chain verifies when head == binding | DETECTED | test_a_fresh_hotel_with_no_receipts_verifies |
| 2 | 320 | --require-sealed flag | DETECTED | test_sealed_flags_refuse_a_level1_answer (also AttributeError in H3 without it) |
| 3 | 344 | level 1 answer refused when SNP was asked for | DETECTED | test_sealed_flags_refuse_a_level1_answer |

## ef906c8 Broker: strict config, orphans, durable state, deleting recovery, 413

Tests run: the 24 tests of hardening_r6_test.go and hardening_r6core_test.go
(-short; the lock-read hunks also with -race).

broker/main.go

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 29 | os/signal, syscall imports | DEP | build |
| 2 | 111 | room.deleteSent field | DEP | build |
| 3 | 119 | hotel.ctl client and cfgMu | DEP | build |
| 4 | 166 | broker.capsOnDisk | DEP | build |
| 5 | 205 | register: consumed saved UUID removed from savedUUIDs | UNTESTED | none |
| 6 | 224 | config: DisallowUnknownFields | DETECTED | TestConfigLoaderFailsOpenOnTypos |
| 7 | 245 | config: empty guest id, duplicate id, shared key hash refused | DETECTED (all three cases are in the test) | TestConfigLoaderFailsOpenOnTypos |
| 8 | 299 | getJSON uses the ctl pool (sync loop cannot be starved by execs) | UNTESTED | TestLongExecsStarveHealthAndTakeTheHotelDown is skipped under -short, asserts the bug, and hangs 300 s when run; see weak tests |
| 9 | 365 | pick reads drain() under cfgMu | UNTESTED (also with -race) | the race tests PATCH labels, never drain |
| 10 | 420 | createResult.lost, batchLabel, createOne takes a marshaled body | DEP | combo d DETECTED |
| 11 | 444 | finish(last) on the no-hotel-left path (single hotel, or every hotel tried) | UNTESTED | TestLostCreateAnswerLeavesAnOrphanRoom uses a second hotel that answers |
| 12 | 457 | finish(...) on the 499 client-gone path | UNTESTED | none |
| 13 | 505 | finish(...) on the 202 path | DETECTED | TestLostCreateAnswerLeavesAnOrphanRoom |
| 14 | 536 | a transport error records the hotel in lost | DETECTED | TestLostCreateAnswerLeavesAnOrphanRoom |
| 15 | 543 | finish(last) on the 4xx no-retry path | UNTESTED | none |
| 16 | 554 | createMany and reapOrphans | DEP | combo d DETECTED |
| 17 | 590 | handleCreate uses createMany (body marshaled once) | DEP | combo d: TestBatchCreateMultipliesTheBodyByCount |
| 18 | 678 | unlabeled room owned by nobody; body over 256 MiB is 413 | DETECTED (both) | TestEmptyGuestIDOwnsUnlabeledRooms; TestNativeFilePutOver256MiBIsCutToTheLimit |
| 19 | 720 | DELETE sets rm.deleteSent | UNTESTED | TestRoomListedAgainStaysDeleting covers the sync-loop case only |
| 20 | 968 | handleStats reads drain() under cfgMu | UNTESTED (-race too) | none |
| 21 | 1052 | syncHotel: a listed room marked deleting by a late list runs again | DETECTED | TestRoomListedAgainStaysDeleting |
| 22 | 1226 | snapshot (live view) reads drain() under cfgMu | UNTESTED (-race too) | none |
| 23 | 1390 | main: listen required; loadCaps after runtime hotels; saveLoop stop signal | N/A (main) | loadCaps order is covered through hotels.go H2 and probe.go H4 |
| 24 | 1416 | main: SIGTERM drains the server then flushes state | N/A (main) | saveLoop flush itself: TestSaveLoopDoesNotFlushWhenStopped |

broker/state.go

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 57 | saveLoop writes dirty state on ctx.Done | DETECTED | TestRestartWithinASecondLosesClientIDs, TestSaveLoopDoesNotFlushWhenStopped |
| 2 | 84 | saveCompat keeps saved UUIDs not yet listed | DETECTED | TestUndecodableClientStateIsReplacedByTheFirstSave |
| 3 | 160 | keepCorruptState | DEP | build |
| 4 | 172 | loadCompat section by section, corrupt copy kept | DETECTED | TestCorruptStateFileIsReplacedNotKept, TestUndecodableClientStateIsReplacedByTheFirstSave |

broker/hotels.go

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 61 | ctl transport; labels() and drain() helpers | DEP | build |
| 2 | 69 | addHotel: runtime hotel takes its caps from capsOnDisk | DETECTED | TestRuntimeHotelCapsAreNotRestoredInMainOrder, TestRuntimeHotelCapsLostAtRestart |
| 3 | 232 | patchHotel under cfgMu; sealed label kept | DETECTED (both) | TestPatchLabelsDropsTheSealedLabel; lock alone (sub-hunk e, -race): TestLabelsPatchRacesWithHotelSelection |
| 4 | 276 | hotelDoc reads labels()/drain() | UNTESTED (-race too) | none |

broker/probe.go

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 37 | probe error hides the hotel URL | DETECTED | TestProbeErrorPutsHotelAddressOnTheLiveView |
| 2 | 147 | probe skips a draining or resting hotel | DETECTED (drain) | TestProbeStartsARoomOnADrainedHotel |
| 2 sub | 153 | resting (backoffUntil) part | UNTESTED | sub-hunk h |
| 3 | 177 | saveCaps keeps entries of hotels not loaded | UNTESTED | none |
| 4 | 199 | loadCaps fills capsOnDisk | DETECTED | the two runtime-caps tests |

broker/images.go, build.go, compat.go

| file H | lines | fix | verdict | caught by |
|--------|-------|-----|---------|-----------|
| images 1 | 68 | selects reads labels() | DETECTED with -race only | TestLabelsPatchRacesWithHotelSelection |
| images 2 | 117 | noRoomReason reads drain() | UNTESTED (-race too) | none |
| images 3 | 250 | placementFor reads labels() | UNTESTED (-race too) | none |
| images 4 | 270 | handleHotels reads labels()/drain() | UNTESTED (-race too) | none |
| build 1 | 89 | ensureBuilds reads drain() | UNTESTED (-race too) | none |
| compat 1 | 421 | compatCreate uses createMany | DEP | combo d |
| ci.yml | 73 | broker job: gofmt, vet, -race -short, govulncheck | N/A | the job itself is the test |

## fae9652 Broker Harbor path

Tests run: the 11 tests of hardening_r6compat_test.go (two are t.Skip pending).

broker/compat.go

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 23 | import math | DEP | combo a |
| 2 | 81 | compatExec.doneAt, execKeep | DEP | build |
| 3, 4 | 186, 230 | compatCatalog takes the guest; free rooms per guest | DEP; sub-hunk c DETECTED | TestCatalogAndQuotaCountRoomsOutsideTheGuestList |
| 5 | 313 | idempotency entry dropped when the answer carries Retry-After | DETECTED | TestIdempotencyReplaysImageNotReadyAfterTheImageIsReady |
| 6 | 361 | create of an unbuilt image after a restart kicks ensureBuilds | DETECTED | TestCreateFromBuiltImageAfterRestartIs409UntilSomeoneGETs |
| 7 | 382 | shape (vcpus, memory_mib, disk_gib) and env reach the hotel | DETECTED (combo a with H1) | TestCompatCreateDropsEnvAndShape (vcpu and env only; memory_gib ceil and disk are not asserted) |
| 8 | 569 | compatQuota free rooms per guest | DETECTED | TestCatalogAndQuotaCountRoomsOutsideTheGuestList |
| 9 | 630 | delete drops the room's exec results | DETECTED | TestFinishedExecsKeepOutputAfterRoomDeletion |
| 10 | 680 | lifetime: extend_by_seconds relative, lifetime_seconds absolute, 48 h cap, 502 when the hotel cannot say | DETECTED (relative, absolute) | TestExtendBySecondsShortensTheRoom |
| 10 sub | 706 | 48 h cap | UNTESTED | sub-hunk g1 |
| 10 sub | 697 | 502 when expires_at is missing | UNTESTED | sub-hunk g2 |
| 11 | 799 | ex.doneAt set when the exec ends | UNTESTED (also with state.go H1, combo l) | none: the one-hour expiry of finished results is unguarded |
| 12 | 973 | tar: truncated is 413 file_too_large; empty stderr gets a message | DETECTED (413) | TestTarOverTheExecCapIsA500WithNoMessage |
| 12 sub | 1004 | empty-stderr fallback message | UNTESTED | sub-hunk k (cosmetic) |
| 13 | 996 | roomSecondsLeft, freeRoomsFor | DEP | build |

broker/build.go, images.go, state.go

| file H | lines | fix | verdict | caught by |
|--------|-------|-----|---------|-----------|
| build 1 | 70 | comment only | N/A | |
| build 2, 3 | 107, 125 | buildOn drops a result for a replaced entry | DETECTED (combo b) | TestStaleBuildResultOverwritesTheNewBuild |
| images 1 | 340 | findSnapshot by hotel.id ref: hotel outside the guest list is 404 | UNTESTED | TestSnapshotRoutesReachHotelsOutsideTheGuestList covers the search and list paths only |
| images 2 | 358 | findSnapshot search skips hotels outside the list | DETECTED | TestSnapshotRoutesReachHotelsOutsideTheGuestList |
| images 3 | 429 | handleSnapshotList skips hotels outside the list | DETECTED | TestSnapshotRoutesReachHotelsOutsideTheGuestList |
| state 1 | 133 | saveCompat drops finished execs older than execKeep | UNTESTED | none (combo l) |

## 707062e Docker guest

Tests run: tests/test_sandbox_guest_hardening.py, tests/test_sandbox_guest_exec.py

cathedral/sandbox_guest.py

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 314 | caps, _guest_start_fault, _run_bounded, auth-pulled file helpers | DEP (import error) | |
| 2 | 339 | DockerClient.run: bytes decoded with replace; output_cap | DETECTED (both) | test_output_that_is_not_utf8_is_replaced_not_fatal; test_run_keeps_at_most_cap_plus_one_bytes_of_output |
| 3 | 615 | docker run faults the request caused are 400 | DETECTED | test_a_bad_entrypoint_is_a_400_not_a_hotel_fault |
| 4 | 694 | exec passes output_cap | DETECTED | test_exec_asks_for_bounded_output |
| 5 | 704 | exit_code_if_stopped | UNTESTED (alone and with H11, combo m) | none |
| 6 | 932 | build context fetch capped at 256 MiB (413) | UNTESTED | none |
| 7 | 966 | _read_room_log capped | UNTESTED | none |
| 8 | 1015 | _auth_pulled loaded from disk at start | DETECTED | test_credentialed_pulls_are_remembered_across_a_restart |
| 9 | 1089 | build context expanded past 1 GiB refused | UNTESTED | none |
| 10 | 1272 | _save_auth_pulled after a credentialed pull | UNTESTED | the restart test writes the file itself |
| 11 | 1325 | egress apply failure on an exited container is 400 entrypoint_exited | UNTESTED | none |
| 12 | 1424 | timeout wrappers: GNU -k 5, BusyBox -s KILL | DETECTED | test_timeout_wrappers_kill_a_command_that_ignores_term |
| 13 | 1456 | log record trimmed to the last EXEC_OUTPUT_CAP bytes | UNTESTED | none |
| 14 | 1637 | push_snapshot untags the registry-named local copy | UNTESTED | none |
| 15 | 1684 | set_network on a frozen room is 409 before the daemon moves | DETECTED | test_network_change_on_a_frozen_room_is_refused_before_the_daemon_moves |
| 16 | 1870 | reconcile removes snapshot images nobody names | DETECTED | test_a_restart_removes_snapshot_images_nobody_names |
| 17 | 1909 | drain sweeps tombstones only; expired snapshots lose their image | DETECTED (both) | test_a_ttl_that_ends_during_the_drain_still_gets_the_two_phase_delete; test_an_expired_snapshot_loses_its_image |

cathedral/sandbox_provider.py H1 (970, sweep_tombstones): DETECTED (three tests).
cathedral/sandbox_server.py H1 (153, install_stop_signal): DETECTED
(test at test_sandbox_guest_hardening.py:201 installs the handler and calls it).
cathedral/cli.py H1, H2 (1723, 1747, serve calls install_stop_signal): N/A
(CLI wiring; UNTESTED in the mutation run).

## 075cf8b Room kit

Tests run: tests/test_room_kit_egress.py, tests/test_room_kit_installer.py,
tests/test_room_kit_sealed_kit.py

room-kit/room_egress.py

| H | lines | fix | verdict | caught by |
|---|-------|-----|---------|-----------|
| 1 | 203 | Rules takes bridges | DEP | |
| 2 | 251 | guard: unbound ports drop when bridges are known; ether type ip6 drop | DETECTED | test_known_bridges_drop_unbound_ports_and_ipv6 |
| 3 | 646 | PROXY_PER_ROOM_MAX, admit, release | DETECTED | test_proxy_admits_a_bounded_number_of_connections_per_room |
| 4 | 669 | handle: over the cap answers 429 and closes | UNTESTED (alone and with H5, combo n) | none |
| 5 | 702 | handle: release in finally | UNTESTED | none |
| 6 | 814 | room_bridges(env) | DETECTED | test_room_bridges_follow_room_net_sh_names |
| 7 | 851 | main passes bridges=room_bridges(env) | UNTESTED | none; the only Rules() construction in the daemon |

Shell files (every test is a text assertion on the script source)

| file H | lines | fix | verdict | caught by |
|--------|-------|-----|---------|-----------|
| install.sh 1 | 18 | key file checked first | DETECTED (text) | test_key_file_is_checked_before_anything_changes |
| install.sh 2 | 74 | trap removes policy-rc.d | DETECTED (text) | test_a_failed_apt_does_not_leave_policy_rc_d_behind |
| install.sh 3, 4, 5 | 148, 163, 175 | tar --no-same-owner, chown root | DETECTED (text) | test_pinned_archives_do_not_keep_their_builders_uid |
| install.sh 6 | 246 | assess again on the mounted volume | DETECTED (text) | test_sizing_sees_the_mounted_volume |
| install.sh 7, 8 | 277, 485 | refuse_restart_with_rooms before each restart | DETECTED (text, regex count and char offsets) | test_live_rooms_are_checked_again_right_before_each_restart |
| room-net.sh 1, 2 | 34, 92 | ip6tables drops on room bridges, removed in down | DETECTED (text) | test_room_net_sh_drops_ipv6_from_room_bridges |
| build-guest.sh 1 | 126 | tracked files only into the initrd | DETECTED (text) | test_the_measured_initrd_takes_tracked_kit_files_only |
| host-net.sh 1 | 14 | usage string | N/A | |
| host-net.sh 2 | 34 | check verb restores rules | DETECTED (text) | test_host_link_rules_are_checked_every_minute |
| install-sealed.sh 1 | 45 | OVMF checked before the build; PREV_IMG | DETECTED (text) | two tests |
| install-sealed.sh 2 | 64 | -net timer | DETECTED (text) | test_host_link_rules_are_checked_every_minute |
| install-sealed.sh 3 | 82 | refuse_sealed_restart_with_rooms | DETECTED (text) | test_sealed_install_refuses_a_restart_with_live_rooms |
| install-sealed.sh 4 | 96 | mismatch disables the unit, restores the old image | DETECTED (text) | test_a_measurement_mismatch_stops_the_guest_and_keeps_the_old_image |

## 91150c1 Builds under the daemon default runtime

| file H | lines | fix | verdict | caught by |
|--------|-------|-----|---------|-----------|
| sandbox_guest.py 1 | 589 | docker build with DOCKER_BUILDKIT=0 | DETECTED | test_builds_use_the_room_daemon_default_runtime |
| config.example.json | 4 | sealed: true instead of a label | N/A | |

## 887ed40 docs only. No fix hunks.

## Combo and sub-hunk runs (summary)

| run | what | result |
|-----|------|--------|
| a | fae9652 compat.go H1+H7 | DETECTED |
| b | fae9652 build.go H2+H3 | DETECTED |
| c | fae9652 compatCatalog counts the whole chain | DETECTED |
| d | ef906c8 main.go H10..H17 + compat.go H1 | DETECTED (both tests) |
| e | ef906c8 patchHotel without cfgMu (-race) | DETECTED |
| f | 94713c4 OverflowError/RecursionError out of the 400 tuple | UNTESTED |
| g1 | fae9652 48 h cap removed | UNTESTED |
| g2 | fae9652 502 when expires_at missing removed | UNTESTED |
| h | ef906c8 probe: resting hotels no longer skipped | UNTESTED |
| j | 2e41dda usage tombstones not filtered by key | UNTESTED |
| k | fae9652 tar empty-stderr message removed | UNTESTED |
| l | fae9652 exec expiry (compat H11 + state H1) | UNTESTED |
| m | 707062e entrypoint_exited (H5 + H11) | UNTESTED |
| n | 075cf8b proxy cap in handle (H4 + H5) | UNTESTED |

## Untested fixes, ranked by the consequence left unguarded

1. 707062e sandbox_guest.py H14 (push_snapshot untag). Without it the
   registry-named copy stays local; the create path (line 1388) pulls only
   for credentialed or always-pull images, so any key on the hotel starts
   another key's pushed private snapshot with no credentials. Should have
   caught it: test_sandbox_guest_hardening.py. Sketch: with the fake docker
   CLI, snapshot a room, push_snapshot(image="registry.example.com/acme/p:1"),
   assert the recorded argv contains ["docker","image","rm",
   "registry.example.com/acme/p:1"] after the push, and that
   image_exists(image) is False afterwards.
2. 707062e sandbox_guest.py H10 (_save_auth_pulled after a credentialed
   pull). The restart test writes the file by hand, so the production write
   is unguarded: after a restart a key without credentials starts another
   key's private image. Sketch: create with registry_auth through the
   provider, close it, start a second provider, assert the ref is in
   _auth_pulled without calling _save_auth_pulled in the test.
3. 2e41dda sandbox_guest.py H1 (_resolve_snapshot visibility). On the Docker
   provider push_snapshot resolves without the inner provider, so key B can
   push key A's snapshot to B's registry (exfiltration). Sketch: two keys on
   DockerGuestProvider with the fake CLI; A snapshots; B calls push_snapshot
   on A's id and name; expect snapshot_not_found.
4. 707062e sandbox_guest.py H11 + H5 (entrypoint_exited is 400). A room
   whose entrypoint exits at once still answers 502 when egress apply
   fails, so the broker rests the hotel 10 s for every guest and retries
   elsewhere: one bad image rests every hotel in turn. Sketch: fake CLI
   where the container exits at once and egress.apply raises; expect
   SandboxOpError(entrypoint_exited, 400).
5. ef906c8 main.go H11, H12, H15 (lost hotels dropped on the non-202
   returns). With one eligible hotel (dedicated guests, the common shape) a
   create whose answer is lost returns 502 and the orphan room is never
   reaped by the first pass; the sync loop adopts it under the guest's label
   and it bills until TTL. Sketch: TestLostCreateAnswerLeavesAnOrphanRoom
   with hotels ["b"] only; after the 502 assert the fake hotel got a DELETE
   for the room (and the guest lists 0 rooms).
6. 94713c4 sandbox_server.py H3 (Content-Length guard). A Content-Length
   of "abc" raises ValueError in _run: the handler dies, the connection
   closes with no answer, the broker rests the hotel; a 10 GiB
   Content-Length is read into memory. Sketch: raw socket to run(app),
   send "POST /v1/sandboxes" with "Content-Length: abc" and with
   "Content-Length: 300000000" and no body; expect a 413 line within 2 s.
7. 707062e H6, H7, H9, H13 (memory caps: build context fetch, room log
   read, tar expansion, log record trim). Each is a customer-driven
   hotel OOM. Sketch: monkeypatch BUILD_CONTEXT_CAP / EXEC_OUTPUT_CAP /
   BUILD_CONTEXT_EXPANDED_CAP to small values; serve a context URL of
   cap+2 bytes (expect 413 build_context_too_large); a tar whose members
   sum past the cap (expect 400 invalid_build_context); a log file of
   cap+1 bytes (returned length == cap); two execs (len(container_stdout)
   <= cap).
8. 075cf8b room_egress.py H7 and H4+H5 (bridges wired in main; proxy cap in
   handle). The guard fix and the fd cap exist only as unit helpers: the
   daemon's Rules() gets bridges on one untested line, and handle() never
   enforces admit(). Sketch: extract rules_for(env, nets, ports) and test
   it from a ROOM_BRIDGE/ROOM_NETS env; for the proxy drive handle() with
   fake asyncio streams, per_room_max=1, two concurrent calls, expect one
   "HTTP/1.1 429" write and pending back to 0 after both finish.
9. ef906c8 main.go H19 (deleteSent). A guest DELETE followed by a late list
   flips the room back to running (quota counts it) until the next sync.
   Sketch: TestRoomListedAgainStaysDeleting variant: create, start a list
   that is delayed, DELETE during the delay, assert the state stays
   deleting after the late list lands.
10. fae9652 compat.go H11 + state.go H1 (exec results expire after an
    hour). Finished results up to 32 MiB each stay in memory for rooms that
    are not deleted. Sketch: run an exec to completion, set ex.doneAt two
    hours back, call saveCompat, GET the exec id, expect 404.
11. fae9652 images.go H1 (hotel.id ref outside the guest list). The guest
    reaches a hotel outside its list (which may hang). Sketch: guest with
    hotels [a]; create from snapshot_id "b.snap_1"; the fake hotel b must
    see no request and the answer is 404.
12. 2e41dda H11, H12 sub, H13 (usage: deleted sandboxes and snapshot cost
    leak across keys). Sketch: alice creates and deletes; bob's usage must
    not show alice's label group; alice snapshots; bob's snapshot cost is 0.
13. 2e41dda sandbox_guest.py H2 (idempotency cleanup after a failed guest
    start). A retry with the same Idempotency-Key replays the document of a
    room that was removed. Sketch: fake CLI fails the first docker run;
    create with idempotency "k" raises; retry with "k" must start a new room.
14. Lock-read hunks (ef906c8 main.go H9, H20, H22; hotels.go H4; images.go
    H2, H3, H4; build.go H1). The race tests PATCH labels only, so a PATCH
    of drain racing pick/handleStats/snapshot is unguarded. Sketch: extend
    TestLabelsPatchRacesWithHotelSelection to alternate {"drain":true/false}
    and to call GET /v1/broker/hotels, /v1/stats and the live view in the
    loop; run under -race.
15. Low: ef906c8 main.go H5 (savedUUIDs never shrinks), probe.go H2 sub
    (resting hotel probed), probe.go H3 (caps of absent hotels dropped),
    fae9652 H10 sub (48 h cap, 502 path), H12 sub (message), 2e41dda H8,
    94713c4 H2 sub (OverflowError, RecursionError: a 5,000-digit integer or
    deep nesting now lands in the 500 branch instead of 400; still answered).

## Tests that pass for the wrong reason

- TestLongExecsStarveHealthAndTakeTheHotelDown (hardening_r6core_test.go:171).
  Skipped under -short, which is what CI runs, so it never runs. Run
  without -short at head it FAILS after 303 s: it asserts the pre-fix
  behaviour (t.Errorf when the hotel stays up and when the other guest's
  create is not 503) and the other guest's create blocks five minutes
  behind the saturated data pool before a 502. The fix (ctl pool) works
  (syncHotel 0.0 s, ok=true) but is guarded by nothing. Also a
  consequence worth a look: the other guest's create still waits the full
  hotel timeout behind one guest's execs.
- TestBatchCreateMultipliesTheBodyByCount: asserts a heap-growth threshold
  (64 MiB) sampled every 20 ms. GC timing dependent; passes under -race
  today but the margin is a heuristic.
- TestUndecodableClientStateIsReplacedByTheFirstSave (sleep 1500 ms for
  the save tick), TestStaleBuildResultOverwritesTheNewBuild (two 100 ms
  sleeps for a goroutine), TestBuildResetWithDrainedHotelCrashesTheBroker
  (300 ms), TestRoomListedAgainStaysDeleting (6 s proxy delay),
  TestRestartWithinASecondLosesClientIDs: timing based synchronisation.
- TestCompatExecIsForgottenAtRestart and TestBackgroundExecIsLostOnBrokerRestart
  are unconditional t.Skip("pending"). They guard nothing; fine as notes,
  but they count as green.
- All of tests/test_room_kit_installer.py and the new tests in
  tests/test_room_kit_sealed_kit.py and test_room_net_sh_drops_ipv6_from_room_bridges
  assert on the script text (substring, regex count, character offsets).
  They prove the lines exist, not that they run. A bash -n plus running
  install.sh's functions against stub binaries would be the behavioural
  floor.
- test_credentialed_pulls_are_remembered_across_a_restart writes the file
  with _save_auth_pulled itself (see ranked item 2).
- TestCompatCreateDropsEnvAndShape sends shape.disk_mib and asserts nothing
  about memory or disk; the code reads shape.disk_gib. One of the two is
  the wrong field name and no test pins it.
- TestConfigLoaderFailsOpenOnTypos: every case is `if err == nil { check }`,
  so a loader that errors for an unrelated reason passes silently. Today
  it is a real guard (all cases fail with H6/H7 reverted).

## Not reached

- No mutation of the CI job, docs or config.example.json.
- main() hunks (listen required, SIGTERM drain, loadCaps order in main)
  have no unit seam; not mutated beyond noting them.
- No live host, broker or customer key touched. Fake docker CLI only.
- The Python guest tests were run as a block (hardening + exec); a hunk
  marked DETECTED there may be caught by a pre-existing test rather than a
  new one; the caught-by column names the new tests that failed.

# P. Python-side gaps of PR #312 closed with tests (reader P, round 6)

Artifact: the untested Python fixes in reader O's catalog (O-mutation.md,
"Untested fixes" 1, 2, 3, 4, 6, 7, 8, 12, 13, 15), on the working tree of
/Users/dreamboat/Documents/projects.nosync/cathedral-sandbox-pr308
(branch fix/review-round-6, started at 6b7dd62; the branch moved to 0904280
during the pass, which touches docs, room-kit/versions.lock and
tests/test_sandbox_provider.py only, none of the files tested here).
Partition: cathedral/*.py, room-kit/*.py, tests/*.py. broker/ untouched by me.
Nothing committed, pushed or stashed. No live host, broker or credential
touched; fake docker CLI only.

Other agents edited the same working tree while this ran; not mine and not
counted below: cathedral/sandbox_api.py (snapshot_id shape check),
cathedral/sandbox_provider.py (duplicate tombstone "api_key" key dropped),
pyproject.toml (hypothesis), tests/test_cli_serve_hardening.py (five tests),
tests/test_round6_properties.py, broker/*. My suites were run on the tree
with those changes present.

Method: each new test was run against a throwaway worktree of the base commit
22e7824 (removed afterwards). Where the base has no seam or is self-consistent,
the test was also run against a worktree of head with that one fix hunk
reverted (the mutation reader O ran; also removed). The venv of the main
worktree ran every test; `cathedral` resolved to the worktree under test.

New files: tests/test_round6_gaps_guest.py (8 tests),
tests/test_round6_gaps_server.py (5), tests/test_round6_gaps_provider.py (2),
tests/test_round6_gaps_room_egress.py (2). Changed: tests/fake_docker_cli.py
(two knobs, below), tests/test_sandbox_guest_hardening.py (one test fixed in
place), room-kit/room_egress.py (rules_for seam), cathedral/sandbox_guest.py
(one real fix, below).

## Items

| O | test | guards (plain terms) | failing assertion on 22e7824 (or before the fix) | head |
|---|------|----------------------|--------------------------------------------------|------|
| O1 (707062e guest H14) | test_round6_gaps_guest.py::test_a_pushed_snapshot_leaves_no_local_copy_under_the_registry_name | After a push, the local copy under the registry name is untagged; a key without credentials that names that image has to pull, and the registry refuses it | `assert ['image', 'rm', 'registry.example.com/acme/pushed:1'] in []` (no untag; the copy stayed local) | pass |
| O2 (707062e guest H10) | test_sandbox_guest_hardening.py::test_credentialed_pulls_are_remembered_across_a_restart (fixed in place) | The credentialed pull itself writes the remembered set to disk; after a restart a key without credentials pulls again and is refused | `assert 'registry.example.com/acme/private:v1' in set()` (second provider's `_auth_pulled` empty; the old test wrote the file itself) | pass |
| O3 (2e41dda guest H1) | test_round6_gaps_guest.py::test_another_key_cannot_push_fork_or_delete_a_snapshot_on_the_docker_provider | On the Docker provider key B cannot push, fork or delete key A's snapshot by id or by name; A still forks it | line 104 `Failed: DID NOT RAISE SandboxOpError` (B's push of A's snapshot id ran; the fake registry got it). On head before my fix: `assert 'cathedral-snap-snap_36f4...:latest' in ['alpine:3.20']` (B's 404 delete removed A's image; see Real bugs) | pass after the fix |
| O4 (707062e guest H11+H5) | test_round6_gaps_guest.py::test_an_entrypoint_that_ends_at_once_is_a_400_when_the_policy_cannot_apply | A room whose entrypoint ends at once, found not running by the egress daemon, is a 400 entrypoint_exited (not a 502 that rests the hotel); its container is removed | `assert (503 == 400)` (egress_unavailable 503 passed through) | pass |
| O6 (94713c4 server H3) | test_round6_gaps_server.py::test_a_bad_or_oversized_content_length_is_refused_before_the_body_is_read[abc / 300000000 / -1] | Raw socket to the real listener: a non-numeric, oversized or negative Content-Length gets a 413 request_too_large within 2 s and the next connection is answered | all three: `assert [] == [b'413']` with answer `b''` (abc: `ValueError: invalid literal for int()` in the handler, connection closed with no answer; 300000000 and -1: no answer within 2 s, the thread sat on the body read) | pass |
| O7 (707062e H6) | test_round6_gaps_guest.py::test_a_build_context_url_past_the_cap_is_a_413 | A context URL answering cap+2 bytes is a 413 build_context_too_large; the read stops at cap+1 | `Failed: DID NOT RAISE SandboxOpError` (the whole 1002-byte answer was read and returned) | pass |
| O7 (707062e H9) | test_round6_gaps_guest.py::test_a_build_context_that_expands_past_the_cap_is_refused | A tar whose members sum past the expanded cap is a 400 invalid_build_context and no build runs | `Failed: DID NOT RAISE SandboxOpError` (extracted and built) | pass |
| O7 (707062e H7) | test_round6_gaps_guest.py::test_a_room_log_read_stops_at_the_cap | A process log of cap+1 bytes reads back cap bytes | `assert 1001 == 1000` | pass |
| O7 (707062e H13) | test_round6_gaps_guest.py::test_the_exec_log_record_keeps_the_last_cap_bytes_only | Two execs of 80 bytes with the cap at 100 leave a 100-byte log record | `assert 160 == 100` | pass |
| O12 (2e41dda H11, H12 sub, H13) | test_round6_gaps_provider.py::test_usage_hides_another_key_s_deleted_sandboxes_and_snapshots | Bob's usage shows neither Alice's deleted sandbox (tombstone) nor her snapshot GiB-months or cost; Alice's own usage shows both | `assert 'alice-job' not in {'alice-job': {...}}` | pass |
| O13 (2e41dda guest H2) | test_round6_gaps_guest.py::test_a_failed_guest_start_frees_the_idempotency_key_for_its_own_key_only | After a failed docker run the retry with the same Idempotency-Key starts a new room (no replay of the removed one); another key's same Idempotency-Key gets its own room | On 22e7824 the retry half passes (base keyed both sides by the bare string) and the test fails on `assert ('sbx_f28a...' != 'sbx_f28a...')` (Bob received Alice's room). Mutant (head with H2 reverted to the bare key): `SandboxOpError: no sandbox sbx_7e5b...` on the retry, the removed room's document replayed | pass |
| O8a (075cf8b room_egress H7) | test_round6_gaps_room_egress.py::test_the_daemon_rules_come_from_room_env_with_every_bridge | The daemon's Rules, built from a room.env by the new `rules_for(env, ports)` seam that main() now calls, carry every bridge (rmbr0, rmnet0, rmnet1), so the guard reads `meta ibrname != {...} return` and `iifname != @ports drop` | `AttributeError: module 'room_egress' has no attribute 'rules_for'` (base has no seam: main built Rules inline with no bridges). Mutant (rules_for without `bridges=`): `assert 'meta ibrname != { "rmbr0", "rmnet0", "rmnet1" } return' in 'chain room_guard {...iifname != @ports return...'` | pass |
| O8b (075cf8b room_egress H4+H5) | test_round6_gaps_room_egress.py::test_proxy_handle_answers_429_past_the_per_room_cap_and_frees_the_slot | handle() with per_room_max=1 and two concurrent connections from one room: exactly one HTTP/1.1 429 (closed), the other goes on (403 here, no policy), pending back to 0 | `assert 0 == 1` with answers `[b'HTTP/1.1 403', b'HTTP/1.1 403']` (no cap in handle) | pass |
| O15 (94713c4 server H2 sub) | test_round6_gaps_server.py::test_a_huge_integer_or_deep_nesting_in_a_create_body_is_a_400 | A 5,000-digit integer (int digit limit, a ValueError on 3.11+) and 100,000-deep nesting (RecursionError) in a create body are a 400 invalid_request | `ValueError: Exceeds the limit (4300 digits) for integer string conversion` raised out of dispatch (connection dropped). Mutant (OverflowError, RecursionError out of the tuple): `assert 500 == 400` for the nesting (`internal_error`) | pass |
| O15 (94713c4 server H2 sub) | test_round6_gaps_server.py::test_an_overflowing_number_in_a_wait_body_is_a_400 | `{"timeout_seconds": 1e400}` on /wait, the one body number that reaches int() with no range check first (OverflowError), is a 400 invalid_request | `OverflowError: cannot convert float infinity to integer` out of dispatch. Mutant: `assert 500 == 400` | pass |
| O15 (2e41dda provider H8) | test_round6_gaps_provider.py::test_an_expired_snapshot_leaves_no_owner_entry | After a 1 s snapshot expires, its owner entry is gone and the owner map has the same keys as the snapshot map | `AttributeError: 'InMemorySandboxProvider' object has no attribute '_snapshot_owner'` (base has no owner map). Mutant (pop removed from the expiry sweep): `assert 'snap_02cc...' not in {'snap_02cc...': 'alice'}` | pass |

Notes on the proofs
- O13, O8a, O15 (owner entry): the base commit has no seam or is self-consistent
  for the hunk, so the mutant run is the proof of the guard; the base run is
  recorded as well. O13 fails on base through the second assertion (per-key
  Idempotency-Key through the Docker provider), which the same test carries.
- O15 create body: on Python 3.13 the 5,000-digit integer is a ValueError from
  the int digit limit, not an OverflowError; the only OverflowError reachable
  from a body is `int(inf)` on /wait, hence the second test. Both were a
  dropped connection on 22e7824.
- No test for a create body OverflowError exists because none is reachable:
  ttl_seconds, count, vcpu, idle_timeout_seconds all hit a range check first
  (checked with 1e400 and 4,000-digit values).

## Real bugs found

1. cathedral/sandbox_guest.py:1785 (DockerGuestProvider.delete_snapshot),
   failed on the fixed code. Mechanism: `existed = self._inner.delete_snapshot(id)`
   returns False for another key's snapshot (visibility, 2e41dda), but the
   method went on to `self._snapshot_images.pop(id)` and
   `docker image rm <image>` regardless. Key B's DELETE /v1/snapshots/<A's id>
   answered 404 to B and removed A's committed image and size metadata; A's
   next fork answered 409 snapshot_image_missing. Cross-key destruction, not
   exfiltration. Fix: return False before touching the image when `existed`
   is False (an expired record's image still goes in the next sweep through
   `_gc_snapshot_images`). Guarded by the O3 test (delete half); failing
   assertion before the fix recorded in the table.

No other test failed on the fixed code. O3's push and fork halves pass on
head: `_resolve_snapshot` honours visibility as the catalog assumed.

## Test support changes

- tests/fake_docker_cli.py: `exit_at_once={argv token: code}` marks a run
  container exited at once (docker run -d still prints the id); `docker
  inspect --format '{{.State.Running}} {{.State.ExitCode}}'` answers
  `true 0` or `false <code>` (the probe exit_code_if_stopped makes). No
  existing behaviour changed.
- room-kit/room_egress.py: `rules_for(env, ports, run=None)` builds the
  daemon's Rules from room.env (networks and bridges); main() calls it. No
  behaviour change.

## Suites run on head (working tree, after the fix)

tests/test_sandbox_guest_hardening.py tests/test_sandbox_guest_exec.py
tests/test_provider_key_isolation.py tests/test_sandbox_server.py
tests/test_room_kit_egress.py tests/test_cli_serve_hardening.py plus the four
new files: 145 passed, 17.6 s (123 in the six suites at the start, 17 new
here, 5 added to tests/test_cli_serve_hardening.py by another agent during
the pass).

Also run because the delete_snapshot fix touches them:
tests/test_sandbox_guest.py test_sandbox_guest_build.py
test_sandbox_guest_create.py test_sandbox_guest_gc.py
test_sandbox_guest_prefetch.py test_sandbox_guest_snapshot.py
test_sandbox_egress.py test_sandbox_provider.py test_agent_websocket.py:
145 passed, 10 skipped (the skips need a docker daemon), 34.8 s.

Throwaway worktrees /private/tmp/claude-501/r6py-base (22e7824) and
/private/tmp/claude-501/r6py-mut (6b7dd62 plus my files) removed.

Working tree changes of this pass: cathedral/sandbox_guest.py (+5, the
delete_snapshot fix), room-kit/room_egress.py (rules_for, main calls it),
tests/fake_docker_cli.py (exit_at_once knob, State inspect),
tests/test_sandbox_guest_hardening.py (one test rewritten in place), and the
four new tests/test_round6_gaps_*.py files.

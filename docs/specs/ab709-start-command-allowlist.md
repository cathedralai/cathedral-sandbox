# AB#709: allowlisted image startup for sealed rooms

Status, 23 Nov 2026: **hotel support is implemented; Desktop integration and live acceptance remain open**. This document reconciles the original spec (#449) with the implementation in #455/#457/#458. It does not enable a template, change an image pin or authorize a hotel roll.

## Source baseline

This is a source audit, not a production readback:

| Repository | Inspected commit | Relevant source |
|---|---|---|
| cathedral-sandbox | `9cd4e941d3dfffe7c8e36b516321b80adbfa0a28` | `cathedral/start_commands.py`, `sandbox_guest.py`, `sandbox_server.py`; `room-kit/room_receipts.py`, `verify_receipts.py` |
| [polariscomputer](https://github.com/bigailabs/polariscomputer/tree/5dfbe02639579f8d14e3fc66596a4679a39fa4eb) | `5dfbe02639579f8d14e3fc66596a4679a39fa4eb` | `polaris/services/cathedral_broker_sealed.py`, `cathedral_agent_templates.py`, `cathedral_sandboxes.py` |
| [cathedral-desktop](https://github.com/cathedralai/cathedral-desktop/tree/ca6bede0bcbceb2646cd08dd682b67414d1fc621) | `ca6bede0bcbceb2646cd08dd682b67414d1fc621` | `Dockerfile`, `desktop/desktop-up` |

## What works in the hotel source

`POST /v1/sandboxes` accepts `start: "image"`. The hotel reads the inspected image's Docker `ENTRYPOINT` followed by `CMD` and checks the exact digest/argv pair against `cathedral/start_commands.json`. A nonmatching pair is refused, with no fallback to a sleeping room.

The allowlist has version 1 and entries shaped as:

```json
{"version": 1, "entries": [{"image_digest": "sha256:<64 hex>", "argv": ["service", "--foreground"], "note": "reviewed service"}]}
```

There are no glob or prefix matches. `image_digest_for_allowlist` uses the first valid inspected `RepoDigests` entry, falling back to the image ID. The Docker run itself uses the validated immutable image **ID**, not the mutable reference. The ID must be valid; an explicitly requested image's ownership is checked again against that ID before running it. Changing a tag after inspection cannot replace the image that runs.

`start_commands_path` selects the configured path, then the installed file, then the package file. Missing or invalid allowlist data prevents provider startup. The production rollout must verify which file was installed and covered by the admitted guest build; the source-tree existence test alone does not prove that deployment fact.

### Default compatibility is narrower than “everything runs sleep”

Without `start: "image"`, the existing path remains:

- Ordinary requests default to the argv `sleep infinity`.
- A request can already supply `entrypoint`; the API's `broker_body` now forwards normalized entrypoints (AB#424).
- These argv values replace Docker CMD, but do not discard an image ENTRYPOINT. They are not an attestation that the effective process is always `sleep`.
- DinD retains its fixed dockerd command and refuses image startup.

The allowlist governs the opt-in image-start path. It is not an allowlist for all commands a customer can run through entrypoint or exec. Unlisted customer images cannot use image startup; allowing more pairs requires separate review.

### Refusals

| Code | Status | Condition |
|---|---|---|
| `invalid_start` | 400 | Non-null `start` other than `image` |
| `start_conflict` | 400 | `start: "image"` and an `entrypoint` field in the request |
| `start_unsupported_image` | 400 | Image startup requested for DinD |
| `start_command_unavailable` | 400 | No usable image ENTRYPOINT/CMD |
| `start_command_not_allowed` | 400 | Digest/argv pair not allowed |
| `image_id_unavailable` | 409 | No valid immutable image ID to run |
| `image_not_owned` | 403 | The ID about to run is not owned by the caller |
| `entrypoint_exited` | 400 | Existing immediate-exit detection reports the process ended |

These are hotel-side conditions. API passthrough and customer refusal wording still need integration tests; this table does not assert that the public API preserves every status/code today.

## Receipt meaning

For image startup, the provider returns the inspected argv and its canonical JSON SHA-256. For other modes it returns null fields. The receipt front includes `start_command` and `start_command_sha256` on create statements, using the successful response's argv and recomputing its hash.

The Python and Go verifiers check field type and hash consistency when present. Null command requires an absent/null hash. An absent command is skipped for compatibility. **Absent or null fields do not prove `sleep infinity`, an allowlist match, or even a successful create.** Custom entrypoints, DinD, old producers and failed creates must not be relabelled as sleeping rooms. The existing verifier comments that call absence “the default” are shorthand, not an additional verification rule.

A complete image-start proof needs a successful signed create statement, the expected command/hash, the image evidence and the admitted guest measurement/allowlist. Hash consistency alone is insufficient. Preserve old receipt bytes and historical template-start evidence; do not backfill a command that was never recorded.

## Desktop still has three integration gaps

1. **Image declaration and allowlist are not aligned.** The inspected Desktop Dockerfile declares `CMD ["sleep", "infinity"]`; `desktop-up` supports `--foreground`, but that is not its image CMD. The hotel allowlist instead names `desktop-up --tunnel --foreground`. Its digest also differs from the pin in [the prefetch runbook](../../ops/roll/PREFETCH_DESKTOP.md). That runbook records a registry refusal for the allowlist digest on 16 Nov; this audit did not repeat that network check or inspect today's production image. Correcting the digest alone would not align the declared command.
2. **The API does not request image startup.** `broker_body` forwards `entrypoint`, not `start: "image"`. Desktop still has the locked exec autostart command, `ensure_started`, `sweep_starts` and `template_start_view`.
3. **No live cutover proof is attached here.** Source merges do not establish that every eligible hotel carries the correct allowlist, that the configured Desktop image matches it, or that Desktop becomes usable without a follow-up start exec.

The current API command also passes the sandbox ID through `--room` and requires a fresh, nonempty `/work/desktop.json`. The image-start implementation must preserve room identity and readiness. The foreground script currently marks local state ready even if no tunnel URL was obtained, so process liveness alone cannot replace the API's link-readiness check. Retain the existing tunnel privacy disclosure.

## Ordered implementation and rollout

These are required gates for the remaining work, not completed steps. SpockChaser owns implementation; Mr Spock coordinates image publication, admitted measurements, hotel selection and rollout; Reviewbot checks the changes and proof.

1. **Build a compatible Desktop image.** Declare a long-running command, preserve room identity without a variable allowlisted argv (for example through validated create environment), and distinguish link readiness from process liveness. Test local startup failure and shutdown behavior. Publish and inspect the resulting immutable image; record its real digest, ID, ENTRYPOINT and CMD before proposing the corresponding allowlist entry. Do not substitute the old prefetch pin by assumption.
2. **Align the hotel build.** Update the allowlist with that exact inspected pair. Review the new measured build and perform the coordinated re-seal/prefetch. Prove every hotel eligible for image-start requests has the required build, or implement an explicit broker eligibility constraint first. An unknown field can be ignored by an older hotel, so sending `start: "image"` without that gate is unsafe.
3. **Wire the API with an explicit startup mode.** Record the selected mode on each created Desktop sandbox. Send `start: "image"` only for the verified image/fleet combination and do not also send `entrypoint`. Preserve sandbox identity, existing network/privacy rules and observable readiness/failure state. Refuse an unsupported combination; do not retry it as an ordinary sleep-and-exec create.
4. **Retire the old path without stranding existing rooms.** Image-start rooms must never enter the exec starter or retry sweep. Existing legacy rooms may still have a pending start attempt, so their recovery must remain correct through the cutover. Once no legacy room needs it, remove the runtime autostart/sweep/attempt code and its reconcile call. Preserve historical audit data and compatibility reads as needed.
5. **Run acceptance on an owned test room.** Record the deployed API, Desktop image and guest measurement. One create must produce a usable Desktop/link with no subsequent start exec. Verify the signed create receipt and image/command binding; test wrong argv/digest, mixed-fleet exclusion and startup failure. Exercise exec/files plus pause/resume while the service runs. A create receipt is evidence of startup, not continued service health.
6. **Rollback through the same boundary.** Stop new image-start creates before removing their image or eligible hotel build. Do not reinterpret already-created image-start rooms as legacy rooms or run the old starter against them. Restore legacy creation only with its matching image and starter path.

## Validation and completion

The existing `tests/test_ab709_start_command.py` covers provider defaults, matching/mismatching pairs, immutable-ID pinning and ownership races, parsing and allowlist validation using FakeDocker. Its shipped-file check proves file presence and parsing, not image publication, guest measurement coverage or a live Desktop. The Go verifier's `TestStartCommandRule` checks receipt hash rules with synthetic receipts.

AB#709 remains open until the image, hotel rollout and API cutover are verified together, the Desktop starts with create, and the redundant runtime starter is removed safely. A spec merge or passing provider unit suite is not completion evidence.

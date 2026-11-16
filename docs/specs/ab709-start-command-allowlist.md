# AB#709: allowlist start-command for sealed rooms

Status: spec for Eng ACK. No code in this PR. Nothing in `cathedral/` changes until this is accepted, because any change there is a new measurement and a re-seal roll of every hotel.

## Problem

- A sealed room always boots as `sleep infinity`. The API never sends a start command, so the hotel falls back to its default.
- A template that needs a process (Desktop, AB#699) is started by a second step: the API runs `desktop-up` inside the room with an exec after the room runs, with retries from a background sweep (`polariscomputer` `polaris/services/cathedral_agent_templates.py`: `ensure_started`, `sweep_starts`, `START_SAFETY_SECONDS`, `START_SWEEP_LIMIT`).
- Three review rounds on AB#699 found races in that step (double starts, stale retries, lost or mislabelled receipts). They are fixed with a flock inside the room, but the API now supervises a process over a network.
- Any customer image with its own service has the same gap: nothing starts it.
- Goal: a room created from an image starts that image's declared command, within rules we set, as one step with the room. Then the Desktop sweep in the API is deleted.

## Current code (cathedral-sandbox main, 939751f era; line numbers at b17d9fe)

- The hotel already carries a start command, but only as a request field:
  - `cathedral/sandbox_server.py:133` reads `payload["entrypoint"]`, else `("sleep", "infinity")`.
  - `cathedral/sandbox_api.py:566` (`CreateSandboxRequest.entrypoint`, default `("sleep", "infinity")`) and `:623` (only checks it is a non-empty list of strings).
  - `cathedral/sandbox_guest.py:1875` picks the argv: `None` for DinD, the request's entrypoint if set, else `sleep infinity`.
  - `cathedral/sandbox_guest.py:807-811` builds `docker run ... <image> <argv>` (or `<image> sleep infinity`). The argv is appended after the image, so it replaces the image's CMD but an image ENTRYPOINT stays and receives it as arguments.
  - `cathedral/sandbox_guest.py:1902-1911` refuses a room whose process ended at once (`entrypoint_exited`, 400).
- Nothing allowlists that field. On the sealed lane it is never set: `polaris/services/cathedral_broker_sealed.py:586-600` (`broker_body`) builds the body without `entrypoint`. The broker does not read the field (no match in `broker/*.go`), it forwards the body.
- The create receipt covers the field only by hash: `room-kit/room_receipts.py:2245-2270` records `customer_request_sha256` over the whole body, `image` and `image_digest`. It does not name the command.
- The tunables list states the command is fixed: `cathedral/tee_box/tunables.py:84` and `:148` ("the entrypoint (`sleep infinity`)"). That text becomes wrong when this ships.
- The original reason for `sleep infinity` is not documented. Believed to be uniformity (every room looks the same to exec, files and pause), not security. To confirm with the author before ACK.
- Exec, files and pause are independent of the main process: exec is `docker exec` (`sandbox_guest.py:897`), pause is `docker pause` (`:1030`).

## Proposal

### Rule

- Default is unchanged: a create that does not ask for the image's start command runs `sleep infinity`.
- A create may ask for it with a new body field `start: "image"`. The hotel then reads the image's own `ENTRYPOINT` + `CMD` (from the local image config after the digest import it already does) as the start argv.
- The hotel starts it only when the pair (image digest, start argv) is on the allowlist. Otherwise it refuses the create (see codes). It never falls back silently to `sleep infinity` when `start: "image"` was asked, so a customer never gets a room without the service they asked for.
- A request `entrypoint` together with `start: "image"` is refused (one source of truth).
- DinD images keep their fixed dockerd command; `start: "image"` on a DinD image is refused.

### Allowlist format

- One JSON file inside the measured guest image: `cathedral/start_commands.json`. Measured with the guest, so changing it is a re-seal roll like any code change.
- Shape:
  ```
  {"version": 1,
   "entries": [
     {"image_digest": "sha256:<64 hex>", "argv": ["/usr/local/bin/room-init"], "note": "desktop"}
   ]}
  ```
- Match is exact: digest equal, argv equal element by element. No globs, no argv[0]-only match, no regex.
- Digest-pinned, not tag-pinned, so a retagged image cannot change what starts. The digest is the one the receipt already records (`image_digest`).
- Launch entries: the Desktop image (`cathedral_desktop_image` pin) with the argv `desktop-up --tunnel` equivalent. Agent room images stay on the default until someone asks.
- Customer images: not on the list at launch, so they are refused. Opening that is a separate decision (see open questions).

### Receipts

- The create receipt gains `start_command` (argv, or null for the default) and `start_command_sha256`, computed by the guest from what it ran, not copied from the API. Same pattern as `network_policy_sha256` (`room_receipts.py:2262-2270`).
- The verifier treats an absent field as `sleep infinity` for old receipts.

### What changes for exec, files, pause, delete

- Exec and files: unchanged, they use `docker exec` into the same container. A service in the main process shares the room's memory and pids budget with the customer's execs; no new limit in this spec.
- Pause: `docker pause` freezes the service too. On resume the service continues; no restart. Documented, no code.
- Main process exits later (crash): the room is gone like any room whose main process ends today (`sandbox_guest.py:2094`, `room_lost`). Documented, not changed.
- Main process exits at once: existing `entrypoint_exited` refusal, with the start command named in the message.
- Idle and lifetime: unchanged.

### API side (polariscomputer, follow-up PR after ACK)

- `broker_body` sends `start: "image"` for templates whose image is on the list (Desktop).
- Delete from `cathedral_agent_templates.py`: `ensure_started`, `sweep_starts`, `_run_attempt`, `sign_attempt`, `START_*` constants, the `autostart` tuple, the reconcile call (`cathedral_sandboxes.py:3091-3093`) and the `template_start_view`.
- Order: hotel change ships and rolls first. The API change flips only after every hotel runs the new measurement, because an old hotel ignores `start` and would run `sleep infinity` with no start step left.

## Refusal codes

All 4xx, unbilled, answered by the hotel and passed through by the API:

| Code | When |
|------|------|
| `start_command_not_allowed` | `start: "image"` and the (digest, argv) pair is not on the list |
| `start_command_unavailable` | image has no ENTRYPOINT or CMD, or the config cannot be read |
| `start_conflict` | `start: "image"` together with a request `entrypoint` |
| `start_unsupported_image` | `start: "image"` on a DinD image |
| `entrypoint_exited` | existing: the process ended at once |

## Tests the hotel PR will add

- Default create: no `start`, argv is `sleep infinity` (pins old behavior).
- `start: "image"`, listed digest and argv: container runs exactly that argv; create receipt carries `start_command` and a matching `start_command_sha256`.
- Listed digest, different argv (image rebuilt with another CMD): `start_command_not_allowed`.
- Unlisted digest: `start_command_not_allowed`, no container left behind, no network pool slot leaked.
- Same tag, different digest: refused (tag is not the key).
- Image with no ENTRYPOINT/CMD: `start_command_unavailable`.
- `start` with `entrypoint`: `start_conflict`. `start` with a DinD image: `start_unsupported_image`.
- Listed argv that exits at once: `entrypoint_exited`.
- Allowlist file: malformed JSON, unknown version, non-sha256 digest, empty argv each fail guest startup (fail closed, not "allow all").
- Exec, file write, pause and resume against a room whose main process is a long-running service.
- Receipt verifier: new receipt verifies; old receipt without the field verifies as `sleep infinity`.
- Guest measurement test: the allowlist file is part of what the measured image hash covers.

## Out of scope

- Customer-supplied or customer-owned allowlist entries.
- Restart policies, health checks, supervising several processes, logs of the main process.
- Per-service resource limits inside a room.
- Desktop image content, the tunnel, and its privacy note.
- Site copy and docs outside this repo.
- The re-seal roll itself (a separate card once code merges).

## Open questions

- Why `sleep infinity` originally? If it was for uniformity only, this spec is safe. Needs the author's word.
- ENTRYPOINT is kept by docker today when an argv is appended. With `start: "image"` we pass no argv and let docker run ENTRYPOINT+CMD; reading both from the image config and also pinning the pair in the list means the match is on the effective command. Confirm that reading both is the intended definition of "the image's start command".
- Do we open customer images later, and by what proof: owner-signed entries (see `room-kit/owner_sign.py`), or a build receipt that names the CMD? Not needed for AB#699.
- Should `start_command` go in the signed create receipt, or in the room's attested state only? This spec says the receipt.
- One flag `start: "image"` or a template-level default for listed images? Flag keeps old API clients unchanged.
- Roll order for mixed hotels: is it acceptable that API keeps the Desktop sweep until the last hotel rolls?

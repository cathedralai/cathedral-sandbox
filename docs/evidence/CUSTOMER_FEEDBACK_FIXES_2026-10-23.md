# Customer Feedback Fixes — 2026-10-23

Applied code fixes and test updates for all Customer customer feedback items
that had a confirmed root cause in the broker or room-kit code. Date: 2026-10-23.

---

## What was fixed (code changes)

### A — noRoom messaging (503 vs 429 for down hotels)
**Root cause:** `noRoomReason` in `broker/images.go` was already returning
503 `hotels_unavailable` for down hotels, but the logic and tests were
incomplete. Now fully tested.

**Behavior after fix:**
- All matching hotels down or draining → **503** `hotels_unavailable`
- Mix of down + full → **503** `hotels_unavailable`
- All matching hotels full (up but no capacity) → **429** `no_free_rooms`

**Files:** `broker/images.go` (logic), `broker/images_test.go` (new tests)

---

### B — Unknown hotel returns 409, not 400
**Root cause:** `parseSelection` in `broker/images.go` returned 400 for
an unknown hotel id in `"hotels": [...]`. Customer contracts expect 409 (the
request is valid but conflicts with known state).

**Files:** `broker/images.go` (status code), `broker/images_test.go` (test updated),
`broker/README.md` (doc updated)

---

### C — guestRooms persisted across broker restarts
**Root cause:** `guestRooms` (the per-guest set of hotel-local room ids used
to filter `GET /v1/hotels/<id>/receipts`) was memory-only. After a broker
restart, the filter dropped all rooms, exposing `count:0` to guests even for
rooms that existed before the restart.

**Fix:** `broker/state.go` — `savedState.GuestRooms` persists the mapping
in `state_dir/client-state.json`. Load and save are wired in `loadCompat` /
`saveCompat`.

**Files:** `broker/state.go` (persist+load), `broker/receipts_test.go` (new test)

---

### D — Allowlist host:port accepted (`example.com:443`, `example.com:80`)
**Root cause:** Both `cathedral/sandbox_api.py` (`normalize_allow_entry`) and
`room-kit/room_egress.py` (`classify`) rejected any entry with a colon,
including `hostname:443`. This contradicted the published docs.

**Fix:**
- `hostname:80` and `hostname:443` are now accepted and normalized to the
  bare hostname (the egress proxy only offers those ports anyway).
- `hostname:<other>` → **400** `invalid_network_allowlist` with message:
  *named hosts only allow TCP 80 and 443*.
- `ip:port` (e.g. `1.2.3.4:443`) → **400** `invalid_network_allowlist` —
  use the bare IP for all-ports access.
- Inline `import ipaddress` and `import json` inside functions were moved
  to module-level imports (workspace no-inline-imports rule).

**Files:** `cathedral/sandbox_api.py`, `room-kit/room_egress.py`,
`tests/test_sandbox_api.py` (new tests)

---

### E — Exec `cmd` must be a list of strings
**Root cause:** `compatExecBody` in `broker/compat.go` already validated that
`cmd` / `command` is a non-empty list of strings and returned 400 `invalid_exec`
for a string value. The existing test in `broker/harbor_test.go` was sending
`"command": "true"` (a string) and expecting 200 — the test was stale and
would have failed.

**Fix:** Updated `harbor_test.go` to:
1. Assert that a string `cmd` returns 400 `invalid_exec`.
2. Use `"cmd": ["true"]` (a list) for the timeout test that follows.

**Files:** `broker/harbor_test.go`

---

### F — Docs: CUSTOMER_SANDBOX_ACCESS
**Created:** `docs/CUSTOMER_SANDBOX_ACCESS_2026-10-21.md`

Covers:
- Hotel selection fields and error codes (409 for unknown hotel)
- Capacity error matrix (503 hotels_unavailable vs 429 no_free_rooms)
- Allowlist entry types including `hostname:80/443` and IP:port guidance
- Missing network field defaults to `internet` on compat path
- Exec `cmd` must be a list
- gVisor (standard room) vs AMD SEV-SNP TEE (sealed room) isolation
- Receipt chain filtering and persistence

---

### G — broker/README.md aligned
`broker/README.md` updated:
- Hotel selection table: 400 → 409 for `unknown_hotel`
- Scatter row: added 503 `hotels_unavailable` for down hotels
- Client exec section: documented `cmd` as list, truncation behaviour,
  and `guestRooms` persistence

---

## Out of scope — ops follow-up required

### Green hotel hardware
The `green` hotel reported in Customer ticket #1 is **down at the hardware
level**. No code fix addresses this.

**Action required (ops):** Restore or replace the `green` hotel hardware /
VM and re-add it to the broker config. Until then, any create that names
`hotels: ["green"]` will correctly return 503 `hotels_unavailable` (not
the misleading 429 "all hotels are full" that was returned before the code
fix above).

---

## How to test

```bash
# Go tests (broker)
cd broker
go test ./...

# Python tests (sandbox API + egress)
cd ..
python -m pytest tests/test_sandbox_api.py -v
```

# Partner self-serve gap map

How a partner gets onto the sandbox broker today, and what the console must
call so Cathedral does not do it by hand. Start with Ditto (SN118). The run
path is already live: create, exec and delete on live.cathedral.computer pass
with an existing partner key on the sealed AMD SEV-SNP pool (three sealed
hotels), Reliquary and the standard pool. The gap is onboarding and
provisioning, not admission or attestation.

This repository is the broker (`broker/`). Guests (customers) and their API
keys live here. The customer console and the Polaris API live elsewhere
(cathedral.computer and, likely, a private polariscomputer repo). Those
repos were read only; this repo does not edit them.

Live already has a config-file guest named `ditto`. `POST /v1/broker/guests`
with that same id returns 409 until that row is removed from the private
config. New Ditto endpoints should use a new id (`ditto` on a fresh broker,
or `ditto-<account>` per signed-in partner). Do not restart the live broker
to try this.

Draft PR #297 (`feature/broker-runtime-guests`) added a similar POST on an
older main and is stale (no guest policy). This document describes the
current-main route.

## Ditto, in full

### What Cathedral does by hand today

1. Guest row. An operator edits the private broker config
   (`/etc/thin-broker/config.json`, not in git) and adds a `guests[]` object
   with `"id": "ditto"`. The loader is `loadBroker` in
   `broker/main.go:266` and the guest loop is `broker/main.go:299-321`. The
   shape is `guestConfig` at `broker/main.go:69-75` and the example is
   `broker/config.example.json:7-10`. There is no reload: a config-file
   guest needs a broker restart. Until this change there was no create
   route, only `GET` and `PATCH` (`broker/guests.go:198-222`).
2. Key issue. The operator generates a random API key, SHA-256 hashes it,
   and writes the 64 hex digits into `key_sha256`. The broker stores hashes
   only (`broker/main.go:10-11`). Auth is `guestFromKey` at
   `broker/main.go:508-513`: Bearer token, SHA-256, map lookup. The
   plaintext key is sent to Ditto by hand. An optional view token is hashed
   into `view_token_sha256` for `/ditto/live` (`broker/main.go:1643-1655`,
   sign-in `broker/main.go:1675-1694`). The broker never returns a
   plaintext guest key.
3. Pool and routing. Ditto is pinned to the sealed AMD SEV-SNP pool. In
   config that is `"default_sealed": true` and/or a `hotels` id list, or a
   `policy` that prefers the sealed class. Placement applies those limits in
   `scope` (`broker/guests.go:157`) and `admit` (`broker/guests.go:107`).
   Policy selectors live in `broker/capacity.go:1-25` and
   `guestPolicy.validate` at `broker/capacity.go:132`. A hotel can also be
   reserved for one guest with `"reserved_for"` (`broker/hotels.go:7-8`,
   `PATCH` at `broker/hotels.go:341`). Ditto today uses the shared sealed
   pool (three sealed hotels), not a reserved hotel.
4. Quotas. Broker: `max_rooms` (absent or 0 means 1,000) and
   `max_creates_per_minute` (`guestLimits` in `broker/guests.go:47-56`).
   Ditto's documented concurrent slot contract is 2 to 8 rooms
   (`cathedral/ditto_profile.py:10-13`, default 8). The guest sees the cap
   on `GET /v1/quota` (`broker/main.go:1371-1402`). `PATCH /v1/broker/guests/<id>`
   can change limits (`broker/guests.go:224`) but a change on a config-file
   guest dies on restart. Hotel-side env `CATHEDRAL_SANDBOX_KEYS` /
   `CATHEDRAL_KEY_QUOTAS` (`cathedral/ditto_profile.py:18-34`) is the
   single-hotel key table used in tests and a direct hotel boot. On the
   live broker path the hotel sees the broker's hotel key, not the guest
   key, so those env vars are not the Ditto live credential.
5. Billing and metering. The broker has no ledger. `GET /v1/usage`
   (`broker/main.go:1405-1409`) merges per-hotel usage for that guest
   label. Console prepaid credit is `GET/POST` on cathedral.computer
   `/v1/credits` and `/v1/account` (public docs:
   cathedral.computer/docs/keys). Ditto on the broker is not billed
   through that console path today. Product-run receipts
   (`cathedral/product_run_receipt.py`, builders
   `build_ditto_execution` / `build_ditto_evidence`) record a harness
   slot; they are not a bill.
6. Console listing. https://cathedral.computer/integrations/ names Ditto
   ("guest ditto, /v1/sandboxes and /ditto/live") with no console button.
   Console keys (`cat_sk_*` from `/v1/keys` or `POST /v1/cli/login/*`)
   open sealed workers on cathedral.computer (`POST /v1/workers`). They
   are a different identity from a broker guest key. A Ditto partner
   cannot mint a broker guest from the Keys page.

### What this repo now exposes

Operator key (`operator_key_sha256`, compared in `isOperator` at
`broker/hotels.go:163`). Never a guest key. Never `ops`.

```
POST /v1/broker/guests
Authorization: Bearer <operator key>
{
  "id": "ditto",
  "key_sha256": "<sha256 hex of the guest key>",
  "view_token_sha256": "<sha256 hex of the view token, optional>",
  "max_rooms": 8,
  "default_sealed": true,
  "policy": {"prefer": [{"class": "sealed"}]}
}
```

Handler: `addGuest` at `broker/guests.go:314`. Persist:
`state_dir/guests.json` (mode 0600, hashes only) via
`saveRuntimeGuestsLocked` (`broker/guests.go:442`) and
`loadRuntimeGuests` (`broker/guests.go:469`, called from
`broker/main.go:1960`). Fail closed:

- no `state_dir`: 409 `no_state_dir`
- guest key or unknown field (including `"ops": true`): 400
- plaintext key in `key_sha256`: 400 `invalid_key_sha256` (must be 64 hex)
- no `hotels` and no `policy`: 400 `missing_scope` (a runtime guest does
  not get every hotel)
- unknown hotel id: 409 `unknown_hotel`
- duplicate id: 409 `guest_exists`
- reused hash or the operator hash: 409 `key_in_use`
- config-file guest with the same id or key wins on load
- `DELETE` of a config-file guest: 409 `config_guest`
- `DELETE` while rooms are up: 409 `guest_has_rooms`

Admission and attestation are unchanged.

### Console route and API the partner should hit

The partner never holds the operator key. The console (or the Cathedral
API in front of the broker) does.

1. Sign in. Existing person flow: Google or email session, or device
   login `POST /v1/cli/login/start` then `POST /v1/cli/login/poll`, then
   `GET /v1/account` (cathedral.computer/docs/keys). Route to add the
   button: `/integrations/` (Ditto card) and a Ditto page such as
   `/integrations/ditto` or `/console/integrations/ditto`.
2. Create endpoint. New Cathedral/Polaris route, session or `cat_sk_*`
   with a new scope (suggested `integrations:ditto`), for example
   `POST /v1/integrations/ditto/endpoint`. Server generates a guest key
   and an optional view token, hashes both, and calls the broker POST
   above. Return the plaintext key and view token once. Do not log them.
   Do not put the operator key in the browser or in this repository.
3. Run. Partner calls `https://live.cathedral.computer/v1/sandboxes`
   with `Authorization: Bearer <guest key>`, same create body as today
   (`cathedral/ditto_profile.py:44-61`: deny-all / `network.mode=none`,
   1/2/10, TTL 600). Live board: `https://live.cathedral.computer/ditto/live`
   with the view token.
4. Limits later. Console can `PATCH` through the same operator proxy:
   `PATCH /v1/broker/guests/<id>` (`broker/guests.go:224`). Runtime
   patches now persist.

`bigailabs/polariscomputer` returned 404 to read-only `gh` (private or
renamed). `cathedralai/cathedral` is the SN39 / sandbox-models tree; it
has `scaffold/polaris.py` (`/api/keys/whoami`, `/v1/attest`,
`/api/billing/ledger`) which is the old attest/billing seam, not broker
guests, and it has no integrations page. The follow-up belongs in
whichever private repo serves cathedral.computer and proxies the broker.

## Other partners (one line each)

| Partner | Manual steps today | Self-serve target |
|---|---|---|
| Affine | No broker guest of its own. Harbor on live.cathedral.computer; attested rollouts. Pilot hosts recovering. Affine claims stay in `cathedral/affine_claim.py`. | Same guest POST if Affine needs its own id; console button on `/integrations/` (Affine card) calling `POST /v1/integrations/affine/endpoint` that wraps `POST /v1/broker/guests` with a sealed-prefer policy. Do not fold Affine skip-rerun into this path. |
| Reliquary | Own dedicated sealed guest and machine, key issued by hand, same config-file guest row as Ditto. Live create/run/delete already pass. | Same `POST /v1/broker/guests` plus `PATCH /v1/broker/hotels/<id>` `reserved_for` (`broker/hotels.go:341`) for the dedicated hotel. Console: `/integrations/` Reliquary card. |
| Agent IDE | Still on staging. Someone else is moving it. Do not touch. | Leave staging and this broker change alone. |
| Claims | No endpoint. Integrations page says observe live; job pay is not wired. Capacity broker and job-reward path only. | First need an endpoint on cathedral.computer (not this repo). Then the same guest POST if Claims will create rooms. |
| Gittensor | Challenge-runs on sealed capacity, arranged beside public Escape Room Open. `POST /v1/challenge-runs` on cathedral.computer, not `/v1/sandboxes`. | Console already has challenge-runs. A broker guest is only needed if Gittensor starts calling the room API directly. |

## Follow-up outside this repository

Exact proposed console/API change (do not land it here):

1. Integrations page (`https://cathedral.computer/integrations/`, docs-site
   or console app): add a "Console" button on the Ditto card that sends a
   signed-in person to `/console/integrations/ditto` (or
   `/integrations/ditto`).
2. New authenticated route on the Cathedral/Polaris API (the service that
   already holds session cookies and `/v1/keys`), suggested
   `POST /v1/integrations/ditto/endpoint`:
   - Require a signed-in account (session or `cat_sk_*` with
     `integrations:ditto`).
   - Generate a guest key and optional view token in process.
   - `POST https://live.cathedral.computer/v1/broker/guests` with the
     operator key from the API host secret store (not the repo, not the
     browser) and the Ditto body in the section above. Use a new guest id
     if `ditto` already exists in the live config.
   - Reply once with `{ "guest_id", "key", "view_token", "api_base":
     "https://live.cathedral.computer" }`.
   - File guess if the console is a Rails/Polaris app: a new controller
     next to the existing keys controller that implements `POST /v1/keys`
     (public docs: cathedral.computer/docs/keys). If it is the
     cathedral.computer workers API, sit it next to `/v1/keys` and
     `/v1/cli/login/*`. `cathedralai/cathedral` is the wrong tree
     (`scaffold/polaris.py:52-57` is `/api/keys/whoami` for attest, not
     this).
3. Do not reuse `POST /v1/keys`. Those keys are `cat_sk_*` for
   `POST /v1/workers` on cathedral.computer, not broker guests.
4. Billing (later): debit `/v1/credits` when a Ditto room runs, using
   `GET /v1/usage` on the broker as the meter. Not required to provision.
5. Affine, Reliquary, Claims, Gittensor: see the table. Agent IDE: no
   change.

## Out of scope here

- Admission, attestation, AMD chain, hotel join.
- Live deploy, config edits on the broker host, merging.
- Agent IDE.
- Opening a PR on polariscomputer or cathedralai/cathedral.

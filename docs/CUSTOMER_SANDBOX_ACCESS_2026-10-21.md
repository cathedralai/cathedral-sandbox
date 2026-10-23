# Customer Sandbox Access — API Reference (2026-10-21)

> **Status:** current as of the Customer feedback fixes committed 2026-10-23.
> See `docs/evidence/CUSTOMER_FEEDBACK_FIXES_2026-10-23.md` for the change log.

---

## Hotel selection (`"hotels"`, `"hotel_labels"`, `"exclude_hotel_labels"`)

| Field | Meaning |
|---|---|
| `"hotels": ["a", "b"]` | Restrict to these hotel ids. An unknown id returns **409** `unknown_hotel`. |
| `"hotel_labels": {"sealed": "true"}` | Only hotels with every listed label pair. |
| `"exclude_hotel_labels": {"sealed": "true"}` | Exclude any hotel with any listed label pair. |

When no hotel matches the selection, the broker returns **409** `no_matching_hotel`.
A sealed hotel takes a create that says `"sealed": true`, a create from a
guest whose `default_sealed` is on, or a create that names it in `"hotels"`.
A plain create from a guest whose only hotel is sealed gets
`no_matching_hotel`. On the Harbor/ctcli path `hotels`, `hotel_labels` and
`exclude_hotel_labels` are not read; your hotel list and sealed default apply.

### Capacity errors

| Condition | HTTP | Error code |
|---|---|---|
| All matching hotels down or draining | **503** | `hotels_unavailable` |
| Mix of down + full (no free room anywhere) | **503** | `hotels_unavailable` |
| All matching hotels up but all rooms full | **429** | `no_free_rooms` |

`503 hotels_unavailable` always carries `Retry-After: 5`.
**A down hotel is not reported as "all hotels are full"** — use the code to
distinguish transient infrastructure issues from genuine capacity exhaustion.

---

## Network allowlist entries

Allowlist entries in `"network": {"mode": "allowlist", "allow": [...]}` can be:

| Entry type | Example | Behavior |
|---|---|---|
| Hostname | `"pypi.org"` | Reachable on TCP 80 and 443 via egress proxy |
| Hostname with port | `"pypi.org:443"` or `"pypi.org:80"` | Normalized to bare hostname; same as above (so `:443` also opens 80) |
| Wildcard hostname | `"*.pythonhosted.org"` | All subdomains, TCP 80 and 443 only |
| IPv4 address | `"1.2.3.4"` | Reachable on **all ports** directly (nftables) |
| IPv4 CIDR | `"140.82.112.0/20"` | All addresses in the range, all ports |

**Important constraints:**
- Only ports 80 and 443 are available for named hosts (the egress proxy
  intercepts these; other ports are dropped).
- `"hostname:8080"` (non-80/443 port) → **400** `invalid_network_allowlist`
  with message: *named hosts only allow TCP 80 and 443*.
- `"1.2.3.4:443"` → **400** `invalid_network_allowlist` — use the bare IP
  `"1.2.3.4"` (which allows all ports).
- IPv6 is **not** supported.
- Private, host and reserved ranges (`10/8`, `172.16/12`, `192.168/16`,
  `100.64/10`, `169.254/16`, `127/8`, `0.0.0.0/8`, multicast) are refused with
  **400** `invalid_network_allowlist`; the host firewall drops them anyway.
- `"internet"` mode gives egress to public addresses; private ranges,
  link-local (cloud metadata) and the host are always dropped. `"deny_all"`
  blocks all egress. A room's policy can be changed live with
  `PUT /v1/sandboxes/<id>/network`; the body must name the `mode`. A room
  created with network `none` has no interface and answers **409**
  `network_not_switchable`; a frozen room answers **409** `sandbox_frozen`.

### Missing `"network"` field

If the create request omits the `"network"` field entirely on the
compatibility (Harbor/ctcli) path, the broker defaults to `"internet"` mode.
For security-sensitive workloads, **always specify** `"network": "deny_all"`
or `"network": "allowlist"` explicitly.

---

## Exec (`POST /v1/sandboxes/<id>/exec`)

Send a non-empty JSON array of strings:

```json
{"cmd": ["/bin/sh", "-c", "echo hello"], "timeout_seconds": 30}
```

- Native `/v1` API: the field is `cmd`. A string value runs through
  `sh -c`; `command` alone is **400** (`cmd is required`).
- Harbor/ctcli path: `cmd` or the alias `command`, list only; a string value
  is **400** `invalid_exec`.
- Exec output is capped at 16 MiB per stream while it is read; the response
  then carries `"truncated": true`. Output that is not UTF-8 is returned
  with replacement characters.
- An entrypoint, user or workdir the image does not have is **400**
  (`invalid_entrypoint`, `invalid_user`, `invalid_workdir`); an entrypoint
  that ends at once is **400** `entrypoint_exited`.

---

## Files (`/v1/sandboxes/<id>/files`, `/tar`, `/stat`)

The native `/v1` files API reaches **`/work` only**, the directory shared
with the room. A path outside `/work` returns **400** `path_outside_work`.
To place a file elsewhere in the room, write it under `/work` and move it
with an exec. Snapshots and forks keep `/work` and the room's own
filesystem. Bodies over 256 MiB are **413** `request_too_large`.

On the Harbor/ctcli path, files, tar and stat run as commands inside the
room: any path works, a PUT takes up to 64 MiB, and a GET over about 12 MiB
is **413** `file_too_large`.

---

## Room isolation: gVisor vs sealed TEE

The broker serves two kinds of hotel:

| Type | Isolation | Notes |
|---|---|---|
| Standard room | **gVisor** (`runsc`) kernel intercept | Protects the hotel host from room workloads; the hotel operator can read room memory. |
| Sealed room | **AMD SEV-SNP** hardware TEE (VM) | The host cannot read the guest's memory or its disk. The attestation binds the receipt key to the measured guest. The operator still holds the hotel API key, so it can call the API like the broker does; a create, exec, process start, network change or delete made that way gets a signed receipt, a file read or write does not. Today the API traffic between the broker and the guest is plain HTTP on the host's link. Use `"sealed": true` or `hotel_labels: {"sealed": "true"}`. |

Sealed hotels are identified by the `sealed: true` label in
`GET /v1/broker/hotels`. A guest's sealed default can be set by the broker
operator via `PATCH /v1/broker/guests/<id>` (`"default_sealed": true`).

---

## Receipt chain (`GET /v1/hotels/<id>/receipts`)

Receipts come from hotels installed with the receipts front: every sealed
hotel, and an unsealed hotel installed with receipts on (the kit's default
is on; the shared hotels run without). A hotel without one answers `404
not_found` on this route, and rooms there get no `X-Room-Receipt` header.
Ask which of your hotels carry receipts. The header comes back on create,
exec, process start, network change and delete; a batch create returns
none (fetch them from the chain).

The receipt chain is **per-hotel, per-boot**. After a broker restart, the
guest→room mapping is **persisted** in `state_dir/client-state.json`, so
`GET /v1/hotels/<id>/receipts` continues to filter correctly (only the
calling guest's own rooms are returned). Without `state_dir`, the filter is
memory-only and resets on restart.

An ops key (`"ops": true` in the guest config) receives the raw, unfiltered
chain.

A guest's chain is marked `"filtered": true`: it holds only that guest's
receipts, so it has gaps. `verify_receipts.py --broker ... --key-file ...`
checks each receipt's signature and attestation binding; the full-chain
checks (no gaps, ends at `head`) apply only to an unfiltered chain.
`--hotel <id>` is required with `--broker`. Add `--require-sealed` (or
`--expected-measurement`) so a level 1, unsealed binding fails instead of
passing as a lesser proof.
Each receipt proves itself: its signature, its link to the receipt before it
and its binding to the attestation. A chain does not prove that nothing was
left out, filtered or not, because `head` is not signed. To check the
receipts of one room, use `--sandbox <id>`.

---

## Error codes quick reference

| Code | HTTP | Meaning |
|---|---|---|
| `unknown_hotel` | 409 | Hotel id in `"hotels"` does not exist or is outside the guest's allowed set |
| `no_matching_hotel` | 409 | No hotel matches `hotel_labels` / `exclude_hotel_labels` |
| `hotels_unavailable` | 503 | All matching hotels are down or draining |
| `no_free_rooms` | 429 | All matching hotels are up but all rooms are occupied |
| `snapshot_hotel_unavailable` | 503 | The hotel that holds the fork's snapshot is down |
| `snapshot_hotel_excluded` | 409 | The fork's snapshot hotel does not match the hotel selection |
| `invalid_network_allowlist` | 400 | An allowlist entry is invalid (see above) |
| `invalid_exec` | 400 | `cmd` is missing, empty, or not a list of strings |
| `path_outside_work` | 400 | A files, tar or stat path is not under `/work` |
| `invalid_network_mode` | 400 | A network change has no `mode` |
| `room_limit` | 429 | Guest has reached its `max_rooms` limit |
| `create_rate_limit` | 429 | Guest has exceeded `max_creates_per_minute` |
| `create_rate_exceeded`, `quota_exhausted`, `key_subquota_exhausted` | 429 | The hotel itself is at a limit; retry after `Retry-After` |
| `invalid_request` | 400 | A field has the wrong shape (an unknown key in `image`, a number for `entrypoint`, nesting past the parser) |
| `invalid_entrypoint`, `invalid_user`, `invalid_workdir`, `entrypoint_exited` | 400 | The image cannot start as asked |
| `sandbox_frozen` | 409 | The room is frozen; thaw it first |
| `network_not_switchable` | 409 | The room was created with network `none` |
| `request_too_large` | 413 | A body over 256 MiB |
| `build_context_too_large` | 413 | A build context over 256 MiB (1 GiB expanded) |
| `file_too_large` | 413 | A Harbor/ctcli file or tar over the exec output limit |
| `internal_error` | 500 | The hotel could not handle the request; the connection is answered, not dropped |

Harbor/ctcli clients get errors in the envelope `{"detail": {"error": <code>, "message": ...}}`.

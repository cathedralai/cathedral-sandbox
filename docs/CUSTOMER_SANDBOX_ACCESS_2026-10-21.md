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
A sealed hotel takes only sealed creates: send `"sealed": true`, or ask the
operator to set your `default_sealed`. Without it, a guest whose only hotel is
sealed gets `no_matching_hotel`.

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
| IPv4 CIDR | `"10.0.0.0/8"` | All addresses in the range, all ports |

**Important constraints:**
- Only ports 80 and 443 are available for named hosts (the egress proxy
  intercepts these; other ports are dropped).
- `"hostname:8080"` (non-80/443 port) → **400** `invalid_network_allowlist`
  with message: *named hosts only allow TCP 80 and 443*.
- `"1.2.3.4:443"` → **400** `invalid_network_allowlist` — use the bare IP
  `"1.2.3.4"` (which allows all ports).
- IPv6 is **not** supported.
- `"internet"` mode gives full egress. `"deny_all"` blocks all egress.
  A room's policy can be changed live with `PUT /v1/sandboxes/<id>/network`.

### Missing `"network"` field

If the create request omits the `"network"` field entirely on the
compatibility (Harbor/ctcli) path, the broker defaults to `"internet"` mode.
For security-sensitive workloads, **always specify** `"network": "deny_all"`
or `"network": "allowlist"` explicitly.

---

## Exec (`POST /v1/sandboxes/<id>/exec`)

The exec body field is **`cmd`** (or the alias `command`). It **must** be a
non-empty JSON array of strings:

```json
{"cmd": ["/bin/sh", "-c", "echo hello"], "timeout_seconds": 30}
```

- A string value for `cmd` (e.g. `"cmd": "echo hello"`) returns **400**
  `invalid_exec`. This was previously silently accepted on some paths;
  the fix was rolled out 2026-10-23.
- Large exec output is truncated by the hotel at `exec_output_limit_bytes`
  (default 16 MiB shown in `GET /v1/sandboxes/catalog`). When truncation
  occurs, the response contains `"truncated": true`.

---

## Files (`/v1/sandboxes/<id>/files`, `/tar`, `/stat`)

The files API reaches **`/work` only**, the directory shared with the room.
A path outside `/work` returns **400** `path_outside_work`. To place a file
elsewhere in the room, write it under `/work` and move it with an exec.
Snapshots and forks keep `/work` and the room's own filesystem.

---

## Room isolation: gVisor vs sealed TEE

The broker serves two kinds of hotel:

| Type | Isolation | Notes |
|---|---|---|
| Standard room | **gVisor** (`runsc`) kernel intercept | Protects the hotel host from room workloads; the hotel operator can read room memory. |
| Sealed room | **AMD SEV-SNP** hardware TEE (VM) | The host cannot read the guest's memory or its disk. The attestation binds the receipt key to the measured guest. The operator still holds the hotel API key, so it can call the API like the broker does; each such call gets a signed receipt. Today the API traffic between the broker and the guest is plain HTTP on the host's link. Use `"sealed": true` or `hotel_labels: {"sealed": "true"}`. |

Sealed hotels are identified by the `sealed: true` label in
`GET /v1/broker/hotels`. A guest's sealed default can be set by the broker
operator via `PATCH /v1/broker/guests/<id>` (`"default_sealed": true`).

---

## Receipt chain (`GET /v1/hotels/<id>/receipts`)

Receipts come from hotels installed with the receipts front: every sealed
hotel, and an unsealed hotel only when its operator turned receipts on. A
hotel without one answers `404 not_found` on this route, and rooms there get
no `X-Room-Receipt` header. Ask which of your hotels carry receipts.

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

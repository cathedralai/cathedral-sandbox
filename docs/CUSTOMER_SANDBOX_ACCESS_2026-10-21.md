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
| Hostname with port | `"pypi.org:443"` or `"pypi.org:80"` | Normalized to bare hostname; same as above |
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

## Room isolation: gVisor vs sealed TEE

The broker serves two kinds of hotel:

| Type | Isolation | Notes |
|---|---|---|
| Standard room | **gVisor** (`runsc`) kernel intercept | Protects the hotel host from room workloads; the hotel operator can read room memory. |
| Sealed room | **AMD SEV-SNP** hardware TEE (VM) | The hotel operator cannot read room memory; attestation binds the guest policy to the hardware measurement. Use `"sealed": true` or `hotel_labels: {"sealed": "true"}`. |

Sealed hotels are identified by the `sealed: true` label in
`GET /v1/broker/hotels`. A guest's sealed default can be set by the broker
operator via `PATCH /v1/broker/guests/<id>` (`"default_sealed": true`).

---

## Receipt chain (`GET /v1/hotels/<id>/receipts`)

The receipt chain is **per-hotel, per-boot**. After a broker restart, the
guest→room mapping is **persisted** in `state_dir/client-state.json`, so
`GET /v1/hotels/<id>/receipts` continues to filter correctly (only the
calling guest's own rooms are returned). Without `state_dir`, the filter is
memory-only and resets on restart.

An ops key (`"ops": true` in the guest config) receives the raw, unfiltered
chain.

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
| `room_limit` | 429 | Guest has reached its `max_rooms` limit |
| `create_rate_limit` | 429 | Guest has exceeded `max_creates_per_minute` |

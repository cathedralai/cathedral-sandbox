# TRR G4 — Sandboxes created well (n=20) — TEMPLATE

## Pass means

20 creates across hotels: time-to-ready distribution; `uname -r` is gVisor inside; `deny_all` blocks; allowlist opens only named hosts; build RUN under gVisor (`scripts/build_runtime_probe.sh`); file put/get; exec output cap.

## Environment

| Field | Value |
| --- | --- |
| UTC | |
| Broker | |
| Hotels used | |
| Ops key | |

## CSV (required)

Save as `TRR_G4_samples_<stamp>.csv`:

```csv
sample,hotel,sandbox_id,create_http,ready_s,uname_r,deny_all_ok,allowlist_ok,build_gvisor_ok,files_ok,exec_cap_ok,notes
1,,,,,,,
```

## Aggregate

| Metric | Value |
| --- | --- |
| n | 20 |
| ready_s p50 / p95 / max | |
| uname gVisor count | |
| deny_all pass count | |
| allowlist pass count | |
| build under gVisor pass | |

## Verdict

| Pass? | YES / NO / BLOCKED |
| --- | --- |
| Blocker | |

# CONST Harbor non-sealed smoke — 20261023T155858Z

Base `https://live.cathedral.computer` guest `const` (trial key). Prefer **nc** then **c46**; avoid nc-sealed / green.

## quota
{"guest":{"allowed_hotels":["nc","c46","c48","nc-sealed"],"default_sealed":true,"id":"const","max_creates_per_minute":600,"max_rooms":1000,"running_sandboxes":0},"hotels":{"c46":{"limits":{"memory_gib":2800,"running_sandboxes":700,"vcpu":700},"usage":{"deleting_sandboxes":0,"frozen_sandboxes":0,"memory_gib":0,"resident_sandboxes":0,"running_sandboxes":0,"vcpu":0}},"c48":{"limits":{"memory_gib":1200,"running_sandboxes":300,"vcpu":300},"usage":{"deleting_sandboxes":0,"frozen_sandboxes":0,"memory_gib":0,"resident_sandboxes":0,"running_sandboxes":0,"vcpu":0}},"green":"unavailable","nc":{"limits":{"memory_gib":5236,"running_sandboxes":1309,"vcpu":1309},"usage":{"deleting_sandboxes":0,"frozen_sandboxes":0,"memory_gib":0,"resident_sandboxes":0,"running_sandboxes":0,"vcpu":0}},"nc-sealed":{"limits":{"memory_gib":4000,"running_sandboxes":1000,"vcpu":1000},"usage":{"deleting_sandboxes":0,"frozen_sandboxes":0,"memory_gib":0,"resident_sandboxes":0,"running_sandboxes":0,"vcpu":0}}},"limits":{"memory_gib":13236,"running_sandboxes":3309,"vcpu":3309},"usage":{"deleting_sandboxes":0,"frozen_sandboxes":0,"memory_gib":0,"resident_sandboxes":0,"running_sandboxes":0,"vcpu":0}}

## hotels
{"hotels":[{"drain":false,"free_rooms":700,"id":"nc","labels":{},"name":"New Cherry","up":true},{"drain":false,"free_rooms":700,"id":"c46","labels":{},"name":"Cherry 46","up":true},{"drain":false,"free_rooms":300,"id":"c48","labels":{},"name":"Cherry 48","up":true},{"drain":false,"free_rooms":1000,"id":"nc-sealed","labels":{"sealed":"true"},"name":"nc-sealed (SEV-SNP)","up":true}]}

## hotel=nc
create HTTP=202
```json
{"created_at":"2026-10-23T15:59:01.169252+00:00","env_keys":[],"expires_at":"2026-10-23T16:59:01.169252+00:00","guest":{"allowlist_fail_closed":false,"container_id":"d76a57ae036f2bc85b2222eb79d2d4700829e410806525d8d3743aa1244825a0","dind":false,"image":"alpine:3.20","network_enforced":true,"network_mode":"deny_all","network_name":"room-nc-net-0","network_switchable":true},"hotel":"nc","id":"nc.sbx_9c6037748a1e","idle_timeout_seconds":null,"image_id":"img_dc2520579e9b","labels":{"broker_guest":"const","customer":"const","smoke":"nonsealed-20261023T155858Z"},"metrics":{"cpu_seconds":0,"deleted_at":null,"disk_bytes":0,"memory_peak_bytes":0,"network_bytes":0,"started_at":"2026-10-23T15:59:01.169252+00:00"},"network":{"allow":[],"enforced_by":"hotel_egress","mode":"deny_all","policy":{"allow":[],"mode":"deny_all"},"policy_sha256":"b1dad3cb08025f5fd7a1c2419631a24729952344bc0d9cc898afa04e92415f68"},"resources":{"disk_gib":10,"memory_gib":4,"vcpu":1},"runtime":"docker","snapshot_id":null,"state":"running","ttl_seconds":3600}
```
poll 1 state=running
exec HTTP=200
```json
{"exit_code": 0, "stdout": "CONST_NS_OK
Linux
", "stderr": "", "duration_ms": 60, "timed_out": false, "truncated": false}
```
deleted nc.sbx_9c6037748a1e


## Verdict

**GREEN** — create→exec→delete on `nc` (non-sealed, `deny_all`). Hotels nc/c46/c48/nc-sealed up; green not in const allowlist this key.

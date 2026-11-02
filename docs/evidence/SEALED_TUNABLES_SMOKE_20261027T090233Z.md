# Sealed tunables smoke — 20261027T090233Z

- Broker: `https://live.cathedral.computer`
- Guest: polaris-sealed
- Expect: create with per-room tunables → status applied → exec → delete

## 1. Create with tunables
```json
{
    "image": "alpine:3.20",
    "sealed": true,
    "network": {
        "mode": "deny_all"
    },
    "tunables": {
        "schema": 1,
        "runsc": {
            "directfs": false,
            "overlay2": "all:self"
        }
    },
    "labels": {
        "smoke": "tunables",
        "job": "tunables-smoke-20261027T090233Z"
    }
}
```
- HTTP 202
```json
{
    "created_at": "2026-10-27T09:02:34.391441+00:00",
    "env_keys": [],
    "expires_at": "2026-10-27T10:02:34.391441+00:00",
    "guest": {
        "allowlist_fail_closed": false,
        "container_id": "d6f6056bd876dc002f4b888faaf3562b025ed7dbf941fa7752a01415601ebacf",
        "dind": false,
        "image": "alpine:3.20",
        "network_enforced": true,
        "network_mode": "deny_all",
        "network_name": "room-sealed-net-1",
        "network_switchable": true
    },
    "hotel": "c46-sealed",
    "id": "c46-sealed.sbx_cb4810fee7f2",
    "idle_timeout_seconds": null,
    "image_id": "img_49c8176e980c",
    "isolation": {
        "attestation_of_host": "/v1/hotels/c46-sealed/attestation",
        "attested_per_room": false,
        "hotel_sealed": true,
        "hotel_tee": "amd_sev_snp",
        "network_mode": "deny_all",
        "room_runtime": "docker"
    },
    "labels": {
        "broker_batch": "f7e776ca-3b5b-4f09-9ef8-b8fb0e1327f9",
        "broker_guest": "polaris-sealed",
        "job": "tunables-smoke-20261027T090233Z",
        "smoke": "tunables"
    },
    "metrics": {
        "cpu_seconds": 0,
        "deleted_at": null,
        "disk_bytes": 0,
        "memory_peak_bytes": 0,
        "network_bytes": 0,
        "started_at": "2026-10-27T09:02:34.391441+00:00"
    },
    "network": {
        "allow": [],
        "enforced_by": "hotel_egress",
        "mode": "deny_all",
        "policy": {
            "allow": [],
            "mode": "deny_all"
        },
        "policy_sha256": "b1dad3cb08025f5fd7a1c2419631a24729952344bc0d9cc898afa04e92415f68"
    },
    "placement_tier": "prefer",
    "resources": {
        "disk_gib": 10,
        "memory_gib": 4,
        "vcpu": 1
    },
    "runtime": "docker",
    "snapshot_id": null,
    "state": "running",
    "ttl_seconds": 3600,
    "tunables": {
        "image_prime": "none",
        "log_driver": "json-file",
        "runtime": "runsc-tun-d0-all-n1",
        "runtime_args": [
            "--platform=systrap",
            "--net-raw",
            "--directfs=false",
            "--overlay2=all:self",
            "--num-network-channels=1"
        ],
        "schema": "cathedral_room_tunables_v1",
        "sha256": "fa296c27f42f2394d8c5c249615251d9cebeb1405c902931e52cd00dd28b7d22",
        "status": "applied",
        "values": {
            "boot": {
                "create_concurrency": 1
            },
            "docker": {
                "log_driver": "json-file"
            },
            "image": {
                "prime": "none"
            },
            "pool": {
                "idle_seconds": 300,
                "refill_parallelism": 1,
                "warm_size": 0
            },
            "runsc": {
                "directfs": false,
                "net_channels": 1,
                "overlay2": "all:self"
            },
            "schema": 1
        }
    }
}
```
- id=`c46-sealed.sbx_cb4810fee7f2` hotel=`c46-sealed` sealed=True
- tunables.status=applied runtime=runsc-tun-d0-all-n1 sha=fa296c27f42f2394d8c5c249615251d9cebeb1405c902931e52cd00dd28b7d22

## 2. State `running`

## 3. Exec
- HTTP 200
{
    "exit_code": 0,
    "stdout": "tunables-smoke-ok\n",
    "stderr": "",
    "duration_ms": 64,
    "timed_out": false,
    "truncated": false
}

## 4. Delete
- HTTP 204

## Verdict: **PASS** tunables applied on sealed hotel

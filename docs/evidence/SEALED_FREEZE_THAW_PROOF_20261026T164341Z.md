# Sealed hotel freeze/thaw proof — 20261026T164341Z

- Broker: `https://live.cathedral.computer`
- Guest: broker-picked sealed hotel (no manual hotel pin)
- Expect: create sealed → freeze → thaw → exec → delete

## 0. Hotels
```json
{
    "hotels": [
        {
            "down_since": "2026-10-26T14:16:05Z",
            "drain": true,
            "free_rooms": 0,
            "id": "nc-sealed-2",
            "labels": {
                "sealed": "true"
            },
            "name": "nc-sealed-2 (SEV-SNP, Reliquary)",
            "up": false
        },
        {
            "down_since": null,
            "drain": false,
            "free_rooms": 480,
            "id": "c46-sealed",
            "labels": {
                "sealed": "true"
            },
            "name": "c46-sealed (SEV-SNP, Reliquary)",
            "up": true
        }
    ]
}
```

## 1. Create (sealed)
- HTTP 202
```json
{
    "created_at": "2026-10-26T16:43:42.303339+00:00",
    "env_keys": [],
    "expires_at": "2026-10-26T17:43:42.303339+00:00",
    "guest": {
        "allowlist_fail_closed": false,
        "container_id": "0525d5a348bb5d9966403b00b4209bba1cd047d6e0045e1a23d96bef1fd73244",
        "dind": false,
        "image": "alpine:3.20",
        "network_enforced": true,
        "network_mode": "deny_all",
        "network_name": "room-sealed-net-0",
        "network_switchable": true
    },
    "hotel": "c46-sealed",
    "id": "c46-sealed.sbx_e6a1abd124e3",
    "idle_timeout_seconds": null,
    "image_id": "img_5cccf0e29c1e",
    "isolation": {
        "attestation_of_host": "/v1/hotels/c46-sealed/attestation",
        "attested_per_room": false,
        "hotel_sealed": true,
        "hotel_tee": "amd_sev_snp",
        "network_mode": "deny_all",
        "room_runtime": "docker"
    },
    "labels": {
        "broker_batch": "7a38e9e3-4017-460b-8cbc-78a380f8e4c0",
        "broker_guest": "polaris-sealed",
        "job": "freeze-thaw-proof-20261026T164341Z",
        "smoke": "freeze-thaw"
    },
    "metrics": {
        "cpu_seconds": 0,
        "deleted_at": null,
        "disk_bytes": 0,
        "memory_peak_bytes": 0,
        "network_bytes": 0,
        "started_at": "2026-10-26T16:43:42.303339+00:00"
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
    "resources": {
        "disk_gib": 10,
        "memory_gib": 4,
        "vcpu": 1
    },
    "runtime": "docker",
    "snapshot_id": null,
    "state": "running",
    "ttl_seconds": 3600
}
```
- sandbox_id: `c46-sealed.sbx_e6a1abd124e3`
- hotel (broker picked): `c46-sealed`

## 2. State before freeze: `running`

## 3. Freeze
- HTTP 200
```json
{
    "id": "c46-sealed.sbx_e6a1abd124e3",
    "state": "frozen",
    "image_id": "img_5cccf0e29c1e",
    "snapshot_id": null,
    "created_at": "2026-10-26T16:43:42.303339+00:00",
    "expires_at": "2026-10-26T17:43:42.303339+00:00",
    "ttl_seconds": 3600,
    "idle_timeout_seconds": null,
    "resources": {
        "vcpu": 1,
        "memory_gib": 4,
        "disk_gib": 10
    },
    "network": {
        "mode": "deny_all",
        "allow": []
    },
    "labels": {
        "broker_batch": "7a38e9e3-4017-460b-8cbc-78a380f8e4c0",
        "broker_guest": "polaris-sealed",
        "job": "freeze-thaw-proof-20261026T164341Z",
        "smoke": "freeze-thaw"
    },
    "env_keys": [],
    "metrics": {
        "cpu_seconds": 0.0,
        "memory_peak_bytes": 0,
        "disk_bytes": 38,
        "network_bytes": 0,
        "started_at": "2026-10-26T16:43:42.303339+00:00",
        "deleted_at": null
    }
}
```

## 4. Thaw
- HTTP 200
```json
{
    "id": "c46-sealed.sbx_e6a1abd124e3",
    "state": "running",
    "image_id": "img_5cccf0e29c1e",
    "snapshot_id": null,
    "created_at": "2026-10-26T16:43:42.303339+00:00",
    "expires_at": "2026-10-26T17:43:42.303339+00:00",
    "ttl_seconds": 3600,
    "idle_timeout_seconds": null,
    "resources": {
        "vcpu": 1,
        "memory_gib": 4,
        "disk_gib": 10
    },
    "network": {
        "mode": "deny_all",
        "allow": []
    },
    "labels": {
        "broker_batch": "7a38e9e3-4017-460b-8cbc-78a380f8e4c0",
        "broker_guest": "polaris-sealed",
        "job": "freeze-thaw-proof-20261026T164341Z",
        "smoke": "freeze-thaw"
    },
    "env_keys": [],
    "metrics": {
        "cpu_seconds": 0.0,
        "memory_peak_bytes": 0,
        "disk_bytes": 38,
        "network_bytes": 0,
        "started_at": "2026-10-26T16:43:42.303339+00:00",
        "deleted_at": null
    }
}
```

## 5. Exec after thaw
- HTTP 200
```json
{
    "exit_code": 0,
    "stdout": "freeze-thaw-ok\nLinux 0525d5a348bb 4.19.0-gvisor #1 SMP Sun Jan 10 15:06:54 PST 2016 x86_64 Linux\n",
    "stderr": "",
    "duration_ms": 64,
    "timed_out": false,
    "truncated": false
}
```

## 6. Delete
- HTTP 204

## Verdict: **PASS** on hotel `c46-sealed` sandbox `c46-sealed.sbx_e6a1abd124e3`

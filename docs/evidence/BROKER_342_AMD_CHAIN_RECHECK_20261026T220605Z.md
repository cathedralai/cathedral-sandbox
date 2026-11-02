# Broker #342 AMD chain recheck — 20261026T220605Z

- Broker: `https://live.cathedral.computer`
- Guest: polaris-sealed
- Expect: capacity reachable; c46-sealed admitted; amd_chain present if guest/operator view exposes it; pending_admission 0; nc-sealed hidden

## 1. GET /v1/broker/capacity
```json
{
    "classes": {
        "sealed": {
            "hotels": 2,
            "joined": 0,
            "up": 1,
            "placeable": 1,
            "pending_admission": 0,
            "draining": 1,
            "slots": 480,
            "free_rooms": 475
        },
        "unsealed": {
            "hotels": 0,
            "joined": 0,
            "up": 0,
            "placeable": 0,
            "pending_admission": 0,
            "draining": 0,
            "slots": 0,
            "free_rooms": 0
        }
    },
    "guest": {
        "active_rooms": 5,
        "id": "polaris-sealed",
        "max_rooms": 10,
        "policy": true
    },
    "hotels": [
        {
            "admission": {
                "amd_chain_required": false,
                "attestation_required": false,
                "state": "admitted"
            },
            "class": "sealed",
            "down_since": null,
            "drain": false,
            "free_rooms": 475,
            "id": "c46-sealed",
            "labels": {
                "sealed": "true"
            },
            "reserved_for": null,
            "slots": 480,
            "source": "broker",
            "tier": "prefer",
            "up": true
        },
        {
            "admission": {
                "amd_chain_required": false,
                "attestation_required": false,
                "state": "pending"
            },
            "class": "sealed",
            "down_since": "2026-10-26T22:03:04Z",
            "drain": true,
            "free_rooms": 0,
            "id": "nc-sealed-2",
            "labels": {
                "sealed": "true"
            },
            "reserved_for": null,
            "slots": 0,
            "source": "broker",
            "tier": "prefer",
            "up": false
        }
    ]
}
```

## 2. Parsed
- guest=polaris-sealed active=5 max=10 policy=True
- class sealed: placeable=1 pending_admission=0 up=1 free=475
- class unsealed: placeable=0 pending_admission=0 up=0 free=0
- hotel c46-sealed: up=True tier=prefer free=475 adm.state=admitted amd_chain_required=False attestation_required=False (config-file hotel: ungated by design; Spock host verifier PASS Genoa / FAIL wrong pin)
- hotel nc-sealed-2: up=False drain=True adm.state=pending
- nc-sealed hidden: OK
- sealed pending_admission=0: OK

## 3. Hotels list
```json
{
    "hotels": [
        {
            "down_since": "2026-10-26T22:03:04Z",
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
            "free_rooms": 475,
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

## 4. Smoke create sealed → delete (wall check)
- create HTTP 202
```json
{
    "created_at": "2026-10-26T22:06:07.267096+00:00",
    "env_keys": [],
    "expires_at": "2026-10-26T23:06:07.267096+00:00",
    "guest": {
        "allowlist_fail_closed": false,
        "container_id": "1cb0c88dc8228698b5c6b819f6210711df0505753701cfe0a5d081adb986ca8c",
        "dind": false,
        "image": "alpine:3.20",
        "network_enforced": true,
        "network_mode": "deny_all",
        "network_name": "room-sealed-net-1",
        "network_switchable": true
    },
    "hotel": "c46-sealed",
    "id": "c46-sealed.sbx_37823fc9ca50",
    "idle_timeout_seconds": null,
    "image_id": "img_6a481e235e4e",
    "isolation": {
        "attestation_of_host": "/v1/hotels/c46-sealed/attestation",
        "attested_per_room": false,
        "hotel_sealed": true,
        "hotel_tee": "amd_sev_snp",
        "network_mode": "deny_all",
        "room_runtime": "docker"
    },
    "labels": {
        "broker_batch": "43148977-30d8-44ee-a4f8-5bc8aa7c74ff",
        "broker_guest": "polaris-sealed",
        "job": "20261026T220605Z",
        "smoke": "amd-chain-recheck"
    },
    "metrics": {
        "cpu_seconds": 0,
        "deleted_at": null,
        "disk_bytes": 0,
        "memory_peak_bytes": 0,
        "network_bytes": 0,
        "started_at": "2026-10-26T22:06:07.267096+00:00"
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
    "ttl_seconds": 3600
}
```
- hotel=c46-sealed sealed=True id=c46-sealed.sbx_37823fc9ca50
- state=running
- delete HTTP 204

## Verdict: **PASS** (capacity + smoke after #342 Genoa pin)

## Note
Guest polaris-sealed may not see operator-only hotel admission.amd_chain detail; Spock verified verifier PASS on c46-sealed Genoa and FAIL on wrong pin. Eng confirms pool still admits sealed rooms post-roll. Milan/Turin need a second ARK pin later.

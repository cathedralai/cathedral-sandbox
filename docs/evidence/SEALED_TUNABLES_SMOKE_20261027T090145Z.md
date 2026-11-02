# Sealed tunables smoke — 20261027T090145Z

- Broker: `https://live.cathedral.computer`
- Guest: polaris-sealed
- Expect: create with per-room tunables → status applied (not 409 tunables_unavailable) → exec → delete; never nc-sealed

## 1. Create with tunables
```json
```
- HTTP 400
```json
{
    "error": {
        "code": "invalid_json",
        "message": "request body is not JSON"
    }
}
```
**FAIL** create HTTP 400

## 5. Capacity after
{
    "classes": {
        "sealed": {
            "hotels": 2,
            "joined": 0,
            "up": 2,
            "placeable": 2,
            "pending_admission": 0,
            "draining": 0,
            "slots": 960,
            "free_rooms": 951
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
        "active_rooms": 9,
        "id": "polaris-sealed",
        "max_rooms": 15,
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
            "free_rooms": 477,
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
                "state": "admitted"
            },
            "class": "sealed",
            "down_since": null,
            "drain": false,
            "free_rooms": 474,
            "id": "nc-sealed-2",
            "labels": {
                "sealed": "true"
            },
            "reserved_for": null,
            "slots": 480,
            "source": "broker",
            "tier": "prefer",
            "up": true
        }
    ]
}

## Verdict: **FAIL**

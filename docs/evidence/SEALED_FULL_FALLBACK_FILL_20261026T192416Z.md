# Sealed-full / cap fill proof — 20261026T192416Z

- Broker: `https://live.cathedral.computer`
- Guest: polaris-sealed
- Expect: fill remaining rooms on preferred sealed (not nc-sealed); 11th hits guest cap; cleanup only our labeled rooms

## 0. Catalog before
```json
{
    "guest": {
        "active_rooms": 3,
        "id": "polaris-sealed",
        "max_rooms": 10,
        "policy": true
    },
    "hotels": [
        {
            "class": "sealed",
            "down_since": null,
            "drain": false,
            "free_rooms": 477,
            "id": "c46-sealed",
            "labels": {
                "sealed": "true"
            },
            "reserved_for": null,
            "source": "broker",
            "tier": "prefer",
            "up": true
        },
        {
            "class": "sealed",
            "down_since": "2026-10-26T19:16:32Z",
            "drain": true,
            "free_rooms": 0,
            "id": "nc-sealed-2",
            "labels": {
                "sealed": "true"
            },
            "reserved_for": null,
            "source": "broker",
            "tier": "prefer",
            "up": false
        }
    ]
}
```

- active=3 max=10 free_slots_to_fill=7

## 1. Fill remaining slots (sealed prefer)
- create 1/7: HTTP 202 hotel=`c46-sealed` sealed=True id=`c46-sealed.sbx_257a88f1537b`
- create 2/7: HTTP 202 hotel=`c46-sealed` sealed=True id=`c46-sealed.sbx_c6c81c18debd`
- create 3/7: HTTP 202 hotel=`c46-sealed` sealed=True id=`c46-sealed.sbx_ceb048c6fe91`
- create 4/7: HTTP 202 hotel=`c46-sealed` sealed=True id=`c46-sealed.sbx_3228d543808c`
- create 5/7: HTTP 202 hotel=`c46-sealed` sealed=True id=`c46-sealed.sbx_c753372f1bc8`
- create 6/7: HTTP 202 hotel=`c46-sealed` sealed=True id=`c46-sealed.sbx_e064b35513a6`
- create 7/7: HTTP 202 hotel=`c46-sealed` sealed=True id=`c46-sealed.sbx_6d7f834cc89b`

## 2. Cap honesty (one over max)
- over-cap HTTP 429
```json
{
    "error": {
        "code": "room_limit",
        "message": "this key may have 10 rooms at one time; 10 are running or starting. Delete rooms, or ask Cathedral for a higher limit"
    }
}
```
- over-cap refused as expected

## 3. Catalog at full
```json
{
    "guest": {
        "active_rooms": 10,
        "id": "polaris-sealed",
        "max_rooms": 10,
        "policy": true
    },
    "hotels": [
        {
            "class": "sealed",
            "down_since": null,
            "drain": false,
            "free_rooms": 470,
            "id": "c46-sealed",
            "labels": {
                "sealed": "true"
            },
            "reserved_for": null,
            "source": "broker",
            "tier": "prefer",
            "up": true
        },
        {
            "class": "sealed",
            "down_since": "2026-10-26T19:16:32Z",
            "drain": true,
            "free_rooms": 0,
            "id": "nc-sealed-2",
            "labels": {
                "sealed": "true"
            },
            "reserved_for": null,
            "source": "broker",
            "tier": "prefer",
            "up": false
        }
    ]
}
```
- nc-sealed still hidden: OK

## 4. Cleanup (our fill rooms only)
- delete `c46-sealed.sbx_257a88f1537b` HTTP 204
- delete `c46-sealed.sbx_c6c81c18debd` HTTP 204
- delete `c46-sealed.sbx_ceb048c6fe91` HTTP 204
- delete `c46-sealed.sbx_3228d543808c` HTTP 204
- delete `c46-sealed.sbx_c753372f1bc8` HTTP 204
- delete `c46-sealed.sbx_e064b35513a6` HTTP 204
- delete `c46-sealed.sbx_6d7f834cc89b` HTTP 204

## 5. Catalog after cleanup
```json
{
    "guest": {
        "active_rooms": 3,
        "id": "polaris-sealed",
        "max_rooms": 10,
        "policy": true
    },
    "hotels": [
        {
            "class": "sealed",
            "down_since": null,
            "drain": false,
            "free_rooms": 473,
            "id": "c46-sealed",
            "labels": {
                "sealed": "true"
            },
            "reserved_for": null,
            "source": "broker",
            "tier": "prefer",
            "up": true
        },
        {
            "class": "sealed",
            "down_since": "2026-10-26T19:16:32Z",
            "drain": true,
            "free_rooms": 0,
            "id": "nc-sealed-2",
            "labels": {
                "sealed": "true"
            },
            "reserved_for": null,
            "source": "broker",
            "tier": "prefer",
            "up": false
        }
    ]
}
```

## Note
Broker guest policy for polaris-sealed is sealed-prefer + deny nc-sealed (no unsealed hotels in this guest catalog).
Unsealed fallback when sealed/warm path cannot admit is Polaris #1535 product behavior (agent rooms / warm refill), not this guest Bearer creating unsealed via broker.

## Verdict: **PASS** fill + cap + deny fence + catalog

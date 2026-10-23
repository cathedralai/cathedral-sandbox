# TRR G1 — A miner joins the pool — TEMPLATE

Fill on #1504 e2e day. Numbers with sample sizes or it did not happen.

## Pass means

Host running SN94 miner bundle registers on testnet **584**; hotel joins broker via operator route (`POST /v1/broker/hotels` / `ctcli hotel join`); probe passes; hotel listed with slots; **&lt;10 minutes** from join to listed.

## Environment

| Field | Value |
| --- | --- |
| UTC start | |
| UTC end | |
| Netuid / network | 584 / test |
| Miner host | |
| Hotkey / UID | |
| Broker base | |
| Operator route used | |

## Commands (record exact)

```bash
# 1. Start / confirm miner bundle
# 2. Hotel join
# 3. Probe
# 4. List hotels / slots
```

## Evidence table

| Sample | t0 (join) | t1 (listed) | seconds | hotel_id | free_slots | probe | notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | | | | | | | |

## Artifacts to attach

- [ ] Broker hotel document (redact secrets)
- [ ] Probe result JSON
- [ ] Metagraph / UID row excerpt
- [ ] Command log

## Verdict

| Pass? | YES / NO / BLOCKED |
| --- | --- |
| Blocker | |

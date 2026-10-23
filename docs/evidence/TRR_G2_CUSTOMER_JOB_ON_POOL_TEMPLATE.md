# TRR G2 — Customer job on pool compute — TEMPLATE

## Pass means

Create with ops key (labeled) lands on the joined hotel; exec runs; receipt verifies (`verify_receipts.py --broker --hotel <id>`, `--require-sealed` where sealed); delete leaves nothing.

## Environment

| Field | Value |
| --- | --- |
| UTC | |
| Broker | |
| Hotel id | |
| Ops key scope | |
| Sealed? | |

## Commands

```bash
# create (record Idempotency-Key)
# poll until running
# exec
# verify_receipts.py ...
# delete
```

## Samples

| # | sandbox_id | hotel | create→ready_s | exec_exit | receipt_ok | delete_ok |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | | | | | | |

## Verdict

| Pass? | YES / NO / BLOCKED |
| --- | --- |
| Blocker | |

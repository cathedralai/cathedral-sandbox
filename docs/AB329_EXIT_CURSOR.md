# AB#329 broker exit collection cursor

This is the recorder prerequisite for the [draft settlement contract](https://github.com/bigailabs/polariscomputer/pull/2033). It does not implement forfeiture, change weights, authorize a maintenance exemption or retry a customer workload. The API collector and validator settlement consumer are not implemented by this change.

## Read latest observations

The existing operator and read-only operator keys can call:

```text
GET /v1/broker/miner-exits?after=
GET /v1/broker/miner-exits?after=<next_cursor from a prior response>
```

An empty `after` opts into an initial snapshot. The response has schema `cathedral_miner_exit_updates_v1`, `exits`, `next_cursor`, `reset_required` and `reset_reason`. It carries `Cache-Control: no-store`. Each record adds an `event_id` and decimal-string `sequence`. The event ID remains unchanged as the room outcome resolves and is persisted in the existing client-state snapshot. The sequence is meaningful only within the cursor's process epoch. Treat the cursor as opaque; it is not a signed receipt or an authorization capability.

Without `after`, the existing list and `since=RFC3339` behavior remain. They do not return a collection cursor. Combining `after` and `since`, supplying multiple `after` values or using a malformed cursor returns HTTP 400, `invalid_exit_cursor`.

Incremental results contain the latest state of every retained record changed after the cursor, sorted by sequence. Repeated updates may coalesce into one record, so sequence gaps alone do not mean missing records. This is not an append-only log of every intermediate transition. A room's `lost` value remains tri-state: unknown, recovered or lost. Repeating an already completed outcome does not create another update.

## Detect incomplete history

HTTP 200 is not sufficient to establish continuity. Require the exact schema and all cursor fields before processing records: an older broker ignores `after` and returns the legacy list. Treat that response as unsupported, not an empty successful update. Always check `reset_required`:

| `reset_reason` | Meaning |
| --- | --- |
| `initial_snapshot` | No prior collection cursor; retained records cannot prove earlier history |
| `epoch_changed` | Different broker process or counter epoch, including restart or rollback |
| `retention_gap` | A revision newer than the collector's cursor was discarded, or an unresolved outcome was discarded after that cursor |
| `cursor_ahead` | The supplied sequence is ahead of this process |
| Empty string | The response contains all retained observed updates after this cursor |

A reset response includes the full retained snapshot and a new cursor. The future API collector must atomically persist the snapshot, the discontinuity and the cursor. It must retain historical gap markers when resuming from that cursor, not reclassify those intervals as clean because a later response is incremental. Empty snapshots never prove there were no exits.

Retention stays bounded at eight days, 50 records per hotel and 1,000 total. Cursor reads also prune aged records even when no new exit arrives. Discarding an already collected terminal record does not create a false gap. Discarding an unresolved record does: the broker can no longer publish its future room outcome. No deletion of the API's retained evidence is implied by broker pruning.

## Persistence and rollout limits

Event IDs become durable when the existing state writer saves them. Legacy records get IDs on load and schedule a save; duplicate saved IDs are separated. A process crash before a save can lose an observation or a newly assigned ID. Therefore the cursor epoch is deliberately not persisted: every restart requires reconciliation even if saved records survive. A deployment with no `state_dir` loses all records at restart and also returns `epoch_changed` for a prior cursor. This is a loss signal, not a new durability guarantee.

The broker can miss exits while it is stopped or lacks room inventory, and its own network outage can resemble miner loss. Cursor continuity only covers observations that this process retained; it is not proof of all physical failures or miner fault. Evidence stays operator-only and contains the same room/guest details as the existing endpoint. It is not a public penalty feed.

The patch can be independently reviewed before the reward-policy decision. Any merge and broker rollout remain with the existing review/release owners. A future collector must handle reset responses, persist evidence before advancing its checkpoint, and keep reward enforcement off until the separate policy, signed-settlement and live-proof gates are satisfied.

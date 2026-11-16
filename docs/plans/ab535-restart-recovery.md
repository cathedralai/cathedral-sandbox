# AB#535 front restart recovery

Problem: a restarted receipts front (same guest boot, new receipt key and binding) loses the in-memory pool state. Its startup list could fail open when the room API does not answer, and it treated a successfully claimed pool room as unclaimed. The first draft of this PR recovered claimed rooms by replaying the stored claim receipt under the new front; review (15 Nov, 9f3e1b2) held it because the receipt proof was not continuous.

Rule: a receipt is only ever served under the binding that signed it. A restarted front never signs, replays or continues a claim made before it.

Contract:

1. Until a valid pool-room list has been read, every authorized room request, create and bulk delete answers 503 `pool_state_unknown`. The list is retried every 5 seconds. Creates wait too, so a pool room made meanwhile can never be listed as unsigned.
2. Unclaimed pool rooms from an earlier front are stale: never claimable, closed to all but delete, claim and record reads (409 `pool_room_stale`). The keeper deletes them; their create's TTL ends them anyway.
3. A successful claim writes a root-only atomic marker before the 200: room, sandbox id, API `created_at`, boot id, binding and claim receipt hash. No answer and no receipt. A marker that matches the listed room, its creation time and this boot, under another binding, marks the room claimed-before. It runs as an ordinary room under the new binding. A claim on it signs nothing: 409 `pool_room_claimed` for another id (the API quarantines the room); for the same id `pool_room_stale` until the new front signs anything for it, then `pool_room_gone`.
4. A delete or room end removes the marker. Reusing a room ID with a different creation time never inherits a claim. A failed marker write never returns a 200.
5. Chain and attestation files are named by boot and binding, so a restart keeps the earlier binding's attestation (with its SNP report) and chain.
6. The proof of a claim made before a restart is receipts 1 and 2 under the earlier binding plus that binding's attestation, kept by the caller at claim. The broker archives bindings, not receipts.

Pool sizing: see room-kit/README.md, "Pool sizing".

Verification: tests/test_room_kit_pool_rooms.py restart cases; tests/test_room_kit_pool_claim_verify.py runs verify_receipts.py on the receipts the front signs (pair accepted, five forged pairs refused, a restart split by binding).

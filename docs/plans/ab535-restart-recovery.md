# AB#535 front restart recovery

Problem: a restarted receipts front loses the in-memory pool state. Its startup list can fail open when the room API does not answer, and it currently treats a successfully claimed pool room as unclaimed.

Contract:

1. Until a valid pool-room list has been read, every authorized room operation fails closed. Retry the list in the background; recover without another front restart.
2. A successful claim writes a root-only, atomic marker before the 200 answer. The marker holds the room, claim answer and signed receipt, original room creation time, and guest boot ID. A new front accepts it only when the API still lists that same pool room and creation time in this boot. A missing or malformed marker leaves the room closed.
3. A delete or room end removes the marker. Reusing a room ID with a different creation time never inherits a claim.
4. No new customer-visible 200 can be sent when marker persistence fails. Existing claim and bulk-delete serialization remains in force.

Verification: fake API list failure/recovery, claimed room restart and replay, marker mismatch, persisted marker write failure, existing pool/serial suites, Python 3.11/3.12 CI. No live guest or re-seal in this PR.

Review HOLD discovered after the first draft: `Ledger` makes a new Ed25519 receipt key and binding on every front process start, resets its in-memory chain, appends to the old `chain-{boot_id}.jsonl`, and overwrites `attestation-{boot_id}.json`. The marker can replay an old claim receipt while the live attestation names a different key; subsequent receipts for that room start at sequence 1 under the new binding. The marker is not enough to prove or continue the old claim. Do not merge this draft until receipt-chain and attestation continuity are designed and tested, or the recovery policy is explicitly narrowed to fail closed. A same-boot two-Ledger reproduction found different bindings, an empty new chain, and the same append path.

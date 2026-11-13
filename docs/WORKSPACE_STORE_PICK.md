# Workspace store: Hippius or Beam (AB#522)

Status: spike, 13 Nov 2026. Public docs and prices only. No account, no spend, no
hotel touched. Context: AB#393 (epic), AB#394 (Hippius due diligence), AB#395
(volumes), AB#397 (billing), AB#398 (customer-held keys).

## The pick

**Hippius S3 as the store, restic from inside the guest, straight to Hippius. Not Beam, for now.**

- Beam (Bittensor SN105, b1m.ai) is a transfer network, not a store. It moves
  bytes between stores it does not own (S3, R2, GCS, Hippius S3, HTTP). A
  workspace that outlives its host still needs a store; Beam could only sit in
  front of one. So the real choice is "Hippius direct" or "Hippius plus Beam".
- Hippius charges nothing to read data out. Beam charges per transfer. A guest
  pulling its own restic repo from Hippius is free and has one less party
  touching the bytes.
- Revisit Beam only if measured Hippius reads (AB#394) cannot restore a
  typical workspace in seconds and Beam's parallel workers can.
- "Beam" read as beam.cloud (serverless GPU, volumes) is out: no S3 API
  listed and it is not a Bittensor neighbour.

## Against the card's criteria

| Criterion | Hippius (SN75) | Beam (SN105) |
|---|---|---|
| API | S3 at `https://s3.hippius.com`, region `decentralized`, path style only. Multipart (parts up to 512 MiB), presigned URLs (7 days max), versioning (Enabled only), Object Lock. Lifecycle accepted but not applied. Conditional writes not documented | SDK (Python, TS, Go, Rust), CLI, HTTP API. `create_transfer(sources, destinations)`. No storage API of its own |
| Restic fit | Plain S3 backend with `-o s3.region=decentralized -o s3.bucket-lookup=path`. Untested here (AB#394) | Not a restic backend. Would copy a restic repo between stores |
| Latency from hotels | Not measured from a hotel. From this workstation (Contabo, St. Louis): TCP connect 27 to 32 ms, TLS done 58 to 64 ms, unauthenticated 403 in 240 to 248 ms (3 runs each). The endpoint resolves to one OVH address in Beauharnois, Quebec. Frankfurt (broker, nc-sealed*) is across the Atlantic from it: expect several times these numbers. Chicago 46 is slated to go | Not measured. Per transfer it adds a hop through orchestrator and workers; the default wait timeout is 300 s |
| Throughput | No published figure. Needs a test from Frankfurt (AB#394 first step) | Vendor claims only: 1 TB in 2 min 42 s (1 Nov 2026, about 6.2 GB/s aggregate across many workers); 107 GB R2 to Hippius in about 6 min (about 300 MB/s) |
| Encryption in the guest | Hippius encrypts with per-bucket keys it holds, so its encryption is not ours. Restic encrypts in the guest before upload; Hippius sees ciphertext only. Fits AB#398 | Workers see the bytes of object-storage transfers (TLS to the worker, not end to end). With restic they see ciphertext, plus sizes and timing. Rooms are end to end but are agent to agent, not store to store |
| Durability | Reed-Solomon 10 data + 20 parity shards across miners; any 10 rebuild a file. No durability figure, no SLA. Deletion timing and non-payment behaviour not documented (AB#394) | Stores nothing. Claims at least 99% transfer success (Sep 2026). No SLA |
| Price per GB-month | $0.006 pay as you go ($6/TB), down to $4.65/TB at 100 TB. 4 GiB kept: about $0.026 a month, $0.00085 a day (matches AB#397's $0.0009) | n/a (still pay the store) |
| Price per GB moved | $0 egress, retrieval free | $0.10 per transfer + $0.01 per GB ($10.10 per TB). One 4 GiB move: about $0.145, more than five months of keeping it on Hippius |
| Pays SN94 neighbours | Yes, a Bittensor subnet. Top-ups by card, BTC, USDC or TAO. Storage miners are paid by SN75 emissions, not directly by our spend | Yes, a Bittensor subnet. Credits by card, TAO or Beam alpha. Miner emissions follow verified delivered volume, so our use moves its rewards. Neither pays SN94 miners |

## What the pick does not solve

- **The key does not move today.** The sealed data volume key comes from the
  chip and the build measurement (`SEALED_DATA_VOLUME.md`, Key source), so it
  cannot open on another host. A workspace that moves needs the restic key
  released by key release (AB#395) or held by the customer (AB#398). The
  store choice does not change that.
- **Rollback.** Without documented conditional writes, an old head can be put
  back. The generation counter at head+1 in our API (AB#395) is the guard;
  Hippius Object Lock and versioning can make old snapshots undeletable for a
  retention window but do not stop a stale read.
- **Availability gap closed only partly.** `SEALED_DATA_VOLUME.md` says there
  is no backup and no replica. Hippius gives an off-host copy; its durability
  is unquantified.

## Not measured

- Authenticated put and get throughput, cold read time, and restore time of a
  4 GiB restic repo, from Frankfurt and Contabo. Restoring 4 GiB in 10 s needs
  about 430 MB/s sustained; at 100 MB/s it takes about 43 s.
- Whether Hippius has a gateway nearer Frankfurt than Quebec.
- Beam end to end time for one 4 GiB object, store to store.

These need a Hippius account and a test bucket on one hotel (AB#394), which
this spike did not do.

## Sources (read 13 Nov 2026)

- https://hippius.com/pricing
- https://docs.hippius.com/storage/s3/compatibility
- https://docs.hippius.com/storage/s3/integration
- https://docs.hippius.com/llms.txt (erasure coding 10 + 20)
- https://docs.b1m.ai/docs/developer-quickstart.md
- https://docs.b1m.ai/docs/billing.md
- https://github.com/Beam-Network/beam
- https://subnetalpha.ai/subnet/beam/
- https://en.cryptonomist.ch/2026/08/02/bittensor-ai-innovations/

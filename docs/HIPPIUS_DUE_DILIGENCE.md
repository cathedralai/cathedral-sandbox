# Hippius due diligence (AB#394)

Status: desk answers only. No number below is measured yet. Measuring needs a
paid Hippius bucket and a run from each hotel, which this change does not do.
Desk facts come from the Hippius docs, fetched 2026-11-13; each cites its page.
Pairs with AB#522 (Hippius or Beam) and the persistent workspace volume in
docs/SEALED_DATA_VOLUME.md.

## The five questions

| Question | Answer today | Source |
|---|---|---|
| Latency and throughput per hotel region | Not measured. One S3 host, `https://s3.hippius.com`, region `decentralized`, path-style only. Under load the gateway answers 503 SlowDown. | [llms-full.txt](https://docs.hippius.com/llms-full.txt) |
| Restic compatibility | Expected to work, not run. Restic needs PUT, ranged GET, HEAD, ListObjectsV2, DELETE (lock files on every run) and bucket create or exists at init; all are listed as supported. Restic does not need conditional writes; Hippius lists none. Use `-o s3.bucket-lookup=path -o s3.region=decentralized`. Ranged GET and DELETE are the likeliest to misbehave on a distributed backend, so the bench exercises both. | [compatibility](https://docs.hippius.com/storage/s3/compatibility) |
| Deletion | API: DeleteObject and DeleteObjects exist; versioning can be enabled and never suspended; lifecycle rules are accepted and not applied, so nothing expires on its own. Not stated anywhere: when shards of a deleted object leave the miners. A client cannot observe that, so it stays a question for Hippius. Our answer to it: encrypt in the guest (restic does, with a key Hippius never sees), so a shard that lingers is ciphertext. | [compatibility](https://docs.hippius.com/storage/s3/compatibility) |
| Non-payment | Pay as you go: read-only 7 days after the balance runs out, suspended (buckets unreachable) 7 days later, data may be deleted after 37 days unpaid, final notice a week before. So a missed top-up is a write outage at day 7 and a read outage at day 14. Price: $6 per TB-month, charged hourly from the balance. Egress price not stated. | [billing](https://docs.hippius.com/use/console/billing) |
| Durability | Arion: Reed-Solomon k=10 data + m=20 parity shards in 2 MiB stripes, CRUSH placement, any 10 of 30 shards rebuild; a warden audits miners and a validator rebuilds lost shards. No durability figure, no SLA, only a status page. | [llms-full.txt](https://docs.hippius.com/llms-full.txt), [status](https://status.hippius.com) |

Encryption: the S3 docs do not say whether Hippius encrypts objects at rest or
who would hold such keys (Drive encrypts on the client; Object Storage does not
say). Treat every byte as readable by Hippius and its miners; encrypt in the guest.

## Measuring

`scripts/hippius_restic_bench.py` runs pinned restic 0.19.1 against a fresh
prefix in a test bucket and writes one JSON file: init, backup MiB/s, median
and p95 of `cat config` with no cache, `check --read-data`, restore with a
sha256 compare, then `forget --prune` with raw-data bytes before and after.
Pinned binary: `restic_0.19.1_linux_amd64.bz2`, sha256
`f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c`
([SHA256SUMS](https://github.com/restic/restic/releases/download/v0.19.1/SHA256SUMS)).

    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... RESTIC_PASSWORD=... \
    python3 scripts/hippius_restic_bench.py --bucket <test-bucket> \
        --hotel-region region-a --out region-a.json

Restic leaves `config` and `keys/` under the prefix after prune; delete the
prefix by hand. Use neutral region labels, not host or supplier names.

| Hotel region | Backup MiB/s | Restore MiB/s | `cat config` median / p95 ms | check --read-data | Bytes gone after prune |
|---|---|---|---|---|---|
| region-a | not measured | not measured | not measured | not measured | not measured |

## Still open after the bench

- When deleted shards leave miners, and whether Hippius can attest it.
- A durability number or SLA in writing.
- Egress price, and whether Object Storage encrypts at rest and with whose key.

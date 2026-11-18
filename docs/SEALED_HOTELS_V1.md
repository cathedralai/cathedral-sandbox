# cathedral_sealed_hotels_v1

The signed per-hotel sealed guest measurement list (AB#382 work package 1).
Contract and decisions: `docs/specs/ab382-signed-hotel-measurements.md`.
Code: `cathedral/sealed_hotels.py` (parser, verifier, signing), `room-kit/verify_sealed_hotels.py`
(standalone customer verifier, pinned key), `scripts/cathedral_sealed_hotels_publish.py` (publisher).

## Envelope

```json
{
  "schema": "cathedral_sealed_hotels_v1",
  "release": 1,
  "generated_at": "2026-11-17T18:00:00Z",
  "valid_from": "2026-11-17T18:00:00Z",
  "valid_until": "2026-11-18T18:00:00Z",
  "key_id": "sealed-hotels-local-1",
  "hotels": {
    "<enrolled hotel ID>": {
      "chip_id": "<full 64-byte SNP CHIP_ID, 128 lowercase hex>",
      "measurements": ["<96 lowercase hex SNP MEASUREMENT>", "..."]
    }
  },
  "signature": {"algorithm": "ed25519", "value_base64": "<64 bytes>"}
}
```

- Exactly these fields at every level; unknown or missing fields refuse.
- `release`: integer 1 to 2^63-1, monotonic per publisher.
- Times: `YYYY-MM-DDTHH:MM:SSZ`. `valid_from < valid_until`, `generated_at < valid_until`.
- `hotels`: non-empty; keys are enrolled hotel IDs (`^[a-z0-9][a-z0-9._-]{0,127}$`). Duplicate hotel IDs (duplicate JSON keys anywhere) refuse.
- `chip_id`: the full report CHIP_ID, not the broker's shortened display ID; all zero refuses. Several operator hotels may name the same chip (several guests on one SNP host); entries are not distinct machines.
- `measurements`: 1 to 16, unique. The publisher sorts them; verifiers do not require order.

## Signature and bytes

- Signature input: canonical JSON of the document without `signature` (sorted keys, `ensure_ascii`, separators `,` and `:`), the `cathedral/policy_registry.py` convention. Floats and non-finite numbers refuse.
- The published bytes are the canonical JSON of the whole document, signature included, with no trailing newline. Verifiers refuse any other serialization, so the digest (`sha256:` + SHA-256 of the exact bytes) has one value per release. The immutable copy is published as `<sha256 hex>.json`.
- The signed bytes must fit the 4096-byte KMS `Sign` RAW limit (`cathedral/signer.py`); about 10 hotels at 2 builds fit. Past that needs a new format version.

## Key pins

`cathedral_sealed_hotels_pins_v1` (`docs/keys/sealed-hotels-pins.json`):
`{"schema", "keys": {"<key_id>": {"algorithm": "ed25519", "public_key_hex", "not_before", "not_after"}}}`.
Every window is closed: a missing or null `not_after` refuses. The `key_id` in an envelope only selects a pinned key; a key carried by the document grants nothing.

## Verification (both verifiers)

Refuses: unsigned or bad signature, unknown key, non-canonical bytes, any schema error above, a verification time outside the key's pin window, `generated_at` outside the pin window, `generated_at` more than 5 minutes in the future, verification before `valid_from` or after `valid_until`, more than 24 hours after `generated_at` (decision 2). Historical mode (`--at`, `historical_at`) applies the same rules at the admission time, which must lie between `generated_at` and now. Rollback check against a recorded `(release, digest)`: a lower release or a same-number different-digest release refuses.

## Golden vector

`tests/fixtures/sealed_hotels/`: `golden-v1.json` (envelope), `golden-pins.json`, `golden-v1.vector.json` (signed bytes, signature, digests). The key is a throwaway derived from a public label (`make_golden.py`), never a production key. Python library and standalone verifier are tested against it.

Open: the Go vector test belongs to the broker slice (work packages 3 and 4).

## Publisher

`scripts/cathedral_sealed_hotels_publish.py` signs via `signer_from_config(path, "sealed_hotels")`, checks the signer key against the pin file, verifies its own output, and keeps durable state (last release and digest, mode 600, atomic write with directory sync, outside the repository). A missing state needs `--init-state` with an explicit `--release` above every release ever published (`--release 1` for the first); a corrupt state refuses and is never reset silently. Outputs are never overwritten.

## Renewal (AB#800)

A release is valid for at most 24 hours, so it is re-signed on a timer on the key host. `ops/sealed-hotels-renew.sh` runs the publisher (next release = recorded + 1; it never creates state), verifies the output with `room-kit/verify_sealed_hotels.py` (built-in pins, expected digest, successor of the recorded release), then writes the exact bytes to Workers KV key `sealed_hotels_current` in the namespace the site Worker binds as `SEALED_HOTELS_STORE`, and reads them back to confirm. It refuses to replace a newer or conflicting release already in KV. `--no-upload` signs and verifies only (it still consumes a release number).

- Units: `ops/sealed-hotels-renew.service` and `ops/sealed-hotels-renew.timer` (every 6 hours at 00, 06, 12, 18 UTC plus up to 15 minutes of jitter, `Persistent=true`). Configuration: `/etc/cathedral/sealed-hotels-renew.env`, see `ops/sealed-hotels-renew.env.example`.
- The Cloudflare token is read from `CLOUDFLARE_API_TOKEN_FILE` (mode 600, Workers KV Storage:Edit on the account) and handed to curl on stdin; it never appears in argv or output.
- Installing the timer is a key custody action for the key's custodians: copy both units to `/etc/systemd/system/`, write the environment file, then `systemctl enable --now sealed-hotels-renew.timer`.

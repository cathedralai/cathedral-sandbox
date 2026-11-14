# One-shot exchange case: good_basic

One good run, the way the API sees it. The same directory is copied byte for byte into the API repository, and
neither side may change it alone: this checker's test says `expected/bundle.json` passes, and the API's test builds
the file from `machine/` and `caller/` and must get the same file.

- `machine/`: the answers as the broker hands them to the API (the API talks to the broker; the folder keeps its
  name), one file per call in call order. `NN_<call>.header` is the `X-Room-Receipt` header text (base64url of the
  canonical receipt JSON, with padding). `NN_<call>.response` is the answer body the API keeps; the first is the
  broker's 202 create document (`id` with the hotel prefix, `hotel`, `isolation`, and `create_request_b64`, the
  create bytes, which the broker returns when asked with `X-Broker-Return-Create-Request: 1`; that member is the one
  source of the create bytes). `exec_request.json` is the exec bytes the API sent; `hotel_attestation_answer.json` is the hotel's attestation
  answer; `amd/vcek_der.bin` is the VCEK as DER and `amd/cert_chain_pem.txt` is the chain as AMD's key server
  returns it (the ASK, then the ARK, as PEM).
- `caller/`: the POST body (with `content_b64`), the API's 202 answer (`oneshot_id`, `state`, `status_url`,
  `reserved_usd`), the recipe (its `create.ttl_seconds` is the timeout plus 600), the context file and the input.
  Outputs stay at or under 65,536 bytes: this version keeps them inline.
- `expected/bundle.json`: the one-shot file in the shapes of spec G4 5.5, in canonical JSON.
  `expected/check.json`: what `verify_receipts.py` prints for it (the command is in `case.json`).
- The run has one input, a context, one inline output, an exec answer, an env of one entry, a decimal-string
  `max_spend_usd`, and no `cwd` and no `user` (absent, never null).

The files are made by `tests/fixtures/receipt_lists_v2/generate.py`; `generate.py --check` rebuilds them byte for byte.
`MANIFEST.json` holds the sha256 of every other file and a root hash over the sorted `path hash` lines.

# K. Affine lane

Artifact: cathedral-sandbox 22e7824 (PR #311 head), frozen at /private/tmp/claude-501/r6.
Files: cathedral/affline_rerun.py (653), cathedral/affine_claim.py (490),
cathedral/affine_validator.py (210). Consumer read with them: cathedral/sandbox_server.py
(route 269, handler 612-628, dispatch 277-301, listener 803-816).

## State in one screen

- The lane adds exactly one hotel route: `POST /v1/affline/validate-rerun`.
- Live in code on every hotel: `sandbox serve` (cli.py:1732) builds SandboxApplication,
  which registers the route unconditionally (sandbox_server.py:269). Listed in the public
  `/openapi.json` (sandbox_server.py:699-704).
- Dormant in deployed form: no install writes `CATHEDRAL_AFFLINE_RERUN_SIGNING_SEED`
  or `CATHEDRAL_AFFLINE_RERUN_SECRET` (grep of room-kit, deploy, scripts, Dockerfiles:
  zero hits outside the module, its tests and two docs). Without the seed the handler
  answers 503 at affline_rerun.py:521, before the body is parsed. Probe:
  `test_without_seed_route_is_503_before_body_parse`.
- Who can reach it: holders of the hotel Bearer key only. The broker does not route the
  path (main.go serveNative default 404 "central booking does not route"; compat falls
  through to the same). The room passthrough always rebuilds `/v1/sandboxes/<hid>/<tail>`
  (main.go:692-695) and rejects `.`/`..` segments (B59). Go probe
  `review6_affine_test.go` (2 tests, pass): direct POST is 404 for native and compat
  agents, 401 without a key; five tail variants never leave `/v1/sandboxes/<hid>/`.
  The Python hotel 404s `/v1/sandboxes/x/affline/validate-rerun` and the `%2e%2e` form.
- From the internet: Caddy on 443 sends every path to the receipts front
  (install.sh:447), which forwards every path it does not serve itself to the API
  (room_receipts.py:368). So a hotel-key holder can call the route over TLS. Customers do
  not hold hotel keys.
- What the route does: pure CPU. JSON parse, base64, sha256, Ed25519 verify and sign.
  No files written, no process run, no docker call, no network call, no provider state
  touched except a read of `provider._keys` for the key's project name. No locks.
  Cannot affect other keys' rooms or the host.
- Long work on the request thread: none. Body is capped at 512 KiB after the stdlib
  handler has already read the whole Content-Length (hotel wide, B54).

## affline_rerun.py

Constants 51-68. `_FORBIDDEN_REQUEST_TRUTHY` 71-81: seven request keys refused when true.
`_ATTESTATION_PLAN` 83-140: static roadmap dict embedded in every receipt.

- `AfflineRerunError` 143-147. ValueError with `category` and `http_status` (default 400).
  Mapped to `{"error":{"code":category}}` by sandbox_server.py:298.
- `AfflineRerunResult` 150-154. receipt dict, ValidatorDecision, http_status.
- `VerifiedAfflineRerunReceipt` 157-161. receipt_id, decision_action, frozen document.
- `sha256_hex` 164-165. Hex digest. Pure.
- `canonical_json` 168-175. sort_keys, compact, ensure_ascii, allow_nan=False. Raises
  plain ValueError on NaN/Infinity and TypeError on non-JSON types. Callers: 208, 224,
  415-417, 440, 474, 498, tests. Invariant: input came from json.loads of finite values.
- `attestation_plan` 178-181. Shallow copy of the static plan. Pure.
- `_b64_field` 184-198. Reads one base64 string field. Trusts: nothing; validates type,
  non-empty, strict base64, decoded size <= 256 KiB. Pure.
- `_claim_bytes` 201-214. `claim_base64`, or `claim` as dict (canonical_json) or str
  (utf-8). Trusts: the dict holds finite values; the str has no lone surrogates. Both
  assumptions fail with uncaught exceptions (hazard 2). Size check on the str path only.
- `_trusted_keys_bytes` 217-227. Same shape for `trusted_keys`. No size check on the str
  path (the 64 KiB cap is applied later in parse_affine_claim_trusted_keys_json).
- `require_trigger_secret` 230-246. Reads env `CATHEDRAL_AFFLINE_RERUN_SECRET`; if set,
  requires header `X-Cathedral-Affline-Trigger` (exact case or all lower case only) equal
  under `secrets.compare_digest`. Trusts: the header value is ASCII. A latin-1 byte in the
  header makes compare_digest raise TypeError (hazard 2a). 401 on mismatch. Env read per
  call. Callers: 519.
- `_reject_fake_request_fields` 249-265. Refuses the seven keys when `True`, `"true"` or
  `1`, and `force_full_rerun: false`. None of these keys is read anywhere else, so the
  check is cosmetic. `"True"` passes. Pure.
- `require_cathedral_signing_key` 268-288. Reads env seed (hex, 32 bytes) and key id.
  Missing seed: 503 with the env var name in the message. Malformed seed or key id: 400
  "key" (an operator fault reported as a client error). Env read per call, key object
  rebuilt per call. Callers: 292, 303, 374, 521.
- `cathedral_signing_public_key_base64` 291-297. Public key of the env seed. Callers:
  none in repo.
- `build_cathedral_trusted_keys_document` 300-322. Trusted keys doc for the rerun receipt
  verifier: one active key, valid from now-1d to now+730d. Callers: tests only.
- `_claim_summary` 325-349. Copies 15 named fields from a verified claim into the receipt.
- `build_affline_rerun_receipt` 352-424. Builds the signed receipt. Refuses
  ACCEPT_RECEIPT. `receipt_id` = sha256(canonical body); signature over body+receipt_id.
  Writes `full_rerun.triggered`, `full_rerun.result` (= decision.full_rerun_result),
  the four sha256s of the inputs, `observed_digests`, `api_key_project`. Trusts: that
  `verify_result` was computed by Cathedral; it is whatever the caller sent when
  `verify_result_base64` is present (hazard 1). Does not record the trusted_keys digest
  or whether the result was supplied. Callers: 612.
- `verify_affline_rerun_receipt` 427-506. Verifier for the receipt. Size cap, canonical
  check, schema, signer, five false/true pins, no accept_receipt, signature shape,
  receipt_id, then key lookup and Ed25519 verify. Honors `status == "revoked"` only;
  ignores `valid_from`/`valid_until` (unlike affine_claim's verifier). Trusted keys doc
  parsed with plain json.loads, no size cap (local input). Callers: tests only. No
  production consumer of rerun receipts exists in the repo.
- `handle_affline_validate_rerun` 509-629. The route body. Order: body <= 512 KiB,
  trigger secret, signing key (503), json.loads (plain, no depth or digit limits), fake
  field check, claim and trusted_keys bytes, three required base64 blobs, optional
  `verify_result_base64`, `spot_check`/`is_king`/`is_dispute` via bool(), `max_age_seconds`
  non-negative int (no upper bound), `run_id` <= 128 chars or derived from the payload
  hash. Parses trusted keys, picks `result_bytes = verify_result or run_tiny_affine_verify`,
  verifies the claim once for the summary (any AffineClaimError -> summary None), then
  calls validate_affine_submission with force_full_rerun=True, refuses ACCEPT_RECEIPT,
  builds the receipt. 200 always, except REJECT with no valid claim -> 400 with a signed
  REJECT receipt. Trusts: caller-supplied trust roots (`trusted_keys`) decide whether the
  caller's claim "verifies"; caller-supplied `verify_result` is the "rerun". Side effects:
  none. Locks: none. Callers: sandbox_server.affline_validate_rerun.

## affine_claim.py

Constants 26-72: schema ids, policy digest, 64 KiB caps, 256 nodes, depth 8, int range,
field sets, allowed enums.

- `AffineClaimError` 75-80. ValueError with category.
- `AffineClaimVerificationKey` 83-94; `verifies_at` 91-94: active or retired, and
  valid_from <= issued_at < valid_until.
- `VerifiedAffineClaim` 97-104. claim_id, bytes, digest, issued_at, document,
  skip_rerun_authorized.
- `sha256_hex` 107-108.
- `digest_affine_verify_bundle` 111-125. Four sha256s over the four byte inputs. Pure.
- `run_tiny_affine_verify` 128-148. Stub verify: payload must be `AFFINE:<int 0..100>`.
  Returns canonical result JSON. int() ValueError (including the 4300-digit limit) is
  caught. Not Affine's real verify code. Callers: affine_validator 94/106,
  affline_rerun 560, tests.
- `_duplicate_safe_object` 151-157. Rejects duplicate JSON keys.
- `_json_integer` 160-167. Int within +-2^63.
- `_validate_json_shape` 170-191. Node, depth, key length, string length, type limits.
- `_parse_json` 194-220. Bounded, duplicate-safe, float-free JSON object parser. Catches
  RecursionError. Callers: 269, 309.
- `canonical_affine_claim_json` 223-233. Canonical dump; wraps dump errors as
  AffineClaimError("schema").
- `affine_claim_body_bytes` 236-244. Canonical body without claim_id and signature.
- `affine_claim_signed_bytes` 247-251. Canonical body without signature.
- `_parse_time` 254-257. Six-fraction-digit UTC only.
- `_require_sha256` 260-263. Lower hex 64.
- `parse_affine_claim_trusted_keys_json` 266-305. Exact top-level and per-key field sets,
  ed25519 only, status enum, 32-byte key, time window parse. Returns a read-only map.
  Callers: affline_rerun 556, cli.py 902.
- `parse_affine_claim_json` 308-389. Bounded parse, canonical bytes check, exact key set,
  schema, policy digest, enums, key id and profile regexes, five sha256 fields, bools,
  `affline_sandbox_tee_claimed` must be False, binding_dev cannot assert attestation or
  skip, confidential_cpu skip needs independent verification and passed, signature shape
  and 64 bytes, claim_id = body digest, issued_at parse. Does not reject a future
  issued_at. Callers: 400.
- `verify_affine_claim` 392-436. Parse, optional max_age check (`clock - timedelta` can
  raise OverflowError for max_age_seconds above about 6.4e10), key lookup, validity at
  issued_at, Ed25519 verify, compute skip_rerun_authorized. Callers: affine_validator 85,
  affline_rerun 570, cli.py 910.
- `issue_affine_claim` 439-490. Test and pilot helper that signs a claim. KeyError on
  missing digests. Callers: tests, affine_claim_cvm.py.

## affine_validator.py

- `ValidatorAction` 25-28: accept_receipt, full_rerun, reject.
- `ValidatorDecision` 31-39. Frozen decision record; `full_rerun_result` is whatever JSON
  the result bytes held.
- `_digests_match` 42-54. Four-field equality between claim and observed digests.
- `validate_affine_submission` 57-198. Verify claim (invalid -> REJECT, with
  json.loads(result) as the "rerun"), recompute observed digests over the given
  `verify_result` or the tiny verify, mismatch -> REJECT, forced (force/spot/king/dispute)
  -> FULL_RERUN or REJECT by `rerun.get("passed")`, else ACCEPT_RECEIPT only with
  skip_rerun_authorized and passed, else FULL_RERUN or REJECT by passed. Trusts:
  `verify_result` is ASCII JSON holding an object. Bytes that are not ASCII raise
  UnicodeDecodeError (95, 119, 133, 169); a JSON list or scalar raises AttributeError at
  135 or 170. When `verify_result` is given nothing is re-run; the caller's bytes are the
  rerun result. Callers: affline_rerun 591, cli.py 950+.
- `decision_to_json` 201-210. Dict view of the decision.

## sandbox_server.py (consumer)

- Route registration 269. Dispatch 277-287 anchors every route regex, matches the raw
  (undecoded) path, unquotes captured groups only. No path normalization.
- `_invoke` 289-301 maps SandboxContractError, SandboxOpError, AfflineRerunError and
  json.JSONDecodeError. Any other exception leaves dispatch.
- `_authenticate` 303-311. Bearer required (require_auth=True in cli serve);
  `provider.authorize` refuses unknown keys in production (sandbox_provider.py:1631).
- `affline_validate_rerun` 612-628. Reads `provider._keys[api_key].project` (private
  attribute, getattr guarded), calls the handler, returns its status and receipt.
- `_Handler._run` 806-816. Reads the full Content-Length body, calls dispatch with no
  try/except. An uncaught exception ends the connection with no response; socketserver
  prints the traceback to stderr. Other connections keep working (ThreadingHTTPServer).

## Hazards (trusted, not checked)

1. `verify_result_base64` is taken as the full re-run result. affline_rerun.py:560 and
   affine_validator.py:106. The signed receipt then states `full_rerun.triggered: true`
   and `full_rerun.result: <caller bytes>` with no field saying the bytes were supplied.
   Cathedral signs an outcome it did not compute. Probe passes:
   `test_cathedral_signs_caller_supplied_verify_result_as_full_rerun`.
2. Eight caller-controlled inputs raise exceptions that `_invoke` does not map, so the
   hotel drops the connection without a response and logs a traceback:
   a. non-ASCII byte in `X-Cathedral-Affline-Trigger` -> TypeError (affline_rerun.py:241);
      runs before the seed check, so it needs only the secret to be set;
   b. deeply nested JSON body -> RecursionError (:524);
   c. integer literal over 4300 digits -> ValueError (:524; also every hotel route through
      `_json`, sandbox_server.py:303);
   d. NaN or Infinity inside a `claim` or `trusted_keys` object -> ValueError (:208, :224);
   e. lone surrogate escape in a `claim` or `trusted_keys` string -> UnicodeEncodeError
      (:210, :226);
   f. `max_age_seconds` above about 6.4e10 -> OverflowError (affine_claim.py:406);
   g. `verify_result_base64` not ASCII -> UnicodeDecodeError (affine_validator.py:95 ff);
   h. `verify_result_base64` holding a JSON list or scalar -> AttributeError
      (affine_validator.py:135, :170).
   b to h need the signing seed configured. Probes pass for all eight.
   Through the deployed chain, case c on `POST /v1/sandboxes/<id>/exec` reaches the API
   as raw bytes (broker forwards room bodies unchanged, main.go:683-710; receipts front
   forwards `self.path` and body unchanged, room_receipts.py:303). The API drops the
   connection; the receipts front answers 502 `hotel_api_no_answer` "the request may have
   run" (room_receipts.py:307) and signs an exec receipt with status 502 for a command
   that never ran. The broker passes the 502 to the guest and does not rest the hotel
   (only creates count `h.failed`, main.go:534; `doBase` records success only, :282).
3. The caller supplies `trusted_keys`, so "claim verifies" is decided by trust roots the
   caller chose. The receipt records `signing_key_id` but not a digest of the trusted
   keys document, so a reader cannot tell which roots were used.
4. The trigger header is matched by exact name or all lower case only; `dict(self.headers)`
   keeps wire casing, so `X-CATHEDRAL-AFFLINE-TRIGGER: <right secret>` is a 401.
5. `verify_affline_rerun_receipt` ignores the key validity window; only `revoked` stops a
   key. The generated trusted keys doc is valid 730 days.
6. `parse_affine_claim_json` accepts a future `issued_at`; `max_age_seconds` bounds only
   staleness.
7. A malformed seed or key id is a 400 "key" to the client. A missing seed is a 503 that
   names the env var.
8. `_reject_fake_request_fields` guards keys no code reads. It is documentation, not a
   control.
9. The hotel reads the entire Content-Length body before the 512 KiB check (B54, hotel
   wide, pending).
10. A double-encoded dot segment (`%252e%252e`) passes the B59 guard (the broker decodes
    one layer, sees `%2e%2e`, not `..`) and reaches the hotel as `%2e%2e`. The Python
    hotel does not normalize, so it is a 404 today. The receipts front forwards
    `self.path` as received (room_receipts.py:303), so it does not normalize either. The
    guard depends on no hop between broker and API normalizing paths. Caddy not tested
    here.
11. Rerun receipts are returned to the caller only. Nothing on the hotel stores them and
    nothing links them to the room receipts chain. By design for a pilot; noted because
    the receipt is Cathedral-signed.
12. `sandbox_server.affline_validate_rerun` reads the provider's private `_keys`. Works on
    InMemorySandboxProvider and its subclasses; silently yields no project otherwise.

## Probes written

- /private/tmp/claude-501/r6/tests/probe_affine_rerun_inputs.py: 13 tests, all pass.
- /private/tmp/claude-501/r6/broker/review6_affine_test.go: 2 tests, both pass.

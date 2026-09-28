# Central access to the supply pool

This is a design reference for reviewers. It specifies how Cathedral's central
service reaches a miner machine and what it may do there. It is not an operator
guide, and no miner accepts a central caller until this design is implemented,
released, and switched on by that miner.

Line references are to this repository at `e4f8e92`.

## Today

No component authenticates a central caller. The worker accepts:

- **Signed validator requests.** An sr25519 signature by a hotkey that the
  miner's own signed snapshot lists as a qualified validator, bound to the
  worker's TLS key, the route, the body hash, and a nonce with at most a
  120-second life, then recorded in a durable replay store
  (`cathedral/validator_access.py` lines 141-160 and 1563-1685).
- **A static bearer token** for SAT work and capabilities. It carries no caller
  identity, no nonce, and no per-caller limit (`cathedral/worker.py` lines
  332-341 and 412-425). The shipped images refuse it as an input
  (`cathedral/audit_miner_entrypoint.py` lines 118-130).

The worker's TLS server requests no client certificate
(`cathedral/cli.py` lines 1513-1518). Its key is generated fresh inside the
guest on every start (`cathedral/audit_miner_entrypoint.py` lines 193-240), and
validators trust it only because fresh vendor evidence binds its SPKI.

The README states the current trust boundary: "Cathedral does not issue a
credential and no Cathedral API is involved" (`README.md` lines 185-189).

## Requirements

1. **The miner opts in.** No central caller is admitted unless the miner
   configures it. Registration or an image update alone does not enable it.
2. **One offline root.** Cathedral's authority derives from a root key kept
   offline. Online keys are short-lived and individually revocable.
3. **Machine identity comes from attestation.** Central must reach the machine
   the vendor evidence describes, not whatever answers at the address.
4. **Central cannot starve validators, and validators cannot starve central.**
   Separate concurrency, rate and replay budgets.
5. **Central access creates no reward-eligible fact.** Nothing central does
   feeds the weight path.

## Design

### Trust chain

```text
Cathedral root key (Ed25519, offline)
  └── central delegation (cathedral_central_delegation_v1, at most 24 h)
        names one online central key, its routes, and its expiry
          └── central request (cathedral_central_request_v1, at most 120 s)
                signed by that online key for one route, body and TLS key
```

The brief suggested a certificate hierarchy with separate intermediates for
machine certificates and for central's client certificate. This design keeps
the offline root and the short-lived central credential, and departs on two
points:

- **No machine certificates.** The worker's TLS key changes on every start, so
  a machine certificate would need issuing on every start by an online CA. The
  attested SPKI already does that job: central verifies fresh evidence exactly
  as a validator does, then pins that SPKI for the session.
- **Signed requests, not mTLS.** Validators connect without a client
  certificate, so the listener could at most use optional client
  authentication. A per-request signature also carries what a TLS session
  cannot: the route, the body hash, a nonce, and the worker's own TLS key.
  That is the same binding validators already use. The code path is not
  shared: #225 adds a separate Ed25519 verifier, the new `central_access`
  module, and reuses only the validator replay store (`ValidatorAccessState`),
  on its own file.

### Miner opt-in

The miner sets one value, `CATHEDRAL_CENTRAL_ROOT_DIGEST`: the SHA-256 of the
root public-key file it trusts. The image admits it as an optional input
alongside its current inputs. Unset, the worker refuses every central request.
The root public key itself ships in the release bundle. Pinning its digest in
the miner's own env file means that shipping a root key in a release does not
by itself switch central access on.

That consent holds only against an honest release. The release-signing key
runs arbitrary code as root on every enrolled miner
([MINER_AUTO_UPDATE.md](MINER_AUTO_UPDATE.md) lines 19-22). A malicious release
can therefore write the digest into the env file, replace the worker, or bypass
the check altogether. The pin records the miner's choice; it does not protect
that choice from whoever holds the release key.

### Delegation

The root signs a delegation containing:

- `schema`: `cathedral_central_delegation_v1`;
- `root_key_id`: which key in the pinned root file signed it;
- `central_key_base64`: the online Ed25519 public key, 32 bytes in canonical
  base64;
- `routes`: an explicit list, initially `POST /v1/capabilities` only;
- `network` and `netuid`: the subnet it is valid for;
- `sequence`: a monotonic integer;
- `issued_at` and `expires_at`: at most 24 hours apart.

This follows the operator endorsement already used for G4 machines, which has
a 24-hour maximum and a locally pinned trust set
(`cathedral/gpu_provider.py` line 40; [G4_OPERATOR_TRUST.md](G4_OPERATOR_TRUST.md)).

### Request

The header `X-Cathedral-Central-Request` carries the delegation and a request
with the same fields as a validator request: worker hotkey, network, netuid,
method, path, body SHA-256, channel binding type and digest, a 32-byte nonce,
`issued_at` and `expires_at`. The online central key signs it. The worker
checks, before reading the body:

1. central access is configured, and the delegation verifies against the
   pinned root;
2. the delegation is current, its sequence is not below the highest seen, and
   it is not revoked;
3. the route is in the delegation's list;
4. the worker hotkey, network, netuid and channel binding are this worker's;
5. the request window is at most 120 seconds and current;
6. the request signature verifies under the delegation's `central_key_base64`.

After reading the body it checks the body hash and records the nonce in a
central replay table, separate from the validator table and its 4096-entry cap
(`cathedral/validator_access.py` line 98).

### Budgets

Central gets its own pool, limiter and replay table:

- one concurrent request and 60 per minute, separate from the validator
  defaults of one concurrent and 120 per minute
  (`cathedral/validator_access.py` lines 101-103);
- a central pool of 2, outside the existing pools of 4, 2, 2 and 2
  (`cathedral/worker.py` lines 69-72).

### Revocation and rotation

- Delegations expire within 24 hours, so a lost online key is useful for at
  most a day.
- For faster revocation, the root signs a `cathedral_central_revocations_v1`
  list with a monotonic sequence. Workers fetch it with the validator-access
  fetch timer and refuse any listed delegation.
- A revocation list has no freshness bound. Its `issued_at` is parsed but not
  checked against a maximum age, and a worker that cannot fetch a newer list
  keeps the one it has. Withholding the list therefore delays revocation
  without failing closed. The 24-hour delegation expiry is the real bound on a
  compromised delegation; revocation can only shorten it.
- Rotating the root means shipping a new root file in a release and each miner
  updating `CATHEDRAL_CENTRAL_ROOT_DIGEST`. That is consent again, by design,
  with the same limit as above: it binds honest releases only.

### Scope

The first route is `POST /v1/capabilities`: read-only health and inventory,
which the pool tracking service needs. Customer work routes come later, each
added to delegations explicitly. Customer SAT currently requires the static
bearer even for signed callers (`cathedral/worker.py` lines 784-789); a later
change would accept a central request in its place. Until customer work
reaches miners, central access stays read-only. The provider contract already
lists "authenticated assignment transport and replay protection" as a
promotion requirement ([PROVIDER_CONTRACT.md](PROVIDER_CONTRACT.md), line 414);
this design supplies it.

### Reward boundary

The validator never reads central traffic, and nothing central does is signed
into the validator's evidence. Central access cannot raise a miner's weight.

## What an attacker gains

| Compromise | Effect |
|---|---|
| Online central key | Read-only capabilities calls on opted-in miners for at most 24 hours, less once revoked |
| A delegation without its key | Nothing; every request must be signed by the delegated key |
| The root key | Central access on opted-in miners until they change their pinned digest |
| A miner machine | No central credential is stored on it |
| The release-signing key | Root on every host that follows its channel, within about an hour; it can enable or bypass central access whatever digest the miner pinned |

The release-signing key is already root on every enrolled miner
([MINER_AUTO_UPDATE.md](MINER_AUTO_UPDATE.md) lines 19-22). Keep the central
root separate from it, so that compromising the central root does not grant
code execution on miners. The reverse does not hold: a release-key compromise
includes everything a central-root compromise gives.

## Implementation plan

1. A new `central_access` module in the `cathedral` package: delegation and
   request formats, the verifier, the revocation list, and the central replay
   table.
2. `cathedral/worker.py`: the central pool, and route admission for a verified
   central request.
3. `cathedral/cli.py` and the image entrypoints: the optional root-digest
   input and its all-or-none checks.
4. `scripts/`: offline tooling to sign delegations and revocation lists.
5. Tests: every refusal above, with a mutation check for each.

Items 1-3 ship switched off. A miner enables them only by setting the root
digest.

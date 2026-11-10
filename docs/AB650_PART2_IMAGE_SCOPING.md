# AB650 part 2: hotel image ownership (Gate S.1)

Status: **PLAN COMPLETE; IMPLEMENTATION BLOCKED ON BUILD POLICY**.

Reviewed offline on 2026-11-10 at `7f91405b9e8374004d7116493336af9372655f79`,
branch `feature/ab650-part2-image-scoping`. No deployment or live qualification
is claimed. The supplied broker live-proof transcript is historical evidence,
not a fresh check. AB604 must remain on hold.

## Decision required before implementation

The brief explicitly says: "If a design choice needs a product decision, stop
coding there, finish the plan with the options and your recommendation."
This is that branch of the task. No product code has been changed.

A create/fork guard alone leaves a supported route to the same private data:
an arbitrary Dockerfile can consume a foreign local snapshot through `FROM`
or external `COPY --from`, then produce a new image. Assigning the output to
the builder does not authorize the input. Both inline builds and the build API
use the shared classic Docker daemon (`cathedral/sandbox_guest.py:673`,
`:1410`, `:1453`, `:1485`). This is a source-level finding; it has not been
executed against a real Docker daemon or hotel.

Builds are reachable on shared sealed hotels. The broker routes authenticated
compatibility clients to builds (`broker/main.go:2107`, `broker/compat.go:205`)
and dispatches to allowed hotels without excluding sealed hotels
(`broker/build.go:90`). `broker/guests_test.go:285` explicitly tests successful
sealed builds. The dedicated-machine signature gate does not apply when the
hotel has no dedicated owner (`room-kit/room_receipts.py:1949`;
`room-kit/sealed/README.md:201`). Disabling these builds changes an existing
product capability, not just an undocumented implementation detail.

| Option | Consequence | Recommendation |
| --- | --- | --- |
| A. Refuse both hotel-side build routes on shared sealed hotels until their inputs are isolated. Customers build elsewhere and use registry images. | Smallest sound boundary; removes currently supported shared sealed builds. Refuse before Docker runs, including inline builds, with a clear 4xx such as `shared_hotel_build_refused`. | **Recommended for Gate S.1**, subject to product approval of this compatibility change. |
| B. Keep builds by isolating the builder's accessible images and credentials per owner. | Preserves Dockerfile behavior but adds runtime/storage design and qualification beyond the brief's minimal change and no-new-image-store scope. | Separate approved implementation scope; keep AB604 off meanwhile. |
| C. Support only a constrained Dockerfile language with complete source authorization. | Needs an explicit supported-language contract, including variables, stages, external copies and inherited build triggers. Handwritten string checks are insufficient. | Do not choose for this minimal fix. |

The concrete decision is whether to accept option A's loss of shared sealed
hotel-side builds, or expand the work to preserve them safely. This plan does
not silently choose a restriction. There is no proposed flag that permits
unscoped image access. Any shared/dedicated deployment policy must come from
trusted hotel configuration, never a customer's label or request header.

## Who can name what today

All file/line references in this section refer to the source commit above.

| Path | Current behavior and evidence |
| --- | --- |
| Broker create/import | `localImageRefusal` rejects snapshot repository spellings and full/bare image IDs with 422 `snapshot_image_by_name` or `image_reference_refused` (`broker/images.go:245`; regression cases in `broker/local_image_guard_test.go:27`). Registry tags/digests remain allowed. |
| Broker identity | Create overwrites `labels.broker_guest` (`broker/main.go:927`); snapshot does likewise and prefixes names (`broker/images.go:579`). Hotel requests authenticate with the shared hotel key (`broker/main.go:517`). |
| Broker snapshot fork | Lists with the guest label, resolves a visible ID/name, and pins placement to that hotel (`broker/images.go:493`, `:525`). This is broker enforcement, not hotel image ownership. |
| Hotel owner identity | `owner_id` combines the hotel-key hash and guest ID; `guest_from` accepts the trusted broker header, with create-label fallback (`cathedral/sandbox_owner.py:25`, `:35`). The server already passes this owner to create (`cathedral/sandbox_server.py:387`). |
| Hotel explicit image | Contract requires a tag or digest; full `sha256:<hex>` still matches the tag-shaped grammar (`cathedral/sandbox_api.py:107`, `:143`). Existing local images skip pulling (`cathedral/sandbox_guest.py:630`, `:647`, `:1620`, `:1714`). No guest or key ownership check runs before Docker starts them. |
| Hotel snapshots | Inner snapshots belong to the hotel API key, not the broker guest (`cathedral/sandbox_provider.py:266`, `:425`, `:811`). Docker fork resolution uses that visibility (`cathedral/sandbox_guest.py:1489`). Two broker guests on the same hotel key therefore need an additional hotel owner check. |
| Snapshot image | Commit creates `cathedral-snap-<snapshot_id>:latest`; `_snapshot_images` and metadata are process memory (`cathedral/sandbox_guest.py:1281`, `:2099`). Commit itself writes no image owner (`:1040`). |
| Builds | Output names/cache keys use content, without owner scope (`cathedral/sandbox_guest.py:1419`, `:1453`). The server and broker do not forward a guest owner to build (`cathedral/sandbox_server.py:721`; `broker/build.go:123`). |
| Pull/prefetch | Explicit refresh pulls, but `_auth_pulled` is a reference-string set, not an ownership map (`cathedral/sandbox_guest.py:445`, `:1620`, `:2578`). Broker prefetch omits guest context (`broker/images.go:740`, `:776`). |
| Existing key tests | Another hotel key cannot list, fork, push or delete a snapshot by snapshot ID/name (`tests/test_provider_key_isolation.py:35`, `:49`; `tests/test_round6_gaps_guest.py:95`). A refused delete leaves the image. These tests do not establish same-key, cross-guest image isolation. |

The trusted principal is the authenticated hotel API key plus broker guest.
Possession of the hotel's broker credential already permits acting as guest
contexts; this change does not make that credential safe to distribute to
customers. End customers keep their broker credentials only.

## Selected ownership design, conditional on the build decision

Use a **hotel-controlled ownership metadata table keyed by immutable Docker
image ID**, next to the existing hotel data volume. This is metadata for the
one existing Docker image store, not another image store. Each record contains
the allowed `owner_hash(owner_id(...))` scopes and provenance (snapshot, approved
build, or registry pull). Registry grants also bind the canonical reference to
the resolved image ID. Do not store raw API keys or registry credentials.

Choose the table over image labels: arbitrary registry images and Dockerfiles
can supply labels, while only hotel code can grant entries in the table. This
also supports two scopes independently pulling identical registry content.
Use a versioned format, exclusive locking, atomic replacement and durable
flush before acknowledging a grant. A failed write must fail the operation.
Missing, corrupt or incomplete metadata grants nothing. No migration infers
ownership from a tag name, a caller-supplied label, `RepoDigests`, or the first
caller to request an old image.

Enforce at `DockerGuestProvider`, before records/work archives are materialized
and before any guest starts:

1. Derive the caller scope from authenticated key and trusted broker guest.
   A direct provider caller without an explicit owner uses the same key/label
   derivation; absence of guest identity is its own scope, never a wildcard.
2. Resolve a local image reference to its immutable ID. Require that scope's
   grant, otherwise return **403 `image_not_owned`** without exposing another
   owner's identity. Apply this to every Docker-resolved alias, digest and ID.
3. Registry references are authorized by a successful pull under the caller's
   credentials or anonymous registry access, then pinned to the returned ID.
   A cache hit is not registry authorization. Never fall back to an old cached
   local image when registry authorization fails. Preserve credential rechecks
   for private images; explicit prefetch always refreshes.
4. A foreign or unowned local artifact cannot be admitted from the local cache.
   If its spelling is also a real registry reference, only a separate successful
   registry resolution may authorize that registry content. Bare IDs have no
   registry fallback. A failed pull of an existing inaccessible local image
   returns `image_not_owned`; a genuinely absent registry image retains the
   existing pull failure behavior.
5. Commit snapshots and grant their resulting ID to the source room's stored
   owner, not the snapshot request's labels. Record that immutable ID alongside
   snapshot metadata. Fork checks the snapshot owner **before** unpacking `/work`
   and checks image ownership before start. Snapshot list/name lookup, push and
   delete use the same guest-and-key scope, retaining existing not-found behavior.
6. Start by the authorized immutable ID with automatic implicit pulling disabled.
   Keep the user-facing image reference separately so DinD detection and tunables
   still use the intended image type. Coordinate pull/tag/commit/push mutations
   with ID resolution and metadata publication. A tag reused during an operation
   must not change the image being authorized or run.

Existing per-key idempotency must not return another guest's room on a shared
hotel key. Either scope replay keys by the same owner or reject mismatched
ownership before returning a replay. Broker request IDs alone are not the hotel
boundary. Failed admission must not leave a room, quota reservation or reusable
success replay. Owner names and image permissions must not rely on optional
customer label filters.

## Edge cases and rollout

| Case | Required behavior |
| --- | --- |
| Two guests pull the same registry image | Each gets authorization from the registry; the immutable content may be shared. One guest's private-registry cache does not grant access to the other. |
| Digest references and aliases | Distinguish OCI manifest digests from Docker config/image IDs. Resolve the actual ID and check its grant; a tag-like `sha256:<id>` must not bypass the check. |
| Tag reuse and concurrent pulls/pushes | Grants remain attached to content IDs. Fork uses its saved ID and cannot silently follow a replaced snapshot tag. Only the ID proven by the current pull may receive a new grant. |
| Snapshot-like registry name | The spelling alone neither grants nor transfers ownership. An authorized registry pull can supply registry content, never another customer's existing local snapshot. Broker's stricter early refusal may still reject the spelling. |
| Build using a snapshot name or ID | No approval from a new output tag or caller-selected LABEL. Under option A both hotel build paths are refused. Under B all base/copy/trigger inputs must be isolated and authorized. |
| Hotel process restart | Durable ownership survives as long as the Docker data does. Missing records fail closed. Snapshot IDs/tars are currently process-local, and restart reconciliation removes unmatched snapshot tags (`cathedral/sandbox_guest.py:2546`); this task does not promise restored snapshot catalogs or change their retention contract. |
| Legacy local image with no owner | Deny new local-cache use by every name/ID, including the apparent rightful owner. Recover through an authenticated registry pull or a new snapshot of an already-owned running room. Do not grandfather all `cathedral-*` images or guess owners. |
| Existing rooms | Admission checks do not stop, delete or relabel existing containers. A running room's already-recorded owner may create a fresh owned snapshot. A re-seal itself still requires the established drain/migration procedure. |
| Warm pools and preloaded images | The room kit has no internal warm room pool (`cathedral/room_tunables.py:21`). Preserve existing warm containers. Refill via registry pull/prefetch with valid provenance before admission; any baked local-only base needs a measured, explicit image-ID allowlist, not a name-prefix exception. Verify the external pool's real base image before roll. |

Implementation and roll order after the decision: wire trusted guest context,
install ownership enforcement and persistence, cover all admitted build paths,
run the tests below, then re-seal and qualify one staging hotel. Warm registry
images through the new provenance path before accepting traffic. Do not enable
sealed snapshots on a mixed fleet containing hotels without this enforcement.
The source and references do not establish the current live pool inventory.

**Any implementation change under `cathedral/` changes the measured hotel guest
image and requires a new seal, approved measurement and hotel roll.** A broker
binary roll alone cannot deliver this boundary. This documentation-only commit
does not itself change the measured guest. No new feature flag is proposed.

## What the broker still does

Keep `localImageRefusal` as defense in depth and keep snapshot-ID placement,
guest labels, namespacing and ownership checks. Owner creates by snapshot image
name can succeed at the hotel but remain intentionally refused by the broker;
the customer owner uses `snapshot_id` there.

Forward server-selected `X-Cathedral-Guest` on image operations and snapshot
list/create/push/delete, using existing `doGuest` (`broker/guestcalls.go:50`).
Never copy a customer-supplied guest header. Keep the create-label fallback for
roll compatibility. The current build/prefetch calls lack this context.

Broker compatibility image records also need explicit owner checks before
lookup, create or rebuild: `broker/compat.go:207` and `:357` read a global image
map, and a read may trigger `ensureBuilds`. A guest ID inside an opaque image-ID
hash (`broker/build.go:63`) is not authorization. Under option B this must not
allow a caller to rebuild another owner's stored Dockerfile/context and acquire
an ownership grant. Address it with the chosen build scope, not a name filter.

## Acceptance tests to add after the decision

Use fake Docker unit tests for the hotel, but give the fake distinct immutable
IDs, mutable tags, registry-only resolution and truthful aliases. The existing
fake reports one ID for every image (`tests/fake_docker_cli.py:97`), which cannot
prove an ID-based boundary unchanged.

- Same hotel key, different guests: foreign snapshot name, tag alias, full ID,
  digest and fork all fail; owner create/fork succeed with rootfs and `/work`.
- Same guest, different hotel keys: refuse crossing the key scope. Missing
  identity never acts as a wildcard. Snapshot list/push/delete stay scoped.
- Unknown legacy image: no start by any local spelling; existing room and warm
  refill work. Failed registry pull never falls back to the cached image.
- Registry sharing, private credentials, snapshot-like registry names, tag reuse,
  an intervening tag replacement, restart, corrupt metadata and failed persistence.
- Replay and rejected batches leave no foreign room, files, quota or success
  record. Snapshot ownership is copied from the source room, not request labels.
- Both build entry points and build-cache reuse follow the chosen policy. Include
  local `FROM`, external `COPY --from` and inherited build triggers; output-only
  ownership is never accepted as evidence of input authorization.
- Broker tests verify guest-header forwarding, spoof resistance, compatibility
  image-record ownership and the unchanged early guard.

Baseline tests in this checkout exercise existing behavior only. Their results
and environment limitations are recorded in `.refs-ab650/REPORT.md`; they do
not demonstrate that this proposed implementation exists.

## Live proof

The commands below are a post-implementation, post-re-seal runbook. They have
not been run in this offline task. Use two disposable funded broker guests
restricted to the same staging hotel; save the serving commit, measurement and
raw HTTP results with the transcript. No production flag change is part of this
task. Broker refusals alone prove the early guard, so a separate authorized
hotel-HTTP run is needed to prove that the measured hotel enforces ownership.

The broker native HTTP API is a customer surface: use two ordinary broker guest keys, both permitted to use the same named sealed hotel. It uses singular `/snapshot`. The public Polaris API uses plural `/snapshots`, public snapshot ids, and public billing fields; do not mix these contracts. The supplied public API acceptance script is supplementary AB#604 proof, not independent hotel enforcement proof.

### 1. Customer fixtures and positive snapshot/fork

Run all blocks in the same Bash session with `curl` and `jq`. Keep that session open while the operator supplies the fixture readback. Set these variables out of band, without saving keys in the evidence:

```bash
set -euo pipefail
: "${BROKER_BASE:?broker HTTPS origin}"
: "${KEY_A:?ordinary guest A broker key}"
: "${KEY_B:?ordinary guest B broker key}"
: "${HOTEL:?same sealed hotel allowed for both guests}"
: "${GUEST_A_ID:?actual broker guest A id}"
: "${GUEST_B_ID:?actual broker guest B id}"
test "$GUEST_A_ID" != "$GUEST_B_ID"
RUN="ab650-$(date -u +%Y%m%dT%H%M%SZ)-$$"
EVIDENCE="${EVIDENCE:-./$RUN}"
mkdir -p "$EVIDENCE"
touch "$EVIDENCE/rooms.tsv" "$EVIDENCE/snapshots.tsv"

# Each call saves its HTTP status and response, but never its credential.
# Successful creates are recorded before assertions, including an unexpected
# successful negative probe, so cleanup can remove every returned room.
call() {
  local site=$1 who=$2 method=$3 path=$4 body=$5 tag=$6
  local key_name="KEY_$who" guest_name="GUEST_${who}_ID" base token
  local -a args
  base=$BROKER_BASE
  token=${!key_name}
  args=(-sS --connect-timeout 15 --max-time 900 -X "$method"
        -H "Authorization: Bearer $token" -H 'User-Agent: ab650-native-proof/1'
        -H 'Content-Type: application/json')
  if [[ $site == hotel ]]; then
    : "${HOTEL_BASE:?measured hotel HTTPS API origin}"
    : "${HOTEL_KEY:?authorized hotel API key, retained only by operator}"
    base=$HOTEL_BASE
    args=(-sS --connect-timeout 15 --max-time 900 -X "$method"
          -H "Authorization: Bearer $HOTEL_KEY"
          -H "X-Cathedral-Guest: ${!guest_name}"
          -H 'User-Agent: ab650-native-proof/1'
          -H 'Content-Type: application/json')
  fi
  [[ $method == GET || $method == DELETE ]] || args+=(--data-binary "$body")
  OUT="$EVIDENCE/$tag.json"
  STATUS=$(curl "${args[@]}" "$base$path" -o "$OUT" -w '%{http_code}')
  printf '%s\n' "$STATUS" > "$EVIDENCE/$tag.status"
  if [[ $path == /v1/sandboxes && $method == POST && $STATUS =~ ^20[02]$ ]]; then
    jq -r --arg site "$site" --arg who "$who" \
      'select(.id != null) | [$site,$who,.id] | @tsv' "$OUT" >> "$EVIDENCE/rooms.tsv"
  fi
  if [[ $path == */snapshot && $method == POST && $STATUS == 202 ]]; then
    jq -r --arg site "$site" --arg who "$who" \
      'select(.result.snapshot_id != null) | [$site,$who,.result.snapshot_id] | @tsv' \
      "$OUT" >> "$EVIDENCE/snapshots.tsv"
  fi
  printf '%s %s %s -> %s\n' "$site" "$method" "$path" "$STATUS"
}
expect() {
  [[ $STATUS == "$1" ]] || { cat "$OUT"; return 1; }
}

# Cleanup is deliberately usable after any failed assertion. Its status is
# checked below; a lost create response still requires operator reconciliation.
cleanup() {
  local site who id n state
  while IFS=$'\t' read -r site who id; do
    [[ -n $id ]] || continue
    call "$site" "$who" DELETE "/v1/sandboxes/$id" '' "cleanup-room-$id" || continue
    [[ $STATUS == 204 || $STATUS == 404 ]] || continue
    for n in $(seq 1 30); do
      call "$site" "$who" GET "/v1/sandboxes/$id" '' "cleanup-poll-$id" || break
      [[ $STATUS == 404 ]] && break
      state=$(jq -r '.state // empty' "$OUT")
      [[ $state == deleted ]] && break
      sleep 1
    done
  done < "$EVIDENCE/rooms.tsv"
  while IFS=$'\t' read -r site who id; do
    [[ -n $id ]] || continue
    call "$site" "$who" DELETE "/v1/snapshots/$id" '' "cleanup-snapshot-$id" || continue
  done < "$EVIDENCE/snapshots.tsv"
}
trap cleanup EXIT

for who in A B; do
  body=$(jq -nc --arg hotel "$HOTEL" --arg run "$RUN" \
    '{image:"alpine:3.20",hotels:[$hotel],sealed:true,ttl_seconds:600,
      resources:{vcpu:1,memory_gib:4,disk_gib:10},network:{mode:"deny_all"},labels:{proof:$run}}')
  call broker "$who" POST /v1/sandboxes "$body" "$who-source-create"
  expect 202
  jq -e --arg hotel "$HOTEL" '.hotel == $hotel' "$OUT" >/dev/null
  id=$(jq -er '.id' "$OUT")
  printf -v "ID_$who" '%s' "$id"
  marker="$RUN-$who"
  body=$(jq -nc --arg marker "$marker" \
    '{cmd:["sh","-c","printf %s \"$1\" > /ab650-root; printf %s \"$1\" > /work/ab650-owner","proof",$marker],timeout_seconds:30}')
  call broker "$who" POST "/v1/sandboxes/$id/exec" "$body" "$who-write-marker"
  expect 200
  jq -e '.exit_code == 0' "$OUT" >/dev/null
  body=$(jq -nc --arg name "$RUN-$who" '{name:$name,ttl_seconds:600}')
  call broker "$who" POST "/v1/sandboxes/$id/snapshot" "$body" "$who-snapshot"
  expect 202
  snap=$(jq -er '.result.snapshot_id' "$OUT")
  printf -v "SNAP_$who" '%s' "$snap"
  image=$(jq -er '.result.image' "$OUT")
  printf -v "IMAGE_$who" '%s' "$image"
  body=$(jq -nc --arg snap "$snap" --arg hotel "$HOTEL" \
    '{snapshot_id:$snap,hotels:[$hotel],sealed:true,ttl_seconds:600,network:{mode:"deny_all"}}')
  call broker "$who" POST /v1/sandboxes "$body" "$who-own-fork-create"
  expect 202
  fork=$(jq -er '.id' "$OUT")
  jq -e --arg hotel "$HOTEL" '.hotel == $hotel' "$OUT" >/dev/null
  call broker "$who" POST "/v1/sandboxes/$fork/exec" \
    '{"cmd":["sh","-c","cat /ab650-root; printf ":"; cat /work/ab650-owner"],"timeout_seconds":30}' \
    "$who-own-fork-exec"
  expect 200
  jq -e --arg expected "$marker:$marker" '.exit_code == 0 and .stdout == $expected' "$OUT" >/dev/null
done
```

Both guests have pulled the same registry image on the same hotel. Both have independently snapshotted and forked their own marker, including the committed root filesystem and `/work` archive.

### 2. Reference readback and broker negatives

Before continuing, have the authorized proof operator read back the fixture's actual Docker image identity and aliases without handing the hotel key to a customer. Record that each supplied reference resolves to `IMAGE_B`'s immutable image ID. The current snapshot response exposes a tag, not the image ID (`cathedral/sandbox_guest.py:2148-2154`).

Supply these values in this same shell after fixture creation:

- `B_IMAGE_ID`: actual full `sha256:<64 hex>` image ID for `IMAGE_B`.
- `B_ALIAS`: actual second local tag for that same image whose last repository component does not start with `cathedral-snap-`; this tests a name that passes the broker string guard. Use a unique fixture name such as `ab650.invalid/proof/<run>:1` and verify that neither anonymous nor A-authorized registry resolution exists for it. Do not retag a public registry reference such as `alpine:3.20`, whose successful registry resolution is allowed by this design. Creating the alias requires a separately authorized fixture step. The deployed customer API has no alias route.
- `B_DIGEST_STATE=present` and `B_DIGEST_REF`: actual locally resolving `repository@sha256:<digest>` for the same private image, if one exists. Confirm that neither anonymous nor A-authorized registry access can retrieve it before asserting a refusal. Do not substitute the config image ID for a registry manifest digest.
- `B_DIGEST_STATE=absent`: only when authorized readback proves this committed image has no `RepoDigests`. Save that readback and mark the digest-alias case not applicable. A snapshot committed locally normally has no registry digest. A fabricated digest is merely a missing-image test. A registry publication that grants A access is an allowed registry use and must not be called an ownership failure.

```bash
: "${B_IMAGE_ID:?real immutable image ID from authorized readback}"
: "${B_ALIAS:?real non-snapshot local alias for IMAGE_B from authorized fixture setup}"
: "${B_DIGEST_STATE:?present or absent, backed by readback}"
[[ $B_IMAGE_ID =~ ^sha256:[0-9a-f]{64}$ ]]
hex=${B_IMAGE_ID#sha256:}
refs=("$IMAGE_B" "${IMAGE_B%:latest}" "library/$IMAGE_B"
      "docker.io/library/$IMAGE_B" "$B_IMAGE_ID" "$hex" "${hex:0:12}" "$B_ALIAS")
if [[ $B_DIGEST_STATE == present ]]; then
  : "${B_DIGEST_REF:?real digest reference resolving to B_IMAGE_ID}"
  refs+=("$B_DIGEST_REF")
else
  [[ $B_DIGEST_STATE == absent ]]
fi

body=$(jq -nc --arg snap "$SNAP_B" --arg hotel "$HOTEL" \
  '{snapshot_id:$snap,hotels:[$hotel],sealed:true,ttl_seconds:600,network:{mode:"deny_all"}}')
call broker A POST /v1/sandboxes "$body" A-foreign-snapshot-create
expect 404
jq -e '.error.code == "snapshot_not_found"' "$OUT" >/dev/null

i=0
for ref in "${refs[@]}"; do
  i=$((i + 1))
  body=$(jq -nc --arg image "$ref" --arg hotel "$HOTEL" \
    '{image:$image,hotels:[$hotel],sealed:true,ttl_seconds:600,network:{mode:"deny_all"}}')
  call broker A POST /v1/sandboxes "$body" "broker-negative-$i-create"
  [[ $STATUS =~ ^4[0-9][0-9]$ ]]
  jq -e '.error.code == "snapshot_image_by_name" or
         .error.code == "image_reference_refused" or
         .error.code == "invalid_image_reference" or
         .error.code == "image_not_owned"' "$OUT" >/dev/null
  if [[ $ref == "$B_ALIAS" ]]; then
    expect 403
    jq -e '.error.code == "image_not_owned"' "$OUT" >/dev/null
  fi
done
```

The alias must receive the hotel's ownership error. Snapshot-name and ID refusals alone only verify the broker guard. If the final implementation chooses a different documented 4xx for `image_not_owned`, replace the exact `403` assertions accordingly before running.

### 3. Independent measured-hotel HTTP proof

The operator uses the same native customer create/exec/snapshot contract directly against the measured hotel API with the shared hotel key and `X-Cathedral-Guest`. This bypasses the broker's string guard. It is a distinct proof step, not an instruction to expose the hotel credential to customers. Use the same key scope as the broker-created fixtures. A dedicated owner-signed hotel is a different tenancy model and is not this shared-hotel test.

```bash
: "${HOTEL_BASE:?measured shared hotel HTTPS API origin}"
: "${HOTEL_KEY:?same authorized hotel API key used by broker for this hotel}"

i=0
for ref in "${refs[@]}"; do
  i=$((i + 1))
  body=$(jq -nc --arg image "$ref" --arg guest "$GUEST_A_ID" \
    '{image:$image,ttl_seconds:600,network:{mode:"deny_all"},labels:{broker_guest:$guest}}')
  call hotel A POST /v1/sandboxes "$body" "hotel-negative-$i-create"
  if [[ $ref == "$hex" || $ref == "${hex:0:12}" || $ref == "${IMAGE_B%:latest}" ]]; then
    # Existing API syntax requires a tag or digest. These forms never reach Docker.
    expect 400
    jq -e '.error.code == "invalid_image_reference"' "$OUT" >/dev/null
  else
    expect 403
    jq -e '.error.code == "image_not_owned"' "$OUT" >/dev/null
  fi
done

hotel_snap_b=${SNAP_B#"$HOTEL."}
body=$(jq -nc --arg snap "$hotel_snap_b" --arg guest "$GUEST_A_ID" \
  '{snapshot_id:$snap,ttl_seconds:600,network:{mode:"deny_all"},labels:{broker_guest:$guest}}')
call hotel A POST /v1/sandboxes "$body" hotel-A-foreign-fork-create
expect 404
jq -e '.error.code == "snapshot_not_found"' "$OUT" >/dev/null

# B can use its exact local image and non-snapshot alias; A can use its own snapshot.
for ref in "$IMAGE_B" "$B_ALIAS" "$B_IMAGE_ID"; do
  body=$(jq -nc --arg image "$ref" --arg guest "$GUEST_B_ID" \
    '{image:$image,ttl_seconds:600,network:{mode:"deny_all"},labels:{broker_guest:$guest}}')
  tag="hotel-B-owner-$(printf %s "$ref" | shasum -a 256 | cut -c 1-12)-create"
  call hotel B POST /v1/sandboxes "$body" "$tag"
  expect 202
  id=$(jq -er '.id' "$OUT")
  call hotel B POST "/v1/sandboxes/$id/exec" \
    '{"cmd":["cat","/ab650-root"],"timeout_seconds":30}' "$tag-exec"
  expect 200
  jq -e --arg expected "$RUN-B" '.exit_code == 0 and .stdout == $expected' "$OUT" >/dev/null
done

hotel_snap_a=${SNAP_A#"$HOTEL."}
body=$(jq -nc --arg snap "$hotel_snap_a" --arg guest "$GUEST_A_ID" \
  '{snapshot_id:$snap,ttl_seconds:600,network:{mode:"deny_all"},labels:{broker_guest:$guest}}')
call hotel A POST /v1/sandboxes "$body" hotel-A-own-fork-create
expect 202
id=$(jq -er '.id' "$OUT")
call hotel A POST "/v1/sandboxes/$id/exec" \
  '{"cmd":["sh","-c","cat /ab650-root; printf ":"; cat /work/ab650-owner"],"timeout_seconds":30}' \
  hotel-A-own-fork-exec
expect 200
jq -e --arg expected "$RUN-A:$RUN-A" '.exit_code == 0 and .stdout == $expected' "$OUT" >/dev/null
```

Repeat a direct hotel create for the B image with the same guest id and a separately configured second hotel API key. It must receive `image_not_owned`; use a hotel instance that actually supports two valid keys. The sealed front normally exposes one hotel key, and miner fronts replace it with an internal key (`room-kit/room_receipts.py:1790-1794`), so changing an unrecognized Bearer token only proves authentication. Do not claim it proves owner-scope separation. Test the two valid key scopes through the hotel API directly in a suitable staging fixture if the deployed front cannot expose them.

### 4. Build bypass regression for recommended option A

The following assertions specify option A, if approved: 403 `shared_hotel_build_refused` for both hotel build routes. If option B is chosen, replace this section with its input-isolation acceptance contract before running. Use only the test B image from above. These are future regression inputs, not proof already run.

```bash
from_b=$(printf 'FROM %s\n' "$IMAGE_B")
copy_b=$(printf 'FROM alpine:3.20\nCOPY --from=%s /ab650-root /ab650-root\n' "$IMAGE_B")

for df in "$from_b" "$copy_b"; do
  tag="build-$(printf %s "$df" | shasum -a 256 | cut -c 1-12)"
  body=$(jq -nc --arg dockerfile "$df" '{dockerfile:$dockerfile}')
  call hotel A POST /v1/images/build "$body" "hotel-$tag"
  expect 403
  jq -e '.error.code == "shared_hotel_build_refused"' "$OUT" >/dev/null

  body=$(jq -nc --arg dockerfile "$df" --arg guest "$GUEST_A_ID" \
    '{build:{dockerfile:$dockerfile,context_multipart:true},ttl_seconds:600,
      network:{mode:"deny_all"},labels:{broker_guest:$guest}}')
  call hotel A POST /v1/sandboxes "$body" "hotel-inline-$tag-create"
  expect 403
  jq -e '.error.code == "shared_hotel_build_refused"' "$OUT" >/dev/null

  body=$(jq -nc --arg dockerfile "$df" --arg hotel "$HOTEL" \
    '{build:{dockerfile:$dockerfile,context_multipart:true},hotels:[$hotel],sealed:true,
      ttl_seconds:600,network:{mode:"deny_all"}}')
  call broker A POST /v1/sandboxes "$body" "broker-inline-$tag-create"
  expect 403
  jq -e '.error.code == "shared_hotel_build_refused"' "$OUT" >/dev/null

  # Published client endpoint: multipart at broker, JSON at hotel.
  # For option A, both test guests must be restricted to this shared sealed
  # hotel so no allowed unsealed hotel's successful build masks the refusal.
  curl -sS --connect-timeout 15 --max-time 900 \
    -H "Authorization: Bearer $KEY_A" -H 'User-Agent: ctcli/ab650-proof' \
    --form-string "dockerfile=$df" "$BROKER_BASE/v1/images/build" \
    -o "$EVIDENCE/broker-$tag.json" -w '%{http_code}\n' \
    > "$EVIDENCE/broker-$tag.status"
  test "$(cat "$EVIDENCE/broker-$tag.status")" = 200
  build_id=$(jq -er '.image_id' "$EVIDENCE/broker-$tag.json")
  state=pending
  for n in $(seq 1 60); do
    status=$(curl -sS --connect-timeout 15 --max-time 60 \
      -H "Authorization: Bearer $KEY_A" -H 'User-Agent: ctcli/ab650-proof' \
      "$BROKER_BASE/v1/images/$build_id" \
      -o "$EVIDENCE/broker-$tag-poll-$n.json" -w '%{http_code}')
    printf '%s\n' "$status" > "$EVIDENCE/broker-$tag-poll-$n.status"
    test "$status" = 200
    state=$(jq -er '.state' "$EVIDENCE/broker-$tag-poll-$n.json")
    [[ $state == pending ]] || break
    sleep 1
  done
  test "$state" = failed
  jq -e '.error == "image_build_failed" and
         (.message | contains("shared_hotel_build_refused"))' \
    "$EVIDENCE/broker-$tag-poll-$n.json" >/dev/null
done
```

The broker build endpoint is asynchronous; a successful registration is not a
safe build. These assertions preserve its current response envelope. If the
chosen implementation adds an immediate broker refusal, update the assertion
to that documented 4xx before running. Under option B, also require ordinary
`FROM alpine:3.20` to succeed and verify that guest A cannot fetch or create
from B's broker build record by its `image_id`. Existing broker code hashes
the guest into IDs but performs global lookups without an owner check
(`broker/compat.go:207-219,357-379`).

### 5. Cleanup and evidence interpretation

```bash
cleanup
trap - EXIT
```

Inspect every `cleanup-*.status` and room poll body. Each recorded room must be absent or terminal deleted, and every snapshot delete must return success or already absent. An operator must reconcile a request whose transport failed before an ID was returned. Remove only the separately authorized B alias fixture using its approved maintenance procedure; the customer API has no image alias delete route. Never run broad image pruning.

Record syntax-invalid forms separately from genuine ownership refusals. Record no-charge/refusal claims only from the relevant API billing evidence. This procedure creates real test rooms and snapshots; it does not authorize a flag flip, deployment, customer contact, or spend. The AB#604 public API ten-fork, receipt and rollback script remains required after Gate S.1, with its own authorization.

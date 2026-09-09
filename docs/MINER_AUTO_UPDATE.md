# Miner auto-update

Status: exercised end to end on a live Intel TDX miner on 2026-09-09.

A confidential `c3-standard-4` TDX guest on GCP was registered on SN39 as UID
213, installed at image `c73070da`, enrolled into this channel, and moved to
`d50ebe66` by a signed stable release. The updater reported `activated` and the
running container really did change.

That run also found two defects that local tests could not, both now fixed and
described under "What counts as success" and "When a restart is unsafe". Read
those two sections before enabling the timer anywhere.

An installed SN39 SNP miner pins its version in one line of
`/etc/cathedral/sn39-snp-miner.env`:

```
SN39_SNP_MINER_IMAGE=ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:<64hex>
```

Nothing on the host has ever changed that line. Publishing a new image does not
move an installed miner, which is why an upgrade has until now meant messaging
the operator. This adds a signed channel the miner follows on its own.

## What updates automatically

The container image, and with it the worker, the entrypoint and the pinned
`snpguest`. That is all.

These never change in a routine release, because changing any of them is a
different kind of decision:

- the miner hotkey, public endpoint and fleet configuration
- validator-access snapshots, keys and replay state
- the trusted miner release public keys
- the systemd units and the launcher on disk
- anything about who may rent capacity on this host

An automatic update does not give Cathedral shell access, does not move wallet
keys, does not change any validator's SNP policy, and does not alter a
provider's consent to rent out capacity. Those are separate, and stay separate.

## Cadence

The timer checks 15 minutes after boot and hourly after that, with up to five
minutes of random delay. That matches the validator's published cadence so
operators only have to learn one number. The jitter keeps a fleet from hitting
the channel in lockstep.

A fleet therefore converges over roughly an hour, not instantly. There is no
push and no instantaneous propagation.

## What the miner checks before installing anything

In order, stopping at the first failure and leaving the running miner alone:

1. The record is strict JSON with no duplicate keys and no unknown fields.
2. Its Ed25519 signature verifies against a key listed in
   `/etc/cathedral/sn39-miner-update-keys.json`.
3. Only then is anything else read. Identity is checked after the signature so
   an unsigned record cannot probe which product or channel a host follows.
4. The `schema` is the miner record schema and the `product` is this product.
   A perfectly valid validator release fails both, and a host holding only
   miner keys cannot verify one at all.
5. The channel matches, and the record has not expired.
6. The sequence does not go backwards, and an existing sequence is not reused
   for different signed bytes. The sequence is recorded **before** the attempt,
   so a release that fails still consumes it. Otherwise a second, different
   record could reuse that sequence and slip past the equivocation check.
7. The pin file names a current image. Without one there would be nothing to
   roll back to, so the update is refused rather than started.
8. The installed launcher matches the `launcher_sha256` the release names and
   accepts its runtime contract. The launcher hard-codes the contract it will
   run, so an incompatible release would otherwise stop a working miner and
   only then fail.
9. The image is digest-pinned to the canonical repository. No mutable tags.
10. The image is pulled, and the registry is confirmed to return that exact
    digest, that platform, and that runtime-contract label.

All of it happens while the previous image is still pinned and serving, so any
of these failing costs nothing.

Only one check runs at a time. An operator running a manual check while the
timer fires is refused with "another update check is already running" rather
than queued, because two processes rewriting the pin is the interleaving that
leaves a miner running neither version.

## What counts as success

The released image is what the running container reports, **and it has been up
long enough to count as running**, and the unit is `active`.

Not "the unit is active" on its own. After an interrupted activation the
*previous* container is often still active and perfectly healthy, and treating
that as success would commit a release that never started.

The dwell is not theoretical caution. On the first live run the upgraded image
could not start and crash-looped. A container that starts and exits immediately
still reports `Running=true` in between, so a check without a dwell sampled one
of those windows, called the release healthy, and committed an update to a miner
that was in fact failing. systemd then hit its start limit and nothing was
serving at all. The check now requires the container to have been up for
`SETTLE_DWELL_SECONDS`, and refuses a unit that is `activating` or `failed`.

## When a restart is unsafe

A restart makes the miner re-read its validator-access snapshot. That snapshot
is short-lived and refreshed out of band. Restarting close to its expiry can
leave the miner unable to start at all.

This is what actually broke the live run: the snapshot lapsed between install
and update, the upgraded image refused to start five times with
`validator access snapshot is absent, stale, or invalid`, and the unit gave up.
The fix was a fresh snapshot, not a rollback.

So `safe_to_activate` now refuses to restart unless the snapshot has at least
`MINIMUM_ACCESS_REMAINING_SECONDS` left, and treats an unreadable snapshot as
unsafe. An unknown answer is not a licence to stop a working miner.

This is the same fragility as cathedral-validator#236. An updater that restarts
miners makes a short-lived, out-of-band credential considerably more dangerous
than it already was.

## If an update fails

The updater will not guess about one thing: whether the released image ever
ran. It matters because the launcher bind-mounts durable state read-write, so
an image that started, wrote, and then died leaves state the previous image may
not understand. Starting the old image against it is corruption, not a
rollback.

So the outcome depends on evidence, not on what the pin file says:

- **Registry unreachable, digest mismatch, wrong contract, incompatible
  launcher.** Nothing changed, and nothing could have run.
- **The release did not come up, and durable state is byte-for-byte unchanged.**
  That is positive evidence it wrote nothing, so the previous image is restored
  and *verified to be running again* before the restoration is reported.
- **The release did not come up, and durable state changed.** It may already
  have written. The updater stops, leaves the pin naming the release, and asks
  for an operator.
- **The restore itself fails, or the previous image does not come back.** Said
  plainly, including that the miner may be running nothing. This is a real
  case: the miner unit allows five starts per 300 seconds, so a release that
  fails repeatedly can exhaust the allowance and the rollback start is refused
  too. It is never reported as a successful restoration.
- **Power lost mid-activation.** The next run decides on what is actually
  running plus whether durable state moved. Released image running: commit.
  Previous image running and nothing written: restore the pin and retry.
  Anything else, including nothing running: stop and ask.

A host in that state reports `"needs_operator": true` from `status`, and every
halt prints what it saw: what was running, what was expected, and whether
durable state changed.

## Pause

```bash
touch /etc/cathedral/sn39-snp-miner-update.paused   # stop updating
rm    /etc/cathedral/sn39-snp-miner-update.paused   # resume
```

The check exits immediately and reports `paused`. Mining is unaffected.

## Status

```bash
cathedral-sn39-miner-update status
```

Reports the pinned image, whether updates are paused, any in-progress stage,
and the last committed record per channel. It reads the same file that holds
the miner hotkey and the validator-access digest and prints neither.

## One-time bootstrap for an already-installed miner

An installed miner has no updater, so the first step cannot be delivered
remotely. It is one operator-applied command, and every later release is
unattended.

```bash
sudo ./install-miner-update.sh \
  --revision <40-character commit> \
  --keys /path/to/sn39-miner-update-keys.json \
  --channel stable \
  --channel-url https://.../sn39-snp-miner/stable.json
```

It prints the current image pin before it changes anything, installs the
updater from that exact pinned revision, verifies the checkout resolved to the
commit that was asked for, and installs the units. It does not enable the timer
and does not change which image is pinned. Enable the timer after one manual
check looks right.

## Publishing a release

Three separate steps. None of them implies the next.

**1. Merge the source.** An ordinary pull request into `main`.

**2. Publish the image.** The existing
`.github/workflows/publish-sn39-snp-miner.yml` builds and pushes an immutable
digest with provenance. This changes nothing on any miner.

**3. Sign and promote.** Offline, on the machine holding the release key.

```bash
# canary, naming the image directly
CATHEDRAL_MINER_RELEASE_PASSPHRASE=... \
python deploy/miner-update/build_signed_miner_release.py canary \
  --private-key /secure/offline/sn39-miner-release-private-key.pem \
  --signing-key-id sn39-miner-release-1 \
  --image ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:<64hex> \
  --runtime-contract snp-signed-validator-fleet-v1 \
  --launcher scripts/run_sn39_snp_miner.sh \
  --version 2026.09.09 --sequence <next> --lifetime-seconds 604800 \
  --out /secure/signed/miner-canary.json

# stable, promoting that exact canary after it has been observed
CATHEDRAL_MINER_RELEASE_PASSPHRASE=... \
python deploy/miner-update/build_signed_miner_release.py stable \
  --private-key /secure/offline/sn39-miner-release-private-key.pem \
  --signing-key-id sn39-miner-release-1 \
  --promote /secure/signed/miner-canary.json \
  --sequence <next> --lifetime-seconds 604800 \
  --out /secure/signed/miner-stable.json
```

Promotion re-signs the canary's image. It never rebuilds, so a stable release
always names the canary that was tested and can be traced back to it. The
signer verifies the canary before promoting it, refuses to overwrite an
existing signed record, and refuses a key that is group or world readable.

Publishing the resulting JSON at the channel URL is the step that actually
moves miners.

## Key separation

The miner release key is not the validator release key and must never be the
same key. Two products sharing one signing key would remove the strongest of
the three barriers between them, leaving only field checks. Keep them
separately generated, separately backed up and separately recorded.

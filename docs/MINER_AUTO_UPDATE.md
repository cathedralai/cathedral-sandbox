# Miner auto-update

Status: implemented and covered by local tests. Not yet exercised on a live
miner, and no signed miner release has been published. Where this page names a
digest or a channel URL, treat it as pending until a release exists.

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
5. The channel matches the one this miner follows, and the record has not
   expired.
6. The sequence does not go backwards, and an existing sequence is not reused
   for different signed bytes.
7. The image is digest-pinned to the canonical repository. No mutable tags.
8. The image is pulled and the registry is confirmed to return that exact
   digest, all while the previous image is still the one pinned.

Only after all of that is the pin rewritten and the unit restarted. The rewrite
replaces one assignment and leaves every other line, including comments,
untouched.

## If an update fails

- Registry unreachable, or the digest does not match: nothing changed.
- The restart fails, or the miner does not come back: the previous image is
  restored and the miner is restarted onto it.
- Power lost mid-activation: on the next run the updater compares the pin
  against its durable record. If the swap never landed it retries. If the new
  image is running and healthy it commits. If the new image is running and is
  not healthy, it **stops and asks for an operator** rather than reverting,
  because reverting could discard state the new version already migrated.

That last case prints a clear reason and exits non-zero. It is the one case
that needs a human, and it is deliberately not automated.

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
  --runtime-contract cathedral.sn39.snp.v1 \
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

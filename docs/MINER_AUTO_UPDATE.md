# Miner auto-update

Status: built and tested locally (unit tests, a mount-namespace emulation of
the updater's systemd sandbox, and `systemd-analyze verify`). **It has not run
on a live miner yet.** The first live run is part of the rollout below.

This replaces draft PR #197. #197 was run once by hand on a TDX guest. Its
review found that the run's `activated` was a false positive, and that the
hourly timer could never apply a release. See
`pool-research/review-sandbox-pr-197-miner-auto-update.md` in the handoff
folder.

A miner follows one signed channel. When the channel names a newer release,
the host installs it without anyone logging in. The miner's hotkey, endpoint,
env file and validator-access material are never touched.

## What a release carries

A release is one signed record (`cathedral/miner_release.py`). It names:

- the **product** (`snp-miner` or `audit-miner`), the **network** and the
  **netuid**. The host refuses a record for anything else. Network and netuid
  come from the host's deploy config and have no defaults;
- the **channel** (`canary` or `stable`) and a **sequence** that never goes
  backwards on a host;
- the container **image**, by digest, in a `ghcr.io/cathedralai/` repository;
- the **host bundle**, by archive and tree digest (`cathedral/miner_bundle.py`):
  - the updater's own code;
  - the product launcher;
  - a drop-in for the miner's systemd unit;
  - the release keys the next check will trust;
- the **state schema**: the durable-state format the image writes. It decides
  whether a failed release may roll back on its own. See "Rollback" below;
- an issue time and an expiry. The lifetime is at most 14 days, and a record
  is refused if it is issued more than 300 seconds in the future. These are
  the validator updater's rules.

So a launcher change, a unit change, a new required input such as the netuid,
a new trust root, and a fix to the updater itself all arrive the same way as a
new image.

## Install (once per host)

This is the only step that needs hands on the host.

Prerequisites:

- the distribution's `python3` (3.10 or newer) and its `python3-cryptography`
  package. The updater installs nothing from a package index;
- `git`, `docker` and `systemd`;
- the miner already installed as a systemd unit. For the SNP miner that is
  `examples/systemd/cathedral-sn<N>-snp-miner.service`. For a new TDX host,
  use `examples/systemd/cathedral-audit-miner.service` and
  `examples/systemd/audit-miner.env.example`. That unit runs whichever
  launcher the active signed release installs.

Take the commit and the trust-root digest from the release announcement, not
from this repository. Then, as root:

```bash
sudo ./deploy/miner-update/install-miner-update.sh \
  --revision <40-hex commit> \
  --keys-sha256 <sha256 of deploy/miner-update/release-keys.json at that commit> \
  --product snp-miner \
  --network <network> --netuid <netuid> \
  --channel stable \
  --channel-url https://<channel host>/snp-miner/stable.json \
  --miner-unit <the miner's unit name>
```

The installer clones that exact commit and checks that `HEAD` is the commit
asked for. It then runs `cathedral/miner_bootstrap.py`, which:

1. refuses unless the committed trust root's SHA-256 equals `--keys-sha256`.
   It prints each key's fingerprint and channels;
2. reads the launcher the miner unit runs today, and refuses if it is not a
   launcher for this product;
3. installs the updater tree under
   `/usr/local/lib/cathedral-miner-update/updater/releases/<tree>`. It is the
   same tree a release of this commit would ship;
4. records the unit's own launcher as the `legacy` release. It links
   `/etc/systemd/system/<unit>.d/50-cathedral-miner-update.conf` to
   `miner/current/unit.conf`, which is empty while `legacy` is current. So
   the miner unit is unchanged;
5. writes `/etc/cathedral/miner-update/config.json`, installs the frozen shim
   and `cathedral-miner-update.service` and `.timer`, and runs
   `systemctl daemon-reload`.

It does not enable the timer. Run one check by hand first:

```bash
cathedral-miner-update check
cathedral-miner-update status
systemctl enable --now cathedral-miner-update.timer
```

## Operator flow

The timer runs `check` 15 minutes after boot, then hourly, with up to 5
minutes of jitter.

| Command | Effect |
|---|---|
| `cathedral-miner-update status` | Config, the active release, the updater tree, the last check, the last refusal, consecutive deferrals, remembered failures, floors. Works without the channel. |
| `cathedral-miner-update pause [--reason TEXT]` / `resume` | Stop and restart checking. A paused check fetches nothing. |
| `cathedral-miner-update pin --version V` or `pin --current` / `unpin` | Hold the miner at one version. Checks still verify the channel and advance the floor, and report `held`. Nothing is installed, including updater updates. |
| `cathedral-miner-update resolve --restore-previous` | After a halt: put the previous release back and verify it runs. |
| `cathedral-miner-update resolve --accept-release` | After a halt: accept the new release, if it is running. |
| `cathedral-miner-update resolve --retry` | Forget a remembered failure, so the next check retries it. |

`check` prints one JSON line and exits with:

| Exit | Meaning | Unit |
|---|---|---|
| 0 | `current`, `activated`, `held`, `paused` or `deferred` | succeeds |
| 10 | `refused` or `rolled_back`. The reason says why, and the miner still runs what it ran before | fails |
| 11 | `halted`. An operator must choose a `resolve` action | fails |
| 12 | `deferred` six checks in a row: the safe-restart gate keeps saying no | fails |

A non-zero exit fails the oneshot unit, so `systemctl --failed` shows a miner
that is not updating.

## What one check does

1. **Recover.** An activation a previous run left unfinished is resolved first
   (see "Rollback").
2. **Verify.** Fetch the record over https, with no redirects and a size cap,
   and a total deadline enforced while reading. Check the signature and the
   key's channel role. Then check product, network, netuid, channel,
   lifetime, not-yet-valid and expiry. Then check the sequence floor and
   equivocation. The sequence is recorded **before** anything else, so a
   failed release still consumes it.
3. **Self-update first.** If the record's bundle is not the tree this updater
   runs from, install it, probe it, make it current, and hand the rest of the
   check to it (see "Self-update").
4. **Activate.**
   - Build `miner/releases/<activation>/`: the launcher, `release.env` (the
     image pin, `CATHEDRAL_NETWORK` and `CATHEDRAL_NETUID`), the unit drop-in
     and a profile.
   - Pull the image and verify its digest, platform and runtime-contract
     label.
   - Check again that a restart is safe.
   - Set the `may_have_run` latch.
   - Point `miner/current` at the new directory with one `rename(2)`.
   - Run `systemctl daemon-reload`, `reset-failed` and `restart`.
   - Commit only when the container reports the released image and has been
     up for 20 seconds.

The operator's env file keeps its old image line. systemd loads `release.env`
after it, and the later assignment wins.

**Safe to restart.** A restart makes the miner re-read its validator-access
snapshot, and the snapshot is short-lived. So the check restarts only when
`/etc/cathedral/validator-access/validator-access.json` has at least 600
seconds left. That is enough for the restart, the settle wait and a rollback
restart. It checks again right after the pull, because a slow pull can use up
the margin. The updater's unit keeps that file readable. #197's unit hid it,
so every unattended check deferred.

## Rollback

#197 allowed a rollback only if a fingerprint of the miner's durable state was
unchanged. The running miner writes that database on every validator request.
So on a live miner, rollback was almost never allowed.

Now each record declares `state_schema`, and every image reads every schema up
to its own. When a release fails to come up, the updater rolls back on its
own in two cases:

- the previous release's schema is at least the new one's. The previous image
  can read anything the new image wrote;
- the image is unchanged, and only the launcher or the unit changed.

Rolling back points `miner/current` back at the previous directory and runs
`daemon-reload`, `reset-failed` and `restart`. `reset-failed` is there
because a crash-looping release can exhaust the unit's start limit. The
rollback is reported only once the previous image is running again. The
failed release is remembered and not retried until a newer record arrives or
an operator runs `resolve --retry`.

Otherwise the updater halts and waits for `resolve`:

- the release raises the schema;
- the previous schema is unknown. This happens on the first move from the
  `legacy` launcher to a different image;
- the previous image does not come back.

## Self-update

Every release ships the updater's code, and a check installs it before it does
anything else. So the rest of each release runs under the code that release
ships. Three guards stop a bad updater from stranding a host:

1. **Probe.** Before the new tree becomes current, the new code runs `probe`
   from its own directory. It verifies the record that delivered it, with the
   trust root it ships and this host's config. It also reads this host's state
   and hashes its own tree. An import error, a broken verifier, or a trust
   root that would lock the host out all fail here, and nothing changes.
2. **First run.** The new updater then runs the rest of the check as a child
   that inherits the lock. If it crashes, meaning any exit status other than
   0, 10, 11 or 12, the old updater is put back.
3. **Shim.** `bin/cathedral-miner-update` is installed once by the bootstrap
   and never replaced. If the current updater crashes on a later run, the
   shim runs the previous updater. That updater makes itself current and
   remembers the crashed release.

A failed updater release is remembered and not retried.

Not updated through the channel: the shim, the updater's own service and
timer, and the host's Python. They are the recovery path. A signed but wrong
sandbox in the updater's own unit would disable the channel that could fix it.
Changing them needs a new bootstrap.

## Signer flow (offline)

Run `deploy/miner-update/build_signed_miner_release.py` on the machine that
holds the keys. Never run it in CI or on a miner.

**Keys.** Give canary and stable separate keys. Keep them encrypted at rest.
The signer refuses an unencrypted key.

```bash
openssl genpkey -algorithm ed25519 -aes-256-cbc -out stable-1.pem   # asks for a passphrase
chmod 600 stable-1.pem
export CATHEDRAL_MINER_RELEASE_PASSPHRASE=...                        # never on the command line
python deploy/miner-update/build_signed_miner_release.py trust-entry \
  --private-key stable-1.pem --key-id stable-1 --channels stable
```

Put each entry under `"keys"` in `deploy/miner-update/release-keys.json`
(schema `cathedral_miner_release_keys_v1`), merge it, and announce the file's
SHA-256. That digest is what `--keys-sha256` pins.

**A release.**

```bash
# 1. Build the bundle from the reviewed commit.
python deploy/miner-update/build_signed_miner_release.py bundle \
  --product snp-miner --out-dir out/

# 2. Publish the archive at a fixed https URL. Then sign a canary.
python deploy/miner-update/build_signed_miner_release.py canary \
  --private-key canary-1.pem --signing-key-id canary-1 \
  --product snp-miner --network <network> --netuid <netuid> \
  --image ghcr.io/cathedralai/<repository>@sha256:<64 hex> --state-schema 1 \
  --bundle-archive out/<archive> --bundle-url https://<host>/<archive> \
  --version 2026.10.01 --sequence <next canary sequence> \
  --lifetime-seconds 604800 --out canary.json

# 3. Publish canary.json at the canary channel URL, watch canary hosts,
#    then promote exactly that canary with the stable key.
python deploy/miner-update/build_signed_miner_release.py stable \
  --private-key stable-1.pem --signing-key-id stable-1 \
  --promote canary.json --bundle-archive out/<archive> \
  --sequence <next stable sequence> --lifetime-seconds 604800 --out stable.json
```

The signer refuses in these cases:

- the lifetime is longer than 14 days, or the record is issued in the future;
- the image is not in the repository the bundle's launcher requires;
- the bundle's trust root would not let the signing key sign that channel,
  because every host's probe would then refuse the release;
- the output file already exists.

**Freshness.** A record expires after at most 14 days. A host with an expired
record keeps running what it has and reports `refused`. Re-sign the same
release weekly with the next sequence. Hosts see the same image and bundle and
do not restart.

**State schema.** `1` is the durable-state format of `cathedral/validator_access.py`
on main when this PR was written. Raise it in any release whose image writes
something an older image cannot read. Never lower it. A release that raises it
halts on failure instead of rolling back.

## Trust root and key rotation

The trust root is `trust/release-keys.json` inside the running updater's tree.
The bootstrap pins it by digest. After that, it changes only through a signed
bundle.

- **Planned rotation.**
  1. Add the new key in a release signed by the current key.
  2. Hosts adopt it through self-update. The probe proves the new trust root
     still accepts the record that delivered it.
  3. Sign from the new key.
  4. Remove the old key in a later release.
- **Revocation.** Ship a trust root without the compromised key, signed by
  another key trusted for that channel. With a single stable key, a
  compromise means a new bootstrap on every host, as for the validator.

Because the release key signs the launcher and the updater, it is
root-equivalent on every enrolled miner. Keep it offline.

## Rollout

1. The key holders generate the canary and stable keys and commit
   `deploy/miner-update/release-keys.json`. No key is committed yet.
2. Sign and publish a record naming the image each host already runs. Hosts
   move from their own launcher to the managed one with one restart. The
   image is unchanged, so rollback is always allowed.
3. Bootstrap one TDX host and one SNP host. Enable the timer. Record the
   signed record, the key fingerprints, `status` before and after, and the
   journal.
4. Then canary, then stable, for real releases.

## Limits

- **Measured SNP guest.** On the planned SNP guest, the root filesystem is
  measured and read-only, and the validator admits the image. There the
  update unit should be the guest image, ordered after validator policy
  (review F10). This updater covers the container lane only.
- **No staged rollout yet.** Every stable host restarts within about an hour
  of publication (review F12).
- **The launchers still `docker pull` on every start** (S-07). A release can
  now ship the launcher split, but this PR does not make it.
- **The G4 GPU miners** update by VM boot image. This record does not describe
  them (review F21).

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

## Trust model

**The release signing key is root on every enrolled miner.** A release carries
the launcher, which the miner unit runs as root, and the updater's own code,
which runs as root. Whoever holds a key trusted for a channel can run any code
as root on every host that follows that channel, within about an hour.

What limits that:

- Keys are held offline, encrypted, and never on a miner or in CI.
- Canary and stable are separate roles. A key trusted only for canary cannot
  sign anything a stable host accepts. A stable release carries only the tree
  the stable signer rebuilt from its own reviewed checkout, so a canary key
  cannot put code or keys onto stable hosts.
- The trust set is host state (`/var/lib/cathedral-miner-update/trust.json`),
  not part of any bundle, with a verified copy beside it (`trust.json.backup`).
  The bootstrap pins it by SHA-256. It changes only forward, through a signed
  release. A key a change removes is revoked on that host for good. No old
  updater tree, old bundle, later bootstrap or repair can bring it back.
- Records live at most 14 days, cannot be issued more than 300 s ahead, and
  never go below a host's sequence floor.

What does not limit it: there is no threshold or quorum. With a single stable
key, a compromise means a new bootstrap on every host, as for the validator.

A network attacker cannot forge a record or make an updater crash. It can deny
updates, and six checks without a verified record page. The fallback judges
the bytes the current updater fetched, so serving each updater different
bytes demotes nothing. What remains: an attacker that breaks the current
updater's connections outright, while letting the previous updater's through,
on two checks in a row, can move the host back to the previous updater. That
updater is still bound by the host trust set and floors. The host stays there
until a release with another updater arrives, or an operator runs
`resolve --retry`.

## What a release carries

A release is one signed record (`cathedral/miner_release.py`). It names:

- the **product** (`snp-miner` or `audit-miner`), the **network** and the
  **netuid**. The host refuses a record for anything else. Network and netuid
  come from the host's deploy config and have no defaults;
- the **channel** (`canary` or `stable`) and a **sequence** that never goes
  backwards on a host;
- the container **image**, by digest, in a `ghcr.io/cathedralai/` repository;
- the **host bundle**, by archive and tree digest (`cathedral/miner_bundle.py`):
  the updater's own code, the product launcher, a drop-in for the miner's
  systemd unit, and a proposed trust root;
- the **state schema**: the durable-state format the image writes. The image
  must carry the same number as its `org.cathedral.state-schema` label. It
  decides whether a failed release may roll back on its own;
- an issue time and an expiry.

So a launcher change, a unit change, a new required input such as the netuid,
a key rotation, and a fix to the updater itself all arrive the same way as a
new image.

## Install (once per host)

This is the only step that needs hands on the host.

Prerequisites:

- the distribution's `python3` (3.10 or newer) and its `python3-cryptography`
  package. The updater installs nothing from a package index;
- `git`, `docker` and `systemd`;
- the miner installed as a systemd unit. For the SNP miner that is
  `examples/systemd/cathedral-sn<N>-snp-miner.service`. For a new TDX host, use
  `examples/systemd/cathedral-audit-miner.service` and
  `examples/systemd/audit-miner.env.example`;
- a page hook at `/usr/local/sbin/cathedral-miner-update-page`: a root-owned
  executable that takes a unit name and reaches a person. A minimal one:

  ```bash
  #!/bin/sh
  # Replace with your pager, webhook or mail command.
  logger -p user.crit "cathedral miner update needs attention: $1"
  ```

Take the commit, the trust-root digest and the minimum sequence from the
release announcement, not from this repository. Then, as root:

```bash
sudo ./deploy/miner-update/install-miner-update.sh \
  --revision <40-hex commit> \
  --keys-sha256 <sha256 of deploy/miner-update/release-keys.json at that commit> \
  --product snp-miner \
  --network <network> --netuid <netuid> \
  --channel stable \
  --channel-url https://<channel host>/snp-miner/stable.json \
  --miner-unit <the miner's unit name> \
  --minimum-sequence <from the announcement>
```

The installer clones that exact commit and checks that `HEAD` is the commit
asked for. It then runs `cathedral/miner_bootstrap.py`, which:

1. refuses unless the committed trust root's SHA-256 equals `--keys-sha256`.
   It writes the host trust set, or moves an existing one forward and revokes
   every key the pinned root drops. It refuses a root that lists a revoked key;
2. reads the launcher the miner unit runs today, and refuses if it is not a
   launcher for this product;
3. installs the updater tree built from the checkout and makes it current. It
   removes any `previous` updater, so nothing falls back to what the bootstrap
   replaced;
4. records the unit's own launcher as the `legacy` release, and links
   `/etc/systemd/system/<unit>.d/50-cathedral-miner-update.conf` to
   `miner/current/unit.conf`. That file is empty while `legacy` is current, so
   the miner unit is unchanged;
5. writes `/etc/cathedral/miner-update/config.json`, and installs the frozen
   shim, `cathedral-miner-update.service`, its timer and
   `cathedral-miner-update-alert@.service`.

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
| `cathedral-miner-update status` | Config, the trust set (generation, keys, revoked), the active release, the stage, the updater trees and their strikes, the last check, the last refusal, the last fallback, deferrals, remembered failures, floors. Works without the channel. |
| `pause [--reason TEXT]` / `resume` | Stop and restart checking. A paused check fetches nothing. |
| `pin --current` / `unpin` | Hold the release that runs now, by image and tree digest. Checks still verify the channel, advance the floor and take trust rotations, and report `held`. Nothing else is installed. |
| `resolve --restore-previous` | After a halt: put the previous release back and verify it runs. |
| `resolve --accept-release` | After a halt: accept the new release, if it is running. |
| `resolve --abandon` | After any halt, including one where neither release can run: record the pending release as failed and clear the stage, so a newer release can activate. It leaves `miner/current` as it is and restarts nothing, and it does not lower the schema floor. |
| `resolve --retry` | Forget remembered failures, of releases and of updater trees. |

`check` prints one JSON line and exits with:

| Exit | Meaning | Unit |
|---|---|---|
| 0 | `current`, `activated`, `probation`, `held`, `paused` or `deferred` | succeeds |
| 10 | `refused` or `rolled_back`. The reason says why, and the miner still runs what it ran before | succeeds (`SuccessExitStatus=10`); logged |
| 11 | `halted`. An operator must choose a `resolve` action | fails and pages |
| 12 | an alert: an `unhealthy` miner (down, restarting, or its unit inactive on a host that is not paused), six checks in a row deferred or without a verified record, a gate that cannot pass, an unreadable trust set, or a `demoted` updater | fails and pages |
| 13 | `fault`: the updater's own logic failed | fails and pages |

The unit's `OnFailure=` starts `cathedral-miner-update-alert@<unit>.service`,
which runs the page hook.

## What one check does

1. **Recover.** Finish whatever a previous run left behind (see step 6
   and "Rollback"). A halt blocks activation, not the channel: the check still
   verifies the record and installs a newer updater. It still exits 11, even
   when the channel is down.
2. **Verify.** Fetch the record over https, with no redirects, a size cap, and
   a total deadline enforced while reading. Verify it against the host trust
   set: signature, key role, product, network, netuid, channel, lifetime,
   not-yet-valid and expiry. Any exception while handling channel bytes is a
   refusal, never a crash. Then check the sequence floor and burn it.
3. **Trust.** If the release's bundle proposes another trust root, move the
   host trust set forward. It must still trust the key that signed this
   release, and must not list a revoked key.
4. **Self-update.** If the record's bundle is not the tree this updater runs
   from, install it, probe it, make it current, and hand the rest of the check
   to it (see "Self-update").
5. **Activate.**
   - If the miner unit is inactive, defer and page. An update never starts a
     stopped miner. `pause` the updater when a stop is meant.
   - Build `miner/releases/<activation>/`: the launcher, `release.env` (the
     image pin, `CATHEDRAL_NETWORK` and `CATHEDRAL_NETUID`), the unit drop-in
     and a profile.
   - Pull the image. Verify its digest, platform, runtime-contract label and
     state-schema label.
   - Check again that a restart is safe.
   - Set the `may_have_run` latch and record the flip time.
   - Point `miner/current` at the new directory with one `rename(2)`.
   - Run `systemctl daemon-reload`, `reset-failed` and `restart`.
6. **Probation.**
   - The release enters probation only if all of these hold:
     - a container of the released image started after the flip;
     - the unit is active;
     - the container stayed up for the 20 s dwell;
     - a second look 45 s later sees the same container, with no new restarts.
   - If the old container is still there, meaning the restart never happened,
     the check starts the release once more. A failed restart is never ignored.
   - A check at least 30 minutes after probation began commits the release,
     if the same container is still up with the same restart count. A second
     `check` run by hand right away reports `probation` and commits nothing.
   - A reboot restarts probation. So does one restart of the container, a
     docker daemon restart say, or a restart by hand. A second restart during
     probation fails the release.
   - An inactive unit during probation pages and changes nothing: a rollback
     would start the miner.
   - Anything else goes to "Rollback".
7. **Escalate.** Every check with no activation in progress looks at the
   miner the host selects, even when the check itself refused or held: after
   a rollback, on a pinned host, with the channel down. A miner that is
   inactive, down, running another image, or restarted since the last check
   pages (`unhealthy`, exit 12). Six checks in a row without a verified record
   (a withheld or expired channel) page too. So does an unreadable trust set,
   at once.

The miner unit's drop-in sets `Restart=always`. The launchers exit 143 on
SIGTERM, a docker daemon restart for one, and the miner units count 143 as
success, so `Restart=on-failure` left the miner stopped. Now only
`systemctl stop` leaves the unit inactive, and `pause` is how an operator says
that is meant.

**Safe to restart.** A restart makes the miner re-read its validator-access
snapshot, and the snapshot is short-lived. So the check restarts only when
`/etc/cathedral/validator-access/validator-access.json` has at least 560 s
left. That covers the restart (up to 180 s, which fits the miner's 30 s stop
and #211's fetch unit, with its 2 min start timeout), the settle wait, the
second look and a rollback restart: 555 s. It checks again right after the
pull.

On a healthy host the snapshot is at most 340 s old. #211 signs one at least
every 140 s (a 120 s timer, 15 s of random delay, 5 s of accuracy), backdated
30 s. Workers fetch on the same timer, with a 30 s deadline. So a 900 s
snapshot always has at least 560 s left, and #211's default passes. A snapshot
lifetime under 900 s cannot pass reliably, and the check alerts at once.

**Deferrals.** Six deferred checks in a row alert, as do six checks in a row
without a verified record. Refusals do not reset the
count: a refusal says nothing about the gate, and resetting on every channel
blip could hide a gate that never opens.

## Rollback

The rollback rule never reads the miner's database, which the running miner
writes on every validator request. #197 fingerprinted that database, so on a
live miner rollback was almost never allowed.

A failed release rolls back on its own when:

- the image is unchanged, and only the launcher or unit changed; or
- the previous release's verified state schema is at least the new one's.
  Every image reads every schema up to its own, so the previous image can read
  whatever the new image wrote.

Rolling back points `miner/current` back at the previous release and starts
it, up to twice, so a registry or systemd blip during the first start does not
strand the host. The launchers in this repository start from the locally
verified image digest when it is present, so a registry outage does not block
a rollback to a managed release. The `legacy` launcher a host ran before it
enrolled may still pull on every start; that is one more reason for the first
managed release to name the image the host already runs (rollout step 2). The
rollback is reported only once the previous image runs again. If it does not
come back, the check halts; a later check starts the previous release once
more, and if it then runs, clears the halt and remembers the failed release.

A failed release is remembered by its image and tree digests, so a re-signed
copy is not retried. A newer release with other content, or `resolve --retry`,
clears it.

Otherwise the updater halts and waits for `resolve`:

- the release raises the schema;
- the previous release's schema is not verified. This covers the first move
  from the `legacy` launcher to a different image;
- the previous release does not come back after two starts.

**State schemas.** The number is `DURABLE_STATE_SCHEMA` in
`cathedral/validator_access.py`, and the miner images carry it as the
`org.cathedral.state-schema` label. `prepare_image` reads the label, and a
label that differs from the record's number is refused.

- Schema 1 is the format before #179 (`8ad7f6e`). Schema 2 is the format
  since #179, which creates `authorization_digest` as a NOT NULL column that
  code from before #179 does not fill. So "all existing images are schema 1"
  is false, and no release may declare 1 for an image built since #179.
- Images built before this change carry no label. The updater takes one over
  only as the image the miner already runs, and its schema then counts as
  unverified. So the first labelled release after such a takeover halts,
  rather than rolls back, if it fails. The same holds for any image from
  before #179: nothing rolls back to it on its own.
- A release may never lower the schema unless the image is unchanged. The
  floor is the highest verified schema of any release that reached the
  `may_have_run` latch here, since that image may have migrated the state. So
  `resolve --abandon` does not lower it: after abandoning a schema-3 release,
  only a release declaring at least 3 activates. Nothing clears the floor.
- The number rises only when code of the current number could no longer read
  or write state that newer code creates: a new required column, a dropped or
  changed table or column, or a column whose meaning changes. A new optional
  column keeps the number. A test pins the tables of schema 2 on that rule.
  Draft #212 adds an optional column and so stays schema 2.

## Self-update

Every release ships the updater's code, and a check installs it before it
activates anything. The trust set is host state, so every updater, current or
previous, verifies against the same keys and revocations. Three guards stop a
bad updater from stranding a host:

1. **Probe.** Before the new tree becomes current, the new code runs `probe`
   from its own directory. It verifies the record that delivered it, reads
   this host's state, and hashes its own tree. It must report the same state
   and trust schemas this updater reads. An import error, a broken verifier or
   a state-format change all fail here, and nothing changes. A failed probe is
   a strike against the new tree.
2. **First run.** The new updater then runs the rest of the check as a child
   that inherits the lock. It runs in its own process group and is killed,
   with anything it started, after a timeout well inside the unit's. It stays
   current only if it fetched and verified the channel and did not fault.
   Otherwise the old updater is put back. It records a strike against the new
   tree only if it can verify the channel itself right then.
3. **Fallback.** On a later run, if the current updater exits with anything
   but 0, 11 or 12, the frozen shim asks the previous updater to judge. A
   refusal stands if the current updater recorded, for that same run and exit
   status, that it verified the channel. Otherwise the previous updater
   fetches and verifies the channel itself, changing nothing. If it can, that
   is a strike against the current tree; if it cannot, the channel is at
   fault and nothing changes.

A tree with two strikes is not used again on that host until a release with
another updater arrives. One induced or transient failure demotes nothing.
When the current updater is demoted, the check alerts (`demoted`, exit 12).

A later updater never changes the state's schema string; the probe refuses
one that does. It may add fields and activation stages. An older updater keeps
fields it does not know. A stage it does not know halts activation, but not
verification, self-update or the fallback, so a demoted updater still works.
`resolve --abandon` clears such a stage.

When a newer updater cannot be installed, the check records which tree and
whose fault it looked like. If the new tree ran and reported its own failure,
or hung, the fault is its own. If it failed before it could say (its probe,
or a handoff that produced nothing), the fallback probes that tree itself. If
the probe passes, the current updater is at fault: the new tree's strike is
taken back and the current updater gets one. So an updater that verifies the
channel but cannot install any newer one is replaced within two checks.

Not updated through the channel: the shim, the updater's own service, timer
and alert units, and the host's Python. The shim's directory is read-only to
the updater. Changing any of them needs a new bootstrap.

## When something fails

| What fails | What the check does | Exit | Operator |
|---|---|---|---|
| The channel is down, or serves garbage | Refuses. Nothing changes. The fallback cannot verify either, so no strike | 10 | Nothing, unless it lasts |
| A record is unsigned, expired, premature, for another host, or below the floor | Refuses. Nothing changes | 10 | Nothing |
| The bundle's trust root lists a revoked key, or drops the key that signed it | Refuses, and remembers the release | 10 | Tell the signer |
| The image cannot be pulled, or its digest, platform, contract or schema label is wrong | Refuses before anything is selected. The sequence is still burned | 10 | Tell the signer |
| The channel is withheld or its record expired, six checks in a row | Alerts | 12 | Tell the signer |
| `trust.json` is unreadable | Alerts at once, and verifies nothing | 12 | `--repair-trust-set` |
| The restart gate is closed | Defers. Six in a row alert | 0, then 12 | Check the validator-access refresher |
| The snapshot's lifetime cannot pass the gate | Alerts at once | 12 | Lengthen the snapshot lifetime to 900 s or more |
| The miner unit is inactive | Defers, never starts it, and alerts | 12 | Start it, or `pause` if intended |
| A new release does not come up, or dies before the next check | Rolls back if the schema rule allows, and remembers the release | 10 | Nothing |
| The same, when the schema rule does not allow it | Halts | 11 | `resolve` |
| The previous release does not come back | Halts. The next check starts it once more | 11 | `resolve` if it stays |
| The miner is down, restarting or inactive, on any check with no activation in progress (after a rollback, on a pinned host, with the channel down) | Alerts | 12 | Look at the miner |
| A release restarts once during probation | Restarts probation | 0 | Nothing |
| A new updater fails its probe or its first run | Keeps the old updater; a strike when the old one can verify | 10 | Nothing; two strikes retire the tree |
| The current updater crashes or cannot verify, and the previous one can verify what it saw | A strike; at two the previous updater becomes current again | 13 or 10, then 12 | Tell the signer |
| The current updater verifies but cannot install a newer updater that the previous one's probe accepts | A strike; at two the previous updater becomes current and installs it | 10, then 12 | Tell the signer |
| The updater's own logic raises | A documented fault, never a bare traceback | 13 | Tell the signer |

## Repairing the trust set

Every change to `trust.json` also writes `trust.json.backup`, and every check
refreshes the backup when it differs. If `trust.json` becomes unreadable,
checks page and verify nothing, and a new bootstrap refuses. Run the
bootstrap again with `--repair-trust-set`. It moves forward from the backup
to the pinned root: every revocation is kept, and a root that lists a revoked
key is refused, as always. A host with a trust set or a backup never starts
over on its own. If neither can be read, deleting both is the only way out,
and it forgets every revocation: bootstrap then only from a root that drops
every key you revoked.

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
  --image ghcr.io/cathedralai/<repository>@sha256:<64 hex> --state-schema 2 \
  --bundle-archive out/<archive> --bundle-url https://<host>/<archive> \
  --version 2026.10.01 --sequence <next canary sequence> \
  --lifetime-seconds 604800 --out canary.json

# 3. Publish canary.json at the canary channel URL and watch canary hosts.
#    The stable signer then promotes exactly that canary, from their own
#    checkout of the same commit.
python deploy/miner-update/build_signed_miner_release.py stable \
  --private-key stable-1.pem --signing-key-id stable-1 \
  --promote canary.json --bundle-archive out/<archive> \
  --sequence <next stable sequence> --lifetime-seconds 604800 --out stable.json
```

The stable command rebuilds the bundle tree from the signer's own checkout and
committed trust root. It refuses unless that equals the canary's tree. It
prints the trust root's digest and every key's role before it signs.

The signer also refuses in these cases:

- the lifetime is longer than 14 days, or the record is issued in the future;
- the image is not in the repository the bundle's launcher requires;
- the bundle's trust root would not let the signing key sign that channel;
- the output file already exists.

**Freshness.** Re-sign the same release weekly with the next sequence. Hosts
see the same image and bundle and do not restart. A host with an expired
record keeps running what it has and reports `refused`.

## Key rotation and revocation

- **Planned rotation.**
  1. Add the new key to `release-keys.json` in a release signed by the current
     key.
  2. Hosts move their trust set forward.
  3. Sign from the new key.
  4. Remove the old key in a later release. Hosts then revoke it for good.
- **Revocation after a compromise.** Ship a trust root without the
  compromised key, signed by another key trusted for that channel. With only
  one stable key, re-bootstrap every host from a revision whose committed root
  drops it. The bootstrap revokes it, and refuses any later root that lists it
  again.

## Rollout

1. The key holders generate the canary and stable keys and commit
   `deploy/miner-update/release-keys.json`. No key is committed yet.
2. Build and publish images from this commit, so they carry the state-schema
   label. Or sign the image each host already runs: the updater takes that
   over unlabelled, with one restart, and the rollback is always allowed.
3. Bootstrap one TDX host and one SNP host, install the page hook, and enable
   the timer. Record the signed record, the key fingerprints, `status` before
   and after, and the journal.
4. Real releases then go canary first, then stable.

## Limits

- **Measured SNP guest.** On the planned SNP guest, the root filesystem is
  measured and read-only, and the validator admits the image. There the update
  unit should be the guest image, ordered after validator policy (review
  F10). This updater covers the container lane only.
- **No staged rollout yet.** Every stable host restarts within about an hour
  of publication (review F12).
- **The G4 GPU miners** update by VM boot image. This record does not describe
  them (review F21).

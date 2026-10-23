# Catalog M-sn94-miner: the SN94 miner images, units and signed update channel

Artifact: cathedral-sandbox PR #312 head, commit 887ed40, read in the worktree
~/Documents/projects.nosync/cathedral-sandbox-pr308 (read-only). Known items
B1 to B132 are not repeated.

Files read line by line:

- Dockerfile.sn94-snp-miner (56 lines)
- Dockerfile.sn94-audit-miner (54)
- examples/systemd/cathedral-sn94-snp-miner.service (34)
- examples/systemd/sn94-snp-miner.env.example (5)
- examples/systemd/cathedral-sn94-policy-republisher.service (92) and .timer (13)
- deploy/miner-update/build_signed_miner_release.py (429)
- deploy/miner-update/cathedral-miner-update (45, the frozen shim)
- deploy/miner-update/install-miner-update.sh (99)
- deploy/miner-update/cathedral-miner-update.service (49), .timer (14),
  cathedral-miner-update-alert@.service (14), miner-unit.conf (24)
- cathedral/miner_updater.py (2543)

Read for context: cathedral/miner_update_cli.py, miner_release.py,
miner_bundle.py, miner_products.py, miner_bootstrap.py, snp_miner_entrypoint.py,
audit_miner_entrypoint.py, validator_access.py (lines 1100 to 1455 and the
module outline), cli.py (serve-snp wiring, startup snapshot check at 2027 to
2041), scripts/run_sn94_snp_miner.sh, scripts/run_sn94_signed_fleet_miner.sh,
examples/systemd/cathedral-validator-access-*.{service,timer},
examples/systemd/cathedral-audit-miner.service, docs/MINER_AUTO_UPDATE.md,
docs/SN94_SNP_MINER_IMAGE.md, docs/MINING.md, docs/AMD_SEV_SNP_FRIEND_TEST.md
(280 to 400), docs/MINER_BOX_RUNBOOK.md, docs/SN94_AUDIT_MINER_OPERATIONS.md,
tests/miner_update_support.py, tests/test_miner_update_unit.py.

Live state assumed from the docs, not checked on a host: the SNP miner on the
The live miner host runs the example unit from docs/AMD_SEV_SNP_FRIEND_TEST.md and is
not enrolled in signed updates (docs/MINER_AUTO_UPDATE.md: "It has not run on a
live miner yet"). deploy/miner-update/release-keys.json does not exist at this
commit, so the bootstrap refuses on every host ("this revision carries no miner
release trust root"). Every updater entry below is therefore latent today.

Format of each entry: name (lines). Purpose. Trusts. Effects. Locks. Callers.
Invariant.

---

## 1. Dockerfile.sn94-snp-miner

### Image build (1 to 56)
- Purpose: the immutable SN94 AMD SEV-SNP worker image.
- Trusts: the pinned python:3.12-slim-bookworm digest (line 3); PyPI wheels by
  hash only (`--require-hashes --only-binary=:all:`, 18 to 24); GitHub for the
  snpguest v0.10.0 binary, pinned by sha256 (28); the build context's
  `cathedral/` tree (30); the build arg CATHEDRAL_IMAGE_CHAIN (34 to 40).
- Effects: downloads snpguest over https at build time (Python default SSL
  context, so the server certificate is verified) and fails the build on a
  digest mismatch; writes image_chain.json only for test-584; runs the sr25519
  known-answer preflight at build time (44), so a broken wheel fails the build.
- Labels: runtime contract `snp-signed-validator-fleet-v1` (8),
  `org.cathedral.state-schema="2"` (13), `org.cathedral.image-chain` (40).
  The state-schema label equals validator_access.DURABLE_STATE_SCHEMA (2);
  tests/test_miner_updater.py:1007 pins the two together.
- Runs as uid 0 (`USER 0:0`, 48) with three root-only 0700 directories (49 to
  51). EXPOSE 8081, STOPSIGNAL SIGTERM, entrypoint `python -I -u -B -m
  cathedral.snp_miner_entrypoint` (56): no arguments accepted.
- Invariant: nothing in the image is configurable at run time except the three
  CATHEDRAL_* inputs the entrypoint admits (hotkey, public endpoint, keys
  digest). The subnet is fixed at build.
- Hazard: `.dockerignore` does not exclude `cathedral/image_chain.json`. A
  stray file in a developer's context would make a finney-94 labelled image
  serve test-584. CI builds from a clean checkout, so this is a local-build
  hazard only.

## 2. Dockerfile.sn94-audit-miner

### Image build (1 to 54)
- Same shape as the SNP image for Intel TDX: contract
  `signed-validator-fleet-v1` (8), state-schema 2 (13), chain arg (30 to 36),
  preflight (40), uid 0 (45), plus the fixed TSM bind target
  `/opt/cathedral-audit-miner/tsm-report` 0755 (47). No snpguest download.
- Entrypoint `cathedral.audit_miner_entrypoint` (54), which runs
  `worker migrate --migration-mode public-legacy-audit` (audit_miner_entrypoint
  264 to 309): the "migration bridge" the docs describe.

## 3. examples/systemd/cathedral-sn94-snp-miner.service (34 lines)

- Purpose: the unit docs/AMD_SEV_SNP_FRIEND_TEST.md installs on the live SNP
  host. ExecStart is `/usr/local/sbin/cathedral-run-sn94-snp-miner` (18), a
  root 0700 copy of scripts/run_sn94_snp_miner.sh.
- Trusts: /etc/cathedral/sn94-snp-miner.env (EnvironmentFile, 17; also a
  start condition, 9); /dev/sev-guest present (ConditionPathExists, 8).
- Ordering: After/Wants network-online, docker.service and
  cathedral-validator-access-fetch.service (3 to 4). Each start of this unit
  queues one fetch first; "Wants= does not block the miner if the fetch fails"
  (7).
- Restart policy: `Restart=on-failure`, `RestartSec=15s`,
  `SuccessExitStatus=129 130 143` (19 to 21), `StartLimitIntervalSec=300`,
  `StartLimitBurst=5` (10 to 11). No OnFailure=.
- Sandbox: User root, UMask 0077, NoNewPrivileges, PrivateTmp, ProtectHome,
  ProtectSystem=strict, ReadOnlyPaths /etc/cathedral/validator-access,
  ReadWritePaths /var/lib/cathedral/validator-access and all of /run (the
  launcher needs /run for its lock, the nft temp file and the docker socket),
  LockPersonality, RestrictSUIDSGID. No capability bounding set: the launcher
  runs nft and docker as full root. TimeoutStopSec 30 s.
- Invariant assumed: a failed launcher exit is restarted. False for exits 129,
  130 and 143, which the unit calls success and `on-failure` does not restart.
- What the unit does that the docs do not say (docs/AMD_SEV_SNP_FRIEND_TEST.md
  351 to 379 only says install, enable, status):
  1. a 143 exit (the launcher's TERM trap, and what the container returns when
     dockerd stops it) leaves the unit inactive with no restart;
  2. five failed starts in 300 s leave the unit failed and page nobody;
  3. a missing /dev/sev-guest skips the unit silently at boot;
  4. stop is `docker rm --force` (SIGKILL to the container) inside 30 s;
  5. it pulls a fresh snapshot fetch before every start.
- Compare examples/systemd/cathedral-audit-miner.service 23 to 27: that unit
  was changed to `Restart=always` in 23ff0d9 for "a clean exit (143 after a
  docker daemon restart)". This unit, added in a66d7c4 two days later, kept
  `on-failure`.

## 4. examples/systemd/sn94-snp-miner.env.example (5 lines)

- Four values: SN94_SNP_MINER_IMAGE (the published digest pin, equals
  docs/SN94_SNP_MINER_IMAGE.md), CATHEDRAL_MINER_HOTKEY (public SS58 only),
  CATHEDRAL_PUBLIC_ENDPOINT (https://IPv4:8081), and
  CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST (sha256 pin of snapshot-keys.json).
- Trusted by the launcher as root:root 0600 input; the launcher checks the
  image prefix and digest shape, the keys digest shape, and passes the three
  CATHEDRAL_* values to the container with explicit `--env` (launcher 187 to
  189). Nothing else from the unit environment reaches the container, which
  is why the release.env variables CATHEDRAL_NETWORK and CATHEDRAL_NETUID
  (miner_updater.render_release_env) do not trip the entrypoint's refusal of
  unknown CATHEDRAL_* inputs (audit_miner_entrypoint 142 to 151).
- Hazard: the repository name is `cathedral-sn39-snp-miner` for an SN94 image.
  Cosmetic, but the launcher's IMAGE_PATH and the updater's launcher profile
  both pin it, so a rename needs a new launcher in a signed bundle.

## 5. examples/systemd/cathedral-sn94-policy-republisher.service (92) and .timer (13)

- Purpose: "Legacy ... not current SN94 mining" (2). Reissues a policy-library
  freshness record every 12 h (timer: OnBootSec 5 min, OnUnitActiveSec 12 h,
  Persistent).
- Trusts: a root-owned venv and checkout under /opt/cathedral-sn94, checked
  by five ExecStartPre runs of the privileged-paths checker (30 to 60); the
  signing key /etc/cathedral/policy-signing-sn94.key and registry
  /etc/cathedral/policy-registry-sn94.json (conditions, 5 to 6).
- Effects: ExecStart (64) runs cathedral_isolated_republisher.py
  republish-install, writing the sqlite state, approval log, history dir and
  lock under /var/lib/cathedral-confidential-sn94, and the registry under
  /etc/cathedral (ReadWritePaths, 82).
- Sandbox: root with only CAP_DAC_READ_SEARCH, PrivateNetwork (no network at
  all), AF_UNIX only, DevicePolicy closed, strict system protection,
  MemoryDenyWriteExecute, syscall filter. Restart=on-failure, 5 min.
- Locks: /var/lib/cathedral-confidential-sn94/policy-writer.lock (program).
- Callers: the timer only.
- Invariant: nothing in the current SN94 miner reads what it writes.
- Hazard: it is named cathedral-sn94-* and has `ReadWritePaths=/etc/cathedral`,
  the directory the miner's env file and validator-access files live in. An
  operator installing it on the miner host by name gives a legacy signing key
  root write access to the miner's trusted directory. No current doc tells
  anyone to install it.

## 6. deploy/miner-update/cathedral-miner-update (shim, 45 lines)

### `run` (24 to 34)
- Purpose: run `cathedral.miner_update_cli` from one installed updater tree
  (`current` or `previous`) with a clean environment.
- Trusts: the symlink `$INSTALL/updater/<which>` resolved with `readlink -e`
  (returns 127 if missing); /usr/bin/python3; the tree's `updater/` dir.
- Effects: `cd` into the release's updater dir, then `exec env -i PATH=...
  LANG=C.UTF-8 PYTHONSAFEPATH=1 PYTHONPATH=<tree>/updater
  CATHEDRAL_MINER_UPDATE_RELEASE=<tree> python3 -s -B -m
  cathedral.miner_update_cli <args>`. The cd matters on Python 3.10, which
  ignores PYTHONSAFEPATH and puts the working directory first on sys.path.
- Locks: none here.
- Callers: lines 36 and 45.
- Invariant: the shim reads no environment and no release can replace it (the
  updater unit mounts its directory read-only).

### Main flow (36 to 45)
- Runs `current`. For any verb but `check`, exits with its status. For
  `check`: 0, 11, 12 exit as is; a status above 128 (a signal) exits as is;
  otherwise, if a `previous` link exists, runs `previous fallback
  --current-status <status>`. So statuses 10 (refused) and 13 (fault) and 127
  reach the fallback.
- Invariant: the fallback never runs for a halt or an alert.

## 7. deploy/miner-update/install-miner-update.sh (99 lines)

### Argument parsing (34 to 44) and preconditions (46 to 59)
- Requires root, a 40-hex revision, a 64-hex trust-root digest, git, docker,
  systemctl, /usr/bin/python3 >= 3.10 and the distro's python3-cryptography.
  Passes product, network, netuid, channel, channel URL, miner unit, minimum
  sequence and --repair-trust-set through to the bootstrap.
- Hazard (doc): lines 18 to 19 say `--minimum-sequence` is "the lowest channel
  sequence this host may accept". The code requires the sequence to be
  exceeded (miner_updater._effective_floor 908 to 914 with
  miner_release.enforce_monotonic_release 601 to 604; pinned by
  tests/test_miner_updater.py:224). Probe
  tests/probe_sn94_updater_silence.py::test_minimum_sequence_... fails.

### Clone and verify (61 to 68)
- `git clone --filter=blob:none` from GitHub into a mktemp dir as root,
  checkout the revision, and refuse unless `rev-parse HEAD` equals it.
- Trusts: GitHub plus TLS for the code bytes; the commit hash pins content.
- Effects: network, disk under mktemp (removed on EXIT).

### Bootstrap (70 to 74)
- `env -i ... PYTHONPATH=<src> python3 -s -B -m cathedral.miner_bootstrap
  install --source <src> --keys-sha256 <digest> <passthrough>`, run from the
  checkout. cathedral/__init__.py is six lines, so the import is light.
- The bootstrap (miner_bootstrap.install 153 to 279) refuses unless the
  committed trust root's sha256 equals --keys-sha256, writes the host trust
  set forward, installs the updater tree, the shim, the units, the drop-in
  symlink and the config, and runs `systemctl daemon-reload`. It does not
  enable the timer and does not touch the miner.

### Operator text (76 to 99)
- Tells the operator to read fingerprints, install the page hook, run one check
  by hand, then enable the timer. "If the miner unit is not running, the check
  pages and starts nothing."

## 8. deploy/miner-update/cathedral-miner-update.service (49 lines)

- Purpose: one `check` through the shim. ConditionPathExists on the config.
  OnFailure pages through cathedral-miner-update-alert@%n.service (10).
  `SuccessExitStatus=10` (20): a refusal is logged, not paged.
- TimeoutStartSec 7800 s (23). miner_update_cli.worst_case_seconds() is 7617
  and the test demands 7617 + 120 = 7737, so 63 s to spare.
- Sandbox: root, ProtectSystem=strict, StateDirectory
  cathedral-miner-update (0700), ReadWritePaths
  /usr/local/lib/cathedral-miner-update, ReadOnlyPaths its bin/ (the shim),
  InaccessiblePaths -/var/lib/cathedral/validator-access (the miner's own
  database), AF_UNIX AF_INET AF_INET6, Protect* and Restrict* set. The
  validator-access snapshot under /etc stays visible on purpose (review F1;
  tests/test_miner_update_unit.py checks every HostPaths entry against this
  file).
- The drop-in symlink under /etc/systemd/system is never written by `check`:
  it points at miner/current/unit.conf, and the updater re-points
  miner/current with one rename under /usr/local/lib.
- Invariant: every documented alert goes through exit 11, 12 or 13. A refusal
  (10) is silent by design; the code must convert what should page into 12.

## 9. deploy/miner-update/cathedral-miner-update.timer (14 lines)

- OnBootSec 15 min, OnUnitActiveSec 1 h, RandomizedDelaySec 5 min,
  Persistent. Only unit: cathedral-miner-update.service.

## 10. deploy/miner-update/cathedral-miner-update-alert@.service (14 lines)

- Oneshot `ExecStart=/usr/local/sbin/cathedral-miner-update-page %i`,
  TimeoutStartSec 1 min. The hook is operator-supplied; without it the page
  is one failed unit in the journal. Same pattern as the validator-access
  alert unit.

## 11. deploy/miner-update/miner-unit.conf (24 lines)

- The drop-in a release ships. Clears ExecStart and sets it to
  miner/current/launcher; adds EnvironmentFile miner/current/release.env (the
  image pin, CATHEDRAL_NETWORK, CATHEDRAL_NETUID, loaded after the operator's
  file so the pin wins); `Restart=always`, `RestartSec=15s`.
- Reaches a host only as `miner/releases/<activation>/unit.conf` once a
  release is active; while miner/current is `legacy`, the drop-in file is
  empty and the operator's unit is unchanged.
- Invariant: on an enrolled host only `systemctl stop` leaves the miner
  inactive, and the updater pages on an inactive miner unless paused.

## 12. deploy/miner-update/build_signed_miner_release.py (429 lines)

Offline signer. Reads no network. Private keys must be encrypted PEM with the
passphrase in CATHEDRAL_MINER_RELEASE_PASSPHRASE.

### `_fail` (81 to 82)
- SystemExit("refusing: ..."). Callers: everywhere below.

### `_load_private_key` (85 to 112)
- Refuses a symlink, a group or world accessible file, an unencrypted key, a
  missing passphrase, a wrong passphrase, a non-Ed25519 key.
- Trusts: the file at --private-key. Effects: reads it.

### `_public_hex` (115 to 118), `_write_new` (121 to 127), `_sign` (130 to 137)
- Raw public key hex; create-only write (`xb`, never overwrites a signed
  artifact) then chmod 0644; Ed25519 over `signed_bytes(body)` (canonical
  JSON without `signature`) and a pretty JSON document.

### `_Bundle` (140 to 159)
- Extracts an archive exactly as a host will (miner_bundle.extract_archive),
  hashes the tree, reads the launcher profile and the bundled trust root.
  `require_key` (153 to 159) refuses a signing key the bundle's own trust
  root would not accept for the channel.

### `_window` (162 to 170)
- issued = --issued-unix or now; expires = issued + lifetime;
  check_validity_window (14 days max, 300 s skew) shared with the host parser.

### `_emit` (173 to 207)
- Re-parses the signed bytes with parse_miner_release against the bundle's
  trust root (self-check), writes the file, prints a summary with the key's
  fingerprint.
- Invariant: nothing is written that a host with that trust root would refuse.

### `command_trust_entry` (210 to 216)
- Prints one trust-root entry {key_id: {public_key_hex, channels}}.

### `command_bundle` (219 to 246)
- assemble_tree from this checkout plus the committed trust root (or
  --trust-root), deterministic gzip tar, written as
  `cathedral-miner-bundle-<product>-<tree>.tar.gz`. Refuses if
  deploy/miner-update/release-keys.json is missing (miner_bundle 136 to 141).

### `command_canary` (249 to 287)
- Checks the bundle launcher's contract against the product, the image's
  repository against the launcher's, the bundle URL is https, the key may
  sign canary per the bundle's trust root; prints what canary hosts will
  trust; signs.
- Trusts: the operator's --image digest (never pulled or inspected here; the
  host's prepare_image checks digest, platform and labels before activation).

### `_announce_trust` (290 to 298), `_rebuild` (301 to 307)
- Print the trust root digest and each key's role; rebuild the tree from this
  checkout for comparison.

### `command_stable` (310 to 376)
- Rebuilds the tree from the stable signer's own checkout and refuses unless
  it equals the canary bundle's tree (so a canary key cannot put code or keys
  onto stable hosts). Verifies the canary record against the bundle's trust
  root, requires --bundle-archive to be the canary's bundle, requires the
  stable key to be allowed for stable, copies the canary's release fields and
  records `promoted_canary`.
- Invariant: a stable record is the exact artifact a canary ran.

### `main` (379 to 425)
- Argparse with four subcommands; MinerReleaseError becomes a refusal.

## 13. cathedral/miner_updater.py (2543 lines)

Pure state machine. Every host effect (docker, systemd, network, clock) is a
callable on MinerUpdaterHost, supplied by miner_update_cli.build_host. All
paths are under HostPaths.root ("/" on a host). Everything runs as root.

### Constants (111 to 186)
- Exit statuses 0/10/11/12/13 (116 to 121); DEFERRAL_ALERT_AFTER 6,
  UNVERIFIED_ALERT_AFTER 6 (128 to 137); PROBATION_MINIMUM_SECONDS 1800;
  PROBATION_RESTARTS_FORGIVEN 1; INACTIVE_UNIT_STATES inactive/deactivating;
  STRIKES_TO_DEMOTE 2; FALLBACK_RECORD_MAX_AGE 600 s, skew 60 s; stage names
  prepared/may_have_run/probation; STATE_SCHEMA_LABEL
  org.cathedral.state-schema; byte caps for state (256 KiB), trust (256 KiB),
  config (16 KiB), pin (4 KiB); regexes for unit names, networks, tree digests.

### Exceptions (189 to 210)
- MinerUpdateError (refusal), MinerUpdateHalted (operator needed),
  MinerUpdateRolledBack (carries the release), GateImpossible (snapshot
  lifetime too short, alerts), TrustSetUnavailable (alerts).

### `Observation` (213 to 220)
- image, started_at (unix float), restarts (unit NRestarts), active (unit
  active and container Running).

### `HostConfig` (226 to 290)
- `from_document` (248 to 284): exact key set, schema, known product, network
  regex, netuid 0..65535, channel in CHANNELS, https channel URL, unit name
  regex, minimum_sequence 0..2^31. `as_document` (286 to 290).
- Callers: load_config, miner_bootstrap.main.
- Invariant: no field has a default.

### `load_config` (293 to 306)
- Reads config.json only if root-controlled (not a symlink, uid 0, no group or
  world write), at most 16 KiB, strict JSON.

### `HostPaths` (309 to 420)
- Every path: config dir and file, pause and pin files, install root, shim,
  updater/releases, updater/current and previous, miner dir, miner/releases,
  miner/legacy, miner/current, state dir, state.json, trust.json,
  trust.json.backup, fetched-record, lock, records dir, the validator-access
  snapshot at /etc/cathedral/validator-access/validator-access.json, systemd
  dir, dropin(unit), operator command /usr/local/sbin/cathedral-miner-update.
- tests/test_miner_update_unit.py checks each against the unit's mounts.

### `MinerUpdaterHost` (426 to 465)
- The injected effects plus run state: running_tree (digest of the tree this
  process runs from, or None), handoff_depth, lock_fd, verified,
  offered_updater, updater_blame.

### `UpdateOutcome` (468 to 494)
- action, reason, exit_status, release summary, alert, verified, recorded
  (a child already recorded it), updater_offered, updater_blame; `as_dict`.

### `_atomic_write` (500 to 525)
- mkstemp in the target directory, write, fsync, chmod, rename, fsync the
  directory. Creates the parent 0700. Raises MinerUpdateError on OSError.
- Callers: write_state, write_trust_state, _trust, _fetch_kept, _save_record,
  miner_bootstrap (config), miner_update_cli._write_operator_file.

### `empty_state` (528 to 555)
- floors per channel, miner {current, stage, pending}, failed release,
  failed_updaters, updater_strikes, last_check, last_refusal, last_fallback,
  consecutive_deferrals, consecutive_unverified, last_fetch,
  schema_high_water, miner_health.

### `read_state` (558 to 602)
- Missing file: empty state. Otherwise at most 256 KiB, strict JSON, schema
  string must match, floors/miner/failed_updaters/updater_strikes dicts,
  stage str or None, counters non-negative ints. Unknown fields are kept.
- Callers: _locked (the gate for every command), _record, _after_check,
  _escalate, _check_locked, _self_update, probe_release, describe_status,
  cli pin, bootstrap repair.
- Invariant: the schema string never changes through the channel (the probe
  refuses a new updater that reports another one).
- Hazard: an unreadable or malformed state.json raises MinerUpdateError, and
  `_locked` (1036 to 1038) returns that refusal before `_after_check`,
  `_escalate` and `_record` run. Exit 10, unit success, no alert, no miner
  health check, and `status` refuses too (describe_status 2439). Contrast
  trust.json, which alerts at once. Probe
  tests/probe_sn94_updater_silence.py::test_a_dead_miner_is_paged_even_when_
  the_updater_state_is_unreadable fails: seven checks with the miner down, all
  exit 10, none page.

### `write_state` (605 to 610)
- canonical_json then _atomic_write 0600.

### `read_pin` (613 to 641), `pin_document` (644 to 654)
- A pin names image, tree_sha256 and version; an unreadable or malformed pin
  refuses rather than guesses. The pin holds content, not a version string.

### `exclusive` (660 to 692)
- The updater lock: O_CREAT|O_RDWR|O_NOFOLLOW on state_dir/lock, flock
  LOCK_EX|LOCK_NB. A second concurrent check is refused, not queued. With an
  inherited descriptor (a handed-off child), checks dev/ino against the lock
  path and re-flocks the same open file description.
- Locks: this is the lock. Callers: _locked.

### `activation_id` (698 to 711)
- sha256 of canonical {image, tree_sha256, product, network, netuid}.

### `render_release_env` (714 to 728)
- `<image_variable>=<image>`, CATHEDRAL_NETWORK, CATHEDRAL_NETUID. Loaded by
  the miner unit after the operator's env file.

### `_activation_files` (731 to 748), `stage_activation` (751 to 798)
- Builds miner/releases/<activation>/ with launcher (0555), unit.conf,
  release.env, profile.json (0444) in a staging dir, then one rename. An
  existing directory is accepted only if every file is root-controlled and
  byte-identical; otherwise "modified" or "unexpected contents" refuses.
- Effects: disk under /usr/local/lib/cathedral-miner-update/miner.
- Callers: _activate.
- Invariant: a directory is complete and immutable before anything points at
  it.

### `read_activation_profile` (801 to 809)
- profile.json of miner/<target>; needs a string `container`.

### `load_trust_state` (816 to 830), `trust_backup_path` (833 to 834),
### `write_trust_state` (837 to 846), `_trust` (849 to 877)
- The host trust set: root-controlled file, at most 256 KiB, parse_trust_state
  (keys, revocations, generation). write_trust_state writes the backup first,
  then the file. `_trust` finishes an interrupted write (a backup one
  generation ahead with a superset of revocations is adopted) and refreshes
  the backup; any read problem raises TrustSetUnavailable (alert).
- Callers: _verify, _rotate_trust, describe_status, bootstrap.
- Invariant: trust only moves forward; a key dropped is revoked for good.

### `rollback_allowed` (883 to 905)
- Unattended rollback only when the image is unchanged, or the previous
  release's verified schema >= the new one's. Unverified previous schema (the
  legacy launcher, an unlabelled image) halts instead.

### `_effective_floor` (908 to 914)
- The persisted floor if >= minimum_sequence, else a synthetic floor
  {sequence: minimum_sequence, signed_sha256: None} which must be exceeded.
  See the install-script doc hazard above.

### `_refuse_known_failure` (917 to 927), `_remember_failure` (930 to 945)
- Failure memory keyed by image and tree digests (a weekly re-sign does not
  retry). `_remember_failure` writes state.

### `_refuse_updater` (948 to 956), `_retire_updater` (959 to 967),
### `_strike` (970 to 985)
- Updater trees retired after STRIKES_TO_DEMOTE strikes; at most 8 remembered;
  `retire=False` counts without retiring (fetch-only failures).

### `_recent` (988 to 995), `_fetch_failed_this_run` (998 to 1008)
- Whether a timestamp another updater wrote belongs to this run (within 600 s
  behind or 60 s ahead); whether the last fetch failed before any bytes.

### `update_once` (1014 to 1019)
- Pause file present: "paused", exit 0, fetches nothing. Else _locked with
  _check_locked and _after_check.
- Callers: cli check, the Harness, the handed-off child.

### `_locked` (1022 to 1075)
- Takes the lock, resets per-run flags, reads state (a failure here returns
  "refused" at once, see the hazard under read_state), runs the body, maps
  exceptions to outcomes: Halted -> 11, RolledBack -> 10, GateImpossible ->
  12, TrustSetUnavailable -> 12, MinerUpdateError/MinerReleaseError/
  BundleError/LauncherProfileError/OSError -> 10, anything else -> 13 with a
  traceback. Runs `after`, then `_record`. Restores the inherited lock fd.
- Invariant: every exception has a documented status; untrusted bytes never
  produce 13.

### `_record` (1078 to 1119)
- Writes last_check (and last_refusal for 10/11/13); counts consecutive
  deferrals and turns the sixth deferral with exit 0 into an alert; resets
  the count on activated/probation/current/held. Skipped when a child already
  recorded.

### `_after_check` (1122 to 1144)
- Counts consecutive_unverified (reset when this run verified). If this run
  did not verify, refused, and a `previous` updater exists, returns without
  escalating: the shim will run the fallback, which escalates. Otherwise
  `_escalate`.

### `_escalate` (1147 to 1185)
- For exit 0 or 10 only: six unverified checks -> 12; otherwise, if no
  activation stage is set and the action is not `current` (which already
  looked), runs `_miner_health` and turns any problem into "unhealthy", 12.
- Invariant: every quiet check with no activation in progress looks at the
  miner. (Not reached when state.json is unreadable.)

### `_fetch` (1188 to 1199), `_verify` (1202 to 1220), `_floor_check` (1223 to 1231)
- Fetch via the injected callable; any exception is a refusal; size cap 16
  KiB. Verify with parse_miner_release against the host trust set and the
  config's product, network, netuid, channel, at now_unix; any exception is a
  refusal. Floor check per channel against _effective_floor.

### `_fetch_kept` (1234 to 1252)
- Fetches, stores the bytes at state_dir/fetched-record (0600) and
  last_fetch {at, sha256, size}, or last_fetch {at, error}. So the fallback
  judges the same bytes.

### `_judge` (1255 to 1278)
- The fallback's verification: if the current updater fetched bytes this run,
  read them from fetched-record and check their sha256; else fetch. Then
  verify and floor-check, changing nothing.

### `_bundle_dir` (1281 to 1302)
- The release tree: an existing releases/<tree> is accepted only if
  root-controlled and still hashing to its digest; else fetch the archive (8
  MiB cap) and install_tree (archive sha256, bounded extraction, tree sha256,
  rename). Any exception is "the release bundle is unusable".

### `_rotate_trust` (1305 to 1331)
- Takes the bundle's trust/release-keys.json through rotate_trust: refused if
  it lists a revoked key or would not trust the key that signed this release
  for this channel. On refusal the tree is retired (unless it is the running
  tree) and the release remembered as failed. Records trust_generation.
- Invariant: a release can rotate keys but never lock the host out or re-add
  a revoked key.

### `_check_locked` (1334 to 1359)
- Requires running_tree to be an installed tree digest. Runs
  reconcile_interrupted_activation first; a halt becomes a `blocker` that
  outranks later channel refusals (so a halt keeps paging while the channel
  is down); a rollback becomes `early`. Re-reads state, then _check_channel.

### `_check_channel` (1362 to 1416)
- Order: fetch and keep; verify (host.verified = True from here); floor
  check; burn the floor {sequence, signed_sha256} and write state before any
  attempt; clear this tree's strikes when no newer tree is waiting; refuse a
  retired updater tree; install the bundle; rotate trust. With a blocker:
  self-update if the record names a new tree and no pin, else return the
  blocker. With an early rollback: return it. Then failure memory, the pin
  (held), self-update, or activate.
- Invariant: a failed activation still consumed its sequence, so a different
  record cannot reuse it (equivocation check). A pinned host still advances
  floors and takes trust rotations.

### `_save_record` (1422 to 1430), `_check_probe` (1433 to 1445)
- Save the fetched record under records/<signed_sha256>.json (others pruned);
  the probe must echo probe ok, signed_sha256, tree_sha256, STATE_SCHEMA and
  TRUST_STATE_SCHEMA.

### `_self_update` (1448 to 1564)
- Refused inside a handoff (depth > 0). Marks offered_updater/ambiguous
  blame. Probe the new tree from its own directory; a failed probe is one
  strike. Then flip updater/previous and updater/current and run the rest of
  the check as a child holding the lock (`handoff`, killed after
  HANDOFF_TIMEOUT 4857 s). Kept only if the child exits 0/10/11/12, reports
  verified true and an action string; the parent's own strikes are then
  dropped. Otherwise the links are restored; blame is "new" if the child gave
  a verdict or hung (124); a strike is counted only if this updater can
  verify what the child fetched, and no strike if the child's fetch failed
  outright.
- Effects: symlink flips under updater/, a child process, state writes.
- Invariant: a new updater is current only after proving a verified check,
  and one transient failure never blacklists a good tree.

### `_probe_as_fallback` (1567 to 1579), `_forgive` (1582 to 1589)
- The previous updater probes the tree the current one could not install;
  take back one strike.

### `fallback_to_previous` (1592 to 1750)
- Run by the shim from the `previous` tree with the current updater's exit
  status. Refuses unless this tree is `previous` and not `current`. A fresh
  last_check for the same status that says verified stands (the refusal is
  the record's fault), unless it names a stalled self-update with ambiguous
  blame, which this updater probes. Otherwise it judges the same bytes
  (`_judge`): cannot verify -> the channel is at fault, escalate only, pass
  the status through; can verify -> a strike against the current tree (never
  retiring it for a fetch-only failure); at two strikes, point updater/current
  back at this tree, remove `previous`, and exit 12 "demoted".
- Locks: the updater lock (a busy lock passes the current status through).
- Invariant: the fallback changes nothing but strikes and the updater links;
  it never activates and never rotates trust.

### `probe_release` (1753 to 1772)
- Run by the new tree before it is current: verify the saved record against
  the host trust set, floor check, confirm it runs from the record's tree,
  rehash its own tree, check the launcher profile. No side effects.

### `_check_launcher` (1781 to 1790)
- The bundle's launcher must declare the product's contract, the record's
  contract and the record image's repository.

### `_restart_miner` (1793 to 1805), `_start` (1808 to 1813)
- `systemctl daemon-reload`, `reset-failed <unit>` (errors ignored),
  `restart <unit>`; `_start` returns the exception instead of raising.

### `_previous` (1816 to 1840)
- What is running before a flip: for `legacy`, the container's image as
  observed now (None if down, so no unattended rollback target); for a
  release, the profile's image and the committed verified schema.

### `_commit` (1843 to 1857), `_clear_stage` (1860 to 1865), `_unit_inactive` (1868 to 1869)
- Commit sets miner.current, clears stage, pending and failed. Clear stage
  only clears. Inactive means ActiveState inactive or deactivating (not
  failed).

### `_miner_health` (1879 to 1917)
- miner/current missing -> problem; unit inactive -> INACTIVE_REASON (stop by
  hand without `pause`); no container and unit not active/activating/reloading
  -> "not running"; then `settle` (up to 90 s for a 20 s dwell) -> "not
  running steadily"; image differs from the selected release -> problem;
  restarts above the baseline kept in state -> problem (one restart between
  hourly checks pages, by design).
- Callers: _escalate, _confirm_current.

### `_confirm_current` (1920 to 1942)
- miner/current already selects this release: run the health check, commit
  the summary, return `current` or `unhealthy` (12).

### `_refuse_schema_decrease` (1945 to 1974)
- A release may not declare a schema below the high-water mark (any release
  that reached may_have_run) or the committed verified schema, unless it is
  the same image. Checked before any pull; not remembered as a failure.

### `_activate` (1977 to 2064)
- Launcher check; `active == target` -> confirm current; schema floor; unit
  inactive -> deferred with alert 12 (never start a stopped miner); gate
  closed -> deferred 0; stage the activation directory; record previous;
  stage `prepared` and write; prepare_image (pull, digest, platform,
  contract label, schema label; any failure clears the stage and refuses;
  the sequence stays burned); an unlabelled image is taken over only if it is
  the image already running; a label that differs is remembered as a
  failure; gate re-checked after the pull; latch `may_have_run` with
  flip_unix and raise schema_high_water; write state; one rename of
  miner/current; restart; `_prove_start`.
- Invariant: the latch is set before the swap and cleared only by proof.

### `_prove_start` (2067 to 2125)
- Accepts a start only if a container of the released image started at or
  after the flip, the unit is active, it stayed up through the 20 s dwell,
  and a second look 45 s later sees the same container with no new restarts.
  A container from before the flip means the restart never took effect: start
  once more. A restart error is never ignored. Success -> stage probation,
  "activated". Otherwise `_fail`.

### `_fail` (2128 to 2146), `_rollback` (2149 to 2187)
- Record the failure in pending; if rollback_allowed, point miner/current back
  at the previous target and start it up to twice, requiring the previous
  image to come back; raise RolledBack (10) with the release remembered as
  failed. If not allowed, or it does not come back, raise Halted (11) with
  what is running now.

### `_valid_pending` (2190 to 2198), `_new_probation` (2201 to 2211)
- Shape check of a pending record; a probation record {started_at, restarts,
  boot_id, entered_unix, restarts_forgiven}.

### `_confirm_probation` (2214 to 2295)
- miner/current changed -> halt. Unit inactive -> unhealthy 12, probation
  kept (a rollback would start the miner). Reboot (boot_id changed) -> look
  again and restart probation, or fail. Same container still up: commit after
  1800 s, else "probation". A changed container: one forgiven restart
  (restarts - baseline <= 1, image unchanged) restarts probation; otherwise
  `_fail`.

### `reconcile_interrupted_activation` (2298 to 2374)
- stage None -> nothing; `prepared` -> clear (nothing was selected); an
  unknown stage (a newer, demoted updater wrote it) -> halt; invalid pending
  -> halt; `probation` -> _confirm_probation; may_have_run with the previous
  target selected -> make sure the previous release runs (one retry), finish
  a halted rollback by remembering the release; with the pending target
  selected -> `_prove_start` (starting the release first if it never ran
  after the flip); anything else selected -> halt.
- Invariant: a check never guesses which release is running; it observes.

### `resolve` (2380 to 2433)
- `retry`: clear failure memory, retired updaters and strikes. `abandon`:
  for any stage beyond prepared, remember the pending release as failed,
  clear the stage, leave miner/current. `accept-release`: requires the
  release to be running (settle), re-points miner/current if needed,
  daemon-reload, commit. `restore-previous`: `_rollback`. Under the lock.

### `describe_status` (2436 to 2489)
- Config, paused, pin (or "invalid: ..."), trust view (or "unavailable:
  ..."), updater links and strikes, miner selection and stage,
  needs_operator, last check, last refusal, counters, floors.
- Hazard: read_state is the first line (2439): an unreadable state.json makes
  `status` refuse, while a bad pin or trust set is reported inline. Probe
  tests/probe_sn94_updater_silence.py::test_status_still_answers_... fails.

---

## Trust chain, as the code has it

1. Signing keys: Ed25519, generated offline, encrypted PEM. Roles: a key is
   listed for canary and/or stable in deploy/miner-update/release-keys.json
   (absent at this commit). The signer refuses an unencrypted key and a key
   the bundle's own trust root would not accept for the channel.
2. What is signed: canonical JSON of {schema, product, network, netuid,
   channel, sequence, issued_unix, expires_unix, release{version, image,
   runtime_contract, state_schema, bundle{url, archive_sha256, tree_sha256},
   promoted_canary for stable}, signing_key_id}. signed_sha256 is the digest
   of those bytes.
3. Host verification (miner_release.parse_miner_release 445 to 579): strict
   JSON (duplicate keys refused), exact key set, signing_key_id looked up in
   the host trust set /var/lib/cathedral-miner-update/trust.json (never the
   bundle's copy, never the network), 64-byte canonical base64 signature,
   Ed25519 verify before any other field is read, then product, network,
   netuid and channel against the deploy config, key role for the channel,
   validity window (expiry > issue, at most 14 days, not before issue minus
   300 s, not at or after expiry), image in a ghcr.io/cathedralai/ repository
   with one lowercase sha256 digest, https bundle URL, stable records must
   name the exact canary (same image and tree).
4. Floors (enforce_monotonic_release 582 to 606): per channel, a lower
   sequence is a rollback and refused; the same sequence with different bytes
   is equivocation and refused; the same bytes are idempotent (the host
   reports `current`). The floor is burned before any attempt. The bootstrap
   floor (--minimum-sequence) must be exceeded.
5. Stale record: refused "release has expired"; six unverified checks in a
   row page. Replayed old record: refused by the floor. A record for another
   product, network, netuid or channel: refused on identity.
6. Bad signature or untrusted key: refused, exit 10, unit success, one
   journal line; the sixth consecutive check without a verified record exits
   12 and pages. A previous updater's fallback judges the same bytes, so a
   channel that feeds each updater different bytes demotes nothing.
7. Downgrade: the sequence floor refuses an older record; the schema floor
   refuses an image declaring a lower durable-state schema unless it is the
   same image. A signer can still sign an older image at a higher sequence
   with the same or higher schema: the key is root, as the docs say.
8. Code path from record to root: the bundle carries the launcher (run by
   the miner unit as root), the unit drop-in, the updater's own code (run by
   the updater unit as root through the shim) and the next trust root. The
   image runs as uid 0 inside the container with every capability dropped.
9. Rotation: a bundle's trust root replaces the host set only forward; keys
   it drops are revoked for good on that host; it must still trust the key
   that signed the delivering release; a revoked key can never be re-added,
   not by a bundle, an old updater tree, a re-bootstrap or a repair.

## The container boundary (scripts/run_sn94_snp_miner.sh 170 to 190)

- `docker run --rm --name cathedral-sn94-snp-miner --init --pull never
  --network host --read-only --tmpfs /run/cathedral-snp-miner (16 MiB, noexec,
  nosuid, nodev, 0700) --mount /etc/cathedral/validator-access ro --mount
  /var/lib/cathedral/validator-access rw --device /dev/sev-guest rwm
  --cap-drop ALL --security-opt no-new-privileges --pids-limit 128 --memory
  1g --memory-swap 1g --ulimit nofile 1024 --stop-timeout 15` plus the three
  CATHEDRAL_* env values.
- Root inside the container (USER 0:0), no user namespace, no capabilities,
  host network namespace (binds 0.0.0.0:8081 directly on the host). The host
  nftables table cathedral_sn94_snp (launcher 144 to 167) drops IPv6 on 8081,
  invalid state, non-SYN new connections, more than 4 SYN/s burst 8 and more
  than 2 concurrent connections per source IP. The table is deleted on
  cleanup.
- Preflight: the two directories must be root 0700 and the three config files
  root 0644 and not symlinks (83 to 105); /dev/sev-guest must be a character
  device the launcher can read and write (107 to 110); the image is pulled
  only when the exact digest is not local, then RepoDigest, linux/amd64 and
  the contract label are checked (115 to 135).
- Stop: the TERM trap exits 143 after `docker rm --force` (SIGKILL to the
  container). No graceful stop.

## Keys and where they live

- Miner coldkey and hotkey private material: a separate wallet machine
  (btcli). Never on the miner. The miner holds only the public SS58 hotkey in
  /etc/cathedral/sn94-snp-miner.env (root 0600) and passes it to the
  container as CATHEDRAL_MINER_HOTKEY.
- The miner does not reach the chain. Validators reach it on 8081 with
  sr25519-signed requests (X-Cathedral-Validator-Request); the worker admits
  a validator only if its hotkey is in the current signed snapshot.
- Snapshot signing seed (Ed25519): the operator's control host,
  /var/lib/cathedral-validator-access/signer/snapshot.seed, owned by the
  cathedral-access service user; the refresh timer signs a 900 s snapshot
  every 2 min from a chain read.
- Snapshot public keys: /etc/cathedral/validator-access/snapshot-keys.json
  (root 0644) on the worker, pinned by sha256 in both the miner env and the
  fetch env.
- Snapshot: /etc/cathedral/validator-access/validator-access.json, installed
  by cathedral-validator-access-fetch.service every 2 min (root, no
  capabilities, AF_INET only, writes only that directory); the worker reloads
  it on inode change without a restart; protected routes close at expiry.
- Replay state: /var/lib/cathedral/validator-access/validator-access.sqlite
  (root 0600), written by the worker on every validator request.
- Worker TLS key: generated inside the container at every start into the
  tmpfs /run/cathedral-snp-miner (0600), self-signed leaf valid 30 days
  (audit_miner_entrypoint 234 to 235). Validators bind to its SPKI through
  the SNP report.
- Release trust root: /var/lib/cathedral-miner-update/trust.json and
  .backup (root 0600). Release private keys: offline only.
- Legacy: /etc/cathedral/policy-signing-sn94.key, read as root by the legacy
  republisher unit if installed.

## Paths that stop a live miner earning without a page

Live host assumed not enrolled (so none of the updater's alerts exist).

1. Docker daemon restart (apt upgrade of docker or containerd, `systemctl
   restart docker`): the container exits 143, the launcher exits 143, the
   example unit counts it as success and `Restart=on-failure` does not
   restart. No OnFailure. The audit example unit and the release drop-in were
   fixed for this; the SNP example unit was not. Probe
   tests/probe_sn94_miner_unit.py::test_the_snp_unit_restarts_after_a_clean_
   signal_exit fails.
2. Any start while the snapshot is stale (a reboot or restart while the
   control host or its URL is unreachable, or more than 15 min after the last
   fetch): the worker refuses to start (cli.py 2040 to 2041), five starts in
   300 s hit the start limit, the unit stays failed. The fetch alarm pages
   only while the snapshot is stale and goes quiet once a fresh one lands; the
   miner stays down. Observed live on TDX in 4f0c702. Probe
   tests/probe_sn94_miner_unit.py::test_the_snp_unit_pages_when_it_stops_
   restarting fails.
3. Snapshot expiry with the worker up: protected routes close; the fetch
   unit's exit 3 pages only if the operator installed
   /usr/local/sbin/cathedral-validator-access-page (docs call it required).
4. /dev/sev-guest missing after a kernel or module change: the unit's
   condition fails and systemd skips it silently at boot.
5. Host clock stepped back more than 135 s: every signed request refused,
   logged once a minute, no page (documented in MINING.md).
6. A self-signed leaf older than 30 days (a container up that long): whether
   validators still accept it depends on cathedral-validator's TLS client,
   not read here.

On an enrolled host, 1 is covered by Restart=always and 2 by the hourly
`unhealthy` page, unless state.json is unreadable (see read_state hazard).

## What the unit files do that the docs do not say

- cathedral-sn94-snp-miner.service: items 1 to 5 under section 3.
- cathedral-miner-update.service: `SuccessExitStatus=10` means every refusal,
  including the unreadable-state refusal, is unit success; the docs' failure
  table (docs/MINER_AUTO_UPDATE.md 362 to 382) has no row for state.json.
- miner-unit.conf: documented in docs/MINER_AUTO_UPDATE.md 220 to 225.
- install-miner-update.sh: the --minimum-sequence wording contradicts the
  floor semantics (exceed, not reach).
- cathedral-sn94-policy-republisher.*: no current doc installs it; its name
  says SN94, its description says legacy.

## Hazards (trusting what was not checked)

1. examples/systemd/cathedral-sn94-snp-miner.service:19-21 trusts that a
   non-zero exit is always a failure; 143 is declared success and not
   restarted.
2. Both example miner units trust systemd's restart loop to recover the miner
   and have no OnFailure=; the start limit ends the loop silently.
3. miner_updater._locked:1036-1038 trusts state.json to be readable; an
   unreadable one skips every alert path and the health check, exit 10.
4. describe_status:2439 trusts state.json before reporting anything.
5. install-miner-update.sh:18-19 documents --minimum-sequence as inclusive;
   the floor is exclusive.
6. Dockerfile.sn94-snp-miner:30 copies the whole `cathedral/` context; a
   stray image_chain.json would change the served subnet under a finney-94
   label (local builds only).
7. The SNP unit's `ReadWritePaths=/run` opens all of /run, not just the lock,
   the nft temp file and the docker socket.
8. The legacy republisher unit has `ReadWritePaths=/etc/cathedral`, the
   miner's trusted config directory, and an SN94 name.
9. audit_miner_entrypoint:234-235 issues a 30-day leaf at start and nothing
   renews it while the container runs.
10. miner_update_cli.safe_to_activate trusts the snapshot's generated_at and
    expires_at from an unsigned read (json.loads, no signature check); the
    gate decides only timing, so a forged file could at worst defer or allow
    a restart, never change what runs. Root-owned 0644 file, so only root
    could forge it.
11. The shim trusts /usr/bin/python3 and the distro cryptography package; a
    distro upgrade of either is outside the signed channel (documented).
12. The signer (command_canary) trusts the operator's --image digest without
    inspecting the image; the host's prepare_image is the only check that the
    digest exists, is linux/amd64 and carries the labels.
13. The worst-case budget leaves 63 s between worst_case_seconds (7617) plus
    the 120 s margin and TimeoutStartSec (7800). Any added host step needs
    the unit changed too.

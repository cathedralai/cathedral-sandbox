# Catalog R: room kit installers run against a fake host (review round 6)

Artifact: cathedral-sandbox, worktree `/Users/dreamboat/Documents/projects.nosync/cathedral-sandbox-pr308`,
branch fix/review-round-6, head a4c28a5, plus two uncommitted changes made for this pass:
`room-kit/install.sh` (ROOM_DESTDIR prefix, 15 insertions, 12 deletions) and the new file
`tests/test_room_kit_installer_behaviour.py` (822 lines, 29 test functions, 40 cases).

Question: do the installers do what the text tests say they do, when run? Out of scope: the
Python and Go code, live hosts, the guest build (build-guest.sh), apt.

Outcome: install.sh runs end to end on the fake host, 13 steps, "done.". room-net.sh,
host-net.sh and step 5 of install-sealed.sh run verbatim. 39 tests pass, 1 strict xfail pins a
defect. 19 of 19 guard removals are caught. Two defects found in install.sh (R1 medium for
stage H, R2 low). Run time 43 s on this Mac.

```
cd /Users/dreamboat/Documents/projects.nosync/cathedral-sandbox-pr308
.venv/bin/python -m pytest -q -p no:cacheprovider tests/test_room_kit_installer_behaviour.py -rx
# 39 passed, 1 xfailed in 43.42s
```

## 1. Command inventory (current line numbers, after the ROOM_DESTDIR edit)

### install.sh (528 lines)

External commands, in order of first use:

| Command | Lines | Faked in the harness |
|---|---|---|
| dirname, pwd, readlink -f | 9, 13 | real |
| id -u | 18 | fake (answers 0) |
| mkdir, chmod, cp, mv, rm, ln, cat, tr, cut, head, tail, wc, seq, sed, awk | throughout | real |
| docker -H unix://$SOCK ps/info/pull | 47, 300 to 302 | fake (room count per call, runtime runsc) |
| curl -fsSL --retry 3 -o | 63 (fetch) | fake (a directory of files) |
| sha512sum, sha256sum -c --quiet - | 62, 64, 176, 200, 295 | real |
| command -v dockerd mkfs.xfs curl bzip2 iptables nft conntrack | 70 to 76 | present on the fake PATH, so apt is not needed |
| apt-get update/install | 88, 89 | fake, never reached |
| systemctl mask/enable/daemon-reload/restart/start | 93, 96, 255, 256, 293, 298, 511 to 517 | fake (logs, keeps an active set) |
| python3 assess.py | 99, 265 | the kit copy's assess.py is a stub |
| python3 -c json | 202 to 204, 278, 288, 289 | real python |
| install -m [-o -g] | 132, 181 to 186, 201, 308, 312, 314 | wrapper: drops -o/-g, runs the real install |
| blkid, mkfs.xfs, truncate | 134 to 140 | blkid not reached (no device); mkfs.xfs fake; truncate real (1 GiB sparse) |
| tar --no-same-owner -x | 161, 170, 178, 190 | real (bsdtar here, GNU tar on CI) |
| $ROOM_OPT/bin/uv python install / venv / pip install | 172 to 175 | the fake archive's uv |
| chown -R root:root, chown poolroom | 191, 261 | fake |
| id poolroom, useradd | 194 | id fake answers "exists"; useradd never reached |
| mountpoint -q, xfs_info | 257, 258 | fake |
| grep ... /proc/mounts | 259 | grep wrapper swaps /proc/mounts for a harness file |
| df -B1 --output=size | 266 | fake (3500 GiB) |
| ip -o route show | 279 | fake (route list from env) |
| python3 size.py, net_plan.py, net_capacity.py | 268, 282, 287 | real |
| sleep | 300, 523 | fake (no wait) |
| ufw status, iptables -S INPUT / -C / -I | 503 to 507 | fake (inactive; policy ACCEPT) |
| curl -s -o /dev/null -w %{http_code} -H @file | 522 | fake (200 only when the header file holds the installed key) |
| $ROOM_OPT/venv/bin/python -V, runsc --version, caddy version | 527 | the fake archives' programs |

Absolute paths written: `/etc/pool-room/*` (machine.json, room.env, room.env.applied, install-state,
daemon.json, api.key, secret.env, reaper.headers, api.env, Caddyfile, size.json, size-unbridged.json),
`/opt/pool-room/{cache,bin,gvisor-*,gvisor,python,venv,src.new,src}`, `/etc/systemd/system/<9 units>`,
`/usr/sbin/policy-rc.d` (apt branch only, line 85), `$ROOM_DATA_IMG`, `$ROOM_DATA_DIR/{work,docker}`.
Read-only fixed paths: `/run/containerd/containerd.sock` (96), `/proc/mounts` (259).
Directory choice: `ROOM_ETC=/etc/pool-room`, `ROOM_OPT=/opt/pool-room`, `ROOM_RUN=/run/pool-room`,
units to `/etc/systemd/system`, all fixed at lines 28 to 33; `ROOM_DATA_DIR`, `ROOM_DATA_IMG`,
`ROOM_API_KEY_FILE` come from room.env. There was no root or prefix override.

### install-sealed.sh (152 lines)

readlink, id -u (18); cat /sys/module/kvm_amd/parameters/sev_snp (23); `[ -c /dev/sev ]` (24, builtin);
df -B1, du -B1 (27, 28); awk /proc/meminfo (32); systemctl is-active (33, 115, 136); command -v
qemu-system-x86_64 mmdebstrap zstd cpio, python3 -c 'import venv' (37 to 42); apt-get (45);
qemu-system-x86_64 -object help (47); readlink (53, 57); build-guest.sh (55); python3 -m venv, pip
install sev-snp-measure (59, 60); sev-snp-measure (62); install -m 0755 -t, install -m 0600 (68, 70);
units to /etc/systemd/system (74, 82, 91); systemctl daemon-reload/enable --now/restart/disable --now
(108, 109, 130, 148); curl -fsS -m 10 -H Bearer (118), curl -fsS -m 5 -o (135); python3 -c json (119,
140); tr (118); sleep 5 (137); date, cp (141); ln -sfn (149).
Writes: `$SEALED_DIR/{images,run,venv,host-net.sh,launch-guest.sh,sealed.env}`, the three units.

### lib/room-net.sh (117 lines)

python3 (ipaddress), tr, cut, iptables, ip6tables (if present), nft, ip link/addr/route, sysctl, grep,
sed, awk, rm -f `$ROOM_DATA_DIR/docker/network/files/local-kv.db`. All faked except python3, tr, cut,
grep, sed, awk, rm.

### sealed/host-net.sh (56 lines)

ip tuntap/addr/link, sysctl, iptables (-N -F -A -C -I -D -X, -t nat), grep, `exec "$0" up`. All faked
except grep and the re-exec.

## 2. What the harness is

`FakeHost` in the test file builds, per test, under pytest's tmp_path:

- `bin/`: fake commands (id, systemctl, docker, curl, sleep, df, du, ufw, qemu-system-x86_64, iptables,
  ip6tables, ip, chown, useradd, apt-get, mkfs.xfs, xfs_info, mountpoint, nft, sysctl, conntrack,
  dockerd, mmdebstrap, zstd, cpio). Each appends `name argv` to a log and answers from `FAKE_*` env
  knobs (room count per `docker ps` call, HTTP codes per poll, routes, links, iptables -C answers,
  sealed room count, attestation failures, measurement). Two wrappers run the real tool: `grep` (swaps
  `/proc/mounts` for a harness file) and `install` (drops `-o`/`-g`, which need root). `python3` and
  `bzip2` are symlinks to the real ones. PATH is `bin:/usr/bin:/bin:/usr/sbin:/sbin`.
- `kit/`: a copy of room-kit without dist/. Changes to the copy: assess.py replaced by a stub that
  writes a fixed machine.json (192 threads, 752 GiB, nothing else running; the real one reads
  /proc and /sys of this machine); versions.lock keeps the real URLs and pins the harness archives'
  real sha512/sha256; `dist/cathedral-test.tar.gz` stands in for the untracked API tarball with its
  real sha256 pinned; `#!/bin/bash` shebangs point at bash 5 (the scripts exec each other through
  the shebang; macOS's /bin/bash is 3.2, Ubuntu's is 5). Everything else in the kit (install.sh,
  lib/*.sh, profiles/v1.sh, size.py, net_plan.py, net_capacity.py, sealed/*.sh) is byte-identical.
- `www/`: three small archives with the real member layout (gvisor.tar.bz2 with `runsc`;
  uv-x86_64-unknown-linux-gnu.tar.gz with `uv-.../uv`; caddy_2.11.4_linux_amd64.tar.gz with `caddy`),
  served by the fake curl under the pinned URLs' file names. The archives carry tiny bash programs
  that answer `--version`, `version`, and `uv python install / venv / pip install`.
- `root/`: ROOM_DESTDIR, with `etc/systemd/system` and `run/pool-room` pre-made (a real host has them).
  The live-room guard needs a socket inode at `$ROOM_DESTDIR/run/pool-room/docker.sock`; the test binds
  an AF_UNIX socket with a relative name from that directory (paths are capped near 104 bytes).
- room.env and sealed.env are the shipped example files plus path overrides (key file, data dir,
  data image at 1 GiB, SEALED_DIR, hotel key, OVMF path) and `ROOM_CUSTOMER=guest-1`. So every run also
  proves the examples are valid installer input.
- Every script runs under `bash -x`; the trace is kept, so the "key never printed" promise is checked
  against the trace itself.

The install.sh change (the only script change): `ROOM_DESTDIR` prefixes `ROOM_ETC`, `ROOM_OPT`,
`ROOM_RUN` and a new `UNIT_DIR=${ROOM_DESTDIR:-}/etc/systemd/system`; the nine `cat > /etc/systemd/system/X`
become `cat > "$UNIT_DIR/X"`. With ROOM_DESTDIR unset every path is the same string as before (checked
with `set -u`); generated unit text is unchanged. `/usr/sbin/policy-rc.d` (apt branch) and the two
read-only fixed paths are not prefixed. install-sealed.sh is not changed (see property f).
Existing text tests still pass (test_room_kit_installer.py counts characters around the guard calls).

The first command that cannot be faked:

- install.sh, main path: none. The whole script reaches "done." (fake commands used in a clean run:
  chown curl df docker id install ip iptables mkfs.xfs mountpoint systemctl ufw uv xfs_info).
- install.sh, apt branch (no dockerd on PATH): line 85, `printf ... > /usr/sbin/policy-rc.d`, a shell
  redirection to a fixed path ("Operation not permitted"). Not reached by any test, by choice.
- install-sealed.sh: line 23 stops first (`cat /sys/module/kvm_amd/parameters/sev_snp`; a cat wrapper
  could fake it, none was added); line 24 `[ -c /dev/sev ]` is a bash builtin test on a device path and
  no PATH stub can fake it. Prefixing hardware probe paths would turn a test knob into a hardware-check
  bypass, so the unit writes at lines 74, 82, 91 were not prefixed either.

## 3. Properties

(a) Live rooms refuse the install before any write. PROVED.
`test_live_rooms_refuse_the_install_before_any_write`: socket present, fake docker reports 2 rooms;
exit 1; stderr names "2 live room(s)" and `ROOM_RESTART_WITH_ROOMS=1`; the only new entries under the
root are the directories etc/pool-room, opt, opt/pool-room/{cache,bin} (no file); no data image; the
only commands run were `id -u` and one `docker -H unix://.../docker.sock ps -q --filter
label=cathedral.sandbox.owner`. Also: a daemon that does not answer refuses with the reason
(`FAKE_DOCKER_PS=fail`); `ROOM_RESTART_WITH_ROOMS=1` runs to "done." without counting.
Exact: the guard (line 58) runs after `mkdir -p` of three directories (line 36), not before.

(b) Unreadable ROOM_API_KEY_FILE or bad ROOM_CUSTOMER refuses before any write. PROVED.
Key file missing, mode 000, or ROOM_API_KEY_FILE empty: exit 1, "must be a readable file", the root is
untouched (not even the directories), only `id -u` ran. ROOM_CUSTOMER in `""`, `a,b`, `a:b`, `-x`, `.x`,
65 chars, `a b`: exit 1, "ROOM_CUSTOMER must be 1 to 64", root untouched.

(c) A pinned download whose checksum differs is refused and nothing is installed. PROVED, with a precise
statement of "nothing". For each of gVisor, uv, Caddy served with one byte appended: exit 1, stderr
"checksum mismatch: <the pinned URL>", no `.part` or archive in the cache, nothing from the archive on
disk (no gvisor dir, no bin/uv, no venv, no bin/caddy), no api.key or secret.env, no docker or API unit,
and no systemctl call other than step 0's `enable --now containerd`. What a refused download does leave
(steps 1 and 2 ran): etc/pool-room/{install-state,machine.json,room.env}, opt/pool-room/bin/room-data.sh,
the data unit file (never loaded: no daemon-reload), and the formatted sparse data image. A re-run picks
these up. Also PROVED: a corrupt pinned API tarball on an installed hotel (CATHEDRAL_TARBALL_SHA256 wrong)
fails the run after the uv/venv/pip steps and before the source swap: /opt/pool-room/src/COMMIT and the
source are untouched, no src.new is left, no unit is restarted. `test_the_shipped_tarball_matches_the_lock`
checks the real dist tarball against versions.lock where it exists (skips on CI: dist/ is untracked).

(d) Clean host: units, key store, daemon config. PROVED.
Exit 0; stdout has "size: 165 slots, quota 165:165:660" (memory limits the fake host:
floor(752 x 0.88 / 4)), "API status: 200", "done.". room-a.service has TimeoutStopSec=600, KillMode=mixed,
User=poolroom, two EnvironmentFile lines, `ExecStart=.../venv/bin/python .../room_api.py sandbox serve
--host 127.0.0.1 --port 18090 --runtime docker`. api.env has `TMPDIR=<ROOM_DATA_DIR>/work`. secret.env is
exactly `CATHEDRAL_SANDBOX_KEYS=<key>:guest-1:165\n`; api.key is the key; reaper.headers is
`Authorization: Bearer <key>`; modes 0640/0600/0600, room.env and Caddyfile 0644. daemon.json parses:
default-runtime runsc, iptables and ip6tables false, hosts `unix://<ROOM_RUN>/docker.sock`, runsc args
from ROOM_RUNSC_FLAGS, data-root under ROOM_DATA_DIR. All 9 units exist; the egress unit is
Before=room-a.service; the docker unit is KillMode=process; the Caddyfile proxies to 127.0.0.1:18092
(receipts) and /room/health to 18091. Downloads went to the three pinned URLs in order. install-state
lists the data image and the units, not `user:poolroom` (the user existed). systemd order: daemon-reload
before the first enable; the API restarted exactly once; receipts and caddy restarted; the reaper timer
started. The 40-char key appears nowhere in the `bash -x` trace or stdout (step 9's `set +x` works).
The final 200 came only because the fake API saw the installed key in the header file, which proves the
key path ROOM_API_KEY_FILE to reaper.headers to curl.

(e) The final check fails the install when the API never answers 200 with the key. PROVED.
`FAKE_API_CODES=401`: exit 1, "API did not answer 200 on /v1/status with its own key (got 401)", no
"done.", exactly 60 polls, each `-H @<ROOM_ETC>/reaper.headers http://127.0.0.1:18090/v1/status`.
`000 000 200`: exit 0 after 3 polls.

(f) install-sealed.sh: live rooms, measurement mismatch. PROVED on a verbatim slice, NOT REACHED as a
whole-script run. The slice is the file's real head (lines 1 to 21: set -euo pipefail, KIT, ENV_FILE,
source, log, root check, UNIT) plus the real text from the step 5 marker (line 111) to the end, with
PREV_IMG, IMG and EXPECTED (what steps 3 and 4 produce) set from env. Steps 1 to 4 are not run: line 24
is a builtin device test (see section 2) and steps 3 and 4 need the guest build, sev-snp-measure and
unit writes to a fixed path. Results: unit active and 3 rooms, exit 1 with "3 live room(s)" and
`SEALED_RESTART_WITH_ROOMS=1`, no restart, current image unchanged, the key not in stdout; with
`SEALED_RESTART_WITH_ROOMS=1` the restart happens, "measurement matches the build", attestation.json
written and a dated copy kept in the image dir; hotel API down, exit 1 "did not answer, so live rooms
cannot be counted", no restart; unit not active (first start), no /v1/sandboxes call, the attestation is
polled until the guest answers (3 polls with 2 failures); measurement differs, exit 1, stdout
"MEASUREMENT DIFFERS: report <got>, build <expected>", `systemctl disable --now` after the restart,
`images/current` points back at PREV_IMG, the differing report is kept with the build; guest stops after
the restart, exit 1 "guest stopped" after one attestation poll. Also PROVED as a whole-script run:
`install.sh --sealed sealed.env` on a host without SEV-SNP hands off to install-sealed.sh and stops at
the first check with "SEV-SNP is not enabled in kvm_amd", writing nothing (no SEALED_DIR).

Beyond the list:

- room-net.sh `up` (3 bridges: pqbr0, rmnet0, rmnet1): local-kv.db removed; for every bridge the five
  private-range drops come before `! -s <net> -j DROP` before `! -o <br> -j ACCEPT`; `-o <br> -j DROP`,
  `-i <br> -j DROP`; the two egress-daemon INPUT accepts; the INPUT jump with the tag; MASQUERADE per
  net with the tag; ip6tables FORWARD drop per bridge; `nft ... meta ibrname <br> drop` per bridge; the
  nft table and chain come after `down`'s delete and before any rule; the FORWARD jump is the last
  iptables call. `up` refuses a routed main CIDR and a routed room network with the exact messages and
  never inserts the FORWARD jump. `down` deletes only the rules carrying the room tag (an untagged
  DOCKER-USER rule in the same table is left), flushes and removes both chains, deletes the nft table,
  deletes pqbr0 and the rmnetN bridges and not another bridge.
- host-net.sh: `up` builds SEALED-SNP0-FWD in the order DROP private, ACCEPT from the guest, DROP,
  ACCEPT established out, DROP out, then the FORWARD and INPUT jumps and one MASQUERADE; `down` removes
  the jumps, the NAT rule, both chains and the tap. `check` with every rule present changes nothing;
  with a missing rule it logs the restore and re-runs `up` (the re-exec goes through the shebang).
- Stage H re-run on an installed hotel: no download (cache hit on the pinned sums), no "config changed",
  no daemon restart, the API restarted once, the room count taken twice (top and step 13). A changed
  ROOM_BRIDGE_CIDR restarts the daemon once with a third count right before it. Rooms that open after the
  top check stop the API restart (step 13) or the daemon restart (step 8) with no restart of anything.
- A data volume without prjquota is refused at step 8 before any key is written.
- ROOM_NETS auto with a 100-port bridge cap: one /22 is planned, the /22 another device routes and this
  room's own bridge route are skipped, room.env equals room.env.applied, api.env carries
  CATHEDRAL_ROOM_NETWORKS=1, the subnet, the bridge prefix and the DNS list.

## 4. Guard-removal proofs

Driver: `/private/tmp/claude-501/-Users-dreamboat/ee2659b3-2cee-4ceb-bf15-2f0be7f105e3/scratchpad/mutate.py`.
It copies tests/ and room-kit/ to a temp dir, deletes or edits one line in the copy, and runs the copied
test module there (`KIT` resolves relative to the test file). Each mutation touched exactly the lines
stated. Run: `SCRATCH=$PWD .venv/bin/python mutate.py` from the scratchpad.

| Mutation (file, change) | Caught by | How it showed |
|---|---|---|
| a1 install.sh:58 first `refuse_restart_with_rooms` call deleted | test_live_rooms_refuse_the_install_before_any_write | files written (room.env.applied, ...); the run still exits 1 at the step 13 guard |
| a2 all three call lines deleted | the same, test_rooms_that_open_during_the_install_stop_the_api_restart | exit 0 and "done." with a live room |
| b1 install.sh:23 key-file check deleted | test_an_unreadable_key_file_refuses_before_any_write (3 of 3) | the run writes config, enables and starts the daemon, then dies at line 306 `tr < file` ("No such file", "Permission denied") |
| b2 install.sh:26 ROOM_CUSTOMER check deleted | test_a_bad_room_customer_refuses_before_any_write (7 of 7) | exit 0 with `CATHEDRAL_SANDBOX_KEYS=<key>:a,b:165` |
| c  install.sh:64 checksum line in fetch deleted | test_a_download_with_the_wrong_checksum... (3 of 3) | exit 0: the tampered archives were extracted and the install finished |
| c2 install.sh:176 tarball sha line deleted | test_a_corrupt_pinned_tarball_leaves_the_running_api_source_alone | exit 0 with the corrupt tarball |
| d  install.sh TimeoutStopSec=600 changed to 90 | test_a_clean_host_gets_the_units... | unit text |
| e  install.sh:525 final 200 check deleted | test_the_final_check_fails_the_install_when_the_api_never_answers_200 | exit 0 with 401 |
| e2 install.sh:522 header file dropped from the status curl | test_the_final_check_fails... (header assertion), test_a_clean_host... (401, exit 1) | first driver run used the wrong -k and reported a miss; corrected run caught it |
| g  install.sh:259 prjquota check deleted | test_a_data_volume_without_project_quota_is_refused | exit 0 |
| f1 install-sealed.sh:129 guard call deleted | test_sealed_restart_with_live_rooms_is_refused_unless_overridden | restart logged with 3 live rooms |
| f2 install-sealed.sh:149 PREV_IMG restore deleted | test_sealed_measurement_mismatch... | current still points at the new image |
| f3 install-sealed.sh:148 disable --now deleted | the same | no disable in the systemctl log |
| f4 install-sealed.sh:136 guest-stopped check deleted | test_sealed_guest_that_stops_fails_the_install_at_once | 180 polls then "no attestation after 15 min" instead of a fast "guest stopped" |
| n1 room-net.sh:89 anti-spoof rule deleted | test_room_net_up_builds_every_bridge_guard... | rule missing |
| n2 room-net.sh FORWARD jump moved to the top of up() | the same | last iptables call is a MASQUERADE; first driver attempt added a second jump instead of moving it and was (rightly) not caught, corrected run caught it |
| n3 room-net.sh:53 routed-CIDR refusal deleted | test_room_net_up_refuses_a_cidr_another_route_uses[main CIDR] | exit 0 |
| h1 host-net.sh:46 `exec "$0" up` deleted | test_host_net_check_restores_missing_rules... | only `-C` calls, no restore |
| h2 host-net.sh:24 private-range drop deleted | test_host_net_up_orders_the_guest_rules... | rule order |

## 5. Defects found in the scripts

R1 (medium, stage H). install.sh:294 marks the new bridge settings as applied before the daemon restart
they need can be refused.

- Code path: step 8 runs `cp room.env room.env.applied` (294), then compares the daemon hash (295),
  logs "room daemon config changed: restarting the room daemon" (296), and only then runs
  `refuse_restart_with_rooms` (297). When a room opened between the top check (58) and here, the guard
  exits 1 with the applied file already updated. The next run computes ROOM_DAEMON_HASH_BEFORE (200)
  from daemon.json and `net_settings`, which reads room.env.applied: both already hold the new values,
  the hashes match, no restart. The room daemon and room-net.sh's firewall keep the old bridge settings
  for good; the API (api.env, restarted at step 13) gets the new ones.
- Reproduced on the fake host (`scratchpad/stale_applied.py`): run 1 clean; run 2 with a new
  ROOM_BRIDGE_CIDR and FAKE_DOCKER_PS="0 1" exits 1 with the applied file at the new CIDR and the
  "config changed" line printed; run 3 with no rooms exits 0, prints "done.", no "config changed", no
  `systemctl restart room-a-docker.service`. With ROOM_NETS grown from one to two CIDRs instead: run 3
  hands the API `CATHEDRAL_ROOM_NETWORKS=2` and both subnets and restarts it, while the daemon and the
  rmnet1 guard rules (room-net.sh up runs at daemon start only) were never built.
- User-visible: the operator sees "done." on a run that applied nothing to the daemon. For a ROOM_NETS
  addition, rooms are placed on a bridge that has none of room-net.sh's rules (no private-range drops,
  no anti-spoof, no MASQUERADE for its subnet, no guest-to-guest nft drop). What stands between those
  rooms and the host is room_egress.py's per-room policy, not checked here.
- Why it matters now: stage H is a re-run on a hotel the broker keeps busy; the window between line 58
  and line 297 is the whole download and pip phase.
- Pinned: `test_a_refused_daemon_restart_is_done_by_the_next_run`, strict xfail with this reason (the
  repo had no xfail before; drop the marker with the fix, or drop the test if the convention is not
  wanted). Fix sketch: compute the after-hash from room.env (give `net_settings` a file argument),
  restart, then copy room.env to room.env.applied; the refusal then exits before the copy and the next
  run sees the change. The auto-mode carry-over at 119 to 128 already assumes "applied means applied".

R2 (low). install.sh:295: the `[ -n "${ROOM_DAEMON_HASH_BEFORE// -/}" ]` guard can never be false, so
every first install restarts the room daemon right after starting it.

- Code path: line 200 hashes `{ cat daemon.json room-net.sh 2>/dev/null; net_settings; }` and on a
  first install both files are missing, so the hash is sha256 of nothing, still a 64-hex digest plus
  "  -"; stripping " -" leaves a non-empty string. The after-hash differs, so `systemctl enable --now
  room-a-docker.service` is followed by `systemctl restart room-a-docker.service` (observed in every
  clean run, with the log line "room daemon config changed"). Dead since the first version (7ea0cae;
  648c076 kept it).
- User-visible: on a first install and on every sealed guest boot (guest-boot.sh runs install.sh on a
  fresh initrd root) the bridge goes down and up once more and dockerd restarts seconds after it
  started; a misleading "config changed" line. No rooms exist yet, so no room is lost; cost is seconds.
  Re-runs are not affected (proved: no restart on an unchanged re-run). Not asserted by the tests either
  way. Fix sketch: set ROOM_DAEMON_HASH_BEFORE only when daemon.json exists, else empty.

Observations, not findings:

- The live-room guard runs after `mkdir -p` of three directories (36 before 58). No file is written.
- A refused step 13 restart on a re-run has already rewritten every config file, every unit and
  /opt/pool-room/src; by design the guard protects restarts, not writes. `Restart=on-failure` would
  bring the new code up at the next crash of the API.
- A refused download leaves the step 1 and 2 files listed under (c) and containerd enabled.
- The corrupt-tarball check (176) comes after `uv python install`, `uv venv` and `uv pip install`
  (172 to 175), so a bad tarball costs those steps but never the running source.

## 6. Limits of this floor

- Linux CI (ubuntu-latest) was not run from this Mac. The harness uses only GNU-compatible invocations
  of the real tools (readlink -f, install -m, tar --no-same-owner --strip-components, sha*sum -c --quiet -,
  truncate -s, bzip2 for GNU tar -j via a PATH symlink) and fakes df and du, whose GNU options the Mac
  lacks. The module skips without bash 4+ or bzip2.
- The fakes answer, they do not model: `docker ps` counts come from a list per call; systemd state is a
  set of active units; iptables never fails. Ordering and argv are what is checked.
- assess.py is stubbed; its own behaviour is not covered here. size.py, net_plan.py and net_capacity.py
  run for real.
- Not reached: the apt branch (step 0), install-sealed.sh steps 1 to 4, build-guest.sh, launch-guest.sh,
  room-data.sh (losetup, mount), uninstall.sh.
- `test_the_shipped_tarball_matches_the_lock` skips where dist/ is absent (CI), passes here.

## 7. Files

- `tests/test_room_kit_installer_behaviour.py` (new): 29 test functions, 40 cases, ruff clean.
- `room-kit/install.sh`: ROOM_DESTDIR prefix only (lines 28 to 33 and the nine unit redirects).
- Scratch (not for the repo): `scratchpad/inspect_install.py` (prints what a run leaves behind),
  `scratchpad/mutate.py` (guard removals), `scratchpad/stale_applied.py` (R1 reproduction).

Next action: owner of #312/#313 decides on R1 (fix order of cp and restart) and whether the xfail pin
stays; CI run of the new module on ubuntu-latest.

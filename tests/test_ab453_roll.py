"""AB#453: dry-run tests for ops/roll/roll.sh with fake ssh, curl and guard on PATH.

Nothing here touches a network or a host. The fakes read canned answers from a scenario directory
and log every call, so each test can assert both the refusal and what was (not) done.
"""
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ROLL = ROOT / "ops" / "roll" / "roll.sh"
CUR = "a" * 96
NEW = "b" * 96
HOTEL = "hotel-x"

FAKE_CURL = r"""#!/bin/bash
F=$FAKE_DIR; url=""; out=""; method=GET; data=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift ;;
    -X) method=$2; shift ;;
    -d) data=$2; shift ;;
    http*) url=$1 ;;
  esac
  shift
done
case "$url" in
  */v1/broker/capacity) cat "$F/capacity.json" ;;
  */v1/broker/hotels/*) echo "$method $url $data" >> "$F/calls.log"
    # patch_codes: one answer per PATCH, in order (000 = timeout); then patch_code; then 200
    code=""; if [ -s "$F/patch_codes" ]; then code=$(head -1 "$F/patch_codes"); sed -i 1d "$F/patch_codes"; fi
    printf '%s' "${code:-$(cat "$F/patch_code" 2>/dev/null || echo 200)}" ;;
  */approved-measurements.json) cat "$F/site.json" ;;
  */escape/open) cat "$F/open.json" ;;
  */attestation) cp "$F/attestation.json" "$out" ;;
esac
"""

FAKE_SSH = r"""#!/bin/bash
F=$FAKE_DIR
args="$*"
# Like real ssh: -n (before the destination) feeds the remote command /dev/null, not our stdin.
nflag=0; rest=(); seen=0
for a in "$@"; do
  if [ $seen = 1 ]; then rest+=("$a"); continue; fi
  case "$a" in -n) nflag=1 ;; root@*) seen=1 ;; esac
done
stdin=""; if [ $nflag = 0 ] && [ ! -t 0 ]; then stdin=$(cat); fi
# FAKE_HOST_EXEC=1: run the install and rollback scripts for real against a fake host tree.
host_exec() {
  echo "ssh $1" >> "$F/calls.log"
  local i=0; while [ "${rest[$i]}" != -- ]; do i=$((i+1)); done
  printf '%s' "$stdin" | bash -s -- "${rest[@]:$((i+1))}"
  exit $?
}
case "$args" in
  *roll-host-image*) echo "ssh image" >> "$F/calls.log"
    if [ "${FAKE_HOST_EXEC:-0}" = 1 ]; then bash -c "${rest[*]}"
    else cat "$F/host_image.txt" 2>/dev/null || echo "roll-host-image current=old booted=old"; fi
    exit 0 ;;
  *build-status-*) echo "ssh build-status" >> "$F/calls.log"; cat "$F/build-status.txt"; exit 0 ;;
  *sealed_measurements*) echo "ssh pins" >> "$F/calls.log"; cat "$F/pins.txt"; exit 0 ;;
  *post_hotel.sh*)
    echo "ssh rooms" >> "$F/calls.log"
    n=$(cat "$F/rooms.txt")
    body=$(python3 -c "import base64,json,sys; print(base64.b64encode(json.dumps({'sandboxes': [{}]*int(sys.argv[1])}).encode()).decode())" "$n")
    echo "{\"status\": 200, \"body_b64\": \"$body\"}"; exit 0 ;;
esac
case "$stdin" in
  *run-build-*) echo "ssh stage-setup" >> "$F/calls.log"; echo "kit=1234567 clean=yes"; echo "build started detached" ;;
  *'NEWIMG=$(basename'*) echo "ssh collect" >> "$F/calls.log"; cat "$F/collect.out" ;;
  *SEALED_SKIP_BUILD*) [ "${FAKE_HOST_EXEC:-0}" = 1 ] && host_exec install
    echo "ssh install" >> "$F/calls.log"; cat "$F/install.out" ;;
  *'ln -sfn "$OLDIMG"'*) [ "${FAKE_HOST_EXEC:-0}" = 1 ] && host_exec rollback
    echo "ssh rollback" >> "$F/calls.log"; echo "RESULT=rolledback unit=active current=old" ;;
  *STAGED_MISSING*) echo "ssh check" >> "$F/calls.log"; cat "$F/check.out" ;;
esac
"""

FAKE_GUARD = "#!/bin/bash\necho 'CONST PATH: GREEN 200'\n"

CHECK_OK = (
    "current=old booted=old unit=active\n"
    "staged files vs manifest: OK\n"
    f"remeasured={NEW}\n"
    "env: hotel and staged differ only in SEALED_DIR and the flags\n"
    "kit=1234567 clean=yes\n"
)


def capacity(measurement, drain=False):
    return json.dumps({"hotels": [{
        "id": HOTEL, "up": True, "drain": drain, "slots": 10, "free_rooms": 10,
        "admission": {"state": "admitted", "measurement": measurement},
    }]})


def attestation():
    report = bytearray(0x1A0)
    report[0x90:0xC0] = bytes.fromhex(NEW)
    return json.dumps({"report_b64": base64.b64encode(bytes(report)).decode(),
                       "binding": {"sealed_secrets": 1, "sealed_exec": 1}})


@pytest.fixture
def env(tmp_path):
    fake = tmp_path / "fake"
    bin_dir = tmp_path / "bin"
    home = tmp_path / "roll-home"
    for d in (fake, bin_dir, home / "plans", home / "state"):
        d.mkdir(parents=True)
    for name, body in (("curl", FAKE_CURL), ("ssh", FAKE_SSH), ("guard", FAKE_GUARD)):
        p = bin_dir / name
        p.write_text(body)
        p.chmod(0o755)
    (tmp_path / "hotels.conf").write_text(f"{HOTEL} 10.0.0.1 /srv/x -\nesc-hotel 10.0.0.2 /srv/e escape\n")
    (tmp_path / "opkey").write_text("not-a-real-key\n")
    (fake / "capacity.json").write_text(capacity(CUR))
    (fake / "site.json").write_text(json.dumps({"measurements": [{"measurement": CUR}, {"measurement": NEW}]}))
    (fake / "open.json").write_text(json.dumps({"live_rooms": 0, "max_rooms": 0, "public_open": True}))
    (fake / "pins.txt").write_text("33 True True\n")
    (fake / "rooms.txt").write_text("0")
    (fake / "check.out").write_text(CHECK_OK)
    (fake / "install.out").write_text("current now new\nRESULT=installed\n")
    (fake / "attestation.json").write_text(attestation())
    plan = (f"COMMIT=1234567\nSTAGE=/root/stage-1234567\nNEWIMG=20260101T000000Z\nCUR={CUR}\nNEW={NEW}\n")
    (home / "plans" / f"{HOTEL}.env").write_text(plan)
    e = dict(os.environ)
    e.update({
        "PATH": f"{bin_dir}:{e['PATH']}", "FAKE_DIR": str(fake), "ROLL_HOME": str(home),
        "ROLL_HOTELS_CONF": str(tmp_path / "hotels.conf"), "ROLL_OPERATOR_KEY_FILE": str(tmp_path / "opkey"),
        "ROLL_GUARD": str(bin_dir / "guard"), "ROLL_FOREGROUND": "1", "ROLL_POLL_SLEEP": "0",
        "ROLL_DRAIN_SETTLE": "0", "ROLL_UNDRAIN_SETTLE": "0", "ROLL_ADMIT_TIMEOUT": "1",
        "HOME": str(tmp_path),
    })
    return e, fake, home


def run(env, *args):
    return subprocess.run(["bash", str(ROLL), *args], env=env, capture_output=True, text=True, timeout=60)


def calls(fake):
    p = fake / "calls.log"
    return p.read_text().splitlines() if p.exists() else []


def plan_sha(home):
    return hashlib.sha256((home / "plans" / f"{HOTEL}.env").read_bytes()).hexdigest()


def no_mutation(fake):
    c = calls(fake)
    assert not any(x.startswith("PATCH") for x in c), c
    assert "ssh install" not in c, c


def test_refuses_when_new_measurement_not_on_site_list(env):
    e, fake, home = env
    (fake / "site.json").write_text(json.dumps({"measurements": [{"measurement": CUR}]}))
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "site list does not approve both builds" in r.stdout
    no_mutation(fake)
    assert not (home / "state" / f"{HOTEL}.env").exists() or "PHASE=drained" not in (home / "state" / f"{HOTEL}.env").read_text()


def test_refuses_when_broker_pins_lack_new_measurement(env):
    e, fake, _ = env
    (fake / "pins.txt").write_text("32 True False\n")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "broker does not pin both builds" in r.stdout
    no_mutation(fake)


def test_refuses_when_rooms_not_zero(env):
    e, fake, _ = env
    (fake / "rooms.txt").write_text("2")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "rooms=2" in r.stdout
    no_mutation(fake)


def test_full_apply_drains_installs_admits_undrains(env):
    e, fake, home = env
    # the broker shows the new build once the install ran: switch the capacity view up front, since
    # the preflight needs CUR admitted and the admission wait needs NEW; the fake serves a sequence
    seq = [capacity(CUR), capacity(CUR, drain=True), capacity(NEW, drain=True)]
    (fake / "capacity.seq").write_text("\n".join(seq))
    (fake / "capacity.json").write_text(seq[0])
    wrapper = fake.parent / "bin" / "curl"
    body = wrapper.read_text().replace(
        '*/v1/broker/capacity) cat "$F/capacity.json" ;;',
        '*/v1/broker/capacity) n=$(cat "$F/n" 2>/dev/null || echo 0); echo $((n+1)) > "$F/n"; '
        'sed -n "$((n>2?3:n+1))p" "$F/capacity.seq" ;;')
    wrapper.write_text(body)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    c = calls(fake)
    assert [x for x in c if x.startswith("PATCH")] == [
        f"PATCH https://live.cathedral.computer/v1/broker/hotels/{HOTEL} {{\"drain\": true}}",
        f"PATCH https://live.cathedral.computer/v1/broker/hotels/{HOTEL} {{\"drain\": false}}",
    ]
    assert "ssh install" in c
    assert "PHASE=done" in (home / "state" / f"{HOTEL}.env").read_text()


def test_resume_from_installed_skips_install_and_undrains(env):
    e, fake, home = env
    (fake / "capacity.json").write_text(capacity(NEW, drain=True))
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=installed\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\nPLAN_SHA={plan_sha(home)}\n")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "resume from phase installed" in r.stdout
    c = calls(fake)
    assert "ssh install" not in c and "ssh check" not in c
    assert [x.split()[-2:] for x in c if x.startswith("PATCH")] == [['{"drain":', 'false}']]
    assert "PHASE=done" in (home / "state" / f"{HOTEL}.env").read_text()


def test_failed_install_rolls_back_and_undrains(env):
    e, fake, home = env
    (fake / "install.out").write_text("install exit 1: rolling back\nRESULT=rolledback unit=active current=old\n")
    # preflight sees CUR admitted; recovery waits for CUR admitted and undrains
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    c = calls(fake)
    patches = [x.split()[-2:] for x in c if x.startswith("PATCH")]
    assert patches == [['{"drain":', 'true}'], ['{"drain":', 'false}']], c
    assert "ssh rollback" not in c  # the host step rolled itself back; recovery must not restart again
    assert "PHASE=rolled_back" in (home / "state" / f"{HOTEL}.env").read_text()


def test_stuck_drained_when_no_build_admitted(env):
    e, fake, home = env
    (fake / "install.out").write_text("RESULT=rolledback unit=failed current=old\n")
    seq = fake / "capacity.seq"
    seq.write_text(capacity(CUR) + "\n" + capacity(CUR, drain=True).replace('"admitted"', '"pending"') + "\n")
    wrapper = fake.parent / "bin" / "curl"
    wrapper.write_text(wrapper.read_text().replace(
        '*/v1/broker/capacity) cat "$F/capacity.json" ;;',
        '*/v1/broker/capacity) n=$(cat "$F/n" 2>/dev/null || echo 0); echo $((n+1)) > "$F/n"; '
        'sed -n "$((n>0?2:1))p" "$F/capacity.seq" ;;'))
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "STUCK DRAINED" in r.stdout
    assert "PHASE=stuck_drained" in (home / "state" / f"{HOTEL}.env").read_text()


def test_pin_patch_is_add_only(env, tmp_path):
    e, _, home = env
    r = run(e, "pin-patch", "1234567")
    assert r.returncode == 0, r.stdout + r.stderr
    patch = home / "plans" / "pin-1234567.py"
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"amd_verifier": "x", "other": 1, "sealed_measurements": [CUR, "c" * 96]}))
    out = subprocess.run(["python3", "-I", str(patch), str(cfg)], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    pins = json.loads(cfg.read_text())["sealed_measurements"]
    assert pins == [CUR, "c" * 96, NEW]
    cfg.write_text(json.dumps({"amd_verifier": "x", "sealed_measurements": ["c" * 96]}))
    out = subprocess.run(["python3", "-I", str(patch), str(cfg)], capture_output=True, text=True)
    assert out.returncode != 0 and "current build is not pinned" in out.stderr


def test_status_runs_locally(env):
    e, _, _ = env
    r = run(e, "status")
    assert r.returncode == 0 and HOTEL in r.stdout


def serve_capacity(fake, seq):
    """Serve the capacity views in order, then repeat the last one."""
    (fake / "capacity.seq").write_text("\n".join(seq) + "\n")
    wrapper = fake.parent / "bin" / "curl"
    wrapper.write_text(wrapper.read_text().replace(
        '*/v1/broker/capacity) cat "$F/capacity.json" ;;',
        '*/v1/broker/capacity) n=$(cat "$F/n" 2>/dev/null || echo 0); echo $((n+1)) > "$F/n"; '
        f'sed -n "$((n+1<{len(seq)}?n+1:{len(seq)}))p" "$F/capacity.seq" ;;'))


def patches(fake):
    return [x.split()[-1] for x in calls(fake) if x.startswith("PATCH")]


# ---- HOLD finding 1: stage must run the collect script and write a plan ------------------------------
def test_stage_collects_and_writes_plan(env, tmp_path):
    e, fake, home = env
    repo = tmp_path / "fake-repo"
    (repo / "room-kit").mkdir(parents=True)
    (repo / "room-kit" / "versions.lock").write_text("CATHEDRAL_COMMIT=abcdef0\n")
    g = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-q", "-m", "kit"], check=True)
    commit = subprocess.run(g + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    bin_dir = tmp_path / "bin"
    (bin_dir / "gh").write_text(f'#!/bin/bash\nexec git clone -q "{repo}" "$4"\n')
    (bin_dir / "scp").write_text('#!/bin/bash\necho "scp" >> "$FAKE_DIR/calls.log"\n')
    for n in ("gh", "scp"):
        (bin_dir / n).chmod(0o755)
    (fake / "build-status.txt").write_text(f"{HOTEL} build exit 0\n")
    c7 = commit[:7]
    (fake / "collect.out").write_text(
        f"{HOTEL} NEWIMG=20261113T000000Z NEW={NEW} LIVE={CUR} | vmlinuz=DIFF OVMF.amdsev.fd=same cmdline=same"
        f" | kit={c7} initrd_kit={c7} api=CATHEDRAL_COMMIT=abcdef0 debug=False\n")
    (home / "plans" / f"{HOTEL}.env").unlink()
    r = run(e, "stage", commit, HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "ssh collect" in calls(fake)
    plan = (home / "plans" / f"{HOTEL}.env").read_text()
    assert f"NEW={NEW}" in plan and f"CUR={CUR}" in plan and "NEWIMG=20261113T000000Z" in plan
    assert not any(x.startswith("PATCH") for x in calls(fake))


# ---- HOLD finding 2: a drain PATCH that applies and then errors ----------------------------------
@pytest.mark.parametrize("code", ["503", "000"])
def test_drain_applied_then_error_is_read_back_and_undrained(env, code):
    e, fake, home = env
    (fake / "patch_codes").write_text(f"{code}\n200\n")
    serve_capacity(fake, [capacity(CUR), capacity(CUR, drain=True)])
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert patches(fake) == ["true}", "false}"], calls(fake)
    assert "ssh install" not in calls(fake)
    assert "PHASE=rolled_back" in (home / "state" / f"{HOTEL}.env").read_text()


def test_drain_error_that_did_not_apply_aborts_without_undrain(env):
    e, fake, home = env
    (fake / "patch_codes").write_text("503\n")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert patches(fake) == ["true}"]
    assert "PHASE=aborted" in (home / "state" / f"{HOTEL}.env").read_text()


def test_resume_of_interrupted_drain_reads_back_and_undrains(env):
    e, fake, home = env
    (fake / "capacity.json").write_text(capacity(CUR, drain=True))
    (home / "state" / f"{HOTEL}.env").write_text(f"PHASE=draining\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\nPLAN_SHA={plan_sha(home)}\n")
    r = run(e, "apply", HOTEL)
    assert patches(fake) == ["false}"], r.stdout
    assert "ssh install" not in calls(fake)
    assert "PHASE=rolled_back" in (home / "state" / f"{HOTEL}.env").read_text()


# ---- HOLD findings 3 and 4: run the real host scripts against a fake host tree ------------------------
INSTALL_LIVE_ROOM = """#!/bin/bash
echo "[sealed] expected measurement x"
echo "sealed: 1 live room(s); a restart ends them with no delete receipt. Wait, or set SEALED_RESTART_WITH_ROOMS=1." >&2
exit 1
"""

# A reset roll as install-sealed.sh does it: owner's volume to data.raw.prev, new empty volume, restart, match.
INSTALL_RESET_OK = """#!/bin/bash
D=$(dirname "$(readlink -f "$2")")
mv -f "$D/data.raw" "$D/data.raw.prev"; echo empty > "$D/data.raw"
systemctl restart "room-sealed-hotel-x.service"
echo "[sealed] guest starting; serial log"
echo "[sealed] measurement matches the build"
"""


@pytest.fixture
def host(env, tmp_path):
    e, fake, home = env
    root = tmp_path / "host"
    d, stage = root / "srv-x", root / "stage"
    s, kit = stage / HOTEL, stage / "kit" / "room-kit"
    for p in (d / "images" / "old", s / "images" / "20260101T000000Z", kit):
        p.mkdir(parents=True)
    (d / "images" / "current").symlink_to("old")
    (d / "run").mkdir()
    (d / "run" / "booted-image").symlink_to(d / "images" / "old")
    (d / "sealed.env").write_text(f"SEALED_DIR={d}\nSEALED_NAME={HOTEL}\n")
    (s / "sealed.env").write_text(f"SEALED_DIR={s}\nSEALED_NAME={HOTEL}\nSEALED_ROOM_SEALED_SECRETS=1\nSEALED_ROOM_SEALED_EXEC=1\n")
    (d / "data.raw").write_text("owner\n")
    (tmp_path / "hotels.conf").write_text(f"{HOTEL} 10.0.0.1 {d} -\n")
    (home / "plans" / f"{HOTEL}.env").write_text(
        f"COMMIT=1234567\nSTAGE={stage}\nNEWIMG=20260101T000000Z\nCUR={CUR}\nNEW={NEW}\n")
    sysctl = tmp_path / "bin" / "systemctl"
    sysctl.write_text(f'#!/bin/bash\n[ "$1" = is-active ] && {{ echo active; exit 0; }}\n'
                      f'[ "$1" = restart ] && ln -sfn "$(readlink -f {d}/images/current)" {d}/run/booted-image\n'
                      f'echo "systemctl $* data=$(cat {d}/data.raw 2>/dev/null)" >> "$FAKE_DIR/calls.log"\n')
    sysctl.chmod(0o755)
    e.update({"FAKE_HOST_EXEC": "1", "ROLL_REMOTE_LOGDIR": str(root)})
    return e, fake, home, d, kit


def test_install_refusal_for_a_live_room_does_not_restart_the_guest(host):
    e, fake, home, d, kit = host
    (kit / "install.sh").write_text(INSTALL_LIVE_ROOM)
    (kit / "install.sh").chmod(0o755)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    c = calls(fake)
    assert not any(x.startswith("systemctl restart") for x in c), c
    assert "RESULT=refused" in r.stdout
    assert os.readlink(d / "images" / "current") == "old"
    assert (d / "sealed.env").read_text() == f"SEALED_DIR={d}\nSEALED_NAME={HOTEL}\n"
    assert "ssh rollback" not in c
    assert patches(fake) == ["true}", "false}"]
    assert "PHASE=rolled_back" in (home / "state" / f"{HOTEL}.env").read_text()


def test_reset_roll_rollback_restores_the_owner_volume_before_booting_old(host):
    e, fake, home, d, kit = host
    (kit / "install.sh").write_text(INSTALL_RESET_OK)
    (kit / "install.sh").chmod(0o755)
    # the broker reads whatever the fake host boots; the new attestation is bad, so recovery rolls back
    curl = fake.parent / "bin" / "curl"
    curl.write_text(curl.read_text().replace(
        '*/v1/broker/capacity) cat "$F/capacity.json" ;;',
        f'*/v1/broker/capacity) [ "$(readlink {d}/images/current)" = old ] && cat "$F/capacity.json" || cat "$F/capacity.new" ;;'))
    (fake / "capacity.new").write_text(capacity(NEW, drain=True))
    bad = json.loads(attestation()); bad["binding"] = {}
    (fake / "attestation.json").write_text(json.dumps(bad))
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1, r.stdout
    assert "ssh rollback" in calls(fake)
    assert (d / "data.raw").read_text() == "owner\n"
    assert not (d / "data.raw.prev").exists()
    restarts = [x for x in calls(fake) if x.startswith("systemctl restart")]
    assert restarts[-1].endswith("data=owner"), restarts
    assert os.readlink(d / "images" / "current") == "old"
    assert patches(fake) == ["true}", "false}"]
    assert "PHASE=rolled_back" in (home / "state" / f"{HOTEL}.env").read_text()


def test_reset_roll_rollback_holds_drained_when_prev_volume_is_gone(host):
    e, fake, home, d, kit = host
    (kit / "install.sh").write_text(INSTALL_RESET_OK)
    (kit / "install.sh").chmod(0o755)
    curl = fake.parent / "bin" / "curl"
    # the broker admits the new build, its attestation is bad, and data.raw.prev is gone by the rollback
    curl.write_text(curl.read_text().replace(
        '*/v1/broker/capacity) cat "$F/capacity.json" ;;',
        f'*/v1/broker/capacity) [ "$(readlink {d}/images/current)" = old ] && cat "$F/capacity.json" || cat "$F/capacity.new" ;;'
    ).replace('*/attestation) cp', f'*/attestation) rm -f {d}/data.raw.prev; cp'))
    (fake / "capacity.new").write_text(capacity(NEW, drain=True))
    bad = json.loads(attestation()); bad["binding"] = {}
    (fake / "attestation.json").write_text(json.dumps(bad))
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "RESULT=held" in r.stdout
    assert os.readlink(d / "images" / "current") == "20260101T000000Z"
    assert patches(fake) == ["true}"]
    assert "PHASE=stuck_drained" in (home / "state" / f"{HOTEL}.env").read_text()


# ---- #472 HOLD round 2 ----------------------------------------------------------------------------
def capacity_by_step(fake, drain=None, install=None, rollback=None):
    """Serve capacity.json until the run reaches a step, then that step's view (latest step wins)."""
    for name, body in (("drain", drain), ("install", install), ("rollback", rollback)):
        if body is not None:
            (fake / f"capacity.{name}").write_text(body)
    curl = fake.parent / "bin" / "curl"
    curl.write_text(curl.read_text().replace(
        '*/v1/broker/capacity) cat "$F/capacity.json" ;;',
        '*/v1/broker/capacity) c=$F/capacity.json; L=$F/calls.log\n'
        '    grep -q "^PATCH" "$L" 2>/dev/null && [ -f "$F/capacity.drain" ] && c=$F/capacity.drain\n'
        '    grep -qx "ssh install" "$L" 2>/dev/null && [ -f "$F/capacity.install" ] && c=$F/capacity.install\n'
        '    grep -qx "ssh rollback" "$L" 2>/dev/null && [ -f "$F/capacity.rollback" ] && c=$F/capacity.rollback\n'
        '    cat "$c" ;;'))


MISSING = json.dumps({"hotels": []})


# Finding 1: after a host rollback, recovery undrains only on CUR admitted and the host proven on OLDIMG.
@pytest.mark.parametrize("after_rollback,host_image,undrains", [
    ("stale_new", "current=old booted=old", False),        # broker still caches NEW
    ("cur", "current=20260101T000000Z booted=20260101T000000Z", False),  # host never left NEW
    ("cur", "current=old booted=old", True),               # control: a real rollback
])
def test_rollback_undrains_only_on_cur_admission_and_old_host_image(env, after_rollback, host_image, undrains):
    e, fake, home = env
    bad = json.loads(attestation()); bad["binding"] = {}
    (fake / "attestation.json").write_text(json.dumps(bad))
    (fake / "host_image.txt").write_text(f"roll-host-image {host_image}\n")
    after = capacity(NEW, drain=True) if after_rollback == "stale_new" else capacity(CUR, drain=True)
    capacity_by_step(fake, drain=capacity(CUR, drain=True), install=capacity(NEW, drain=True), rollback=after)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "ssh rollback" in calls(fake)
    state = (home / "state" / f"{HOTEL}.env").read_text()
    if undrains:
        assert patches(fake) == ["true}", "false}"], r.stdout
        assert "PHASE=rolled_back" in state
    else:
        assert patches(fake) == ["true}"], r.stdout
        assert "PHASE=stuck_drained" in state


# Finding 2: a drain-only stuck hotel resumes as drain-only and is never restarted.
def test_drain_only_stuck_resume_never_restarts_the_guest(env):
    e, fake, home = env
    (fake / "patch_codes").write_text("503\n")
    capacity_by_step(fake, drain=MISSING)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "PHASE=stuck_drained" in (home / "state" / f"{HOTEL}.env").read_text(), r.stdout
    (fake / "rooms.txt").write_text("1")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    c = calls(fake)
    assert "ssh rollback" not in c and "ssh install" not in c, c
    assert "false}" not in patches(fake)
    assert "PHASE=stuck_drained" in (home / "state" / f"{HOTEL}.env").read_text()


# Finding 2: a stuck install resume rolls back only once drain=true and zero rooms are read back.
@pytest.mark.parametrize("cap,rooms", [(MISSING, "0"), (capacity(NEW, drain=True), "1"),
                                       (capacity(NEW, drain=False), "0"), (capacity(NEW, drain=True), "?")])
def test_stuck_install_resume_needs_drain_and_zero_rooms_before_rollback(env, cap, rooms):
    e, fake, home = env
    (fake / "capacity.json").write_text(cap)
    (fake / "rooms.txt").write_text(rooms if rooms != "?" else "x")
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=stuck_drained\nSTUCK_FROM=installed\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\n"
        f"PLAN_SHA={plan_sha(home)}\n")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "ssh rollback" not in calls(fake), r.stdout
    assert patches(fake) == []
    assert "PHASE=stuck_drained" in (home / "state" / f"{HOTEL}.env").read_text()


# Finding 3: a resumed run is bound to the plan it preflighted.
def test_resume_refuses_a_replaced_plan(env):
    e, fake, home = env
    (fake / "capacity.json").write_text(capacity(CUR, drain=True))
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=drained\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\nPLAN_SHA={plan_sha(home)}\n")
    other = "d" * 96
    (home / "plans" / f"{HOTEL}.env").write_text(
        f"COMMIT=1234567\nSTAGE=/root/stage-1234567\nNEWIMG=20260202T000000Z\nCUR={CUR}\nNEW={other}\n")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "plan" in r.stdout + r.stderr
    c = calls(fake)
    assert "ssh install" not in c and "ssh rollback" not in c, c
    assert patches(fake) == []
    assert "PHASE=drained" in (home / "state" / f"{HOTEL}.env").read_text()


# Finding 4: two hotels on the same current build with different new builds keep both new pins.
def test_pin_patch_keeps_every_new_build_for_a_shared_current(env, tmp_path):
    e, _, home = env
    other = "d" * 96
    (home / "plans" / "hotel-y.env").write_text(
        f"COMMIT=1234567\nSTAGE=/root/stage-1234567\nNEWIMG=20260101T000000Z\nCUR={CUR}\nNEW={other}\n")
    r = run(e, "pin-patch", "1234567")
    assert r.returncode == 0, r.stdout + r.stderr
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"amd_verifier": "x", "sealed_measurements": [CUR]}))
    out = subprocess.run(["python3", "-I", str(home / "plans" / "pin-1234567.py"), str(cfg)],
                         capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    pins = json.loads(cfg.read_text())["sealed_measurements"]
    assert sorted(pins) == sorted([CUR, NEW, other]), pins

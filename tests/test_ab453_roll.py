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
  */restart-check) echo "GET restart-check" >> "$F/calls.log"; cat "$F/restart.json"; printf '\n%s' "$(cat "$F/restart.code")" ;;
  */v1/broker/hotels/*) if [ "$method" = GET ]; then echo "GET hotel" >> "$F/calls.log"; cat "$F/hotel.json"; exit 0; fi
    echo "$method $url $data" >> "$F/calls.log"
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
# FAKE_HOST_EXEC=1: run the install and rollback scripts for real against a fake host tree, with
# the remote command as given (timeout ... bash -s -- args), as sshd would run it.
host_exec() {
  echo "ssh $1" >> "$F/calls.log"
  printf '%s' "$stdin" | "${rest[@]}"
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
    # A guest-TLS hotel: the host has no hotel key, as post_hotel.sh answers it.
    [ "$n" = nokey ] && { echo '{"status": 0, "error": "no guest ip or key file in sealed.env"}'; exit 0; }
    body=$(python3 -c "import base64,json,sys; print(base64.b64encode(json.dumps({'sandboxes': [{}]*int(sys.argv[1])}).encode()).decode())" "$n")
    echo "{\"status\": 200, \"body_b64\": \"$body\"}"; exit 0 ;;
esac
case "$stdin" in
  *run-build-*) [ "${FAKE_STAGE_EXEC:-0}" = 1 ] && host_exec stage-setup
    echo "ssh stage-setup" >> "$F/calls.log"; echo "kit=1234567 clean=yes"; echo "build started detached" ;;
  *'NEWIMG=$(basename'*) echo "ssh collect" >> "$F/calls.log"; cat "$F/collect.out" ;;
  *SEALED_SKIP_BUILD*) [ "${FAKE_HOST_EXEC:-0}" = 1 ] && host_exec install
    echo "ssh install" >> "$F/calls.log"; cat "$F/install.out" ;;
  *'ln -sfn "$OLDIMG"'*) [ "${FAKE_HOST_EXEC:-0}" = 1 ] && host_exec rollback
    echo "ssh rollback" >> "$F/calls.log"; echo "RESULT=rolledback unit=active current=old" ;;
  *STAGED_MISSING*) [ "${FAKE_CHECK_EXEC:-0}" = 1 ] && host_exec check
    echo "ssh check" >> "$F/calls.log"; cat "$F/check.out" ;;
esac
"""

FAKE_GUARD = "#!/bin/bash\necho 'CONST PATH: GREEN 200'\n"

CHECK_OK = (
    "custom_guest_hold=none\n"
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
    # GET /v1/broker/hotels/<id>: the broker's own view before a guest restart (AB#875)
    (fake / "hotel.json").write_text(json.dumps({"id": HOTEL, "drain": True, "rooms_in_use": 0}))
    # GET .../restart-check: absent by default (a broker from before the guard), so the tests above
    # exercise the hotel document fallback; the guard tests below set it.
    (fake / "restart.json").write_text(json.dumps({"error": {"code": "hotel_not_found", "message": "no hotel x"}}))
    (fake / "restart.code").write_text("404")  # what a broker from before the guard answers
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
        "HOME": str(tmp_path), "CATHEDRAL_SNP_LOCK_DIR": str(tmp_path / "run-lock"),
    })
    for k in ("CATHEDRAL_SNP_LOCK_FD", "CATHEDRAL_SNP_LOCK_OWNER", "CATHEDRAL_SNP_LOCK_WAIT", "ROOM_DESTDIR"):
        e.pop(k, None)
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
    # apply reads capacity once in preflight (CUR admitted), then again after install (NEW admitted).
    # drain does not re-read capacity on the happy path; a middle drained/CUR view only shifts NEW later.
    serve_capacity(fake, [capacity(CUR), capacity(NEW, drain=True)])
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


# ---- #472 Bugbot round (fixed after merge) -----------------------------------------------------------
# A systemd-run that, like the real one, starts the child with only the -E variables it was given.
FAKE_SYSTEMD_RUN = r"""#!/bin/bash
echo "systemd-run $*" >> "$FAKE_DIR/calls.log"
envs=(); while [ $# -gt 0 ]; do
  case "$1" in -E) envs+=("$2"); shift 2 ;; --unit=*|--collect) shift ;; *) break ;; esac
done
exec env -i PATH="$PATH" FAKE_DIR="$FAKE_DIR" "${envs[@]}" "$@"
"""


# Bugbot "Detached runs drop endpoint overrides": the detached child must use the caller's endpoints.
def test_detached_apply_keeps_every_endpoint_override(env, tmp_path):
    e, fake, home = env
    p = tmp_path / "bin" / "systemd-run"
    p.write_text(FAKE_SYSTEMD_RUN)
    p.chmod(0o755)
    del e["ROLL_FOREGROUND"]
    e.update({"ROLL_BROKER_URL": "https://broker.test", "ROLL_BROKER_HOST": "192.0.2.10",
              "ROLL_SITE_URL": "https://site.test/approved-measurements.json",
              "ROLL_ATTEST_URL_BASE": "https://site.test/v1/hotels", "ROLL_ESCAPE_OPEN_URL": "https://api.test/v1/escape/open"})
    serve_capacity(fake, [capacity(CUR), capacity(CUR), capacity(NEW, drain=True)])
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    sd = [x for x in calls(fake) if x.startswith("systemd-run")]
    assert len(sd) == 1
    for kv in ("ROLL_BROKER_URL=https://broker.test", "ROLL_BROKER_HOST=192.0.2.10", "ROLL_ADMIT_TIMEOUT=1",
               "ROLL_SITE_URL=https://site.test/approved-measurements.json", "ROLL_POLL_SLEEP=0",
               "ROLL_ATTEST_URL_BASE=https://site.test/v1/hotels", "ROLL_ESCAPE_OPEN_URL=https://api.test/v1/escape/open"):
        assert kv in sd[0], sd[0]
    assert patches(fake) == ["true}", "false}"]
    assert all("https://broker.test/v1/broker/hotels/" in x for x in calls(fake) if x.startswith("PATCH"))
    assert "PHASE=done" in (home / "state" / f"{HOTEL}.env").read_text()


def test_detached_stage_keeps_every_endpoint_override(env, tmp_path):
    e, fake, home = env
    p = tmp_path / "bin" / "systemd-run"
    p.write_text('#!/bin/bash\necho "systemd-run $*" >> "$FAKE_DIR/calls.log"\n')
    p.chmod(0o755)
    del e["ROLL_FOREGROUND"]
    e.update({"ROLL_BROKER_URL": "https://broker.test", "ROLL_STAGE_TIMEOUT": "7"})
    r = run(e, "stage", "1234567", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    sd = [x for x in calls(fake) if x.startswith("systemd-run")]
    assert "ROLL_BROKER_URL=https://broker.test" in sd[0] and "ROLL_STAGE_TIMEOUT=7" in sd[0], sd


# Bugbot "Happy-path undrain ignores broker readback": an undrain that applies and then errors is done.
def test_undrain_that_applied_then_errored_finishes_done(env):
    e, fake, home = env
    (fake / "patch_codes").write_text("200\n503\n")
    serve_capacity(fake, [capacity(CUR), capacity(NEW, drain=True), capacity(NEW, drain=False)])
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert patches(fake) == ["true}", "false}"]
    state = (home / "state" / f"{HOTEL}.env").read_text()
    assert "PHASE=done" in state and "stuck" not in state


def test_undrain_that_did_not_apply_is_not_done(env):
    e, fake, home = env
    (fake / "patch_codes").write_text("200\n503\n503\n")
    serve_capacity(fake, [capacity(CUR), capacity(NEW, drain=True)])
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "PHASE=done" not in (home / "state" / f"{HOTEL}.env").read_text()


# Bugbot "Refused install can leave guest stopped": a guest the installer stopped is restarted on OLDIMG.
HOST_SYSTEMCTL = """#!/bin/bash
F=$FAKE_DIR
case "$1" in
  is-active) cat "$F/unit_state" 2>/dev/null || echo active; exit 0 ;;
  show) cat "$F/unit_inv" 2>/dev/null || echo inv0; exit 0 ;;
  stop) echo inactive > "$F/unit_state" ;;
  restart) ln -sfn "$(readlink -f {d}/images/current)" {d}/run/booted-image
    echo active > "$F/unit_state"; echo "inv-$(date +%s%N)" > "$F/unit_inv" ;;
esac
echo "systemctl $* data=$(cat {d}/data.raw 2>/dev/null)" >> "$F/calls.log"
"""

# install-sealed.sh under set -e: the reset roll's EXIT trap stopped the guest before "guest starting".
INSTALL_STOPPED_BEFORE_LOG = """#!/bin/bash
echo "[sealed] expected measurement x"
systemctl stop room-sealed-hotel-x.service
echo "sealed: could not start the guest" >&2
exit 1
"""


def host_systemctl(e, d):
    p = Path(e["PATH"].split(":")[0]) / "systemctl"
    p.write_text(HOST_SYSTEMCTL.replace("{d}", str(d)))
    p.chmod(0o755)


def test_installer_that_stopped_the_guest_before_logging_is_restarted_on_old(host):
    e, fake, home, d, kit = host
    host_systemctl(e, d)
    (kit / "install.sh").write_text(INSTALL_STOPPED_BEFORE_LOG)
    (kit / "install.sh").chmod(0o755)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "RESULT=refused" not in r.stdout and "RESULT=rolledback" in r.stdout, r.stdout
    c = calls(fake)
    assert any(x.startswith("systemctl restart") for x in c), c
    assert (fake / "unit_state").read_text().strip() == "active"
    assert os.readlink(d / "images" / "current") == "old"
    assert patches(fake) == ["true}", "false}"]
    assert "PHASE=rolled_back" in (home / "state" / f"{HOTEL}.env").read_text()


def test_live_room_refusal_with_same_invocation_still_does_not_restart(host):
    e, fake, home, d, kit = host
    host_systemctl(e, d)
    (kit / "install.sh").write_text(INSTALL_LIVE_ROOM)
    (kit / "install.sh").chmod(0o755)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "RESULT=refused" in r.stdout
    assert not any(x.startswith("systemctl restart") for x in calls(fake))


# Bugbot "Host proof mixes path and basename": an absolute images/current still proves OLDIMG.
@pytest.mark.parametrize("saved_oldimg", ["old", "abs"])
def test_rollback_proof_accepts_an_absolute_images_current(host, saved_oldimg):
    e, fake, home, d, kit = host
    (d / "images" / "current").unlink()
    (d / "images" / "current").symlink_to(d / "images" / "old")
    old = str(d / "images" / "old") if saved_oldimg == "abs" else "old"
    (fake / "capacity.json").write_text(capacity(CUR, drain=True))
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=stuck_drained\nSTUCK_FROM=installed\nHOST_ROLLED_BACK=1\nTS=20260101T000000Z\nOLDIMG={old}\n"
        f"COMMIT=1234567\nPLAN_SHA={plan_sha(home)}\n")
    r = run(e, "apply", HOTEL)
    assert "current=old booted=old" in r.stdout, r.stdout
    assert patches(fake) == ["false}"], r.stdout
    assert "PHASE=rolled_back" in (home / "state" / f"{HOTEL}.env").read_text()


def test_preflight_reads_an_absolute_images_current_as_the_image_name(host):
    e, fake, home, d, kit = host
    (d / "images" / "current").unlink()
    (d / "images" / "current").symlink_to(d / "images" / "old")
    stage = Path((home / "plans" / f"{HOTEL}.env").read_text().split("STAGE=")[1].split("\n")[0])
    import shutil
    shutil.rmtree(stage / HOTEL / "images" / "20260101T000000Z")
    e["FAKE_CHECK_EXEC"] = "1"
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1 and "staged image" in r.stdout
    assert "host: current=old booted=old unit=active" in r.stdout, r.stdout
    no_mutation(fake)


# Bugbot "Stage kit setup is not retryable": a failed bootstrap is redone, not skipped, on retry.
def test_stage_kit_bootstrap_is_redone_after_a_failed_first_attempt(env, tmp_path):
    e, fake, home = env
    repo = tmp_path / "fake-repo"
    (repo / "room-kit").mkdir(parents=True)
    (repo / "room-kit" / "versions.lock").write_text("CATHEDRAL_COMMIT=abcdef0\n")
    md = repo / "room-kit" / "make-dist.sh"
    md.write_text('#!/bin/bash\n[ -f "$FAKE_DIR/make-dist-fail" ] && { rm -f "$FAKE_DIR/make-dist-fail"; exit 1; }\n'
                  'echo "make-dist $1" >> "$FAKE_DIR/calls.log"\n')
    md.chmod(0o755)
    g = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    subprocess.run(g + ["add", "-A"], check=True)
    subprocess.run(g + ["commit", "-q", "-m", "kit"], check=True)
    commit = subprocess.run(g + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    c7 = commit[:7]
    bin_dir = tmp_path / "bin"
    (bin_dir / "gh").write_text(f'#!/bin/bash\nexec git clone -q "{repo}" "$4"\n')
    (bin_dir / "scp").write_text('#!/bin/bash\nsrc="${@: -2:1}"; dst="${@: -1}"; cp "$src" "${dst#*:}"\n')
    (bin_dir / "systemd-run").write_text('#!/bin/bash\necho "systemd-run $*" >> "$FAKE_DIR/calls.log"\n')
    for n in ("gh", "scp", "systemd-run"):
        (bin_dir / n).chmod(0o755)
    sroot = tmp_path / "hostroot"
    (sroot / "stage-older").mkdir(parents=True)
    for n in ("post_hotel.sh", "post_hotel_guest.sh"):
        (sroot / "stage-older" / n).write_text("#!/bin/bash\n")
    live = tmp_path / "live-x"
    (live / "build").mkdir(parents=True)
    (live / "build" / "base-x").write_text("base\n")
    (live / "sealed.env").write_text(f"SEALED_DIR={live}\nSEALED_NAME={HOTEL}\n")
    (tmp_path / "hotels.conf").write_text(f"{HOTEL} 10.0.0.1 {live} -\n")
    (fake / "build-status.txt").write_text(f"{HOTEL} build exit 0\n")
    (fake / "collect.out").write_text(
        f"{HOTEL} NEWIMG=20261113T000000Z NEW={NEW} LIVE={CUR} | vmlinuz=DIFF OVMF.amdsev.fd=same cmdline=same"
        f" | kit={c7} initrd_kit={c7} api=CATHEDRAL_COMMIT=abcdef0 debug=False\n")
    (home / "plans" / f"{HOTEL}.env").unlink()
    e.update({"FAKE_STAGE_EXEC": "1", "ROLL_STAGE_ROOT": str(sroot)})
    n = sroot / f"stage-{commit}"

    (fake / "make-dist-fail").write_text("1")
    r = run(e, "stage", commit, HOTEL)
    assert r.returncode == 1, r.stdout + r.stderr
    assert (n / "kit").is_dir() and not (n / "post_hotel.sh").exists() and not (n / "kit.ready").exists()
    assert not (home / "plans" / f"{HOTEL}.env").exists()

    r = run(e, "stage", commit, HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "make-dist abcdef0" in calls(fake)
    assert (n / "post_hotel.sh").exists() and (n / "post_hotel_guest.sh").exists() and (n / "kit.ready").exists()
    assert (home / "plans" / f"{HOTEL}.env").exists()


# Bugbot on #607: a missing images/current reads empty, never the link's own name "current".
def test_missing_images_current_reads_empty_and_is_not_proof(host):
    e, fake, home, d, kit = host
    (d / "images" / "current").unlink()
    (fake / "capacity.json").write_text(capacity(CUR, drain=True))
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=stuck_drained\nSTUCK_FROM=installed\nHOST_ROLLED_BACK=1\nTS=20260101T000000Z\nOLDIMG=current\n"
        f"COMMIT=1234567\nPLAN_SHA={plan_sha(home)}\n")
    r = run(e, "apply", HOTEL)
    assert "host reads current= booted=old" in r.stdout, r.stdout
    assert patches(fake) == []
    assert "PHASE=stuck_drained" in (home / "state" / f"{HOTEL}.env").read_text()


def test_preflight_reads_a_missing_images_current_as_empty(host):
    e, fake, home, d, kit = host
    (d / "images" / "current").unlink()
    stage = Path((home / "plans" / f"{HOTEL}.env").read_text().split("STAGE=")[1].split("\n")[0])
    import shutil
    shutil.rmtree(stage / HOTEL / "images" / "20260101T000000Z")
    e["FAKE_CHECK_EXEC"] = "1"
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "host: current= booted=old unit=active" in r.stdout, r.stdout
    no_mutation(fake)



# AB#875: a guest restart needs the broker's word too. A create queued or in flight at the broker is
# not in the hotel's room list yet; the install restarts the guest, so it must wait for 0 there.
@pytest.mark.parametrize("hotel_doc, why", [
    ({"id": HOTEL, "drain": True, "rooms_in_use": 1}, "broker_rooms_in_use=1"),
    ({"id": HOTEL, "drain": False, "rooms_in_use": 0}, "hotel_drain=False"),
    ({"id": HOTEL, "drain": True}, "broker_rooms_in_use=?"),
    ({"id": HOTEL, "drain": True, "rooms_in_use": True}, "broker_rooms_in_use=?"),
    ("not json", "hotel_drain=?"),
])
def test_install_waits_for_zero_rooms_in_use_at_the_broker(env, hotel_doc, why):
    e, fake, home = env
    (fake / "hotel.json").write_text(hotel_doc if isinstance(hotel_doc, str) else json.dumps(hotel_doc))
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert why in r.stdout, r.stdout
    c = calls(fake)
    assert "ssh install" not in c, c
    patches = [x.split()[-2:] for x in c if x.startswith("PATCH")]
    assert patches == [['{"drain":', 'true}'], ['{"drain":', 'false}']], c  # drained, then undrained


def test_install_runs_once_the_broker_reads_zero_in_use(env):
    e, fake, home = env
    serve_capacity(fake, [capacity(CUR), capacity(NEW, drain=True)])
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    c = calls(fake)
    assert c.index("GET hotel") < c.index("ssh install"), c
    assert "creates in flight included" in r.stdout


def test_stuck_install_resume_waits_for_zero_in_use_at_the_broker_before_rollback(env):
    e, fake, home = env
    (fake / "capacity.json").write_text(capacity(NEW, drain=True))
    (fake / "hotel.json").write_text(json.dumps({"id": HOTEL, "drain": True, "rooms_in_use": 1}))
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=stuck_drained\nSTUCK_FROM=installed\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\n"
        f"PLAN_SHA={plan_sha(home)}\n")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "broker_rooms_in_use=1" in r.stdout, r.stdout
    assert "ssh rollback" not in calls(fake)
    assert patches(fake) == []
    assert "PHASE=stuck_drained" in (home / "state" / f"{HOTEL}.env").read_text()


def test_resume_from_drained_waits_for_zero_in_use_at_the_broker(env):
    # A roll killed after the drain resumes at PHASE=drained and goes straight to the pre-install gate.
    e, fake, home = env
    (fake / "hotel.json").write_text(json.dumps({"id": HOTEL, "drain": True, "rooms_in_use": 1}))
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=drained\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\nPLAN_SHA={plan_sha(home)}\n")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "broker_rooms_in_use=1" in r.stdout, r.stdout
    assert "ssh install" not in calls(fake)



def guard(fake, code, body):
    (fake / "restart.code").write_text(str(code))
    (fake / "restart.json").write_text(body if isinstance(body, str) else json.dumps(body))


GUARD_OK = {"hotel": HOTEL, "restart_ok": True, "drain": True, "rooms": 0, "reasons": []}
REFUSED = {"error": {"code": "restart_refused", "message": "x"},
           "check": {"restart_ok": False, "reasons": ["the room count is not known (no good room list from the hotel)"]}}


def test_install_runs_when_the_restart_guard_says_ok(env):
    e, fake, home = env
    guard(fake, 200, GUARD_OK)
    (fake / "hotel.json").write_text(json.dumps({"id": HOTEL, "drain": True, "rooms_in_use": 7}))  # not read
    serve_capacity(fake, [capacity(CUR), capacity(NEW, drain=True)])
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    c = calls(fake)
    assert c.index("GET restart-check") < c.index("ssh install"), c
    assert "GET hotel" not in c


@pytest.mark.parametrize("code, body, why", [
    (409, REFUSED, "room count is not known"),
    (200, {"restart_ok": False}, "unknown http=200"),
    (200, "not json", "unknown http=200"),
    (500, {"error": {"code": "x"}}, "unknown http=500"),
    (401, {"error": {"code": "unauthorized"}}, "unknown http=401"),
])
def test_install_refused_unless_the_guard_says_ok(env, code, body, why):
    e, fake, home = env
    guard(fake, code, body)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert why in r.stdout, r.stdout
    c = calls(fake)
    assert "ssh install" not in c and "GET hotel" not in c, c


def test_guard_ok_still_needs_zero_rooms_on_the_hotel(env):
    e, fake, home = env
    guard(fake, 200, GUARD_OK)
    (fake / "rooms.txt").write_text("0")
    serve_capacity(fake, [capacity(CUR), capacity(NEW, drain=True)])
    # preflight reads rooms=0; make the hotel show a room only after the drain
    ssh = fake.parent / "bin" / "ssh"
    ssh.write_text(ssh.read_text().replace('n=$(cat "$F/rooms.txt")',
        'n=$(cat "$F/rooms.txt"); grep -q "PATCH" "$F/calls.log" 2>/dev/null && n=1'))
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "restart_guard=ok hotel_rooms=1" in r.stdout, r.stdout
    assert "ssh install" not in calls(fake)


def test_rollback_needs_the_guard_too(env):
    e, fake, home = env
    guard(fake, 409, REFUSED)
    (fake / "capacity.json").write_text(capacity(NEW, drain=True))
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=stuck_drained\nSTUCK_FROM=installed\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\n"
        f"PLAN_SHA={plan_sha(home)}\n")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "ssh rollback" not in calls(fake)
    assert "PHASE=stuck_drained" in (home / "state" / f"{HOTEL}.env").read_text()



def test_old_broker_falls_back_to_the_hotel_document(env):
    # A broker from before the guard: 404 hotel_not_found for "<hotel>/restart-check", hotel document reads.
    e, fake, home = env
    (fake / "hotel.json").write_text(json.dumps({"id": HOTEL, "drain": True, "rooms_in_use": 1}))
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "broker_rooms_in_use=1" in r.stdout and "no restart guard" in r.stdout, r.stdout
    assert "ssh install" not in calls(fake)


@pytest.mark.parametrize("restart_body", [{"error": {"code": "hotel_not_found"}}, "<html>404</html>"])
def test_unknown_hotel_or_missing_route_refuses_when_the_hotel_document_does_not_read(env, restart_body):
    e, fake, home = env
    guard(fake, 404, restart_body)
    (fake / "hotel.json").write_text(json.dumps({"error": {"code": "hotel_not_found"}}))
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "hotel_drain=None" in r.stdout or "hotel_drain=?" in r.stdout, r.stdout
    assert "ssh install" not in calls(fake)


# ---- Guest-TLS and miner-mode hotels (chi-ur-2 roll, 26 Nov) -----------------------------------------
# The host cannot ask a guest-TLS hotel's API for its rooms. Only the broker's restart guard can prove
# it empty; the broker's hotel document (rooms_in_use) is never a substitute (it leaves out rooms the
# guard counts), and a broker without the guard refuses.
NOT_DRAINED = {"error": {"code": "restart_refused", "message": "x"},
               "check": {"restart_ok": False, "count_known": True, "rooms": 0, "reasons": ["the hotel is not drained"]}}


@pytest.mark.parametrize("code, body", [
    (404, {"error": {"code": "hotel_not_found", "message": "no hotel x"}}),  # broker before the guard
    (404, "404 page not found"),                                              # no guard route at all
])
def test_guest_tls_hotel_without_a_restart_guard_refuses_even_at_zero_broker_rooms(env, code, body):
    e, fake, _ = env
    (fake / "rooms.txt").write_text("nokey")
    (fake / "hotel.json").write_text(json.dumps({"id": HOTEL, "drain": True, "rooms_in_use": 0}))
    guard(fake, code, body)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "rooms=?" in r.stdout, r.stdout
    no_mutation(fake)


@pytest.mark.parametrize("check", [
    {"restart_ok": False, "count_known": True, "rooms": 1, "reasons": ["the hotel is not drained", "1 rooms"]},
    {"restart_ok": False, "count_known": False, "rooms": 0,
     "reasons": ["the hotel is not drained", "the room count is not known (no good room list from the hotel)"]},
    {"restart_ok": False, "count_known": True, "rooms": 0, "reasons": ["the hotel is not drained", "1 unreaped"]},
])
def test_guest_tls_hotel_refuses_unless_the_guard_proves_zero(env, check):
    e, fake, _ = env
    (fake / "rooms.txt").write_text("nokey")
    guard(fake, 409, {"error": {"code": "restart_refused", "message": "x"}, "check": check})
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "rooms=?" in r.stdout, r.stdout
    no_mutation(fake)


def test_guest_tls_hotel_with_an_unreadable_guard_refuses(env):
    e, fake, _ = env
    (fake / "rooms.txt").write_text("nokey")
    guard(fake, 200, "not json")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "rooms=?" in r.stdout
    no_mutation(fake)


@pytest.mark.parametrize("before", [NOT_DRAINED, GUARD_OK])
def test_guest_tls_hotel_rolls_when_the_guard_proves_zero(env, before):
    e, fake, home = env
    (fake / "rooms.txt").write_text("nokey")
    # preflight reads the guard before the drain (not drained is its only reason), the later checks after
    guard(fake, 409 if before is NOT_DRAINED else 200, before)
    curl = fake.parent / "bin" / "curl"
    curl.write_text(curl.read_text().replace(
        '*/restart-check) echo "GET restart-check" >> "$F/calls.log"; cat "$F/restart.json"; printf \'\\n%s\' "$(cat "$F/restart.code")" ;;',
        '*/restart-check) echo "GET restart-check" >> "$F/calls.log"; '
        'if grep -q "PATCH.*true}" "$F/calls.log" 2>/dev/null; then cat "$F/restart.after"; printf \'\\n200\'; '
        'else cat "$F/restart.json"; printf \'\\n%s\' "$(cat "$F/restart.code")"; fi ;;'))
    (fake / "restart.after").write_text(json.dumps(GUARD_OK))
    serve_capacity(fake, [capacity(CUR), capacity(NEW, drain=True)])
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    c = calls(fake)
    assert "ssh install" in c
    assert "GET hotel" not in c  # the broker's hotel document is never the room count
    assert "PHASE=done" in (home / "state" / f"{HOTEL}.env").read_text()


# install-sealed.sh refuses to restart a miner-mode guest (SEALED_MINER=1) unless told the hotel was
# drained through the control plane. The roll passes that only for a miner hotel, after its own drain.
INSTALL_RECORD_FLAG = """#!/bin/bash
echo "install restart_with_rooms=${SEALED_RESTART_WITH_ROOMS:-unset}" >> "$FAKE_DIR/calls.log"
if grep -q '^SEALED_MINER=1' "$2" && [ "${SEALED_RESTART_WITH_ROOMS:-0}" != 1 ]; then
  echo "sealed: miner hotel: the host holds no hotel key, so live rooms cannot be counted" >&2; exit 1
fi
systemctl restart "room-sealed-hotel-x.service"
echo "[sealed] guest starting; serial log"
echo "[sealed] measurement matches the build"
"""


@pytest.mark.parametrize("miner,guard_ok,flag", [(True, True, "1"), (False, True, "0")])
def test_restart_flag_only_for_a_miner_hotel(host, miner, guard_ok, flag):
    e, fake, home, d, kit = host
    if guard_ok:
        guard(fake, 200, GUARD_OK)
    if miner:
        for env_file in (d / "sealed.env", Path(str(d).replace("srv-x", "stage")) / HOTEL / "sealed.env"):
            env_file.write_text(env_file.read_text() + "SEALED_MINER=1\n")
    (kit / "install.sh").write_text(INSTALL_RECORD_FLAG)
    (kit / "install.sh").chmod(0o755)
    curl = fake.parent / "bin" / "curl"
    curl.write_text(curl.read_text().replace(
        '*/v1/broker/capacity) cat "$F/capacity.json" ;;',
        f'*/v1/broker/capacity) [ "$(readlink {d}/images/current)" = old ] && cat "$F/capacity.json" || cat "$F/capacity.new" ;;'))
    (fake / "capacity.new").write_text(capacity(NEW, drain=True))
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"install restart_with_rooms={flag}" in calls(fake)
    assert any(x.startswith("systemctl restart") for x in calls(fake))
    assert "PHASE=done" in (home / "state" / f"{HOTEL}.env").read_text()


def test_miner_hotel_gets_no_restart_flag_without_the_guards_ok(host):
    # A broker without the guard (the fixture's default 404): the installer keeps its own refusal,
    # so the guest is never restarted on the strength of a weaker count.
    e, fake, home, d, kit = host
    for env_file in (d / "sealed.env", Path(str(d).replace("srv-x", "stage")) / HOTEL / "sealed.env"):
        env_file.write_text(env_file.read_text() + "SEALED_MINER=1\n")
    (kit / "install.sh").write_text(INSTALL_RECORD_FLAG)
    (kit / "install.sh").chmod(0o755)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    c = calls(fake)
    assert "install restart_with_rooms=0" in c, c
    assert not any(x.startswith("systemctl restart") for x in c), c
    assert "PHASE=rolled_back" in (home / "state" / f"{HOTEL}.env").read_text()


# ---- AB#1008 PR 2: the host lock and the custom guest hold marker (spec r9 5.3, 5.10, 14.1) -----------
LAUNCH = "cg-0123456789ab"
HOST_LOCK_LIB = ROOT / "room-kit" / "sealed" / "host-lock.sh"
INSTALL_OK = """#!/bin/bash
systemctl restart "room-sealed-hotel-x.service"
echo "[sealed] guest starting; serial log"
echo "[sealed] measurement matches the build"
"""
LOCK_SYSTEMCTL = """#!/bin/bash
echo "systemctl $* record=$(cat "$CATHEDRAL_SNP_LOCK_DIR/cathedral-snp-host.owner" 2>/dev/null || echo none)" >> "$FAKE_DIR/calls.log"
[ "$1" = is-active ] && { echo active; exit 0; }
exit 0
"""
needs_flock = pytest.mark.skipif(not __import__("shutil").which("flock") or not Path("/proc/self/status").exists(),
                                 reason="needs util-linux flock and /proc (Linux), as on the hosts")


def hold_marker(d, state="held", launch=LAUNCH):
    (d / "custom-guest.hold").write_text(json.dumps({"launch_id": launch, "state": state}) + "\n")


def admit_new_when_installed(fake, d):
    curl = fake.parent / "bin" / "curl"
    curl.write_text(curl.read_text().replace(
        '*/v1/broker/capacity) cat "$F/capacity.json" ;;',
        f'*/v1/broker/capacity) [ "$(readlink {d}/images/current)" = old ] && cat "$F/capacity.json" || cat "$F/capacity.new" ;;'))
    (fake / "capacity.new").write_text(capacity(NEW, drain=True))


def logging_flock(e, fake):
    import shutil
    p = Path(e["PATH"].split(":")[0]) / "flock"
    p.write_text(f'#!/bin/bash\necho "flock $*" >> "$FAKE_DIR/calls.log"\nexec {shutil.which("flock")} "$@"\n')
    p.chmod(0o755)


def resume_drained(home):
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=drained\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\nPLAN_SHA={plan_sha(home)}\n")


@needs_flock
def test_roll_call_graph_runs_under_one_lock_from_host_install_to_write_units(host, tmp_path):
    # roll host_install -> install.sh -> install-sealed.sh -> write-units.sh (spec 5.3, 14.1), all real
    # except install-sealed.sh's SNP-host sections (assess, packages, build, start), which are cut.
    import shutil
    e, fake, home, d, kit = host
    shutil.copy2(ROOT / "room-kit" / "install.sh", kit / "install.sh")
    shutil.copytree(ROOT / "room-kit" / "sealed", kit / "sealed")
    text = (kit / "sealed" / "install-sealed.sh").read_text()
    head = text[:text.index("# ---------------------------------------------------------------- 1. assess")]
    lock = text[text.index("# >>> host lock"):text.index("# <<< host lock")]
    unit = text[text.index("# ---------------------------------------------------------------- 4. unit"):
                text.index("# ---------------------------------------------------------------- 5. start and check")]
    (kit / "sealed" / "install-sealed.sh").write_text(head + lock + unit + INSTALL_OK.split("\n", 1)[1])
    bin_dir = Path(e["PATH"].split(":")[0])
    (bin_dir / "systemctl").write_text(LOCK_SYSTEMCTL)
    (bin_dir / "id").write_text('#!/bin/bash\ncase "${1:-}" in -u) echo 0 ;; *) exit 0 ;; esac\n')
    (bin_dir / "id").chmod(0o755)
    logging_flock(e, fake)
    units = tmp_path / "fake-root"
    e["ROOM_DESTDIR"] = str(units)
    admit_new_when_installed(fake, d)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "RESULT=installed" in r.stdout and "PHASE=done" in (home / "state" / f"{HOTEL}.env").read_text()
    c = calls(fake)
    # flock -n 9 is roll.sh's own per-hotel run lock on the operator machine (run_apply); the host lock
    # is taken once, by the roll's host step, and never again below it.
    assert [x for x in c if x.startswith("flock")] == ["flock -n 9", "flock -w 60 9"], c
    enable = [x for x in c if x.startswith("systemctl enable")]
    assert enable and '"phase": "host_install"' in enable[0] and '"owner": "roll:hotel-x:' in enable[0], c
    assert f"ExecStartPre=/bin/sh -c '[ ! -e {d}/custom-guest.hold ]" in (
        units / "etc/systemd/system/room-sealed-hotel-x.service").read_text()
    assert not (tmp_path / "run-lock" / "cathedral-snp-host.owner").exists()


@needs_flock
@pytest.mark.parametrize("state", ["held", "kit_start"])
def test_a_held_hotel_gets_result_held_at_every_resume_until_the_marker_goes(host, state):
    # A roll paused after preflight and its drain, resumed at R11, R12, R13 and R14: RESULT=held every
    # time, nothing on the host changes and the hotel is never undrained. After R15 it proceeds.
    e, fake, home, d, kit = host
    (kit / "install.sh").write_text(INSTALL_OK)
    (kit / "install.sh").chmod(0o755)
    hold_marker(d, state)
    env_before = (d / "sealed.env").read_text()
    for _ in range(4):
        resume_drained(home)
        r = run(e, "apply", HOTEL)
        assert r.returncode == 1, r.stdout
        assert f"RESULT=held launch={LAUNCH} state={state}" in r.stdout
        assert "PHASE=drained" in (home / "state" / f"{HOTEL}.env").read_text()
        assert os.readlink(d / "images" / "current") == "old"
        assert (d / "sealed.env").read_text() == env_before and not list(d.glob("sealed.env.bak-*"))
        c = calls(fake)
        assert not any(x.startswith("systemctl") for x in c), c
        assert patches(fake) == [], c
    (d / "custom-guest.hold").unlink()  # R15
    admit_new_when_installed(fake, d)
    r = run(e, "apply", HOTEL)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "RESULT=installed" in r.stdout and "PHASE=done" in (home / "state" / f"{HOTEL}.env").read_text()


@needs_flock
def test_preflight_refuses_a_held_hotel_before_the_drain(host):
    e, fake, home, d, kit = host
    e["FAKE_CHECK_EXEC"] = "1"
    hold_marker(d, "kit_start")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert "host: custom_guest_hold=kit_start launch=" + LAUNCH in r.stdout
    assert "a custom guest holds hotel-x" in r.stdout
    no_mutation(fake)
    (d / "custom-guest.hold").unlink()
    r = run(e, "apply", HOTEL)
    assert "host: custom_guest_hold=none" in r.stdout, r.stdout


@needs_flock
def test_a_rollback_of_a_held_hotel_is_refused_and_the_run_stays_stuck(host):
    e, fake, home, d, kit = host
    hold_marker(d, "held")
    (fake / "capacity.json").write_text(capacity(CUR, drain=True))
    (home / "state" / f"{HOTEL}.env").write_text(
        f"PHASE=installed\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\nPLAN_SHA={plan_sha(home)}\n")
    (d / "images" / "current").unlink()
    (d / "images" / "current").symlink_to("20260101T000000Z")
    r = run(e, "apply", HOTEL)
    assert r.returncode == 1
    assert f"RESULT=held launch={LAUNCH}" in r.stdout and "host rollback refused, nothing changed" in r.stdout
    assert "PHASE=stuck_drained" in (home / "state" / f"{HOTEL}.env").read_text()
    assert os.readlink(d / "images" / "current") == "20260101T000000Z"
    assert not any(x.startswith("systemctl") for x in calls(fake))
    assert patches(fake) == []


@needs_flock
def test_install_stops_with_nothing_changed_while_another_step_holds_the_host_lock(host, tmp_path):
    e, fake, home, d, kit = host
    (kit / "install.sh").write_text(INSTALL_OK)
    (kit / "install.sh").chmod(0o755)
    e["CATHEDRAL_SNP_LOCK_WAIT"] = "1"
    holder = subprocess.Popen(["bash", "-c", f"source {HOST_LOCK_LIB}; snp_lock_take custom-guest hold-stop hotel-x "
                               f"{LAUNCH} 900 || exit 9; echo ready; sleep 60"], env=e, stdout=subprocess.PIPE, text=True,
                              start_new_session=True)
    try:
        assert holder.stdout.readline().strip() == "ready"
        resume_drained(home)
        r = run(e, "apply", HOTEL)
    finally:
        os.killpg(holder.pid, 9)
        holder.wait()
    assert r.returncode == 1
    assert "RESULT=busy" in r.stdout and "custom_guest_lifecycle_busy" in r.stdout and '"phase": "hold-stop"' in r.stdout
    assert "PHASE=drained" in (home / "state" / f"{HOTEL}.env").read_text()
    assert os.readlink(d / "images" / "current") == "old" and not list(d.glob("sealed.env.bak-*"))
    assert patches(fake) == [] and not any(x.startswith("systemctl") for x in calls(fake))


def test_host_steps_run_under_the_roll_deadline():
    text = ROLL.read_text()
    assert "HOST_STEP_MAX=3600" in text
    assert text.count('timeout --kill-after=30s "$HOST_STEP_MAX"') == 2
    for fn in ("host_install() {", "host_rollback() {", "host_check() {"):
        body = text[text.index(fn):]
        assert body.index('cat "$HOST_LOCK_LIB"') < body.index("REMOTE")

"""AB#453: dry-run tests for ops/roll/roll.sh with fake ssh, curl and guard on PATH.

Nothing here touches a network or a host. The fakes read canned answers from a scenario directory
and log every call, so each test can assert both the refusal and what was (not) done.
"""
import base64
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
  */v1/broker/hotels/*) echo "$method $url $data" >> "$F/calls.log"; printf '%s' "$(cat "$F/patch_code" 2>/dev/null || echo 200)" ;;
  */approved-measurements.json) cat "$F/site.json" ;;
  */escape/open) cat "$F/open.json" ;;
  */attestation) cp "$F/attestation.json" "$out" ;;
esac
"""

FAKE_SSH = r"""#!/bin/bash
F=$FAKE_DIR
args="$*"
stdin=""; [ -t 0 ] || stdin=$(cat)
case "$args" in
  *sealed_measurements*) echo "ssh pins" >> "$F/calls.log"; cat "$F/pins.txt"; exit 0 ;;
  *post_hotel.sh*)
    echo "ssh rooms" >> "$F/calls.log"
    n=$(cat "$F/rooms.txt")
    body=$(python3 -c "import base64,json,sys; print(base64.b64encode(json.dumps({'sandboxes': [{}]*int(sys.argv[1])}).encode()).decode())" "$n")
    echo "{\"status\": 200, \"body_b64\": \"$body\"}"; exit 0 ;;
esac
case "$stdin" in
  *SEALED_SKIP_BUILD*) echo "ssh install" >> "$F/calls.log"; cat "$F/install.out" ;;
  *'ln -sfn "$OLDIMG"'*) echo "ssh rollback" >> "$F/calls.log"; echo "RESULT=rolledback unit=active current=old" ;;
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
        f"PHASE=installed\nTS=20260101T000000Z\nOLDIMG=old\nCOMMIT=1234567\n")
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

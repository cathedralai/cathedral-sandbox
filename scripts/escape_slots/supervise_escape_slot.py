#!/usr/bin/env python3
"""Host supervisor for one Escape slot: one sealed guest serves at most one attempt (AB#683).

A slot is a sealed hotel (room-kit/sealed) joined to the broker once, reserved
for Escape, with one room slot. This process runs beside it on the host and
makes sure a guest that served an attempt is destroyed and replaced by a new
launch (new SEV-SNP guest, new REPORT_ID, new receipt key, new scratch key)
before anything else can land on it. Design: escape-room
docs/mission-m-m/plans/AB683.md, Stage 1 S2 and section 11.

What it does, every poll (default 5 s):
- reads the guest with GET only, using the slot's hotel key (as
  install-sealed.sh does): /room/receipts?limit=1, /v1/sandboxes and, once per
  launch, /room/attestation;
- tracks one launch through booting -> fresh -> in_use -> retiring;
- retires a launch that served an attempt: systemctl stop, confirm QEMU is
  gone, delete scratch.raw, systemctl start (launch-guest.sh makes a new one).

What it never does: create or touch a room, call the broker, send anything
but GET to the guest, rebuild the image. Do not run install-sealed.sh on a slot
while its supervisor runs; it restarts the unit and moves images/current.

"Used" is decided from the guest's own receipt chain. Every action a player
can cause in a room (create, exec, files, delete) and the Escape plant are
signed into the chain (room_receipts.py SIGNED and the plant), and the chain
starts empty at each boot. A launch is used once its chain is non-empty, a
room is listed, or its binding changes (the receipts front restarted and lost
its chain). Used is sticky for the life of the launch.

Ordering assumption: the API creates the room before it plants the secret
(AB683.md P5 step 3 before 6). A plant with no room would read as an ended
attempt and retire the guest at once, which is the safe direction.

Live systemctl calls need CATHEDRAL_ESCAPE_SLOT_LIVE_OK=yes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

SCHEMA = "cathedral_escape_slot_supervise_v1"
LIVE_ENV = "CATHEDRAL_ESCAPE_SLOT_LIVE_OK"
DEFAULT_GUEST_URL = "http://10.215.0.2:18090"  # room-kit/sealed/guest-constants.sh
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,58}$")  # launch-guest.sh SEALED_NAME rule
HEX64 = re.compile(r"^[0-9a-f]{64}$")
# The room API reaps a room within GC_GRACE_SECONDS of its expires_at
# (cathedral/sandbox_api.py). A room still listed past that plus a margin is stuck.
ROOM_GC_GRACE_SECONDS = 300
ROOM_EXPIRY_MARGIN_SECONDS = 60

Fetch = Callable[[str], "tuple[int | None, dict | None]"]
Systemctl = Callable[[list], "tuple[int, str]"]


def die(message: str) -> None:
    raise SystemExit(f"refusing escape slot supervise: {message}")


# ---------------------------------------------------------------- slot config


@dataclass(frozen=True)
class SlotConfig:
    name: str
    sealed_dir: Path
    key_file: Path

    @property
    def unit(self) -> str:
        return f"room-sealed-{self.name}.service"  # install-sealed.sh UNIT

    @property
    def scratch(self) -> Path:
        return self.sealed_dir / "scratch.raw"

    @property
    def serial_log(self) -> Path:
        return self.sealed_dir / "run" / "serial.log"

    @property
    def expected_measurement_file(self) -> Path:
        return self.sealed_dir / "images" / "current" / "expected-measurement"


def parse_sealed_env(path: Path) -> dict:
    """Plain KEY=VALUE lines only. A value that needs the shell is refused, not guessed."""
    values: dict = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
            die(f"{path}:{number}: not a KEY=VALUE line")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if any(c in value for c in "$`"):
            die(f"{path}:{number}: {key} must be a plain value, not a shell expression")
        values[key] = value
    return values


def load_slot(sealed_env: Path) -> SlotConfig:
    """Read and check the slot's sealed.env. Called at start and before every launch."""
    if not sealed_env.is_absolute() or not sealed_env.is_file():
        die(f"sealed.env must be an absolute path to a file: {sealed_env}")
    env = parse_sealed_env(sealed_env)
    name = env.get("SEALED_NAME", "")
    if not NAME_RE.fullmatch(name):
        die("SEALED_NAME missing or invalid")
    if env.get("SEALED_MINER", "0") != "0":
        # A miner hotel serves only /room/attestation on the plain port and
        # holds no hotel key on the host, so this process cannot read it.
        die("SEALED_MINER must be 0 on an Escape slot")
    if env.get("SEALED_DATA_GIB", "0") != "0":
        # launch-guest.sh makes data.raw on any start when this is set, and a
        # data volume outlives the guest: state would cross attempts.
        die("SEALED_DATA_GIB must be 0 on an Escape slot")
    sealed_dir = Path(env.get("SEALED_DIR", ""))
    if not sealed_dir.is_absolute() or not sealed_dir.is_dir():
        die("SEALED_DIR missing or not a directory")
    if (sealed_dir / "data.raw").exists():
        die(f"{sealed_dir / 'data.raw'} exists: an Escape slot must have no data volume")
    key_file = Path(env.get("SEALED_API_KEY_FILE", ""))
    if not key_file.is_absolute() or not key_file.is_file():
        die("SEALED_API_KEY_FILE missing or not a file")
    return SlotConfig(name=name, sealed_dir=sealed_dir, key_file=key_file)


# ---------------------------------------------------------------- live I/O


def http_fetcher(guest_url: str, key_file: Path, timeout: float = 5.0) -> Fetch:
    """GET-only reader of the guest. Returns (status, json) or (None, None) when unreachable."""
    key = key_file.read_text(encoding="ascii").strip()
    if not key:
        die("hotel key file is empty")
    base = guest_url.rstrip("/")

    def fetch(path: str) -> tuple:
        request = urllib.request.Request(
            base + path, method="GET", headers={"Authorization": f"Bearer {key}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as answer:
                status, body = answer.status, answer.read()
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except (OSError, ValueError):
            return None, None
        try:
            return status, json.loads(body)
        except ValueError:
            return status, None

    return fetch


def live_systemctl(args: list) -> tuple:
    if args and args[0] != "show" and os.environ.get(LIVE_ENV) != "yes":
        die(f"set {LIVE_ENV}=yes only after the slot is set up and the owner agreed")
    done = subprocess.run(
        ["systemctl", *args], capture_output=True, text=True, timeout=180, check=False
    )
    return done.returncode, done.stdout


# ---------------------------------------------------------------- supervisor


@dataclass
class Launch:
    started_at: float
    state: str = "booting"
    binding_sha256: str | None = None
    used: bool = False
    fresh_at: float | None = None
    in_use_at: float | None = None
    empty_polls: int = 0
    latest_expiry: float | None = None
    alerted: set = field(default_factory=set)


def _expiry(room: dict) -> float | None:
    raw = room.get("expires_at") if isinstance(room, dict) else None
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw).timestamp()
    except ValueError:
        return None


class SlotSupervisor:
    def __init__(
        self,
        *,
        sealed_env: Path,
        fetch: Fetch,
        systemctl: Systemctl,
        clock: Callable[[], float] = time.time,
        out: Callable[[str], None] = lambda line: print(line, flush=True),
        boot_timeout: float = 15 * 60,
        fresh_max_age: float = 6 * 3600,
        max_attempt: float = 4 * 3600,
        empty_polls_to_retire: int = 2,
    ) -> None:
        self.sealed_env = sealed_env
        self.slot = load_slot(sealed_env)
        self.fetch = fetch
        self.systemctl = systemctl
        self.clock = clock
        self.out = out
        self.boot_timeout = boot_timeout
        self.fresh_max_age = fresh_max_age
        self.max_attempt = max_attempt
        self.empty_polls_to_retire = empty_polls_to_retire
        self.failed_boots = 0
        self.hold_until = 0.0
        # The launch already running when the supervisor starts is treated as
        # unknown history: it gets "booting" and the normal reads decide.
        self.launch = Launch(started_at=clock())

    # ------------------------------------------------------------ logging

    def log(self, action: str, **fields) -> None:
        document = {"schema": SCHEMA, "slot": self.slot.name, "action": action,
                    "state": self.launch.state, "at": round(self.clock(), 3), **fields}
        self.out(json.dumps(document, sort_keys=True))

    def alert(self, code: str, message: str, *, once_per_launch: bool = True) -> None:
        if once_per_launch and code in self.launch.alerted:
            return
        self.launch.alerted.add(code)
        self.out(f"[OPERATOR-ALERT] escape slot {self.slot.name}: {code}: {message}")

    def move(self, state: str, reason: str, **fields) -> None:
        before = self.launch.state
        self.launch.state = state
        self.log("transition", previous=before, reason=reason, **fields)

    # ------------------------------------------------------------ unit

    def unit_status(self) -> tuple:
        code, text = self.systemctl(["show", "-p", "ActiveState", "-p", "MainPID", self.slot.unit])
        props = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        try:
            pid = int(props.get("MainPID", "-1"))
        except ValueError:
            pid = -1
        return (props.get("ActiveState", "unknown") if code == 0 else "unknown"), pid

    def retire(self, reason: str) -> bool:
        """Stop the guest, confirm it is gone, drop its scratch, start a new launch."""
        if self.launch.state != "retiring":
            self.move("retiring", reason, used=self.launch.used)
        self.systemctl(["stop", self.slot.unit])
        state, pid = self.unit_status()
        # Restart=no: a guest killed after TimeoutStopSec ends "failed", not "inactive".
        if state not in ("inactive", "failed") or pid != 0:
            self.boot_failed(f"unit still {state} pid {pid} after stop; scratch kept")
            return False
        if state == "failed":
            self.systemctl(["reset-failed", self.slot.unit])
        # Re-read the config before every launch: data.raw or a miner flag
        # added since start would carry state into the next attempt.
        self.slot = load_slot(self.sealed_env)
        self.slot.scratch.unlink(missing_ok=True)
        if self.slot.scratch.exists():
            die(f"could not delete {self.slot.scratch}")
        if self.slot.serial_log.is_file():
            # QEMU overwrites serial.log each boot; keep the last launch's for boot timing.
            os.replace(self.slot.serial_log, self.slot.serial_log.with_name("serial.prev.log"))
        if self.clock() < self.hold_until:
            # Backing off after repeated failed launches: the old guest is gone
            # and its scratch deleted; the next launch waits.
            return False
        code, _ = self.systemctl(["start", self.slot.unit])
        if code != 0:
            self.boot_failed(f"systemctl start exited {code}")
            return False
        self.launch = Launch(started_at=self.clock())
        self.log("launched", reason=reason, scratch_deleted=True)
        return True

    def boot_failed(self, detail: str) -> None:
        self.failed_boots += 1
        self.log("boot_failed", detail=detail, failed_boots=self.failed_boots)
        if self.failed_boots >= 3:
            backoff = min(60 * 2 ** (self.failed_boots - 3), 1800)
            self.hold_until = self.clock() + backoff
            self.alert("boot_failing",
                       f"{self.failed_boots} failed launches in a row ({detail}); "
                       f"next launch in {backoff} s; slot out of service",
                       once_per_launch=False)

    # ------------------------------------------------------------ one poll

    def step(self) -> None:
        launch = self.launch
        if launch.state == "retiring":
            if self.clock() >= self.hold_until:
                self.retire("retry")
            return
        unit_state, _ = self.unit_status()
        if unit_state in ("inactive", "failed"):
            if launch.state == "booting":
                self.boot_failed(f"unit {unit_state} while booting")
            self.retire(f"unit_{unit_state}")
            return

        r_status, receipts = self.fetch("/room/receipts?limit=1")
        s_status, rooms_doc = self.fetch("/v1/sandboxes")
        if r_status in (401, 403) or s_status in (401, 403):
            # Wrong key or a miner image: a config error, not a dead guest.
            # Never retire for it, or a misconfigured slot restarts forever.
            self.alert("guest_refused_key",
                       f"guest answered {r_status}/{s_status}; check SEALED_API_KEY_FILE")
            return
        answered = (r_status == 200 and isinstance(receipts, dict)
                    and s_status == 200 and isinstance(rooms_doc, dict)
                    and isinstance(rooms_doc.get("sandboxes"), list))
        if answered:
            answered = self.observe(receipts, rooms_doc["sandboxes"])
            if self.launch is not launch or self.launch.state == "retiring":
                return
        self.check_clocks(answered)

    def observe(self, receipts: dict, rooms: list) -> bool:
        """Apply one good answer. False when the answer is not one we understand."""
        launch, now = self.launch, self.clock()
        binding = receipts.get("binding_sha256")
        if not isinstance(binding, str) or not HEX64.fullmatch(binding):
            return False
        if launch.binding_sha256 is None:
            launch.binding_sha256 = binding
            self.check_measurement()
        elif binding != launch.binding_sha256:
            # The receipts front restarted inside the guest and lost its chain.
            # Whatever happened before is no longer visible: never hand this out.
            launch.used = True
            self.retire("binding_changed")
            return True
        count = receipts.get("count")
        chain_used = (isinstance(count, int) and count > 0) or bool(receipts.get("receipts"))
        if chain_used or rooms:
            launch.used = True
        if launch.state == "booting":
            self.failed_boots = 0
            boot_seconds = round(now - launch.started_at, 3)
            if launch.used:
                launch.in_use_at = now
                self.move("in_use", "first_answer_used", boot_seconds=boot_seconds)
            else:
                launch.fresh_at = now
                self.move("fresh", "first_answer_empty_chain", boot_seconds=boot_seconds)
        elif launch.state == "fresh" and launch.used:
            launch.in_use_at = now
            self.move("in_use", "chain_not_empty", rooms=len(rooms))
        if launch.state != "in_use":
            return True
        expiries = [e for e in (_expiry(r) for r in rooms) if e is not None]
        if expiries:
            launch.latest_expiry = max(expiries)
        if rooms:
            launch.empty_polls = 0
            return True
        launch.empty_polls += 1
        if launch.empty_polls >= self.empty_polls_to_retire:
            self.retire("attempt_ended")
        return True

    def check_clocks(self, answered: bool) -> None:
        launch, now = self.launch, self.clock()
        if launch.state == "booting" and not answered:
            if now - launch.started_at > self.boot_timeout:
                self.boot_failed("no answer within the boot timeout")
                self.retire("boot_timeout")
        elif launch.state == "fresh":
            if launch.fresh_at is not None and now - launch.fresh_at > self.fresh_max_age:
                self.retire("fresh_max_age")
        elif launch.state == "in_use":
            if launch.in_use_at is not None and now - launch.in_use_at > self.max_attempt:
                self.retire("max_attempt")
            elif (launch.latest_expiry is not None
                  and now > launch.latest_expiry + ROOM_GC_GRACE_SECONDS
                  + ROOM_EXPIRY_MARGIN_SECONDS):
                self.retire("room_past_expiry")

    def check_measurement(self) -> None:
        """Alert when the guest is not the build in images/current (install-sealed.sh ran?)."""
        status, doc = self.fetch("/room/attestation")
        got = None
        if status == 200 and isinstance(doc, dict) and isinstance(doc.get("binding"), dict):
            got = doc["binding"].get("measurement")
        try:
            want = self.slot.expected_measurement_file.read_text(encoding="ascii").strip()
        except OSError:
            want = None
        self.log("measurement", measurement=got, expected=want)
        if got is None or want is None or got != want:
            self.alert("measurement_mismatch",
                       f"guest measurement {got} differs from images/current {want}")

    def run(self, poll_seconds: float, max_polls: int = 0) -> None:
        self.log("start", unit=self.slot.unit)
        polls = 0
        while max_polls <= 0 or polls < max_polls:
            self.step()
            polls += 1
            time.sleep(poll_seconds)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sealed-env", required=True, type=Path,
                        help="the slot's sealed.env (absolute path)")
    parser.add_argument("--guest-url", default=DEFAULT_GUEST_URL,
                        help="where this host reaches the slot's guest port 18090")
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--boot-timeout", type=float, default=15 * 60)
    parser.add_argument("--fresh-max-age", type=float, default=6 * 3600)
    parser.add_argument("--max-attempt-seconds", type=float, default=4 * 3600)
    parser.add_argument("--max-polls", type=int, default=0, help="0 = run until stopped")
    return parser


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    slot = load_slot(args.sealed_env)
    supervisor = SlotSupervisor(
        sealed_env=args.sealed_env,
        fetch=http_fetcher(args.guest_url, slot.key_file),
        systemctl=live_systemctl,
        boot_timeout=args.boot_timeout,
        fresh_max_age=args.fresh_max_age,
        max_attempt=args.max_attempt_seconds,
    )
    supervisor.run(args.poll_seconds, args.max_polls)
    return 0


if __name__ == "__main__":
    sys.exit(main())

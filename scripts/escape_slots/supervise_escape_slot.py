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

Broker destroy (AB#683 escape-destroy): the broker retires a launch when the
API's attempt cleanup asks, and the slot's net-check timer carries that to
this host (--retire-channel, one shot per timer run; see
write-escape-units.sh). The channel drops one request file per launch in
run/escape-retire/; the supervisor retires the launch if it is the one
running, and writes <report_id>.stopped once the unit is stopped with
MainPID 0 and scratch is deleted (for every retire, its own included). A
requested launch that is not the running one is not running (one unit, one
guest), so it is recorded stopped at once. The channel posts each stopped
record back to the broker, which only then answers "destroyed".

What it never does: create or touch a room, send anything but GET to the
guest, rebuild the image. Only the --retire-channel one shot calls the
broker, and only its own slot's escape-retire route. Do not run install-sealed.sh on a slot
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

Guest TLS slot (SEALED_MINER=1 with SEALED_ESCAPE_SLOT=1, the chi-escape
re-seal of 24 Nov): the guest serves the hotel key routes only over HTTPS on
SEALED_MINER_TLS_PORT, and the broker installs the hotel key in each launch.
The supervisor then reads https://<SEALED_GUEST_IP>:<SEALED_MINER_TLS_PORT>
with a copy of the broker's hotel key for this slot in SEALED_API_KEY_FILE
(the retire channel needs it at the broker too). The broker's own
hotel_key_install receipt opens every such chain, so it does not count as use.

Live systemctl calls need CATHEDRAL_ESCAPE_SLOT_LIVE_OK=yes.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
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
DEFAULT_MINER_TLS_PORT = "18443"  # room-kit/sealed/build-guest.sh SEALED_MINER_TLS_PORT
# The broker's hotel key install (room_receipts.py INSTALL_ACTION): signed into the
# chain of a guest TLS launch before any player can reach it, so it is not use.
INSTALL_ACTION = "hotel_key_install"
# Receipts read per poll on a guest TLS slot: enough to see past the install
# receipts. A full page of installs only is read as used (fail toward retire).
TLS_RECEIPTS_LIMIT = 16
IPV4_RE = re.compile(r"^(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,58}$")  # launch-guest.sh SEALED_NAME rule
HEX64 = re.compile(r"^[0-9a-f]{64}$")
RETIRE_REQUEST_SCHEMA = "cathedral.escape.retire_request/v1"  # broker escape_destroy.go
RETIRE_CONFIRM_SCHEMA = "cathedral.escape.retire_confirm/v1"
SNP_REPORT_ID = slice(0x140, 0x160)  # AMD SEV-SNP ABI ATTESTATION_REPORT REPORT_ID
SNP_REPORT_MIN_LEN = 0x4A0
STOPPED_KEEP = 64  # stopped records kept for late broker requests
# The room API reaps a room within GC_GRACE_SECONDS of its expires_at
# (cathedral/sandbox_api.py). A room still listed past that plus a margin is stuck.
ROOM_GC_GRACE_SECONDS = 300
ROOM_EXPIRY_MARGIN_SECONDS = 60
# A fresh guest answers 401 until the broker installs the hotel key in it, which the live
# broker log shows 4 to 5 s after the guest first answers (chi-escape, 26 Nov). A booting
# guest that still refuses after this long has the wrong key.
KEY_INSTALL_GRACE_SECONDS = 60

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
    # Guest TLS slot: the guest's HTTPS origin on the tap; None on a plain slot.
    tls_guest_url: str | None = None

    @property
    def receipts_path(self) -> str:
        if self.tls_guest_url:
            return f"/room/receipts?limit={TLS_RECEIPTS_LIMIT}"
        return "/room/receipts?limit=1"

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

    @property
    def retire_dir(self) -> Path:
        return self.sealed_dir / "run" / "escape-retire"


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
    miner = env.get("SEALED_MINER", "0")
    tls_guest_url = None
    if miner == "1" and env.get("SEALED_ESCAPE_SLOT") == "1":
        # Guest TLS slot: the plain port serves only /room/attestation, so read
        # the guest over its TLS port on the tap with the slot's hotel key copy.
        guest_ip = env.get("SEALED_GUEST_IP", "")
        port = env.get("SEALED_MINER_TLS_PORT", DEFAULT_MINER_TLS_PORT)
        if not IPV4_RE.fullmatch(guest_ip):
            die("SEALED_GUEST_IP must be the guest's IPv4 address on a guest TLS slot")
        if not re.fullmatch(r"[1-9][0-9]{0,4}", port) or int(port) > 65535:
            die("SEALED_MINER_TLS_PORT must be a TCP port")
        tls_guest_url = f"https://{guest_ip}:{port}"
    elif miner != "0":
        # A miner hotel that is not an Escape slot: the host holds no hotel key.
        die("SEALED_MINER must be 0 on an Escape slot (or 1 with SEALED_ESCAPE_SLOT=1)")
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
    return SlotConfig(name=name, sealed_dir=sealed_dir, key_file=key_file, tls_guest_url=tls_guest_url)


# ---------------------------------------------------------------- live I/O


def http_fetcher(guest_url: str, key_file: Path, timeout: float = 5.0) -> Fetch:
    """GET-only reader of the guest. Returns (status, json) or (None, None) when unreachable."""
    key = key_file.read_text(encoding="ascii").strip()
    if not key:
        die("hotel key file is empty")
    base = guest_url.rstrip("/")
    kwargs: dict = {}
    if base.startswith("https://"):
        # The guest's TLS key is new each launch and self-signed (its binding
        # names it). This read crosses only the host's own tap to the guest, the
        # same path the plain slot reads over HTTP, and the host already holds
        # the key it sends, so the certificate adds nothing to check here.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs["context"] = context

    def fetch(path: str) -> tuple:
        request = urllib.request.Request(
            base + path, method="GET", headers={"Authorization": f"Bearer {key}"}
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout, **kwargs) as answer:
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
    report_id: str | None = None  # SNP REPORT_ID of this launch, from /room/attestation
    used: bool = False
    fresh_at: float | None = None
    in_use_at: float | None = None
    empty_polls: int = 0
    latest_expiry: float | None = None
    refused_since: float | None = None  # first 401/403 of the current refusal run
    room_ids: set = field(default_factory=set)
    alerted: set = field(default_factory=set)


def _expiry(room: dict) -> float | None:
    raw = room.get("expires_at") if isinstance(room, dict) else None
    if not isinstance(raw, str):
        return None
    try:
        return datetime.fromisoformat(raw).timestamp()
    except ValueError:
        return None


def report_id_of(report_b64) -> str | None:
    """REPORT_ID of an SEV-SNP report, or None (missing, malformed, all zeros)."""
    if not isinstance(report_b64, str):
        return None
    try:
        report = base64.b64decode(report_b64, validate=True)
    except ValueError:
        return None
    if len(report) < SNP_REPORT_MIN_LEN:
        return None
    rid = report[SNP_REPORT_ID]
    return rid.hex() if any(rid) else None


def _write_json(path: Path, doc: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="ascii") as handle:
        json.dump(doc, handle, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def _read_json(path: Path) -> dict | None:
    try:
        doc = json.loads(path.read_text(encoding="ascii"))
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def write_stopped(slot: SlotConfig, report: str, binding: str, reason: str, at: float) -> None:
    _write_json(slot.retire_dir / f"{report}.stopped",
                {"report_id": report, "binding_sha256": binding, "reason": reason, "stopped_at": round(at, 3)})
    kept = sorted(slot.retire_dir.glob("*.stopped"), key=lambda p: p.stat().st_mtime)
    for old in kept[:-STOPPED_KEEP]:
        old.unlink(missing_ok=True)


def read_requests(slot: SlotConfig) -> list:
    """(report_id, binding_sha256) of each well-formed request file."""
    out = []
    if not slot.retire_dir.is_dir():
        return out
    for path in sorted(slot.retire_dir.glob("*.request")):
        doc = _read_json(path)
        if doc is None:
            continue
        report, binding = doc.get("report_id"), doc.get("binding_sha256")
        if (isinstance(report, str) and HEX64.fullmatch(report) and path.stem == report
                and isinstance(binding, str) and HEX64.fullmatch(binding)):
            out.append((report, binding))
    return out


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
        if self.launch.report_id and self.launch.binding_sha256:
            # Stopped, MainPID 0, scratch gone: the broker may now say destroyed.
            write_stopped(self.slot, self.launch.report_id, self.launch.binding_sha256, reason, self.clock())
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
        self.serve_retire_requests()
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

        r_status, receipts = self.fetch(self.slot.receipts_path)
        s_status, rooms_doc = self.fetch("/v1/sandboxes")
        if r_status in (401, 403) or s_status in (401, 403):
            # Wrong key or a miner image: a config error, not a dead guest.
            # Never retire for it, or a misconfigured slot restarts forever.
            # While booting, the broker may not have installed the hotel key yet:
            # alert only once the refusal outlasts KEY_INSTALL_GRACE_SECONDS.
            now = self.clock()
            if launch.refused_since is None:
                launch.refused_since = now
            if launch.state != "booting" or now - launch.refused_since >= KEY_INSTALL_GRACE_SECONDS:
                self.alert("guest_refused_key",
                           f"guest answered {r_status}/{s_status}; check SEALED_API_KEY_FILE")
            return
        launch.refused_since = None
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
        elif launch.report_id is None:
            self.read_report_id()  # the first read failed; a destroy waits on it
        if binding != launch.binding_sha256:
            # The receipts front restarted inside the guest and lost its chain.
            # Whatever happened before is no longer visible: never hand this out.
            launch.used = True
            self.retire("binding_changed")
            return True
        ids = {r.get("id") if isinstance(r, dict) else None for r in rooms}
        chain_used = self.chain_used(receipts)
        if chain_used or rooms:
            launch.used = True
        if launch.state == "booting":
            self.failed_boots = 0
            boot_seconds = round(now - launch.started_at, 3)
            if launch.used:
                launch.in_use_at, launch.room_ids = now, set(ids)
                self.move("in_use", "first_answer_used", boot_seconds=boot_seconds)
            else:
                launch.fresh_at = now
                self.move("fresh", "first_answer_empty_chain", boot_seconds=boot_seconds)
        elif launch.state == "fresh" and launch.used:
            launch.in_use_at, launch.room_ids = now, set(ids)
            self.move("in_use", "chain_not_empty", rooms=len(rooms))
        if launch.state != "in_use":
            return True
        # One attempt per launch: the attempt's rooms are the ones listed on the
        # poll that found the launch used. The chain is read before the rooms and
        # a create is signed only after the room exists, so a used chain with no
        # room listed means the attempt already ended. Any room id not seen on
        # that poll is a second attempt or a handover: retire at once.
        if not ids <= launch.room_ids:
            self.retire("new_room_on_used_launch")
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

    def chain_used(self, receipts: dict) -> bool:
        count = receipts.get("count")
        page = receipts.get("receipts")
        if not self.slot.tls_guest_url:
            return (isinstance(count, int) and count > 0) or bool(page)
        if not isinstance(page, list):
            return isinstance(count, int) and count > 0
        if len(page) >= TLS_RECEIPTS_LIMIT or (isinstance(count, int) and count > len(page)):
            return True  # more chain than this page shows: never guess it is only installs
        for receipt in page:
            statement = receipt.get("statement") if isinstance(receipt, dict) else None
            if not isinstance(statement, dict) or statement.get("action") != INSTALL_ACTION:
                return True
        return False

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

    def read_report_id(self, status=None, doc=None) -> None:
        """Learn this launch's REPORT_ID from an attestation of its own binding."""
        if status is None:
            status, doc = self.fetch("/room/attestation")
        if status != 200 or not isinstance(doc, dict):
            return
        if doc.get("binding_sha256") != self.launch.binding_sha256:
            return  # not this launch's attestation: the binding check retires it
        report = report_id_of(doc.get("report_b64"))
        if report is not None:
            self.launch.report_id = report
            self.log("launch_report", report_id=report)

    def check_measurement(self) -> None:
        """Alert when the guest is not the build in images/current (install-sealed.sh ran?)."""
        status, doc = self.fetch("/room/attestation")
        self.read_report_id(status, doc)
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

    def still_tracked_launch(self) -> bool:
        """True when the guest answers now with the binding and REPORT_ID this supervisor tracks."""
        status, doc = self.fetch("/room/attestation")
        if status != 200 or not isinstance(doc, dict):
            return False
        if doc.get("binding_sha256") != self.launch.binding_sha256:
            return False
        return report_id_of(doc.get("report_b64")) == self.launch.report_id

    def serve_retire_requests(self) -> None:
        """Act on the broker's retire requests the channel dropped in run/escape-retire/."""
        for report, binding in read_requests(self.slot):
            if (self.slot.retire_dir / f"{report}.stopped").is_file():
                continue
            launch = self.launch
            if launch.state == "retiring":
                return  # the stop in progress writes its own record
            if launch.report_id == report:
                launch.used = True
                self.retire("broker_destroy")
                return
            if launch.report_id is not None:
                # One unit runs one guest. Confirm the request's launch is not it only on a
                # fresh attestation of the launch we track: the unit can restart on its own
                # (Restart=on-failure) into a launch we have not seen yet, which may be the
                # one the broker wants destroyed. Anything else waits; the binding check
                # retires an unknown launch.
                if self.still_tracked_launch():
                    write_stopped(self.slot, report, binding, "not_running", self.clock())
                    self.log("retire_not_running", report_id=report, running=launch.report_id)
                continue
            unit_state, pid = self.unit_status()
            if unit_state in ("inactive", "failed") and pid == 0:
                write_stopped(self.slot, report, binding, f"unit_{unit_state}", self.clock())
                self.log("retire_not_running", report_id=report, running=None)
            # Otherwise the running launch is not known yet: wait for its attestation.

    def run(self, poll_seconds: float, max_polls: int = 0) -> None:
        self.log("start", unit=self.slot.unit)
        polls = 0
        while max_polls <= 0 or polls < max_polls:
            self.step()
            polls += 1
            time.sleep(poll_seconds)


# ---------------------------------------------------------------- retire channel

Request = Callable[[str, str, "bytes | None"], "tuple[int | None, dict | None]"]


def broker_url_of(sealed_env: Path) -> str:
    """SEALED_BROKER_URL: plain https origin, from the slot's own sealed.env (no built-in list)."""
    env = parse_sealed_env(sealed_env)
    if env.get("SEALED_ESCAPE_SLOT") != "1":
        die("SEALED_ESCAPE_SLOT=1 is not set: this host is not a fresh slot")
    url = env.get("SEALED_BROKER_URL", "")
    if not re.fullmatch(r"https://[A-Za-z0-9.-]+(:[0-9]{1,5})?", url):
        die("SEALED_BROKER_URL must be an https origin (no path, user, query)")
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never carry the hotel key elsewhere
        return None


def broker_requester(broker_url: str, key_file: Path, timeout: float = 10.0) -> Request:
    key = key_file.read_text(encoding="ascii").strip()
    if not key:
        die("hotel key file is empty")
    opener = urllib.request.build_opener(_NoRedirect)

    def request(method: str, path: str, body: bytes | None) -> tuple:
        headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(broker_url + path, data=body, method=method, headers=headers)
        try:
            with opener.open(req, timeout=timeout) as answer:
                status, raw = answer.status, answer.read(65536)
        except urllib.error.HTTPError as exc:
            return exc.code, None
        except (OSError, ValueError):
            return None, None
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, None

    return request


def retire_channel(slot: SlotConfig, request: Request, *, wait_seconds: float = 150.0,
                   poll_seconds: float = 2.0, clock: Callable[[], float] = time.monotonic,
                   sleep: Callable[[float], None] = time.sleep,
                   out: Callable[[str], None] = lambda line: print(line, flush=True)) -> int:
    """One net-check run: pull retires, hand them to the supervisor, confirm the stops.

    Returns the number of stops confirmed. A launch not stopped within
    wait_seconds is left for the next timer run; the broker keeps answering
    "pending" (never "destroyed") until its confirm arrives.
    """
    path = f"/v1/broker/hotels/{slot.name}/escape-retire"

    def log(action: str, **fields) -> None:
        out(json.dumps({"schema": SCHEMA, "slot": slot.name, "action": action, **fields}, sort_keys=True))

    status, doc = request("GET", path, None)
    if (status != 200 or not isinstance(doc, dict) or doc.get("schema") != RETIRE_REQUEST_SCHEMA
            or doc.get("slot") != slot.name or not isinstance(doc.get("retire"), list)):
        log("channel_unreadable", status=status)
        return 0
    wanted = {}
    for item in doc["retire"]:
        report = item.get("report_id") if isinstance(item, dict) else None
        binding = item.get("binding_sha256") if isinstance(item, dict) else None
        if isinstance(report, str) and HEX64.fullmatch(report) and isinstance(binding, str) and HEX64.fullmatch(binding):
            wanted[report] = binding
    slot.retire_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    for stale in slot.retire_dir.glob("*.request"):
        if stale.stem not in wanted:
            stale.unlink(missing_ok=True)  # confirmed, or no longer asked
    for report, binding in wanted.items():
        target = slot.retire_dir / f"{report}.request"
        if not target.exists():
            _write_json(target, {"report_id": report, "binding_sha256": binding})
            log("retire_requested", report_id=report)
    confirmed, deadline = 0, clock() + wait_seconds
    pending = dict(wanted)
    while pending:
        for report, binding in list(pending.items()):
            stopped = _read_json(slot.retire_dir / f"{report}.stopped")
            if stopped is None or stopped.get("binding_sha256") != binding:
                continue
            body = json.dumps({"schema": RETIRE_CONFIRM_SCHEMA, "slot": slot.name, "report_id": report,
                               "binding_sha256": binding, "state": "stopped"}, sort_keys=True).encode()
            code, _ = request("POST", path, body)
            log("retire_confirmed" if code == 200 else "retire_confirm_failed", report_id=report, status=code)
            if code == 200:
                confirmed += 1
                (slot.retire_dir / f"{report}.request").unlink(missing_ok=True)
            del pending[report]  # a failed post is retried on the next timer run
        if not pending or clock() >= deadline:
            break
        sleep(poll_seconds)
    for report in pending:
        log("retire_waiting", report_id=report)
    return confirmed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--sealed-env", required=True, type=Path,
                        help="the slot's sealed.env (absolute path)")
    parser.add_argument("--guest-url", default=None,
                        help="where this host reaches the slot's guest port 18090 (default "
                             f"{DEFAULT_GUEST_URL}; a guest TLS slot uses its HTTPS port)")
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--boot-timeout", type=float, default=15 * 60)
    parser.add_argument("--fresh-max-age", type=float, default=6 * 3600)
    parser.add_argument("--max-attempt-seconds", type=float, default=4 * 3600)
    parser.add_argument("--max-polls", type=int, default=0, help="0 = run until stopped")
    parser.add_argument("--retire-channel", action="store_true",
                        help="one net-check run of the broker retire channel, then exit")
    parser.add_argument("--channel-wait-seconds", type=float, default=150.0)
    return parser


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    slot = load_slot(args.sealed_env)
    if args.retire_channel:
        url = broker_url_of(args.sealed_env)
        retire_channel(slot, broker_requester(url, slot.key_file), wait_seconds=args.channel_wait_seconds)
        return 0
    supervisor = SlotSupervisor(
        sealed_env=args.sealed_env,
        fetch=http_fetcher(args.guest_url or slot.tls_guest_url or DEFAULT_GUEST_URL, slot.key_file),
        systemctl=live_systemctl,
        boot_timeout=args.boot_timeout,
        fresh_max_age=args.fresh_max_age,
        max_attempt=args.max_attempt_seconds,
    )
    supervisor.run(args.poll_seconds, args.max_polls)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Operator lifecycle fault injection (spec-r9 5.4, 7.2, 11; test plan 14.1).

The real operator script runs as a subprocess against:
- a fake API (the 4.3 admin routes) and a fake broker (the operator view,
  restart-check and drain) in one in-process HTTP server, which can drop the
  reply of a request after it applied it;
- a fake SSH that plays the host phases against a JSON host model.

CG_FAULT=op:<step>:<sub> kills the script right after an act and before its
journal entry. A rerun (resume) must reach the same end state with every
effect applied once: one kit stop, one tuple move per fence, one boot per
generation."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
OP = REPO / "ops" / "custom-guest" / "custom_guest.py"
HOTEL, LAUNCH = "chi-ur-2", "cg-0123456789ab"
ADMIN = "/api/admin/cathedral/dedicated/custom-guest"
MEASUREMENT = "ab" * 48
G0, REF0 = 7, "order-ref-0"


def iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


# ---------------------------------------------------------------- fake host (over fake SSH)

FAKE_SSH = r'''#!/usr/bin/env python3
import fcntl, json, os, shlex, sys, time, uuid
path = os.environ["FAKE_HOST"]
lock = open(path + ".lock", "w")
fcntl.flock(lock, fcntl.LOCK_EX)
h = json.load(open(path))
argv = shlex.split(sys.argv[2])
phase, opts = argv[1], dict(zip(argv[2::2], argv[3::2]))
data = json.loads(sys.stdin.read() or "{}")
h["calls"].append(phase + (":" + opts["--part"] if "--part" in opts else ""))
def log(event, **f):
    h["t"] += 1
    h["journal"].append({"event": event, "t": h["t"], "boot_id": h["boot_id"], **f})
def has(event, **m):
    return any(e["event"] == event and all(e.get(k) == v for k, v in m.items()) for e in h["journal"])
kit = h["kit"]
fail = h["fail"].get(phase)
if fail:
    r = {"ok": False, "error_code": fail, "detail": "injected"}
elif phase == "facts":
    r = {"ok": True, "kit_unit": dict(kit), "kit_absent": kit["state"] != "active", "custom_unit": h["custom_unit"],
         "marker": h["marker"], "launch_dir": h["launch_dir"], "journal": h["journal"], "boot_id": h["boot_id"],
         "inbox_dir": h["inbox"], "staging_dir": h["staging"]}
elif phase == "inbox":
    h["inbox"] = True
    r = {"ok": True, "inbox": "/srv/custom-guest/inbox"}
elif phase == "intake":
    if not h["inbox"]:
        r = {"ok": False, "error_code": "custom_guest_request_invalid", "detail": "no inbox"}
    else:
        h["inbox"], h["staging"], h["launch_dir"] = False, False, True
        log("intake_done")
        r = {"ok": True, "report": {"ok": True}, "files": {}}
elif phase == "hold-stop" and opts["--part"] == "a":
    if h["marker"] is None:
        h["marker"] = {"launch_id": os.environ["FAKE_LAUNCH"], "state": "held"}
    if not has("kit_stop"):
        log("kit_attestation_before", attestation="att")
        log("kit_stop", state="intent")
    if kit["state"] == "active":
        kit["state"] = "inactive"
        h["kit_stops"] += 1
    r = {"ok": True, "next": "b", "kit_attestation_before": "att"}
elif phase == "hold-stop":
    if not has("kit_stop") or kit["state"] == "active":
        r = {"ok": False, "error_code": "custom_guest_hold_failed", "detail": "part b before part a"}
    else:
        if not has("kit_stopped"):
            log("kit_stopped")
        r = {"ok": True, "kit_attestation_before": "att"}
elif phase == "unhold":
    if kit["state"] != "active":
        r = {"ok": False, "error_code": "custom_guest_hold_failed", "detail": "the kit stopped"}
    else:
        h["marker"] = None
        log("unheld")
        r = {"ok": True}
elif phase == "hold-baseline":
    if not has("baselined"):
        log("baselined", fingerprint_sha256="f" * 64)
    r = {"ok": True}
elif phase == "boot":
    gen = data["generation"]
    if not has("booted", generation=gen):
        log("boot", state="intent", generation=gen, token=uuid.uuid4().hex)
        log("token_used", generation=gen)
        log("booted", generation=gen)
        h["boots"] += 1
    h["custom_unit"] = {"ActiveState": "active"}
    r = {"ok": True, "generation": gen}
elif phase == "verify-disks":
    r = {"ok": True}
elif phase == "stop":
    if (h["custom_unit"] or {}).get("ActiveState") == "active":
        log("exit", service_result="success", exit_status="0")
    h["custom_unit"] = {"ActiveState": "inactive"}
    r = {"ok": True}
elif phase == "return-kit":
    if kit["state"] != "active":
        kit.update(state="active", invocation_id=uuid.uuid4().hex, active_enter=int(time.time()))
        h["marker"] = {"launch_id": os.environ["FAKE_LAUNCH"], "state": "kit_start", "disk_verified": True}
        log("kit_boot", invocation_id=kit["invocation_id"], measurement=h["kit_measurement"])
        h["kit_returns"] += 1
    r = {"ok": True, "kit_boot": {"invocation_id": kit["invocation_id"], "measurement": h["kit_measurement"],
                                  "active_enter": kit["active_enter"]}, "disk_verified": True}
elif phase == "return-finish":
    if data.get("record_state") != "returned":
        r = {"ok": False, "error_code": "custom_guest_state_conflict", "detail": "the record is not returned"}
    else:
        h["marker"], h["launch_dir"], h["custom_unit"] = None, False, None
        if not has("return_finished"):
            log("return_finished")
        r = {"ok": True}
elif phase == "discard":
    h["launch_dir"] = h["inbox"] = h["staging"] = False
    r = {"ok": True}
else:
    r = {"ok": False, "error_code": "custom_guest_request_invalid", "detail": "phase " + phase}
lose = h["lose"].get(phase, 0)
if lose:
    h["lose"][phase] = lose - 1
json.dump(h, open(path, "w"))
if lose:
    sys.exit(255)  # the ssh connection dropped: no RESULT line
print("RESULT " + json.dumps(r))
'''


# ---------------------------------------------------------------- fake API and broker

# PR 3 contract (bigailabs/polariscomputer#2336 at 4a235e6, polaris/services/cathedral_custom_guest.py):
# apply_patch, _check_host_fields, _start_hold, _finish_hold, _fence_ready, _finalize, live_rows.
FIELD_KEYS = {"hold_phase", "manifest", "bootstrap", "host_data_hex", "expected_measurement", "host", "stop_reason",
              "error_code", "error_detail"}
INPUT_KEYS = {"ovmf_url", "ovmf_sha256", "reference_initrd_version", "reference_initrd_url", "reference_initrd_sha256",
              "qemu_version", "sev_snp_measure_version", "policy", "chip_id", "product", "cpuid", "ark_sha256",
              "tcb_floor", "public_host", "ports"}
EVIDENCE_KEYS = {"barrier_evidence", "kit_attestation_before", "earlier_holders", "sev_baseline", "disk_fingerprint",
                 "disk_verified", "kit_boot"}
DOC_STATES = {"requested", "staged", "measured"}
EVIDENCE_STATES = {"holding", "held", "booting", "running", "stopping", "stopped", "returning"}
TRANSITIONS = {"requested": {"staged", "cancelled"}, "staged": {"measured", "cancelled"}, "measured": {"cancelled"},
               "approved": {"holding", "cancelled"}, "holding": {"approved", "held"}, "held": {"booting", "returning"},
               "booting": {"running", "stopped"}, "running": {"stopping", "stopped"}, "stopping": {"stopped"},
               "stopped": {"booting", "returning"}, "returning": {"returned"}}
STOP_REASONS = {"booting": {"boot_failed"},
                "running": {"guest_shutdown", "qemu_exit", "host_reboot", "isolation_failed", "sev_platform_changed"}}
PHASES = ["intent", "drained", "fenced", "inventoried", "kit_stopping", "kit_stopped", "kit_down_set", "baselined"]
ABORTABLE = {"intent", "drained", "fenced", "inventoried", "kit_stopping"}


def conflict(msg):
    return 409, {"error": "custom_guest_state_conflict", "message": msg}


def shape(msg):
    return 422, {"error": "custom_guest_request_invalid", "message": msg}


class World:
    def __init__(self):
        self.lock = threading.Lock()
        self.host_path: Path | None = None
        self.record = {"launch_id": LAUNCH, "hotel": HOTEL, "owner_scope": "user:x", "state": "approved",
                       "generation": 0, "journal_seq": 0, "hold_ack": True, "hold_phase": None, "host": {},
                       "owner_requests": [{"action": "return", "waive_notice": True}], "stop_reason": None,
                       "error_code": None, "request": {},
                       "bootstrap_signature_b64": "c2ln", "manifest_sha256": "m" * 64, "bootstrap_sha256": "b" * 64}
        self.broker = {"id": HOTEL, "drain": False, "reserved_for": "cathedral-customer-sealed", "pin_only": True,
                       "runtime": False, "reservation_generation": G0, "reservation_ref": REF0,
                       "custom_guest_hold": None, "miner_hotkey": None, "labels": {}, "rooms_in_use": 0}
        self.restart = {"restart_ok": True, "rooms": 0, "creating": 0, "queued": 0, "pool_claims": 0, "unreaped": 0,
                        "hotel_rooms": 0, "count_known": True, "claims": 0}
        self.room_count, self.stored_work, self.omit = 0, None, set()
        self.rooms_active = 0      # fence fenced answers 409 rooms_active this many times
        self.secret_calls = 0      # fence kit_down answers 409 secret_calls_in_flight this many times
        self.fence_refuse: dict[str, str] = {}  # target -> broker code passed through
        self.admission: dict | None = None      # overrides the admission derived from the host kit
        self.lose: dict[str, int] = {}  # "<METHOD> <last path part>" -> replies to drop after applying
        self.calls: list[str] = []
        self.refused: list[str] = []
        self.tuple_moves = 0

    def host(self) -> dict:
        return json.loads(self.host_path.read_text())

    def view(self) -> dict:
        kit = self.host()["kit"]
        up = kit["state"] == "active"
        adm = {"state": "admitted" if up else "pending", "measurement": self.host()["broker_measurement"],
               "attested_at": iso(kit["active_enter"] + 1) if up else None, "chip_id": "chip-1",
               "hotel_key_install": {"signer": "k1"}}
        return {**self.broker, "up": up, "admission": self.admission or adm}

    def live(self) -> dict:
        return {"generation": self.broker["reservation_generation"], "ref": self.broker["reservation_ref"]}

    def set_tuple(self, t: dict) -> None:
        if self.live() != t:
            self.tuple_moves += 1
        self.broker["reservation_generation"], self.broker["reservation_ref"] = t["generation"], t["ref"]

    def live_rows(self) -> dict:
        return {"hotel": HOTEL, "rooms": {"room": [], "pool_room": [], "dedicated_room": []},
                "counts": {"room": self.room_count, "pool_room": 0, "dedicated_room": 0},
                **{k: v for k, v in (("room_count", self.room_count), ("stored_work", self.stored_work))
                   if k not in self.omit}}

    def patch(self, body: dict) -> tuple[int, dict]:
        rec = self.record
        host = json.loads(json.dumps(rec["host"]))
        if not isinstance(body, dict) or set(body) - {"from", "to", "generation", "journal_seq", "fields"} or \
                not {"from", "to", "generation", "journal_seq"} <= set(body) or body["journal_seq"] < 1:
            return shape("body keys")
        fields = body.get("fields") or {}
        if set(fields) - FIELD_KEYS:
            return shape(f"fields may hold only {sorted(FIELD_KEYS)}: got {sorted(set(fields) - FIELD_KEYS)}")
        seq, frm, to = body["journal_seq"], body["from"], body["to"]
        digest = json.dumps(body, sort_keys=True)
        if seq == rec["journal_seq"]:
            return (200, {"changed": False}) if host.get("last_patch") == digest else conflict("seq reused")
        if seq < rec["journal_seq"]:
            return conflict("seq behind")
        if frm != rec["state"]:
            return conflict(f"the record is {rec['state']}, not {frm}")
        if to != frm and to not in TRANSITIONS.get(frm, set()):
            return conflict(f"{frm} cannot move to {to}")
        want_gen = rec["generation"] + 1 if to == "booting" and frm != "booting" else rec["generation"]
        if body["generation"] != want_gen:
            return conflict(f"generation must be {want_gen}")
        if any(k in fields for k in ("manifest", "bootstrap", "host_data_hex", "expected_measurement")) and \
                frm not in DOC_STATES:
            return conflict("documents are fixed")
        if "host" in fields:
            at = frm if to == frm else to
            for k, v in fields["host"].items():
                if k in INPUT_KEYS:
                    if at not in DOC_STATES:
                        return conflict(f"host.{k} is a launch input")
                elif k in EVIDENCE_KEYS:
                    if at not in EVIDENCE_STATES:
                        return conflict(f"host.{k} is hold evidence")
                else:
                    return shape(f"host.{k} is not an operator field")
                if v is None:
                    return shape(f"host.{k} cannot be removed")
            host.update(fields["host"])
        reason = fields.get("stop_reason", rec["stop_reason"] if to == frm else None)
        if to == "stopped" and frm in STOP_REASONS and reason not in STOP_REASONS[frm]:
            return shape(f"{frm} to stopped needs a stop_reason")
        phase = rec["hold_phase"]
        if frm == "approved" and to == "holding":
            if fields.get("hold_phase", "intent") != "intent":
                return conflict("a hold starts at intent")
            phase = "intent"
        elif "hold_phase" in fields:
            if not (frm == "holding" and to == "holding"):
                return conflict("hold_phase changes only while holding")
            if fields["hold_phase"] not in PHASES or PHASES.index(fields["hold_phase"]) < PHASES.index(phase):
                return conflict("hold_phase moves forward only")
            phase = fields["hold_phase"]
        res, bh = host.get("reservation") or {}, host.get("broker_hold") or {}
        if to == "holding" and phase and PHASES.index(phase) >= PHASES.index("fenced") and res.get("expect") != "fenced":
            return conflict("fenced and later need the fence first")
        if to == "holding" and phase and PHASES.index(phase) >= PHASES.index("kit_down_set") and not bh.get("kit_down_at"):
            return conflict("kit_down_set needs fence kit_down first")
        if frm == "holding" and to == "held" and phase != "baselined":
            return conflict("held only at baselined")
        if frm == "holding" and to == "approved" and (phase not in ABORTABLE or bh.get("kit_down_at")):
            return conflict("no abort once the kit stopped")
        if frm == "approved" and to == "holding":
            if not rec["hold_ack"]:
                return 422, {"error": "custom_guest_hold_ack_required"}
            if self.broker["custom_guest_hold"] is not None:
                return 409, {"error": "custom_guest_hold_conflict"}
            prev = host.get("reservation") or {}
            host["reservation"] = {"attempt": int(prev.get("attempt") or 0) + 1, "original": self.live(),
                                   "fenced": None, "restored": None, "expect": "original", "intent": None}
            host["reservation_guest"] = self.broker["reserved_for"]
            host["drain_before"] = self.broker["drain"] is True
            host["broker_hold"] = {}
        elif (frm, to) in (("holding", "approved"), ("returning", "returned")):
            accepted = [res["restored"]] if res.get("restored") and res.get("expect") == "restored" else []
            if to == "approved" and res.get("expect") == "original":
                accepted.append(res["original"])
            if self.live() not in accepted:
                return 409, {"error": "custom_guest_reservation_moved"}
            if self.broker["custom_guest_hold"] is not None:
                return 409, {"error": "custom_guest_hold_conflict"}
            if self.broker["drain"] != bool(host.get("drain_before")):
                return conflict("restore the drain to drain_before first")
            host["reservation"] = {**res, "expect": None, "closed": to}
        if phase == "inventoried" and rec["hold_phase"] != "inventoried" and to == "holding":
            if self.room_count:
                return 409, {"error": "custom_guest_rooms_present"}
            if self.stored_work is not None:
                return 409, {"error": "custom_guest_stored_work_present"}
        rec["state"], rec["generation"], rec["journal_seq"] = to, want_gen, seq
        rec["hold_phase"] = phase if to == "holding" else (None if to == "approved" else rec["hold_phase"])
        if to == "booting":
            rec["stop_reason"] = None
        elif "stop_reason" in fields or to == "stopped":
            rec["stop_reason"] = reason
        for k in ("error_code", "error_detail"):
            if k in fields:
                rec[k] = fields[k]
        host["last_patch"] = digest
        rec["host"] = host
        return 200, {"changed": True, "launch": rec}

    def fence(self, to: str) -> tuple[int, dict]:
        rec, b = self.record, self.broker
        host = rec["host"]
        res, bh = host.get("reservation") or {}, host.setdefault("broker_hold", {})
        state, phase = rec["state"], rec["hold_phase"]
        if not res or res.get("expect") is None:
            return conflict("no hold in progress")
        fenced = res.get("fenced") or {"generation": res["original"]["generation"] + 1,
                                       "ref": f"cg:{LAUNCH}:{res['attempt']}"}
        hold = b["custom_guest_hold"]
        if to == "fenced":
            if state != "holding" or phase not in ("drained", "fenced", "inventoried", "kit_stopping") \
                    or bh.get("kit_down_at"):
                return conflict("fenced is sent from drained")
            at = self.live() == fenced and hold == {"launch": LAUNCH, "kit_down": False}
        elif to == "kit_down":
            if not ((state == "holding" and phase in ("kit_stopped", "kit_down_set", "baselined"))
                    or state in ("held", "booting", "running", "stopping", "stopped")
                    or (state == "returning" and "disk_verified" not in host)) or res["expect"] != "fenced":
                return conflict("kit_down from kit_stopped to R7")
            at = self.live() == res["fenced"] and hold == {"launch": LAUNCH, "kit_down": True}
        else:
            abort = state == "holding" and phase in ABORTABLE and not bh.get("kit_down_at")
            if not (abort or state == "returning") or res["expect"] not in ("fenced", "restored"):
                return conflict("restored by the abort or R12")
            restored = res.get("restored") or {"generation": res["fenced"]["generation"] + 1,
                                               "ref": res["original"]["ref"]}
            at = self.live() == restored and hold is None
        if not at:
            if to == "fenced" and self.rooms_active:
                self.rooms_active -= 1
                return 409, {"error": "rooms_active"}
            if to == "kit_down" and self.secret_calls:
                self.secret_calls -= 1
                return 409, {"error": "secret_calls_in_flight"}
            if to in self.fence_refuse:
                return 409, {"error": self.fence_refuse[to]}
            if to == "fenced":
                if self.live() != res["original"]:
                    return 409, {"error": "custom_guest_reservation_moved"}
                self.set_tuple(fenced)
                b["custom_guest_hold"] = {"launch": LAUNCH, "kit_down": False}
            elif to == "kit_down":
                b["custom_guest_hold"] = {"launch": LAUNCH, "kit_down": True}
            else:
                self.set_tuple(restored)
                b["custom_guest_hold"], b["drain"] = None, True
        if to == "fenced":
            res.update(fenced=fenced, expect="fenced")
            if state == "holding" and phase == "drained":
                rec["hold_phase"] = "fenced"
        elif to == "kit_down":
            bh.setdefault("kit_down_at", iso(time.time()))
            if state == "holding" and phase == "kit_stopped":
                rec["hold_phase"] = "kit_down_set"
        else:
            res.update(restored=restored, expect="restored")
        host["reservation"] = res
        return 200, {"launch_id": LAUNCH, "to": to, "sent": not at, "tuple": self.live()}

    def handle(self, method: str, path: str, body: dict | None) -> tuple[int, dict]:
        if method == "GET" and path == f"{ADMIN}?hotel={HOTEL}":
            return 200, {"launches": [self.record]}
        if method == "PATCH" and path == f"{ADMIN}/{LAUNCH}":
            return self.patch(body)
        if method == "POST" and path == f"{ADMIN}/{LAUNCH}/fence":
            if not isinstance(body, dict) or set(body) != {"to"}:
                return shape("fence body")
            return self.fence(body["to"])
        if method == "GET" and path == f"{ADMIN}/{LAUNCH}/live-rows":
            return 200, self.live_rows()
        if method == "GET" and path == f"/v1/broker/hotels/{HOTEL}":
            return 200, self.view()
        if method == "GET" and path == f"/v1/broker/hotels/{HOTEL}/restart-check":
            return 200, {**self.restart, "drain": self.broker["drain"]}
        if method == "PATCH" and path == f"/v1/broker/hotels/{HOTEL}":
            self.broker["drain"] = bool(body["drain"])
            return 200, self.view()
        return 404, {"error": "not_found"}


def serve(world: World) -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def go(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n)) if n else None
            assert self.headers["Authorization"].startswith("Bearer ")
            with world.lock:
                key = f"{self.command} {self.path.split('?')[0].rsplit('/', 1)[-1]}"
                world.calls.append(f"{self.command} {self.path} {json.dumps(body, sort_keys=True) if body else ''}")
                status, doc = world.handle(self.command, self.path, body)
                if status >= 400:
                    world.refused.append(f"{status} {doc.get('error')} {self.command} {self.path}")
                drop = world.lose.get(key, 0)
                if drop and status == 200:
                    world.lose[key] = drop - 1
                    self.close_connection = True
                    return
            raw = json.dumps(doc).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        do_GET = do_PATCH = do_POST = go

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class Rig:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.world = World()
        self.srv = serve(self.world)
        self.home = tmp / "home"
        self.home.mkdir()
        (self.home / "hosts.conf").write_text(f"{HOTEL} fakehost {REPO} 203.0.113.10\n")
        for k in ("admin-key", "operator-key"):
            (self.home / k).write_text("test-key\n")
        (tmp / "fake_ssh.py").write_text(FAKE_SSH)
        (tmp / "fake_scp.py").write_text("import sys\nopen(sys.argv[0] + '.log', 'a').write(sys.argv[-1] + '\\n')\n")
        self.host_path = tmp / "host.json"
        self.world.host_path = self.host_path
        now = int(time.time())
        self.host_path.write_text(json.dumps({
            "kit": {"state": "active", "invocation_id": "inv-0", "active_enter": now - 100, "enabled": True},
            "marker": None, "launch_dir": True, "inbox": False, "staging": False, "custom_unit": None, "journal": [],
            "boot_id": "boot-1", "t": 0,
            "calls": [], "fail": {}, "lose": {}, "kit_stops": 0, "kit_returns": 0, "boots": 0,
            "kit_measurement": MEASUREMENT, "broker_measurement": MEASUREMENT}))
        self.since = iso(now - 1000)
        self.run("record-versions", "--where", "operator", "--commit", "abcdef1", launch=False)

    def close(self):
        self.srv.shutdown()

    def env(self, **extra: str) -> dict:
        url = f"http://127.0.0.1:{self.srv.server_address[1]}"
        env = {k: v for k, v in os.environ.items() if "proxy" not in k.lower()}
        env.update(CG_HOME=str(self.home), CG_API_URL=url, CG_BROKER_URL=url, CG_SSH=f"{sys.executable} {self.tmp}/fake_ssh.py",
                   CG_SCP=f"{sys.executable} {self.tmp}/fake_scp.py",
                   CG_POLL="0.02", CG_FENCE_WAIT="2", CG_H7_WAIT="2", CG_ADMIT_WAIT="1", FAKE_HOST=str(self.host_path),
                   FAKE_LAUNCH=LAUNCH, NO_PROXY="*")
        env.update(extra)
        return env

    def run(self, step: str, *args: str, launch: bool = True, **env: str) -> tuple[int, dict]:
        argv = [sys.executable, str(OP), step, "--hotel", HOTEL, *(["--launch-id", LAUNCH] if launch else []), *args]
        p = subprocess.run(argv, capture_output=True, text=True, env=self.env(**env), timeout=120)
        out = [ln for ln in p.stdout.splitlines() if ln.startswith("{")]
        return p.returncode, (json.loads(out[-1]) if out else {"stdout": p.stdout, "stderr": p.stderr[-2000:]})

    def hold(self, *extra: str, **env: str) -> tuple[int, dict]:
        return self.run("hold", "--path", "platform", "--dedicated-since", self.since, *extra, **env)

    def host(self) -> dict:
        return self.world.host()

    def set_host(self, **changes) -> None:
        h = self.host()
        h.update(changes)
        self.host_path.write_text(json.dumps(h))

    def journal(self) -> list[dict]:
        path = self.home / HOTEL / "journal.jsonl"
        return [json.loads(x) for x in path.read_text().splitlines()]

    def fences(self, to: str) -> int:
        return sum(1 for c in self.world.calls if c.startswith("POST") and f'"to": "{to}"' in c)


@pytest.fixture
def rig(tmp_path):
    r = Rig(tmp_path)
    yield r
    r.close()


def assert_held(rig: Rig) -> None:
    rec, b, h = rig.world.record, rig.world.broker, rig.host()
    assert rec["state"] == "held" and rec["hold_phase"] == "baselined", rec
    assert (b["reservation_generation"], b["reservation_ref"]) == (G0 + 1, f"cg:{LAUNCH}:1")
    assert b["custom_guest_hold"] == {"launch": LAUNCH, "kit_down": True}
    assert b["drain"] is True
    assert h["kit"]["state"] == "inactive" and h["kit_stops"] == 1
    assert h["marker"] == {"launch_id": LAUNCH, "state": "held"}
    assert rig.world.tuple_moves == 1
    host = rec["host"]
    assert host["reservation"]["original"] == {"generation": G0, "ref": REF0}
    assert host["reservation"]["fenced"] == {"generation": G0 + 1, "ref": f"cg:{LAUNCH}:1"}
    assert host["drain_before"] is False and host["barrier_evidence"]["stored_work"] is None
    assert host["broker_hold"]["kit_down_at"] and host["kit_attestation_before"] == "att"
    assert not [c for c in rig.world.refused if c.startswith("422")], rig.world.refused


def assert_approved_after_abort(rig: Rig, code: str, fenced: bool) -> None:
    rec, b, h = rig.world.record, rig.world.broker, rig.host()
    assert rec["state"] == "approved" and rec["error_code"] == code, rec
    assert b["custom_guest_hold"] is None and b["drain"] is False
    want = (G0 + 2, REF0) if fenced else (G0, REF0)
    assert (b["reservation_generation"], b["reservation_ref"]) == want
    assert h["kit"]["state"] == "active" and h["kit_stops"] == 0 and h["marker"] is None


# ---------------------------------------------------------------- hold (11.2)

def test_hold_reaches_held_in_order(rig):
    rc, out = rig.hold()
    assert rc == 0, out
    assert_held(rig)
    done = [e["sub"] for e in rig.journal() if e.get("step") == "hold#1" and e["phase"] == "done"]
    order = ["eligible", "H1", "H2", "phase_drained", "H3", "phase_fenced", "H4", "phase_inventoried", "H5",
             "H6a_reads", "H6a", "H6b", "H7", "phase_kit_down_set", "H8", "phase_baselined", "H9", "end"]
    assert done == order
    assert rig.host()["calls"].count("hold-stop:a") == 1 and rig.host()["calls"].count("hold-stop:b") == 1
    # H6b reads no room list, restart-check or live rows: a stopped kit cannot answer.
    after_h6a = rig.world.calls[[i for i, c in enumerate(rig.world.calls) if '"hold_phase": "kit_stopping"' in c][0]:]
    assert not [c for c in after_h6a if "restart-check" in c or "live-rows" in c]


# phase_fenced and phase_kit_down_set have no act: the API moves the phase at the fence (PR 3 _finalize).
HOLD_ACTS = ["H1", "H2", "phase_drained", "H3", "phase_inventoried", "H6a", "H6b", "H7", "H8", "phase_baselined",
             "H9"]


@pytest.mark.parametrize("sub", HOLD_ACTS)
def test_killed_after_each_hold_act_resumes_once(rig, sub):
    rc, _ = rig.hold(CG_FAULT=f"op:hold#1:{sub}")
    assert rc == 137
    rc, out = rig.run("resume")
    assert rc == 0, out
    assert_held(rig)
    assert rig.fences("fenced") == 1 and rig.fences("kit_down") == 1
    assert rig.run("resume") == (0, {"ok": True, "open": None})


@pytest.mark.parametrize("lost", ["PATCH custom-guest-L", "POST fence", "PATCH hotel", "host hold-stop",
                                  "host hold-baseline"])
def test_lost_replies_resolve_by_observing(rig, lost):
    if lost.startswith("host "):
        rig.set_host(lose={lost.split()[1]: 1})
    else:
        method, route = lost.split()
        rig.world.lose[f"{method} {LAUNCH if route == 'custom-guest-L' else HOTEL if route == 'hotel' else route}"] = 1
    rc, out = rig.hold()
    assert rc == 0, out
    assert_held(rig)


def test_h3_waits_out_rooms_active(rig):
    rig.world.rooms_active = 3
    rc, out = rig.hold()
    assert rc == 0, out
    assert_held(rig)
    assert rig.fences("fenced") == 4


def test_h7_retries_secret_calls_in_flight(rig):
    rig.world.secret_calls = 4
    rc, out = rig.hold()
    assert rc == 0, out
    assert_held(rig)
    assert rig.fences("kit_down") == 5


def test_h7_gives_up_forward_only(rig):
    rig.world.secret_calls = 10 ** 6
    rc, out = rig.hold(CG_H7_WAIT="0.3")
    assert rc == 1 and out["error_code"] == "secret_calls_in_flight", out
    rec = rig.world.record
    assert rec["state"] == "holding" and rec["hold_phase"] == "kit_stopped"
    assert rig.world.broker["custom_guest_hold"] == {"launch": LAUNCH, "kit_down": False}
    assert rig.host()["kit"]["state"] == "inactive", "no abort once the kit stopped"
    rig.world.secret_calls = 0
    rc, out = rig.run("resume")
    assert rc == 0, out
    assert_held(rig)


@pytest.mark.parametrize("setup,code", [
    (lambda w: w.restart.update(rooms=1), "custom_guest_rooms_present"),
    (lambda w: w.restart.update(count_known=False), "custom_guest_rooms_present"),
    (lambda w: w.restart.pop("claims"), "custom_guest_hold_unsupported"),
    (lambda w: w.broker.update(rooms_in_use=2), "custom_guest_rooms_present"),
    (lambda w: setattr(w, "room_count", 1), "custom_guest_rooms_present"),
    (lambda w: w.omit.add("room_count"), "custom_guest_barrier_failed"),
    (lambda w: setattr(w, "stored_work", {"volumes": 1}), "custom_guest_stored_work_present"),
    (lambda w: w.omit.add("stored_work"), "custom_guest_stored_work_present"),
])
def test_h4_aborts_while_the_kit_never_stopped(rig, setup, code):
    setup(rig.world)
    rc, out = rig.hold()
    assert rc == 1 and out["error_code"] == code, out
    assert_approved_after_abort(rig, code, fenced=True)
    assert rig.run("resume") == (0, {"ok": True, "open": None}), "the aborted attempt is closed"


def test_h3_rooms_active_timeout_aborts_without_a_tuple_move(rig):
    rig.world.rooms_active = 10 ** 6
    rc, out = rig.hold(CG_FENCE_WAIT="0.3")
    assert rc == 1 and out["error_code"] == "custom_guest_barrier_failed", out
    assert_approved_after_abort(rig, "custom_guest_barrier_failed", fenced=False)
    assert rig.world.tuple_moves == 0


def test_h5_earlier_holder_aborts_unless_toby_ok(rig):
    rig.since = iso(time.time() + 10)
    rc, out = rig.hold()
    assert rc == 1 and out["error_code"] == "custom_guest_earlier_holder_unconfirmed", out
    assert_approved_after_abort(rig, "custom_guest_earlier_holder_unconfirmed", fenced=True)
    rc, out = rig.hold("--h5-ok", "core-msg-42", "--h5-holder", "previous order")
    assert rc == 0, out
    rec, b = rig.world.record, rig.world.broker
    assert rec["state"] == "held"
    assert (b["reservation_generation"], b["reservation_ref"]) == (G0 + 3, f"cg:{LAUNCH}:2"), "attempt 2 fences G+3"
    ok = [e for e in rig.journal() if e.get("step") == "h5" and e["sub"] == "toby_ok" and e["phase"] == "done"]
    assert ok[0]["detail"] == {"ref": "core-msg-42", "holder": "previous order"}


@pytest.mark.parametrize("sub", ["restore", "drain", "approved"])  # unhold has no act: H4 wrote no marker
def test_killed_during_abort_resumes_the_abort(rig, sub):
    rig.world.restart["rooms"] = 1
    rc, _ = rig.hold(CG_FAULT=f"op:abort#1:{sub}")
    assert rc == 137
    rc, out = rig.run("resume")
    assert rc == 0, out
    assert_approved_after_abort(rig, "custom_guest_rooms_present", fenced=True)
    assert rig.world.tuple_moves == 2
    assert rig.run("resume") == (0, {"ok": True, "open": None})


def test_no_abort_once_the_kit_stopped(rig):
    rc, _ = rig.hold(CG_FAULT="op:hold#1:H6a")
    assert rc == 137
    rig.world.broker["custom_guest_hold"] = None  # the hold was lost while the kit was down
    rc, out = rig.run("resume")
    assert rc == 1 and out["error_code"] == "custom_guest_hold_lost", out
    assert rig.world.record["state"] == "holding"
    rc, out = rig.run("abort")
    assert rc == 1 and out["error_code"] == "custom_guest_hold_failed", out
    assert rig.host()["kit"]["state"] == "inactive" and rig.world.tuple_moves == 1


def test_hold_refused_without_versions_or_ack(rig, tmp_path):
    (rig.home / HOTEL / "journal.jsonl").unlink()
    rc, out = rig.hold()
    assert rc == 1 and out["error_code"] == "custom_guest_hold_unsupported"
    rig.run("record-versions", "--where", "operator", "--commit", "abcdef1", launch=False)
    rig.world.record["hold_ack"] = False
    rc, out = rig.hold()
    assert rc == 1 and out["error_code"] == "custom_guest_hold_ack_required"
    assert rig.world.calls == [c for c in rig.world.calls if c.startswith("GET")], "nothing written"


@pytest.mark.parametrize("change,code", [
    ({"miner_hotkey": "5Fminer"}, "custom_guest_miner_hotel"),
    ({"pin_only": False}, "custom_guest_hotel_not_dedicated"),
    ({"reserved_for": "someone-else"}, "custom_guest_hotel_not_dedicated"),
    ({"runtime": True}, "custom_guest_hold_unsupported"),
])
def test_hold_refused_on_an_ineligible_broker_view(rig, change, code):
    rig.world.broker.update(change)
    rc, out = rig.hold()
    assert rc == 1 and out["error_code"] == code, out
    assert rig.world.record["state"] == "approved" and rig.host()["kit_stops"] == 0


# ---------------------------------------------------------------- boot and stop (11.3, 11.5)

def held(rig: Rig) -> None:
    rc, out = rig.hold()
    assert rc == 0, out


@pytest.mark.parametrize("sub", [None, "booting", "host_boot", "disks", "running"])
def test_boot_resumes_with_one_start_per_generation(rig, sub):
    held(rig)
    rc, out = rig.run("boot", **({"CG_FAULT": f"op:boot#1:{sub}"} if sub else {}))
    if sub:
        assert rc == 137
        rc, out = rig.run("resume")
    assert rc == 0, out
    rec = rig.world.record
    assert rec["state"] == "running" and rec["generation"] == 1
    assert rig.host()["boots"] == 1


def test_boot_failure_records_stopped_boot_failed(rig):
    held(rig)
    rig.set_host(fail={"boot": "custom_guest_isolation_failed"})
    rc, out = rig.run("boot")
    assert rc == 1 and out["error_code"] == "custom_guest_isolation_failed", out
    rec = rig.world.record
    assert rec["state"] == "stopped" and rec["stop_reason"] == "boot_failed"
    rig.set_host(fail={})
    rc, out = rig.run("boot")
    assert rc == 0 and rig.world.record["generation"] == 2, "a new boot is a new generation"


@pytest.mark.parametrize("sub", [None, "stopping", "host_stop", "stopped"])
def test_stop_resumes(rig, sub):
    held(rig)
    assert rig.run("boot")[0] == 0
    rc, out = rig.run("stop", **({"CG_FAULT": f"op:stop#1:{sub}"} if sub else {}))
    if sub:
        assert rc == 137
        rc, out = rig.run("resume")
    assert rc == 0, out
    assert rig.world.record["state"] == "stopped"
    assert rig.host()["custom_unit"] == {"ActiveState": "inactive"}


# ---------------------------------------------------------------- return (11.6)

def assert_returned(rig: Rig) -> None:
    rec, b, h = rig.world.record, rig.world.broker, rig.host()
    assert rec["state"] == "returned", rec
    assert (b["reservation_generation"], b["reservation_ref"]) == (G0 + 2, REF0)
    assert b["custom_guest_hold"] is None and b["drain"] is False
    assert h["kit"]["state"] == "active" and h["kit_returns"] == 1
    assert h["marker"] is None and h["launch_dir"] is False and h["custom_unit"] is None
    assert rig.world.tuple_moves == 2


@pytest.mark.parametrize("sub", [None, "R0", "R1_R10", "R12", "R13", "R14", "R15"])
def test_return_resumes_from_every_step(rig, sub):
    held(rig)
    rc, out = rig.run("return", **({"CG_FAULT": f"op:return:{sub}"} if sub else {}))
    if sub:
        assert rc == 137
        rc, out = rig.run("resume")
    assert rc == 0, out
    assert_returned(rig)


def test_return_after_a_stopped_guest(rig):
    held(rig)
    assert rig.run("boot")[0] == 0 and rig.run("stop")[0] == 0
    rc, out = rig.run("return")
    assert rc == 0, out
    assert_returned(rig)


def test_r11_needs_the_admission_of_the_returned_kit(rig):
    held(rig)
    rig.set_host(broker_measurement="cd" * 48)
    rc, out = rig.run("return")
    assert rc == 1 and out["error_code"] == "custom_guest_return_not_admitted", out
    rec, b = rig.world.record, rig.world.broker
    assert rec["state"] == "returning" and rec["error_code"] == "custom_guest_return_not_admitted"
    assert (b["reservation_generation"], b["reservation_ref"]) == (G0 + 1, f"cg:{LAUNCH}:1"), "no restore"
    rig.set_host(broker_measurement=MEASUREMENT)
    rc, out = rig.run("resume")
    assert rc == 0, out
    assert_returned(rig)


def test_r15_runs_after_the_commit_whatever_the_api_says(rig):
    held(rig)
    rc, _ = rig.run("return", CG_FAULT="op:return:R14")
    assert rc == 137 and rig.world.record["state"] == "returned"
    rc, out = rig.run("reconcile")
    assert rc == 2 and any(a.startswith("R15 open") for a in out["alerts"]), out
    rc, out = rig.run("resume")
    assert rc == 0, out
    assert_returned(rig)
    assert rig.run("reconcile")[0] == 0


def test_return_needs_a_waiver_or_the_notice(rig):
    held(rig)
    rig.world.record["owner_requests"] = []
    rc, out = rig.run("return")
    assert rc == 1 and out["error_code"] == "custom_guest_state_conflict"
    rc, out = rig.run("return", "--notice-sent-at", iso(time.time() - 3600))
    assert rc == 1, "a notice one hour old is not 72 h"
    rc, out = rig.run("return", "--notice-sent-at", iso(time.time() - 73 * 3600))
    assert rc == 0, out
    assert_returned(rig)


# ---------------------------------------------------------------- reconcile (5.4)

def test_reconcile_refuses_when_the_api_is_ahead_of_the_journal(rig):
    held(rig)
    rig.world.record["journal_seq"] = 10 ** 6
    rc, out = rig.run("reconcile")
    assert rc == 3 and out["error_code"] == "custom_guest_journal_behind"


@pytest.mark.parametrize("hold", [None, {"launch": LAUNCH, "kit_down": False}, {"launch": "cg-aaaaaaaaaaaa", "kit_down": True}])
def test_reconcile_alerts_on_hold_loss(rig, hold):
    held(rig)
    rig.world.broker["custom_guest_hold"] = hold
    rc, out = rig.run("reconcile")
    assert rc == 2 and out["alerts"][0].startswith("custom_guest_hold_lost"), out
    assert "fence kit_down again" in out["alerts"][0]
    assert rig.world.record["state"] == "held", "reconcile writes no state for a lost hold"


def test_reconcile_projects_a_guest_exit_to_stopped(rig):
    held(rig)
    assert rig.run("boot")[0] == 0
    h = rig.host()
    h["t"] += 1
    h["journal"].append({"event": "exit", "t": h["t"], "boot_id": "boot-1", "service_result": "exit-code",
                         "exit_status": "1"})
    h["custom_unit"] = {"ActiveState": "failed"}
    rig.host_path.write_text(json.dumps(h))
    rc, out = rig.run("reconcile")
    assert rc == 0, out
    rec = rig.world.record
    assert rec["state"] == "stopped" and rec["stop_reason"] == "qemu_exit"
    assert rig.host()["boots"] == 1, "reconcile starts nothing"


@pytest.mark.parametrize("event,reason", [("sev_platform_changed", "sev_platform_changed"),
                                          ("kit_data_changed", "isolation_failed")])
def test_reconcile_projects_a_host_stop_reason(rig, event, reason):
    held(rig)
    assert rig.run("boot")[0] == 0
    h = rig.host()
    for ev in (event, "exit"):
        h["t"] += 1
        h["journal"].append({"event": ev, "t": h["t"], "boot_id": "boot-1", "service_result": "success",
                             "exit_status": "0"})
    rig.host_path.write_text(json.dumps(h))
    rc, out = rig.run("reconcile")
    assert rig.world.record["state"] == "stopped" and rig.world.record["stop_reason"] == reason
    assert any(event in a for a in out["alerts"])


def test_cancel_before_any_hold(rig):
    rc, out = rig.run("cancel")
    assert rc == 0, out
    assert rig.world.record["state"] == "cancelled" and rig.host()["launch_dir"] is False


def test_no_key_value_in_any_output_or_argv(rig):
    rc, out = rig.hold()
    assert rc == 0
    text = json.dumps(rig.journal()) + json.dumps(rig.host()["calls"])
    assert "test-key" not in text


# ---------------------------------------------------------------- Astra review of #780 (findings 2, 3, 6, 9, 10)

def test_return_rechecks_the_kit_boot_after_a_host_reboot(rig):
    """Finding 2: R1 to R11 done, then a host reboot before R12: resume observes the new kit boot again."""
    held(rig)
    rig.world.fence_refuse["restored"] = "reservation_conflict"
    rc, out = rig.run("return")
    assert rc == 1 and out["error_code"] == "reservation_conflict", out
    assert rig.world.record["host"]["kit_boot"]["invocation_id"] == rig.host()["kit"]["invocation_id"]
    h = rig.host()
    h["kit"].update(invocation_id="inv-after-reboot", active_enter=int(time.time()) + 5)
    h["boot_id"] = "boot-2"
    rig.host_path.write_text(json.dumps(h))
    rig.world.fence_refuse = {}
    rig.world.admission = {"state": "pending", "measurement": MEASUREMENT, "attested_at": None,
                           "hotel_key_install": {"signer": "k1"}}
    rc, out = rig.run("resume")
    assert rc == 1 and out["error_code"] == "custom_guest_return_not_admitted", out
    rec, b = rig.world.record, rig.world.broker
    assert rec["host"]["kit_boot"]["invocation_id"] == "inv-after-reboot", "R1 to R10 recorded the new boot"
    assert (b["reservation_generation"], b["reservation_ref"]) == (G0 + 1, f"cg:{LAUNCH}:1"), "no R12 on stale evidence"
    rig.world.admission = None
    rc, out = rig.run("resume")
    assert rc == 0, out
    assert rig.world.record["state"] == "returned"


@pytest.mark.parametrize("stop_works", [True, False])
def test_boot_failure_after_the_start_stops_qemu_before_recording_stopped(rig, stop_works):
    """Finding 3: a failure after QEMU may have started records stopped only once the unit is down."""
    held(rig)
    rig.set_host(fail={"verify-disks": "custom_guest_kit_data_changed", **({} if stop_works else {"stop": "custom_guest_stop_failed"})})
    rc, out = rig.run("boot")
    rec = rig.world.record
    if stop_works:
        assert rc == 1 and out["error_code"] == "custom_guest_kit_data_changed", out
        assert rec["state"] == "stopped" and rec["stop_reason"] == "boot_failed"
        assert rig.host()["custom_unit"] == {"ActiveState": "inactive"}
    else:
        assert rc == 1 and out["error_code"] == "custom_guest_stop_failed", out
        assert rec["state"] == "booting", "never stopped on paper while QEMU may run"


def test_intake_reaches_staged(rig):
    """Finding 6: the inbox observer passes once the host made the inbox."""
    import hashlib
    files = rig.home / HOTEL / LAUNCH / "files"
    files.mkdir(parents=True)
    digests = {}
    for name in ("vmlinuz", "initrd", "root.raw"):
        (files / name).write_bytes(name.encode() * 10)
        digests[name] = hashlib.sha256((files / name).read_bytes()).hexdigest()
    (rig.home / "inputs.json").write_text(json.dumps({"reference_initrds": {"1": digests["initrd"]},
                                                       "ovmf_sha256": "0f" * 32}))
    (rig.home / "test-image.json").write_text(json.dumps({"kernel_sha256": digests["vmlinuz"],
                                                           "initrd_sha256": digests["initrd"],
                                                           "root_sha256": digests["root.raw"]}))
    rig.world.record.update(state="requested", request={
        "kernel": {"sha256": digests["vmlinuz"], "bytes": 70}, "initrd": {"reference": "1", "sha256": digests["initrd"]},
        "root_disk": {"sha256": digests["root.raw"], "bytes": 80}})
    rig.set_host(launch_dir=False)
    rc, out = rig.run("intake")
    assert rc == 0, out
    rec = rig.world.record
    assert rec["state"] == "staged" and rec["host"]["reference_initrd_sha256"] == digests["initrd"]
    assert rig.host()["calls"].count("inbox") == 1 and rig.host()["calls"].count("intake") == 1
    assert len((rig.tmp / "fake_scp.py.log").read_text().split()) == 3


@pytest.mark.parametrize("left", ["inbox", "staging", "launch_dir"])
def test_cancel_discards_inbox_and_staging_leftovers(rig, left):
    """Finding 9: cancel discards whenever any of the launch's folders is on the host."""
    rig.world.record["state"] = "requested"
    rig.set_host(**{"launch_dir": False, "inbox": False, "staging": False, left: True})
    rc, out = rig.run("cancel")
    assert rc == 0, out
    h = rig.host()
    assert rig.world.record["state"] == "cancelled" and not (h["inbox"] or h["staging"] or h["launch_dir"])
    assert h["calls"].count("discard") == 1


def test_return_without_a_waiver_after_the_notice(rig):
    """Finding 10: an owner return request without a waiver passes once the 72 h notice is old enough."""
    held(rig)
    rig.world.record["owner_requests"] = [{"action": "return", "waive_notice": False}]
    rc, out = rig.run("return", "--notice-sent-at", iso(time.time() - 3600))
    assert rc == 1 and out["error_code"] == "custom_guest_state_conflict"
    rc, out = rig.run("return", "--notice-sent-at", iso(time.time() - 73 * 3600))
    assert rc == 0, out
    assert_returned(rig)

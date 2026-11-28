#!/usr/bin/env python3
"""Operator lifecycle of one custom SNP guest on a dedicated host (spec-r9 5.4, 7.2, 11).

  custom-guest.sh <step> --hotel H --launch-id L [options]

Steps (each one verify-before-act; a rerun resumes from the journal):
  fetch       download the owner's kernel and root and the reference initrd, check digests
  intake      requested -> staged   (broker checks, the 4.1 gate, upload, host intake)
  measure     staged -> measured    (manifest, bootstrap, HOST_DATA, expected measurement)
  hold        approved -> held      (H1 to H9; H3, H4 or H5 failing aborts while the kit never stopped)
  abort       holding -> approved   (only while the kit never stopped)
  boot        held|stopped -> booting -> running (or stopped, boot_failed)
  stop        running -> stopping -> stopped
  return      held|stopped -> returning -> returned (R0 to R15; the owner's folder is wiped now only on a
              waiver sent after the stop, else by `wipe`)
  wipe        returned: remove the owner's launch folder once the API allows it (72 h after the stop, Q5)
  sweep       the operator timers (ops/custom-guest/systemd): --what reconcile (every minute) or wipe (every
              15 min) over every unfinished launch of the hotel; no --launch-id; alerts are OPS-ALERT lines
  check       read only, for a heartbeat: overdue wipes, the timers, and the sweeper's OPS-ALERT lines
  resume      rerun the open step of this launch (R15 of an open return whatever the API says)
  reconcile   read both journals, systemd and the record; project exits; watch the hold; alert
  cancel      requested|staged|measured|approved -> cancelled (staged files deleted)
  record-versions --where NAME --commit SHA ...   the roll.sh commits of 5.10, before the first hold

Runs on the operator machine only. It reads and writes the API with the admin
key and the broker with the operator key, both read from files into headers,
never printed and never in argv. Host phases run over SSH
(custom-guest-host.sh); no credential goes to the host.

Config (env): CG_HOME (~/.cathedral-custom-guest: journals, hosts.conf, inputs.json,
test-image.json), CG_API_URL, CG_ADMIN_KEY_FILE, CG_BROKER_URL, CG_OPERATOR_KEY_FILE,
CG_SITE_URL, CG_SSH, CG_SCP, CG_PLATFORM_GUEST, and the waits CG_FENCE_WAIT (1800 s),
CG_H7_WAIT (600 s), CG_ADMIT_WAIT (1800 s), CG_SEND_WAIT (900 s: a broker PATCH the API calls
unresolved), CG_POLL (15 s).
hosts.conf: one line per hotel: <hotel> <ssh target> <repo dir on the host> <public host>.
"""
from __future__ import annotations

import argparse
import calendar
import contextlib
import fcntl
import hashlib
import http.client
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

HOME = os.path.expanduser(os.environ.get("CG_HOME", "~/.cathedral-custom-guest"))
API = os.environ.get("CG_API_URL", "https://api.polaris.computer").rstrip("/")
BROKER = os.environ.get("CG_BROKER_URL", "https://live.cathedral.computer").rstrip("/")
SITE = os.environ.get("CG_SITE_URL", "https://cathedral.computer").rstrip("/")
ADMIN_KEY_FILE = os.path.expanduser(os.environ.get("CG_ADMIN_KEY_FILE", os.path.join(HOME, "admin-key")))
OPERATOR_KEY_FILE = os.path.expanduser(os.environ.get("CG_OPERATOR_KEY_FILE", os.path.join(HOME, "operator-key")))
PLATFORM_GUEST = os.environ.get("CG_PLATFORM_GUEST", "cathedral-customer-sealed")
SSH = shlex.split(os.environ.get("CG_SSH", "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes"))
# -O: the legacy protocol. Plain scp asks for the sftp subsystem, which the hotel's forced command refuses.
SCP = shlex.split(os.environ.get("CG_SCP", "scp -q -O -o BatchMode=yes -o StrictHostKeyChecking=yes"))
FENCE_WAIT = float(os.environ.get("CG_FENCE_WAIT", "1800"))
H7_WAIT = float(os.environ.get("CG_H7_WAIT", "600"))
ADMIT_WAIT = float(os.environ.get("CG_ADMIT_WAIT", "1800"))
SEND_WAIT = float(os.environ.get("CG_SEND_WAIT", "900"))
POLL = float(os.environ.get("CG_POLL", "15"))
UA = "cathedral-custom-guest/1"
ADMIN = "/api/admin/cathedral/dedicated/custom-guest"
HOLD_PHASES = ("intent", "drained", "fenced", "inventoried", "kit_stopping", "kit_stopped", "kit_down_set", "baselined")
HOST_DEADLINE = {"intake": 7200, "hold-baseline": 5400, "verify-disks": 5400, "return-kit": 5400, "measure": 1800,
                 "return-finish": 1800}


DETAIL_MAX = 300


def one_line(text: object, limit: int = DETAIL_MAX) -> str:
    """A detail for the API: one line of printable ASCII, whitespace collapsed, at most `limit` characters.
    A serial tail has newlines and control bytes, and the API refuses those with a 422 (rehearsal B, run 3: a
    boot failure could not be recorded). Anything outside 0x20 to 0x7e becomes a space; an empty result says so."""
    flat = "".join(c if " " <= c <= "~" else " " for c in str(text))
    flat = " ".join(flat.split())[:limit].rstrip()
    return flat or "no detail given"


class Blocked(Exception):
    """A step stops here; the record keeps the error for the operator or Toby."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


class Abort(Blocked):
    """A hold step failed while the kit never stopped: undo the hold (11.2)."""


class Transport(Exception):
    """No answer: the effect may or may not have happened. observe() decides."""


def utc(stamp: str) -> float:
    """Seconds since the epoch of a YYYY-MM-DDTHH:MM:SSZ stamp, whatever the local zone."""
    return calendar.timegm(time.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ"))


def wipe_pending(rec: dict) -> bool:
    """Q5: the API allows the folder wipe (wipe_ok, on its clock), or a wipe already started; not yet done."""
    return not rec.get("wiped_at") and (rec.get("wipe_ok") is True or bool(rec.get("wipe_started_at")))


ALERT_TAG = "OPS-ALERT"


def ops_alert(hotel: str, launch: str, text: str) -> None:
    """One journal line per alert on the operator machine (systemd keeps the units' stderr), with a fixed tag a
    heartbeat greps: `OPS-ALERT custom_guest hotel=<h> launch=<l> <alert>`."""
    print(f"{ALERT_TAG} custom_guest hotel={hotel} launch={launch} {text}", file=sys.stderr, flush=True)


LOCK_WAIT = float(os.environ.get("CG_OP_LOCK_WAIT", "120"))


@contextlib.contextmanager
def op_lock(hotel: str, wait: bool):
    """One step of a hotel at a time on this machine: the sweeper's reconcile and wipe write the same journal as
    the operator's steps. A step waits up to CG_OP_LOCK_WAIT s; the sweeper does not wait (yields False)."""
    d = os.path.join(HOME, hotel)
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(d, "op.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.time() + (LOCK_WAIT if wait else 0)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.time() >= deadline:
                    if not wait:
                        yield False
                        return
                    raise Blocked("custom_guest_lifecycle_busy", f"another custom-guest.sh step of {hotel} runs here")
                time.sleep(0.5)
        yield True
    finally:
        os.close(fd)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fault(where: str) -> None:
    """Test hook: CG_FAULT=op:<step>:<sub> kills the script right after that act, before the journal
    (op:fence:<target>: right after a fence POST, its answer unread)."""
    if os.environ.get("CG_FAULT") == where:
        os._exit(137)


# ---------------------------------------------------------------- HTTP

class Http:
    def __init__(self, base: str, key_file: str):
        self.base, self.key_file = base, key_file

    def call(self, method: str, path: str, body: dict | None = None, timeout: float = 30) -> tuple[int, dict]:
        try:
            key = open(self.key_file).read().strip()
        except OSError as e:
            raise Blocked("custom_guest_hold_failed", f"cannot read a key file: {e.strerror}")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {key}", "User-Agent": UA,
                                              "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw.strip() else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                doc = json.loads(raw) if raw.strip() else {}
            except ValueError:
                doc = {"detail": raw[:200].decode("utf-8", "replace")}
            return e.code, doc if isinstance(doc, dict) else {"detail": doc}
        except (urllib.error.URLError, http.client.HTTPException, ConnectionError, TimeoutError, OSError) as e:
            raise Transport(f"{method} {path}: {e}")


def error_code(doc: dict) -> str:
    for k in ("error", "code", "error_code"):
        v = doc.get(k)
        if isinstance(v, str):
            return v
        if isinstance(v, dict) and isinstance(v.get("code"), str):
            return v["code"]
    d = doc.get("detail")
    if isinstance(d, dict):
        return error_code(d)
    return "unknown"


# ---------------------------------------------------------------- operator journal (5.4)

class Journal:
    """~/.cathedral-custom-guest/<hotel>/journal.jsonl, one fsynced line per event."""

    def __init__(self, hotel: str):
        self.dir = os.path.join(HOME, hotel)
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self.path = os.path.join(self.dir, "journal.jsonl")

    def entries(self, launch: str | None = None) -> list[dict]:
        out = []
        try:
            with open(self.path) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except ValueError:
                        continue
                    if launch is None or e.get("launch_id") in (launch, None):
                        out.append(e)
        except FileNotFoundError:
            pass
        return out

    def max_seq(self) -> int:
        return max((e.get("seq", 0) for e in self.entries()), default=0)

    def write(self, launch: str | None, generation: int | None, step: str, sub: str, phase: str,
              detail: object = None) -> int:
        seq = self.max_seq() + 1
        line = json.dumps({"seq": seq, "launch_id": launch, "generation": generation, "step": step, "sub": sub,
                           "phase": phase, "at": now_iso(), "detail": detail}, sort_keys=True) + "\n"
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        return seq

    def find(self, launch: str, step: str | None = None, sub: str | None = None, phase: str | None = None) -> list[dict]:
        return [e for e in self.entries(launch) if e.get("launch_id") == launch
                and (step is None or e.get("step") == step) and (sub is None or e.get("sub") == sub)
                and (phase is None or e.get("phase") == phase)]

    def done(self, launch: str, step: str, sub: str) -> bool:
        return bool(self.find(launch, step, sub, "done"))


# ---------------------------------------------------------------- the lifecycle

def phase_at_least(rec: dict, phase: str) -> bool:
    hp = rec.get("hold_phase")
    return hp in HOLD_PHASES and HOLD_PHASES.index(hp) >= HOLD_PHASES.index(phase)


def host_of(rec: dict) -> dict:
    """The record's operator facts and hold evidence (PR 3 admin_view: record["host"])."""
    return rec.get("host") or {}


def tuple_of(view: dict) -> dict:
    return {"generation": view.get("reservation_generation"), "ref": view.get("reservation_ref")}


def unresolved_of(rec: dict) -> dict | None:
    """The broker PATCH the API sent and has no answer for (PR 3 host.reservation.unresolved), or None."""
    return (host_of(rec).get("reservation") or {}).get("unresolved") or None


def target_live(rec: dict, to: str, view: dict) -> bool:
    """Whether a broker read shows fence target ``to`` for this record (the read side of the API's _at_target)."""
    host = host_of(rec)
    res = host.get("reservation") or {}
    if not res.get("fenced") or view.get("reserved_for") != host.get("reservation_guest"):
        return False
    hold, live = view.get("custom_guest_hold"), tuple_of(view)
    if to == "fenced":
        return live == res["fenced"] and hold == {"launch": rec["launch_id"], "kit_down": False}
    if to == "kit_down":
        return live == res["fenced"] and hold == {"launch": rec["launch_id"], "kit_down": True}
    restored = res.get("restored") or {"generation": res["fenced"]["generation"] + 1, "ref": res["original"]["ref"]}
    return live == restored and hold is None


OUT = ("sending", "unanswered")  # PR 3 send entries whose PATCH may have left ("claimed" never did)


def sends_out(pending: dict) -> int:
    """How many calls' copies of the unresolved PATCH may be out (PR 3 sends: intent_id -> claimed, sending,
    unanswered or answered)."""
    return sum(1 for v in (pending.get("sends") or {}).values() if v in OUT)


def settled_by_read(rec: dict, pending: dict, view: dict) -> bool:
    """The API's settle rule, read side (4.6): resolved when no copy can be out, or a read shows the whole target
    and the PATCH moves the generation or only one copy can be out. A generation past the fence alone is not
    enough: the hold must agree with the tuple."""
    out = sends_out(pending)
    return out == 0 or (target_live(rec, pending.get("to"), view) and (bool(pending.get("bumps")) or out == 1))


def host_conf_of(hotel: str) -> tuple[str, str, str]:
    path = os.path.join(HOME, "hosts.conf")
    try:
        for line in open(path):
            w = line.split("#", 1)[0].split()
            if len(w) == 4 and w[0] == hotel:
                return w[1], w[2], w[3]
    except OSError:
        pass
    raise Blocked("custom_guest_hold_failed", f"{path} has no line for {hotel}")


def host_call(hotel: str, phase: str, launch_args: list[str], data: dict | None = None, **opts: str) -> dict:
    """One host phase over SSH. ``launch_args`` is ["--launch-id", L], or [] for `folders` (all launches)."""
    target, repo, _ = host_conf_of(hotel)
    argv = [f"{repo}/ops/custom-guest/custom-guest-host.sh", phase, "--hotel", hotel, *launch_args]
    for k, v in opts.items():
        argv += [f"--{k.replace('_', '-')}", str(v)]
    try:
        p = subprocess.run([*SSH, target, shlex.join(argv)], input=json.dumps(data or {}), capture_output=True,
                           text=True, timeout=HOST_DEADLINE.get(phase, 900) + 120)
    except subprocess.TimeoutExpired:
        raise Transport(f"host phase {phase} gave no answer")
    lines = [ln for ln in p.stdout.splitlines() if ln.startswith("RESULT ")]
    if not lines:
        raise Transport(f"host phase {phase} gave no result (exit {p.returncode}): {p.stderr.strip()[-300:]}")
    return json.loads(lines[-1][len("RESULT "):])


class Op:
    def __init__(self, hotel: str, launch: str, opts: argparse.Namespace):
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,58}", hotel) or not re.fullmatch(r"cg-[0-9a-f]{12}", launch):
            raise Blocked("custom_guest_request_invalid", "bad --hotel or --launch-id")
        self.hotel, self.launch, self.o = hotel, launch, opts
        self.j = Journal(hotel)
        self.api = Http(API, ADMIN_KEY_FILE)
        self.broker = Http(BROKER, OPERATOR_KEY_FILE)
        self.stash: dict = {}

    # ---------------- reads
    def record(self) -> dict:
        for attempt in range(3):
            try:
                status, doc = self.api.call("GET", f"{ADMIN}?hotel={self.hotel}")
                break
            except Transport:
                if attempt == 2:
                    raise Blocked("custom_guest_journal_behind", "the API did not answer")
                time.sleep(1)
        if status != 200:
            raise Blocked(error_code(doc) if status != 404 else "custom_guest_not_found", f"API list {status}")
        items = doc if isinstance(doc, list) else doc.get("launches") or doc.get("items") or doc.get("records") or []
        for r in items:
            if r.get("launch_id") == self.launch:
                return r
        raise Blocked("custom_guest_not_found", f"no record {self.launch} on {self.hotel}")

    def view(self) -> dict:
        for attempt in range(3):
            try:
                status, doc = self.broker.call("GET", f"/v1/broker/hotels/{self.hotel}")
                break
            except Transport:
                if attempt == 2:
                    raise Blocked("custom_guest_hold_failed", "the broker did not answer")
                time.sleep(1)
        if status != 200:
            raise Blocked("custom_guest_hold_failed", f"broker hotel read {status}")
        return doc

    def restart_check(self) -> dict:
        try:
            status, doc = self.broker.call("GET", f"/v1/broker/hotels/{self.hotel}/restart-check")
        except Transport as e:
            raise Blocked("custom_guest_barrier_failed", str(e))
        if status not in (200, 409):
            raise Blocked("custom_guest_barrier_failed", f"restart-check {status}")
        return doc

    def live_rows(self) -> dict:
        try:
            status, doc = self.api.call("GET", f"{ADMIN}/{self.launch}/live-rows")
        except Transport as e:
            raise Blocked("custom_guest_barrier_failed", str(e))
        if status != 200:
            raise Blocked("custom_guest_barrier_failed", f"live-rows {status} {error_code(doc)}")
        return doc

    # ---------------- host phases
    def host_conf(self) -> tuple[str, str, str]:
        return host_conf_of(self.hotel)

    def host(self, phase: str, data: dict | None = None, **opts: str) -> dict:
        return host_call(self.hotel, phase, ["--launch-id", self.launch], data, **opts)

    def host_ok(self, phase: str, data: dict | None = None, **opts: str) -> dict:
        """A host phase is idempotent: a lost answer is resolved by running it again."""
        for attempt in range(2):
            try:
                r = self.host(phase, data, **opts)
                break
            except Transport:
                if attempt == 1:
                    raise
        if not r.get("ok"):
            raise Blocked(r.get("error_code") or "custom_guest_hold_failed", str(r.get("detail", ""))[:300])
        return r

    def facts(self) -> dict:
        r = self.host("facts")
        if not r.get("ok"):
            raise Blocked(r.get("error_code") or "custom_guest_hold_failed", str(r.get("detail", "")))
        return r

    @staticmethod
    def hj(facts: dict, event: str) -> list[dict]:
        return [e for e in facts.get("journal", []) if e.get("event") == event]

    # ---------------- writes
    def patch(self, seq: int, frm: str, to: str, fields: dict | None = None, generation: int | None = None) -> None:
        end = time.time() + SEND_WAIT
        while True:
            rec = self.record()
            body = {"from": frm, "to": to, "generation": rec.get("generation", 0) if generation is None else generation,
                    "journal_seq": seq, "fields": fields or {}}
            status, doc = self.api.call("PATCH", f"{ADMIN}/{self.launch}", body)
            if status == 200:
                return
            code = error_code(doc)
            if status == 409 and code == "custom_guest_send_unresolved":
                # A record PATCH never reaches the broker: sent again only once a read shows the send resolved.
                self.wait_unresolved(f"PATCH {frm} -> {to}", end)
                continue
            if status == 409 and code == "custom_guest_state_conflict":
                raise self.conflict(f"PATCH {frm} -> {to}")
            raise Blocked(code, f"PATCH {frm} -> {to}: {status}")

    def fence(self, to: str) -> tuple[int, dict]:
        return self.api.call("POST", f"{ADMIN}/{self.launch}/fence", {"to": to}, timeout=60)

    def conflict(self, what: str) -> Blocked:
        """custom_guest_state_conflict: the record moved under this call. Read it back, say what it shows, stop."""
        rec = self.record()
        res, pending = self.res(rec), unresolved_of(rec) or {}
        return Blocked("custom_guest_state_conflict",
                       f"{what}: refused, nothing sent. The record is now {rec['state']}/{rec.get('hold_phase')}, "
                       f"intent {res.get('intent')}, expect {res.get('expect')}, unresolved {pending.get('to')}. "
                       f"Stopped: read the record before the next step")

    def wait_unresolved(self, why: str, end: float) -> None:
        """A broker PATCH may still be in flight (4.6, 11.2). Wait on reads of the record and the broker; send
        nothing. Returns once a read shows the send resolved; past ``end`` it stops for Toby."""
        while True:
            pending = unresolved_of(self.record()) or {}
            view = self.view()
            print(json.dumps({"waiting": "unresolved_broker_send", "launch_id": self.launch, "for": why,
                              "send": pending.get("to"), "sent_at": pending.get("at"), "out": sends_out(pending),
                              "live": tuple_of(view)}), file=sys.stderr, flush=True)
            if time.time() >= end:
                raise Blocked("custom_guest_send_unresolved",
                              f"{why}: the {pending.get('to')} PATCH sent at {pending.get('at')} is still unresolved "
                              f"after {int(SEND_WAIT)} s. Nothing was resent. Toby decides, or rerun once it lands")
            time.sleep(POLL)  # at least one wait per refusal: the API's own read just said unresolved
            rec = self.record()
            pending = unresolved_of(rec)
            if pending is None or settled_by_read(rec, pending, self.view()):
                return

    def fence_step(self, to: str, exc: type, retry: tuple[str, ...] = ("rooms_active",),
                   wait: float | None = None) -> None:
        """Drive POST .../fence to a 200 (4.3, 7.2). The API reads the hotel before it sends and answers sent:false
        at the target, so a POST after a lost answer finishes the API's own transaction instead of skipping it.

        - ``retry`` codes (rooms_active; secret_calls_in_flight at H7): wait and POST again until ``wait``.
        - no answer, or reservation_moved with this target unresolved in the record: the send is in doubt. Only a
          generation-moving PATCH (fenced from original, restored) is sent again: the first copy to land moves the
          generation past every other copy. Any other send is waited on by reads, never resent.
        - custom_guest_send_unresolved: another send is in doubt: wait on reads, then POST again.
        - custom_guest_state_conflict: read the record back and stop.
        Waiting on a send that never resolves stops with custom_guest_send_unresolved (a Blocked, never an abort).
        """
        end = time.time() + (FENCE_WAIT if wait is None else wait)
        send_end = time.time() + SEND_WAIT
        while True:
            try:
                status, doc = self.fence(to)
            except Transport:
                status, doc = 0, {}
            fault(f"op:fence:{to}")  # test hook: die with the API's answer unread
            if status == 200:
                if doc.get("stale"):
                    # PR 3 recorded the answer but the record moved on (another call settled this step): it did
                    # not finalize. The sub's observe reads the record back and decides.
                    print(json.dumps({"stale_answer": to, "launch_id": self.launch}), file=sys.stderr, flush=True)
                return
            code = error_code(doc) if 0 < status < 500 else "no_answer"
            if status == 409 and code in retry and time.time() < end:
                time.sleep(POLL if code == "rooms_active" else min(POLL, 5))
                continue
            if status == 409 and code == "custom_guest_state_conflict":
                raise self.conflict(f"fence {to}")
            pending = unresolved_of(self.record())
            if code in ("no_answer", "custom_guest_reservation_moved") and pending is not None \
                    and pending.get("to") == to and pending.get("bumps"):
                if time.time() >= send_end:
                    raise Blocked("custom_guest_send_unresolved", f"fence {to}: {sends_out(pending)} copies may be "
                                  f"out, none answered or seen; Toby decides")
                print(json.dumps({"resending": to, "launch_id": self.launch, "out": sends_out(pending),
                                  "why": "it moves the generation: the first copy to land fails every other"}),
                      file=sys.stderr, flush=True)
                time.sleep(min(POLL, 5))
                continue
            if code == "custom_guest_send_unresolved" or (
                    code in ("no_answer", "custom_guest_reservation_moved") and pending is not None):
                self.wait_unresolved(f"fence {to}", send_end)
                continue
            if code == "no_answer":
                # Nothing unresolved: the API finished or never began. A POST reads first, so it is safe again.
                if time.time() >= end:
                    raise Blocked("custom_guest_hold_failed", f"fence {to}: the API did not answer")
                time.sleep(min(POLL, 5))
                continue
            raise exc("custom_guest_barrier_failed" if code == "rooms_active" else code, f"fence {to}: {status} {code}")

    def drain(self, value: bool) -> None:
        status, doc = self.broker.call("PATCH", f"/v1/broker/hotels/{self.hotel}", {"drain": value})
        if status != 200:
            raise Blocked(error_code(doc), f"broker drain {value}: {status}")

    # ---------------- verify before act (5.4)
    def sub(self, step: str, name: str, observe, act=None, generation: int | None = None,
            recheck: bool = False) -> None:
        """observe() -> True (done) or False (ready), or raises Blocked. act(seq) may lose its reply.

        recheck: observe again even when the journal shows the sub done (evidence a host reboot can make stale).
        """
        if self.done_now(step, name) and not recheck:
            return
        seq = self.j.write(self.launch, generation, step, name, "intent")
        try:
            if not observe():
                if act is None:
                    raise Blocked("custom_guest_journal_behind", f"{step} {name}: not done and nothing to do")
                try:
                    act(seq)
                except Transport:
                    pass
                fault(f"op:{step}:{name}")
                if not observe():
                    raise Blocked("custom_guest_hold_failed", f"{step} {name}: the postcondition did not hold")
        except Blocked as e:
            self.j.write(self.launch, generation, step, name, "failed", {"error_code": e.code, "detail": e.detail[:300]})
            raise
        self.j.write(self.launch, generation, step, name, "done", self.stash.pop(name, None))

    def run_entries(self, step: str, sub: str, phase: str | None = None) -> list[dict]:
        """Entries of ``sub`` in the current run of ``step``: after its latest begin. A step that was closed and
        begun again (a refused abort reopened, a boot rerun) never trusts what its earlier run journaled."""
        begins = self.j.find(self.launch, step, "begin")
        start = begins[-1]["seq"] if begins else 0
        return [e for e in self.j.find(self.launch, step, sub, phase) if e["seq"] > start]

    def done_now(self, step: str, sub: str) -> bool:
        return bool(self.run_entries(step, sub, "done"))

    def begin(self, step: str, generation: int | None = None) -> None:
        if not self.open_step(step):
            self.j.write(self.launch, generation, step, "begin", "intent", {"argv": sys.argv[1:]})

    def end(self, step: str, generation: int | None = None) -> None:
        self.j.write(self.launch, generation, step, "end", "done")

    def open_step(self, step: str) -> bool:
        begins = self.j.find(self.launch, step, "begin")
        ends = self.j.find(self.launch, step, "end", "done")
        return bool(begins) and (not ends or ends[-1]["seq"] < begins[-1]["seq"])

    def set_phase(self, step: str, phase: str, fields: dict | None = None) -> None:
        def observe() -> bool:
            return phase_at_least(self.record(), phase)

        def act(seq: int) -> None:
            self.patch(seq, "holding", "holding", {"hold_phase": phase, **(fields or {})})

        self.sub(step, f"phase_{phase}", observe, act)

    def res(self, rec: dict | None = None) -> dict:
        """host.reservation: the API writes the tuples (H1 and the fence intents), never this script."""
        return host_of(rec or self.record()).get("reservation") or {}

    # ================================================================ fetch and intake
    def files_dir(self) -> str:
        d = os.path.join(HOME, self.hotel, self.launch, "files")
        os.makedirs(d, mode=0o700, exist_ok=True)
        return d

    def inputs(self) -> dict:
        try:
            return json.load(open(os.path.join(HOME, "inputs.json")))
        except (OSError, ValueError):
            raise Blocked("custom_guest_not_reference_initrd", f"{HOME}/inputs.json (published inputs) is missing")

    def test_image(self) -> dict | None:
        try:
            return json.load(open(os.path.join(HOME, "test-image.json")))
        except (OSError, ValueError):
            return None

    def step_fetch(self) -> None:
        req = self.record()["request"]
        d = self.files_dir()
        want = {"vmlinuz": (req["kernel"].get("url"), req["kernel"]["sha256"], req["kernel"]["bytes"]),
                "root.raw": (req["root_disk"].get("url"), req["root_disk"]["sha256"], req["root_disk"]["bytes"]),
                "initrd": (f"{SITE}/dedicated/inputs/{req['initrd']['sha256']}/"
                           f"cathedral-custom-initrd-{req['initrd']['reference']}.cpio.zst", req["initrd"]["sha256"], None)}
        for name, (url, sha, size) in want.items():
            path = os.path.join(d, name)
            if not os.path.exists(path):
                if not url or not url.startswith("https://"):
                    raise Blocked("custom_guest_url_refused", f"{name}: only https URLs are fetched")
                tmp = path + ".part"
                with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": UA}), timeout=60) as r, \
                        open(tmp, "wb") as f:
                    shutil.copyfileobj(r, f, 8 << 20)
                os.replace(tmp, path)
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8 << 20), b""):
                    h.update(chunk)
            if h.hexdigest() != sha or (size is not None and os.path.getsize(path) != size):
                os.remove(path)
                raise Blocked("custom_guest_digest_mismatch", f"{name} differs from the request")
        print(json.dumps({"ok": True, "files": d}))

    def broker_eligible(self, view: dict, at_hold: bool) -> dict:
        """5.1 miner rule, 7.1 guest TLS, 7.2 broker support and the dedicated paths, on a fresh operator read."""
        labels = view.get("labels") or {}
        if view.get("miner_hotkey") or labels.get("miner") == "true" or str(view.get("id", "")).startswith("miner-"):
            raise Blocked("custom_guest_miner_hotel", "the broker shows a miner hotel")
        if not isinstance((view.get("admission") or {}).get("hotel_key_install"), dict):
            # Only a "guest_tls" config hotel has a key installer (broker/hotel_key_install.go:60-66).
            raise Blocked("custom_guest_hotel_not_guest_tls", "the operator view shows no guest TLS key installer")
        if "custom_guest_hold" not in view or view.get("runtime") is not False:
            raise Blocked("custom_guest_hold_unsupported", "the broker has no custom_guest_hold or the hotel joined at runtime")
        if not at_hold:
            return {}
        path = self.o.path
        if path == "platform":
            if view.get("reserved_for") != PLATFORM_GUEST or view.get("pin_only") is not True:
                raise Blocked("custom_guest_hotel_not_dedicated", "platform path needs the platform guest and pin_only")
        elif path == "self-serve":
            if not self.o.direct_guest or not self.o.order or view.get("reserved_for") != self.o.direct_guest \
                    or view.get("reservation_ref") != self.o.order:
                raise Blocked("custom_guest_hotel_not_dedicated", "self-serve path needs the owner's direct guest and ready order")
        else:
            raise Blocked("custom_guest_hotel_not_dedicated", "--path platform or self-serve is required")
        return {"path": path, "reserved_for": view.get("reserved_for")}

    def step_intake(self) -> None:
        step = "intake"
        self.begin(step)
        rec = self.record()
        req = rec["request"]
        test = self.test_image()
        is_test = bool(test) and (req["kernel"]["sha256"], req["initrd"]["sha256"], req["root_disk"]["sha256"]) == \
            (test.get("kernel_sha256"), test.get("initrd_sha256"), test.get("root_sha256"))
        if self.o.toby_go:
            self.sub(step, "toby_go", lambda: bool(self.j.find(self.launch, step, "toby_go_ref")),
                     lambda seq: self.j.write(self.launch, None, step, "toby_go_ref", "done", {"ref": self.o.toby_go}))
        toby = [e["detail"]["ref"] for e in self.j.find(self.launch, step, "toby_go_ref", "done")]

        def gate() -> bool:
            if not is_test and not toby:
                raise Blocked("custom_guest_toby_go_required", "a customer image needs --toby-go <message ref>")
            return True

        self.sub(step, "gate", gate)
        self.sub(step, "broker", lambda: bool(self.broker_eligible(self.view(), at_hold=False)) or True)
        def inbox(seq: int) -> None:
            self.stash["inbox"] = self.host_ok("inbox")

        # The host phase is idempotent; a rerun after a lost answer runs it again.
        self.sub(step, "inbox", lambda: "inbox" in self.stash or self.record()["state"] != "requested", inbox)
        target, _, _ = self.host_conf()
        d = self.files_dir()

        def upload(seq: int) -> None:
            inbox = f"/srv/custom-guest/{self.hotel}/inbox/{self.launch}/"
            for name in ("vmlinuz", "initrd", "root.raw"):
                src = os.path.join(d, name)
                if not os.path.isfile(src):
                    raise Blocked("custom_guest_digest_mismatch", f"{src} is missing; run fetch first")
                p = subprocess.run([*SCP, src, f"{target}:{inbox}{name}"], capture_output=True, text=True, timeout=36000)
                if p.returncode != 0:
                    raise Blocked("custom_guest_hold_failed", f"upload {name}: {p.stderr.strip()[-200:]}")
            self.stash["upload"] = {"uploaded": True}

        self.sub(step, "upload", lambda: self.record()["state"] != "requested" or "upload" in self.stash, upload)
        data = {"request": req, "inputs": {"reference_initrds": self.inputs().get("reference_initrds", {})},
                "test_image": test, "toby_go": toby[-1] if toby else None}

        def intake(seq: int) -> None:
            self.stash["host_intake"] = self.host_ok("intake", data)

        self.sub(step, "host_intake", lambda: "host_intake" in self.stash or self.record()["state"] != "requested", intake)

        def staged(seq: int) -> None:
            inputs = self.inputs()
            self.patch(seq, "requested", "staged", {"host": {
                "reference_initrd_version": req["initrd"]["reference"], "reference_initrd_sha256": req["initrd"]["sha256"],
                "reference_initrd_url": f"{SITE}/dedicated/inputs/{req['initrd']['sha256']}/"
                                        f"cathedral-custom-initrd-{req['initrd']['reference']}.cpio.zst",
                "ovmf_sha256": inputs.get("ovmf_sha256"),
                "ovmf_url": f"{SITE}/dedicated/inputs/{inputs.get('ovmf_sha256')}/OVMF.amdsev.fd"}})

        self.sub(step, "staged", lambda: self.record()["state"] != "requested", staged)
        self.end(step)

    def step_measure(self) -> None:
        step = "measure"
        self.begin(step)
        rec = self.record()
        _, _, public_host = self.host_conf()
        data = {"request": rec["request"], "owner_scope": rec["owner_scope"], "public_host": public_host,
                "ovmf_sha256": self.inputs().get("ovmf_sha256")}

        def act(seq: int) -> None:
            r = self.host_ok("measure", data)
            chip = (self.view().get("admission") or {}).get("chip_id")
            # PR 3 takes the documents as fields and the host and chip facts under fields.host (4.5).
            host = {"qemu_version": r["qemu_version"], "sev_snp_measure_version": r["sev_snp_measure_version"],
                    "policy": "0x30000", "public_host": public_host, "ports": r["bootstrap"]["ports"]}
            if chip:
                host["chip_id"] = chip
            self.patch(seq, "staged", "measured", {
                **{k: r[k] for k in ("manifest", "bootstrap", "host_data_hex", "expected_measurement")}, "host": host})

        self.sub(step, "measured", lambda: self.record()["state"] != "staged", act)
        self.end(step)

    # ================================================================ hold (11.2)
    def attempt(self) -> int:
        rec = self.record()
        attempt = int(self.res(rec).get("attempt") or 0)
        # The API counts attempts at H1 (_start_hold): the next one is the last one plus 1.
        return max(attempt, 1) if rec["state"] == "holding" else attempt + 1

    def step_hold(self) -> None:
        rec = self.record()
        if rec["state"] == "held":
            n = int(self.res(rec).get("attempt") or 1)
            if self.open_step(f"hold#{n}"):
                self.end(f"hold#{n}")  # H9 landed and the run died before its end entry
            print(json.dumps({"ok": True, "state": "held"}))
            return False
        if rec["state"] not in ("approved", "holding"):
            raise Blocked("custom_guest_state_conflict", f"hold needs approved, the record is {rec['state']}")
        if not rec.get("hold_ack"):
            raise Blocked("custom_guest_hold_ack_required", "the owner has not given hold_ack/v1")
        if not [e for e in self.j.entries() if e.get("step") == "versions" and e.get("phase") == "done"]:
            raise Blocked("custom_guest_hold_unsupported", "record the deployed roll.sh commits first (record-versions, 5.10)")
        n = self.attempt()
        if rec["state"] == "holding" and self.open_step(f"abort#{n}") and self.abort_untouched(n):
            self.close_abort(n, "hold")  # no restore was sent: going forward is still allowed (11.2)
        if rec["state"] == "holding" and self.open_step(f"abort#{n}"):
            # 11.2: once an abort began, its restore may be sent; after that only the abort follows (PR 3 refuses
            # every other step). Finish it with resume or abort.
            raise Blocked("custom_guest_state_conflict", f"attempt {n} is aborting: run resume (or abort), not hold")
        step = f"hold#{n}"
        self.begin(step)
        try:
            self.hold_steps(step, n)
        except Abort as e:
            self.abort(n, e.code)
            raise
        self.end(step)

    def hold_steps(self, step: str, n: int) -> None:
        ref = f"cg:{self.launch}:{n}"

        def eligible() -> bool:
            self.stash["eligible"] = self.broker_eligible(self.view(), at_hold=True)
            return True

        self.sub(step, "eligible", eligible)

        # H1 intent: the original tuple, drain and the reservation guest, read live.
        def h1_observe() -> bool:
            r = self.record()
            if r["state"] == "holding" and self.res(r).get("attempt") == n:
                return True
            if r["state"] == "approved":
                return False
            raise Blocked("custom_guest_state_conflict", f"record {r['state']}")

        def h1_act(seq: int) -> None:
            # The API reads the original tuple, drain and reservation guest live at this PATCH (_start_hold).
            self.patch(seq, "approved", "holding", {"hold_phase": "intent", "error_code": None})

        self.sub(step, "H1", h1_observe, h1_act)

        # H2 drain.
        self.sub(step, "H2", lambda: bool(self.view().get("drain")), lambda seq: self.drain(True))
        self.set_phase(step, "drained")

        # H3 fence and hold: one PATCH moves the ref and sets the hold.
        def h3_observe() -> bool:
            rec, v = self.record(), self.view()
            res = self.res(rec)
            t, hold = tuple_of(v), v.get("custom_guest_hold") or {}
            orig = res["original"]
            fenced = res.get("fenced") or {"generation": orig["generation"] + 1, "ref": ref}
            at = t == fenced and hold.get("launch") == self.launch
            # Done only when the API recorded it too: a broker result alone leaves the API's fence transaction
            # unfinished (expect still original), and the next phase PATCH would be refused (4.3, 5.4).
            if at and res.get("expect") == "fenced" and unresolved_of(rec) is None:
                return True
            if at or t == orig:
                return False  # the act POSTs the fence: at the target the API only records it (sent: false)
            raise Blocked("custom_guest_reservation_moved", f"live tuple {t}")

        def h3_act(seq: int) -> None:
            self.fence_step("fenced", Abort)  # the API writes the fenced tuple before its PATCH

        self.sub(step, "H3", h3_observe, h3_act)
        self.set_phase(step, "fenced")

        # H4 inventory: zero rooms and zero stored work, from both sides.
        def h4() -> bool:
            rc, v, rows = self.restart_check(), self.view(), self.live_rows()
            if "claims" not in rc:
                raise Abort("custom_guest_hold_unsupported", "restart-check has no claims count (broker below PR 2)")
            counts = {k: rc.get(k) for k in ("rooms", "creating", "queued", "pool_claims", "unreaped", "hotel_rooms", "claims")}
            rooms = rows.get("room_count")
            if not isinstance(rooms, int) or isinstance(rooms, bool):
                raise Abort("custom_guest_barrier_failed", "live-rows has no room_count")
            if not rc.get("count_known") or any(counts.values()) or v.get("rooms_in_use") or rooms:
                raise Abort("custom_guest_rooms_present", f"counts {counts}, rooms_in_use {v.get('rooms_in_use')}, live rows {rooms}")
            if "stored_work" not in rows or rows["stored_work"] is not None:
                raise Abort("custom_guest_stored_work_present", f"stored_work {rows.get('stored_work', 'absent')}")
            self.stash["H4"] = {"restart_check": rc, "rooms_in_use": v.get("rooms_in_use"), "live_rows": rooms,
                                "stored_work": None, "at": now_iso()}
            return True

        self.sub(step, "H4", h4)
        evidence = (self.j.find(self.launch, step, "H4", "done") or [{}])[-1].get("detail")
        self.set_phase(step, "inventoried", {"host": {"barrier_evidence": evidence}})

        # H5 earlier holders.
        def h5() -> bool:
            f = self.facts()
            start = (f.get("kit_unit") or {}).get("active_enter")
            since = self.o.dedicated_since
            since_t = utc(since) if since else None
            ok = [e for e in self.j.find(self.launch, "h5", "toby_ok", "done")]
            if start is not None and since_t is not None and start > since_t:
                self.stash["H5"] = {"kit_start": start, "dedicated_since": since, "result": "later"}
                return True
            if ok:
                self.stash["H5"] = {"kit_start": start, "dedicated_since": since, "toby_ok": ok[-1]["detail"]}
                return True
            raise Abort("custom_guest_earlier_holder_unconfirmed",
                        "the kit started before the dedication (or the time is unknown) and no Toby OK is journaled")

        if self.o.h5_ok:
            self.sub("h5", "toby_ok", lambda: "toby_ok" in self.stash,
                     lambda seq: self.stash.__setitem__("toby_ok", {"ref": self.o.h5_ok, "holder": self.o.h5_holder}))
        self.sub(step, "H5", h5)

        # H6a: only while the kit unit is active.
        def h6a_observe() -> bool:
            f = self.facts()
            if self.hj(f, "kit_stop") and f["kit_absent"]:
                return True
            if (f.get("kit_unit") or {}).get("state") == "active":
                return False
            raise Blocked("custom_guest_kit_failed", "the kit is absent and this launch never stopped it: Toby decides")

        def h6a_act(seq: int) -> None:
            v, rc = self.view(), self.restart_check()
            res = self.res()
            hold = v.get("custom_guest_hold") or {}
            if hold.get("launch") != self.launch:
                raise Blocked("custom_guest_hold_lost", "the hold is missing: send fence fenced again before the kit stops")
            if tuple_of(v) != res.get("fenced"):
                raise Blocked("custom_guest_reservation_moved", f"live tuple {tuple_of(v)}")
            if not rc.get("count_known") or rc.get("claims", 1) or any(
                    rc.get(k) for k in ("rooms", "creating", "queued", "pool_claims", "unreaped", "hotel_rooms")):
                raise Blocked("custom_guest_rooms_present", "restart-check is not zero with a known count")
            self.j.write(self.launch, None, step, "H6a_reads", "done", {"hold": hold, "tuple": tuple_of(v), "restart_check": rc})
            if not phase_at_least(self.record(), "kit_stopping"):
                h5 = (self.j.find(self.launch, step, "H5", "done") or [{}])[-1].get("detail")
                self.patch(seq, "holding", "holding",
                           {"hold_phase": "kit_stopping", **({"host": {"earlier_holders": h5}} if h5 else {})})
            r = self.host_ok("hold-stop", part="a")
            self.stash["H6a"] = {"kit_attestation_before": r.get("kit_attestation_before")}

        self.sub(step, "H6a", h6a_observe, h6a_act)

        # H6b: no room list, restart-check or count_known: a stopped kit cannot answer.
        def h6b_observe() -> bool:
            return phase_at_least(self.record(), "kit_stopped") and bool(self.hj(self.facts(), "kit_stopped"))

        def h6b_act(seq: int) -> None:
            v, rec = self.view(), self.record()
            hold = v.get("custom_guest_hold") or {}
            if hold.get("launch") != self.launch or tuple_of(v) != self.res(rec).get("fenced") \
                    or not host_of(rec).get("barrier_evidence"):
                raise Blocked("custom_guest_hold_lost", "H6b needs the hold, the fenced tuple and H4's evidence: Toby decides")
            r = self.host_ok("hold-stop", part="b")
            att = r.get("kit_attestation_before")
            self.patch(seq, "holding", "holding",
                       {"hold_phase": "kit_stopped", **({"host": {"kit_attestation_before": att}} if att else {})})

        self.sub(step, "H6b", h6b_observe, h6b_act)

        # H7 kit_down, authorized by the record, not a live room list.
        def h7_observe() -> bool:
            rec = self.record()
            hold = self.view().get("custom_guest_hold") or {}
            # As at H3: done only once the API recorded broker_hold.kit_down_at, not on the broker result alone.
            return hold.get("launch") == self.launch and hold.get("kit_down") is True \
                and bool((host_of(rec).get("broker_hold") or {}).get("kit_down_at")) and unresolved_of(rec) is None

        def h7_act(seq: int) -> None:
            # The first attempt closed secret admission; the count can only fall (7.2). kit_down moves no
            # generation, so a lost one is waited on by reads, never sent again blind.
            self.fence_step("kit_down", Blocked, retry=("secret_calls_in_flight",), wait=H7_WAIT)

        self.sub(step, "H7", h7_observe, h7_act)
        self.set_phase(step, "kit_down_set")  # the API records broker_hold.kit_down_at at the fence

        # H8 host baseline.
        def h8_act(seq: int) -> None:
            self.stash["H8"] = self.host_ok("hold-baseline")

        self.sub(step, "H8", lambda: bool(self.hj(self.facts(), "baselined")), h8_act)
        h8 = (self.j.find(self.launch, step, "H8", "done") or [{}])[-1].get("detail") or {}
        evidence = {k: v for k, v in (("sev_baseline", h8.get("sev_baseline")),
                                      ("disk_fingerprint", h8.get("fingerprint_sha256"))) if v is not None}
        self.set_phase(step, "baselined", {"host": evidence} if evidence else None)

        # H9 held.
        def h9_act(seq: int) -> None:
            self.patch(seq, "holding", "held")

        self.sub(step, "H9", lambda: self.record()["state"] == "held", h9_act)

    # ================================================================ abort (11.2)
    def kit_down_code(self) -> str | None:
        """None while the kit runs; else why no abort is possible (the kit stopped, only forward or Toby)."""
        f = self.facts()
        if (f.get("kit_unit") or {}).get("state") == "active":
            return None
        return "custom_guest_kit_failed" if not self.hj(f, "kit_stop") else "custom_guest_hold_failed"

    def abort_untouched(self, n: int) -> bool:
        """abort#n never began the restore: no restore sub journaled, and the record has no restore intent, no
        restore expect and no unresolved send."""
        if self.run_entries(f"abort#{n}", "restore"):
            return False
        rec = self.record()
        res = self.res(rec)
        return not res.get("intent") and res.get("expect") != "restored" and unresolved_of(rec) is None

    def close_abort(self, n: int, by: str) -> None:
        self.j.write(self.launch, None, f"abort#{n}", "refused", "done", {"closed_by": by})
        self.end(f"abort#{n}")

    def abort(self, n: int, code: str) -> None:
        step = f"abort#{n}"
        # Eligibility before any journal entry: a refused abort must leave nothing open that blocks going forward.
        refused = self.kit_down_code()
        if refused:
            if not self.open_step(step):
                raise Blocked(refused, "the kit is not active: no abort, only forward (or Toby decides); "
                                       "nothing was journaled, run resume to go on")
            if self.abort_untouched(n):
                self.close_abort(n, "abort")
                raise Blocked(refused, f"the kit is not active: abort#{n} never began the restore and is closed "
                                       "as refused; run resume to go on")
        self.begin(step)
        # The first run's error code is the one the record gets, whatever a resumed run was told.
        first = self.run_entries(step, "reason", "done")
        if first:
            code = first[-1]["detail"]["error_code"]
        else:
            self.j.write(self.launch, None, step, "reason", "done", {"error_code": code})

        def kit_never_stopped() -> bool:
            f = self.facts()
            if (f.get("kit_unit") or {}).get("state") != "active":
                raise Blocked("custom_guest_kit_failed" if not self.hj(f, "kit_stop") else "custom_guest_hold_failed",
                              "the kit is not active: no abort, only forward (or Toby decides)")
            return True

        self.sub(step, "kit_active", kit_never_stopped)
        self.sub(step, "unhold", lambda: (self.facts().get("marker") or {}).get("launch_id") != self.launch,
                 lambda seq: self.host_ok("unhold"))

        def restored_observe() -> bool:
            rec, v = self.record(), self.view()
            res, pending = self.res(rec), unresolved_of(rec)
            t, orig = tuple_of(v), res.get("original")
            if pending is None and v.get("custom_guest_hold") is None and t == orig and res.get("expect") == "original":
                return True  # no fence landed and none is in flight: the original tuple is the end state
            if pending is None and res.get("expect") == "restored" and target_live(rec, "restored", v):
                return True  # the API recorded the restore
            # A read showing original cannot prove an unanswered H3 PATCH will not land (4.6): never done here.
            if pending is not None or t in (orig, res.get("fenced"), res.get("restored")):
                return False
            raise Blocked("custom_guest_reservation_moved", f"live tuple {t}: Toby decides")

        def restore(seq: int) -> None:
            pending = unresolved_of(self.record())
            if pending is not None and pending.get("to") == "fenced" and pending.get("bumps"):
                # The H3 PATCH may still land: move the generation past it (the same fenced PATCH, G+1), then
                # restore (G+2). A late copy then fails its fence at the broker (11.2).
                self.fence_step("fenced", Blocked)
            self.fence_step("restored", Blocked)

        self.sub(step, "restore", restored_observe, restore)
        before = bool(host_of(self.record()).get("drain_before"))
        self.sub(step, "drain", lambda: bool(self.view().get("drain")) == before, lambda seq: self.drain(before))

        def approved(seq: int) -> None:
            self.patch(seq, "holding", "approved", {"error_code": code})

        self.sub(step, "approved", lambda: self.record()["state"] == "approved", approved)
        if self.open_step(f"hold#{n}"):
            self.end(f"hold#{n}")  # the attempt is over: resume must not take it up again
        self.end(step)

    def step_abort(self) -> None:
        rec = self.record()
        n = int(self.res(rec).get("attempt") or 1)
        # An abort whose approved PATCH landed before the run died is finished (its subs observe done).
        if rec["state"] != "holding" and not (rec["state"] == "approved" and self.open_step(f"abort#{n}")):
            raise Blocked("custom_guest_state_conflict", f"abort needs holding, the record is {rec['state']}")
        self.abort(int(self.res(rec).get("attempt") or 1), self.o.reason or "custom_guest_hold_failed")
        return None

    # ================================================================ boot, stop (11.3, 11.5)
    def close_boots(self, upto: int) -> None:
        """End every open boot#N up to ``upto``: that boot is over, and resume must never take it up again (11.4)."""
        for e in self.j.find(self.launch, sub="begin"):
            step = e["step"]
            if step.startswith("boot#") and int(step.split("#", 1)[1]) <= upto and self.open_step(step):
                self.end(step, int(step.split("#", 1)[1]))

    def booted_now(self, gen: int) -> bool:
        """The guest of ``gen`` runs now: its "booted" entry is from this host boot and this unit run (11.3)."""
        f = self.facts()
        mine = [e for e in self.hj(f, "booted") if e.get("generation") == gen]
        if not mine:
            return False
        e, unit = mine[-1], f.get("custom_unit") or {}
        if unit.get("ActiveState") == "active" and e.get("boot_id") == f.get("boot_id") \
                and e.get("invocation_id") and e.get("invocation_id") == unit.get("InvocationID"):
            return True
        raise Blocked("custom_guest_boot_failed", f"generation {gen} booted, but not in this host boot and unit run "
                      "(a host reboot or a QEMU exit since); nothing restarts it (11.4)")

    def step_boot(self, bound: int | None = None) -> bool | None:
        """bound: resume of an open boot#N. It stays on generation N: it finishes that boot or closes it, and never
        allocates a new generation (11.4: a relaunch is an explicit boot command)."""
        rec = self.record()
        st, cur = rec["state"], int(rec.get("generation") or 0)
        if bound is not None:
            booting_now = st == "booting" and cur == bound
            not_started = st in ("held", "stopped") and cur == bound - 1 \
                and not self.done_now(f"boot#{bound}", "booting")
            if not (booting_now or not_started):
                self.close_boots(bound)
                print(json.dumps({"ok": True, "state": st, "generation": cur, "closed": f"boot#{bound}"}))
                return False
            gen = bound
        elif st == "booting":
            gen = cur
        elif st in ("held", "stopped"):
            gen = cur + 1
        elif st == "running":
            self.close_boots(cur)
            print(json.dumps({"ok": True, "state": "running"}))
            return False
        else:
            raise Blocked("custom_guest_state_conflict", f"boot needs held or stopped, the record is {rec['state']}")
        self.close_boots(gen - 1)
        step = f"boot#{gen}"
        self.begin(step, gen)
        frm = rec["state"]

        def booting(seq: int) -> None:
            self.patch(seq, frm, "booting", {"error_code": None}, generation=gen)

        self.sub(step, "booting", lambda: self.record()["state"] in ("booting", "running")
                 and int(self.record().get("generation") or 0) == gen, booting, gen)
        rec = self.record()
        data = {"generation": gen, "bootstrap_signature_b64": rec["bootstrap_signature_b64"],
                "manifest_sha256": rec["manifest_sha256"], "bootstrap_sha256": rec["bootstrap_sha256"]}
        try:
            # Observed on every run of this step: a journaled "booted" from before a host reboot proves nothing.
            self.sub(step, "host_boot", lambda: self.booted_now(gen), lambda seq: self.host_ok("boot", data), gen,
                     recheck=True)
            # verify-disks only reads and compares; a rerun runs it again.
            self.sub(step, "disks", lambda: "disks" in self.stash,
                     lambda seq: self.stash.__setitem__("disks", self.host_ok("verify-disks", context=f"boot{gen}")), gen)
            if not self.booted_now(gen):  # once more right before running is recorded
                raise Blocked("custom_guest_boot_failed", f"generation {gen} is not running on the host")
        except Blocked as e:
            if self.record()["state"] == "booting":
                seq = self.j.write(self.launch, gen, step, "boot_failed", "intent", {"error_code": e.code})
                # QEMU may have started: the record says stopped only once the host shows the unit down.
                if not self.guest_down():
                    self.j.write(self.launch, gen, step, "boot_failed", "failed", {"error_code": e.code})
                    raise Blocked("custom_guest_stop_failed",
                                  f"boot failed ({e.code}) and the guest unit did not stop; the record stays booting")
                self.patch(seq, "booting", "stopped", {"stop_reason": "boot_failed", "error_code": e.code,
                                                       "error_detail": one_line(e.detail)})
                self.j.write(self.launch, gen, step, "boot_failed", "done")
            self.end(step, gen)
            raise

        def running(seq: int) -> None:
            self.patch(seq, "booting", "running")

        self.sub(step, "running", lambda: self.record()["state"] == "running", running, gen)
        self.end(step, gen)

    def guest_down(self) -> bool:
        """Run the host stop phase (idempotent) and read the unit back: True only when it is not running."""
        try:
            self.host_ok("stop")
            unit = self.facts().get("custom_unit") or {}
        except (Blocked, Transport):
            return False
        return unit.get("ActiveState", "inactive") in ("inactive", "failed")

    def step_stop(self) -> None:
        rec = self.record()
        if rec["state"] == "stopped":
            print(json.dumps({"ok": True, "state": "stopped"}))
            return
        if rec["state"] not in ("running", "stopping"):
            raise Blocked("custom_guest_state_conflict", f"stop needs running, the record is {rec['state']}")
        gen = int(rec.get("generation") or 0)
        step = f"stop#{gen}"
        self.begin(step, gen)
        self.sub(step, "stopping", lambda: self.record()["state"] in ("stopping", "stopped"),
                 lambda seq: self.patch(seq, "running", "stopping"), gen)
        # The host stop phase is idempotent; a rerun after a lost answer runs it again.
        self.sub(step, "host_stop", lambda: "host_stop" in self.stash,
                 lambda seq: self.stash.__setitem__("host_stop", self.host_ok("stop")), gen)
        self.sub(step, "stopped", lambda: self.record()["state"] == "stopped",
                 lambda seq: self.patch(seq, "stopping", "stopped"), gen)
        self.close_boots(gen)  # an open boot of this generation is over: resume must not start it again
        self.end(step, gen)

    # ================================================================ return (11.6)
    def step_return(self) -> None:
        step = "return"
        rec = self.record()
        if not self.open_step(step):
            if rec["state"] not in ("held", "stopped"):
                raise Blocked("custom_guest_state_conflict", f"return needs held or stopped, the record is {rec['state']}")
        self.begin(step)
        if self.record()["state"] == "returned":
            self.return_finish(step)
            self.end(step)
            return
        self.sub(step, "R0", lambda: self.record()["state"] in ("returning", "returned"),
                 lambda seq: self.patch(seq, self.record()["state"], "returning"))

        def kit(seq: int) -> None:
            r = self.host_ok("return-kit")
            self.patch(seq, "returning", "returning",
                       {"host": {"kit_boot": r["kit_boot"], "disk_verified": r["disk_verified"]}})

        def kit_current() -> bool:
            boot, unit = host_of(self.record()).get("kit_boot") or {}, self.facts().get("kit_unit") or {}
            return bool(boot) and unit.get("state") == "active" and boot.get("invocation_id") == unit.get("invocation_id")

        # Until R12 gives the hotel back, the evidence must be about the kit boot that runs now: a host reboot
        # after R11 makes the journaled R1 to R11 stale, so both are observed again on every run (5.4, 11.6).
        before_r12 = not self.done_now(step, "R12")
        self.sub(step, "R1_R10", kit_current, kit, recheck=before_r12)

        def r11() -> bool:
            boot = host_of(self.record())["kit_boot"]
            end = time.time() + ADMIT_WAIT
            while True:
                v = self.view()
                adm = v.get("admission") or {}
                at = adm.get("attested_at")
                at_t = utc(at) if at else 0
                rc = self.restart_check()
                if v.get("up") and adm.get("state") == "admitted" and adm.get("measurement") == boot["measurement"] \
                        and at_t >= (boot.get("active_enter") or 0) and rc.get("count_known") is True \
                        and kit_current():
                    self.stash["R11"] = {"admission": adm, "count_known": True}
                    return True
                if time.time() >= end:
                    seq = self.j.write(self.launch, None, step, "R11_wait", "failed")
                    self.patch(seq, "returning", "returning", {"error_code": "custom_guest_return_not_admitted"})
                    raise Blocked("custom_guest_return_not_admitted", "no admission for the R9 boot")
                time.sleep(POLL)

        self.sub(step, "R11", r11, recheck=before_r12)

        def r12_observe() -> bool:
            rec, v = self.record(), self.view()
            res = self.res(rec)
            if res.get("expect") == "restored" and unresolved_of(rec) is None and target_live(rec, "restored", v):
                return True  # the API recorded the restore, not only the broker
            if tuple_of(v) in (res.get("fenced"), res.get("restored")) or unresolved_of(rec) is not None:
                return False
            raise Blocked("custom_guest_reservation_moved", f"live tuple {tuple_of(v)}: Toby decides")

        self.sub(step, "R12", r12_observe, lambda seq: self.fence_step("restored", Blocked))
        before = bool(host_of(self.record()).get("drain_before"))
        self.sub(step, "R13", lambda: bool(self.view().get("drain")) == before, lambda seq: self.drain(before))
        self.sub(step, "R14", lambda: self.record()["state"] == "returned",
                 lambda seq: self.patch(seq, "returning", "returned", {"error_code": None}))
        self.return_finish(step)
        self.end(step)

    def return_finish(self, step: str) -> None:
        def done() -> bool:
            f = self.facts()
            return f.get("marker") is None and f.get("custom_unit") is None

        def r15(seq: int) -> None:
            # An older host tool removes the owner's folder in return-finish, and its facts lack launch_dir_bytes.
            # Running it would record that removal as a wipe that never waited (Q5): stop before it.
            if "launch_dir_bytes" not in self.facts():
                raise Blocked("custom_guest_hold_unsupported", "the host tool reports no launch_dir_bytes, so its "
                              "return-finish would remove the owner's folder now: deploy the host tool first, then resume")
            self.host_ok("return-finish", {"record_state": self.record()["state"]})

        self.sub(step, "R15", done, r15)
        # Q5: the kit is back; the owner's launch folder stays until the API allows the wipe. A waiver sent after
        # the stop allows it now; otherwise `wipe` removes it 72 h after the stop. An API without wipe_ok keeps it.
        if "wipe_ok" in self.record():
            self.report_kept(step)
        if wipe_pending(self.record()):
            self.wipe_folder(step)

    # ================================================================ wipe (Q5)
    def wipe_call(self, to: str) -> None:
        status, doc = self.api.call("POST", f"{ADMIN}/{self.launch}/wipe", {"to": to})
        if status != 200:
            raise Blocked(error_code(doc) or "custom_guest_wipe_failed",
                          f"POST wipe {to}: {status} {str(doc.get('message', ''))[:200]}")

    def report_kept(self, step: str) -> None:
        """R15k: the record shows the folder's bytes on the host while it waits (they hold disk until the wipe)."""
        def act(seq: int) -> None:
            f = self.facts()  # no folder (an older script's R15 removed it): 0 bytes held
            size = int(f.get("launch_dir_bytes") or 0) if f.get("launch_dir") else 0
            status, doc = self.api.call("POST", f"{ADMIN}/{self.launch}/wipe", {"to": "kept", "launch_dir_bytes": size})
            if status != 200:
                raise Blocked(error_code(doc) or "custom_guest_wipe_failed",
                              f"POST wipe kept: {status} {str(doc.get('message', ''))[:200]}")

        self.sub(step, "R15k", lambda: self.record().get("launch_dir_bytes") is not None
                 or bool(self.record().get("wiped_at")), act)

    def wipe_folder(self, step: str) -> None:
        """W1 ask the API (its clock decides), W2 remove the folder on the host, W3 record it. Each resumes."""
        self.sub(step, "W1", lambda: self.record().get("wipe_started_at") is not None,
                 lambda seq: self.wipe_call("started"))
        self.sub(step, "W2", lambda: not self.facts().get("launch_dir"),
                 lambda seq: self.host_ok("wipe", {"record_state": self.record()["state"]}))
        self.sub(step, "W3", lambda: self.record().get("wiped_at") is not None, lambda seq: self.wipe_call("done"))

    def step_wipe(self) -> bool:
        """The sweeper: run by the operator's timer after each reconcile. Nothing to do until the API says so."""
        rec = self.record()
        if rec["state"] != "returned":
            raise Blocked("custom_guest_state_conflict", f"wipe needs returned, the record is {rec['state']}")
        if "wipe_ok" not in rec:
            raise Blocked("custom_guest_notice_pending",
                          "the API record has no wipe_ok (an API before the Q5 stop clock): deploy the API first")
        if not rec.get("wiped_at") and (wipe_pending(rec) or rec.get("launch_dir_bytes") is None):
            self.begin("wipe")
            self.report_kept("wipe")  # a launch an older script returned: its bytes were never reported
            if wipe_pending(self.record()):
                self.wipe_folder("wipe")
            self.end("wipe")
            rec = self.record()
        print(json.dumps({"ok": True, "state": rec["state"], "wiped_at": rec.get("wiped_at"),
                          "wipe_due_at": rec.get("wipe_due_at")}))
        return False

    # ================================================================ cancel, resume, reconcile
    def step_cancel(self) -> None:
        rec = self.record()
        if rec["state"] == "cancelled":
            return
        if rec["state"] not in ("requested", "staged", "measured", "approved") or rec.get("hold_phase"):
            raise Blocked("custom_guest_state_conflict", f"cancel needs no hold, the record is {rec['state']}")
        step = "cancel"
        self.begin(step)
        frm = rec["state"]
        def discarded() -> bool:
            f = self.facts()
            return not (f.get("launch_dir") or f.get("inbox_dir") or f.get("staging_dir"))

        self.sub(step, "discard", discarded, lambda seq: self.host_ok("discard"))
        self.sub(step, "cancelled", lambda: self.record()["state"] == "cancelled",
                 lambda seq: self.patch(seq, frm, "cancelled"))
        self.end(step)

    def step_resume(self) -> None:
        opened = []
        for e in self.j.find(self.launch, sub="begin"):
            if self.open_step(e["step"]) and e["step"] not in opened:
                opened.append(e["step"])
        # An open abort that never began the restore, with the kit already stopped, can never finish: close it
        # and resume the hold it interrupted (forward recovery, 11.2).
        while opened and opened[-1].startswith("abort#"):
            n = int(opened[-1].split("#", 1)[1])
            if not (self.abort_untouched(n) and self.kit_down_code()):
                break
            self.close_abort(n, "resume")
            opened.pop()
        if not opened:
            print(json.dumps({"ok": True, "open": None}))
            return False
        step = opened[-1]
        kind = step.split("#", 1)[0]
        # The options the step began with (--path, --dedicated-since, --h5-ok, ...) carry over unless given now.
        argv = (self.j.find(self.launch, step, "begin")[-1].get("detail") or {}).get("argv") or []
        try:
            # parse_known_args: a step begun by an older script may carry an option since removed (--notice-sent-at).
            saved = parser().parse_known_args(argv)[0]
        except SystemExit:
            saved = None
        for k in RESUMED_OPTIONS:
            if saved is not None and getattr(self.o, k, None) is None:
                setattr(self.o, k, getattr(saved, k))
        if kind == "boot":
            return self.step_boot(bound=int(step.split("#", 1)[1]))
        return {"intake": self.step_intake, "measure": self.step_measure, "hold": self.step_hold,
                "abort": self.step_abort, "stop": self.step_stop, "return": self.step_return,
                "cancel": self.step_cancel, "wipe": self.step_wipe}[kind]()

    def step_reconcile(self) -> int:
        """Reads only, and projects host facts forward into the record. Starts nothing (5.4)."""
        rec = self.record()
        if int(rec.get("journal_seq") or 0) > self.j.max_seq():
            detail = f"API journal_seq {rec.get('journal_seq')} > local {self.j.max_seq()}"
            ops_alert(self.hotel, self.launch, f"custom_guest_journal_behind: {detail} (the steps ran on another machine?)")
            print(json.dumps({"ok": False, "error_code": "custom_guest_journal_behind", "detail": detail}))
            return 3
        alerts: list[str] = []
        f = self.facts()
        st = rec["state"]
        # Hold watch: from H3 to the restore the operator view must name this launch.
        held_states = ("held", "booting", "running", "stopping", "stopped")
        restore_done = self.j.done(self.launch, "return", "R12") or st in ("returned", "cancelled")
        if (st == "holding" and phase_at_least(rec, "fenced")) or st in held_states or (st == "returning" and not restore_done):
            hold = self.view().get("custom_guest_hold") or {}
            want_down = st != "holding" or phase_at_least(rec, "kit_down_set")
            if hold.get("launch") != self.launch or (want_down and hold.get("kit_down") is not True):
                alerts.append(f"custom_guest_hold_lost: operator view shows {hold or None}; send "
                              f"fence {'kit_down' if want_down else 'fenced'} again")
        if st == "returned" and f.get("marker"):
            alerts.append("R15 open: the marker is still on the host; run resume")
        if st == "returned" and rec.get("wipe_overdue") is True:
            alerts.append(f"custom_guest_wipe_overdue: the API allowed the wipe and marks it overdue since "
                          f"{rec.get('wipe_overdue_at')}; the folder holds {rec.get('launch_dir_bytes')} bytes; run wipe")
        for ev in ("sev_platform_changed", "kit_data_changed", "reboot_required"):
            if self.hj(f, ev):
                alerts.append(f"host journal: {ev}")
        # Projection: a running guest that the host shows stopped becomes stopped. Never backward.
        if st == "running":
            boots = self.hj(f, "token_used")
            last_boot = boots[-1] if boots else None
            after = [e for e in f.get("journal", []) if last_boot and e.get("t", 0) > last_boot.get("t", 0)]
            reason = None
            for e in after:
                if e["event"] == "sev_platform_changed":
                    reason, code = "sev_platform_changed", "custom_guest_sev_platform_changed"
                elif e["event"] in ("kit_data_changed", "isolation_failed"):
                    reason, code = "isolation_failed", f"custom_guest_{e['event']}"
                elif e["event"] == "host_boot" and e.get("boot_id") != last_boot.get("boot_id"):
                    reason, code = "host_reboot", None
                elif e["event"] == "exit" and reason is None:
                    clean = e.get("service_result") == "success" and e.get("exit_status") in ("0", "")
                    reason, code = ("guest_shutdown" if clean else "qemu_exit"), None
                if reason in ("sev_platform_changed", "isolation_failed", "host_reboot"):
                    break
            if reason:
                seq = self.j.write(self.launch, rec.get("generation"), "reconcile", "project", "intent", {"reason": reason})
                self.patch(seq, "running", "stopped", {"stop_reason": reason, "error_code": code})
                self.j.write(self.launch, rec.get("generation"), "reconcile", "project", "done", {"reason": reason})
                self.close_boots(int(rec.get("generation") or 0))
        for a in alerts:
            ops_alert(self.hotel, self.launch, a)
        print(json.dumps({"ok": not alerts, "state": self.record()["state"], "alerts": alerts}))
        return 2 if alerts else 0


RESUMED_OPTIONS = ("toby_go", "path", "direct_guest", "order", "dedicated_since", "h5_ok", "h5_holder", "reason")


def step_record_versions(hotel: str, where: list[str], commits: list[str]) -> None:
    if not where or len(where) != len(commits) or not all(re.fullmatch(r"[0-9a-f]{7,40}", c) for c in commits):
        raise Blocked("custom_guest_request_invalid", "--where NAME --commit SHA, one pair per conveyor or operator machine")
    j = Journal(hotel)
    j.write(None, None, "versions", "roll_sh", "done", dict(zip(where, commits)))
    print(json.dumps({"ok": True, "versions": dict(zip(where, commits))}))


# ---------------------------------------------------------------- the sweeper (Q5) and its read-only check

SWEEP_UNITS = ("cathedral-custom-guest-reconcile@{hotel}", "cathedral-custom-guest-wipe@{hotel}")


def list_launches(hotel: str) -> list[dict]:
    try:
        status, doc = Http(API, ADMIN_KEY_FILE).call("GET", f"{ADMIN}?hotel={hotel}")
    except Transport as e:
        raise Blocked("custom_guest_journal_behind", f"the API did not answer: {e}")
    if status != 200:
        raise Blocked(error_code(doc) if status != 404 else "custom_guest_not_found", f"API list {status}")
    items = doc if isinstance(doc, list) else doc.get("launches") or doc.get("items") or doc.get("records") or []
    return [r for r in items if isinstance(r, dict) and isinstance(r.get("launch_id"), str)]


def step_sweep(o: argparse.Namespace) -> int:
    """The operator timers' entry (ops/custom-guest/systemd): reconcile every launch of the hotel that is not
    finished (every minute), or wipe every returned launch whose folder is still there (every 15 min). Skips while
    an operator step of the hotel holds the lock; every alert and every refusal is an OPS-ALERT journal line."""
    with op_lock(o.hotel, wait=False) as got:
        if not got:
            print(json.dumps({"ok": True, "what": o.what, "skipped": "a custom-guest.sh step of this hotel runs"}))
            return 0
        try:
            items = list_launches(o.hotel)
        except Blocked as e:
            ops_alert(o.hotel, "-", f"{e.code}: {e.detail}")
            print(json.dumps({"ok": False, "error_code": e.code, "detail": e.detail}))
            return 1
        results = []
        for r in items:
            launch, st = r["launch_id"], r.get("state")
            if st == "cancelled" or (st == "returned" and r.get("wiped_at")):
                continue
            if o.what == "wipe" and st != "returned":
                continue
            try:
                op = Op(o.hotel, launch, o)
                if o.what == "reconcile":
                    rc = op.step_reconcile()
                else:
                    op.step_wipe()
                    rc = 0
            except (Blocked, Transport) as e:
                code, detail = (e.code, e.detail) if isinstance(e, Blocked) else ("custom_guest_journal_behind", str(e))
                ops_alert(o.hotel, launch, f"{code}: {detail}")
                rc = 1
            results.append({"launch_id": launch, "state": st, "rc": rc})
        bad = any(x["rc"] for x in results)
        print(json.dumps({"ok": not bad, "what": o.what, "launches": results}))
        return 2 if bad else 0


# Each unit prints one JSON line per run ({"ok": ..., "what": ...}); its timer period in minutes.
SWEEP_PERIOD_MIN = {"reconcile": 1, "wipe": 15}
JOURNAL_DENIED = ("insufficient permissions", "not seeing messages from other users", "permission denied")


def step_check(o: argparse.Namespace) -> int:
    """Read only, for a heartbeat: overdue wipes in the API, launch folders on the host that the API does not list,
    the two timers (where systemd runs), and the sweeper units' journal in the last --since-min minutes (where
    journald runs): its OPS-ALERT lines, and at least one run line per unit, so an unreadable journal cannot pass
    as a quiet one. Sends nothing."""
    found, notes = [], []
    alert = lambda launch, what: found.append(f"{ALERT_TAG} custom_guest hotel={o.hotel} launch={launch} {what}")
    listed: set[str] = set()
    try:
        for r in list_launches(o.hotel):
            listed.add(r["launch_id"])
            if r.get("wipe_overdue") is True:
                alert(r["launch_id"], f"custom_guest_wipe_overdue: since {r.get('wipe_overdue_at')}, "
                                      f"{r.get('launch_dir_bytes')} bytes on the host")
    except Blocked as e:
        alert("-", f"{e.code}: {e.detail}")
    # A folder whose launch the API no longer lists (its hotel or owner scope unlisted) is swept by nothing.
    try:
        h = host_call(o.hotel, "folders", [])
        if not h.get("ok"):
            raise Blocked(h.get("error_code") or "custom_guest_hold_failed", str(h.get("detail", ""))[:300])
        for f in h.get("folders") or []:
            if f.get("launch_id") not in listed:
                alert(f.get("launch_id"), f"custom_guest_folder_unlisted: {f.get('bytes')} bytes on the host and the "
                                          "API does not list the launch, so no sweep wipes it: list the hotel and the "
                                          "owner scope again, then let the wipe run")
    except (Blocked, Transport) as e:
        code, detail = (e.code, e.detail) if isinstance(e, Blocked) else ("custom_guest_host_unreadable", str(e))
        alert("-", f"{code}: the host's launch folders were not read: {detail}")
    units = [u.format(hotel=o.hotel) for u in SWEEP_UNITS]
    if shutil.which("systemctl"):
        for u in units:
            r = subprocess.run(["systemctl", "is-active", f"{u}.timer"], capture_output=True, text=True)
            if r.stdout.strip() != "active":
                alert("-", f"custom_guest_sweeper_down: {u}.timer is {r.stdout.strip() or 'unknown'}")
    else:
        notes.append("no systemctl here: the timers were not checked (run this on the operator machine)")
    if shutil.which("journalctl"):
        for u in units:
            what = u.split("@", 1)[0].rsplit("-", 1)[1]
            r = subprocess.run(["journalctl", "--no-pager", "-o", "cat", "--since", f"-{o.since_min}min",
                                "-u", f"{u}.service"], capture_output=True, text=True)
            denied = [x for x in JOURNAL_DENIED if x in r.stderr.lower()]
            if r.returncode != 0 or denied:
                alert("-", f"custom_guest_journal_unreadable: journalctl -u {u}.service exit {r.returncode}"
                           f"{', ' + denied[0] if denied else ''}: {one_line(r.stderr)[-200:]} (add the user to "
                           "systemd-journal)")
                continue
            found.extend(ln for ln in r.stdout.splitlines() if ln.startswith(ALERT_TAG))
            runs = 0
            for ln in r.stdout.splitlines():
                try:
                    runs += json.loads(ln).get("what") == what
                except (ValueError, AttributeError):
                    pass
            if o.since_min > SWEEP_PERIOD_MIN[what] and not runs:
                alert("-", f"custom_guest_sweeper_silent: {u}.service wrote no run line in {o.since_min} min "
                           f"(it runs every {SWEEP_PERIOD_MIN[what]} min)")
            elif o.since_min <= SWEEP_PERIOD_MIN[what]:
                notes.append(f"--since-min {o.since_min} is within {u}'s period: its runs were not counted")
    else:
        notes.append("no journalctl here: the sweeper's journal was not read")
    for line in found:
        print(line)
    print(json.dumps({"ok": not found, "alerts": len(found), "notes": notes}))
    return 2 if found else 0


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="custom-guest.sh", description=__doc__.splitlines()[0])
    ap.add_argument("step", choices=["fetch", "intake", "measure", "hold", "abort", "boot", "stop", "return", "resume",
                                     "reconcile", "cancel", "wipe", "sweep", "check", "record-versions"])
    ap.add_argument("--hotel", required=True)
    ap.add_argument("--launch-id")
    ap.add_argument("--toby-go", help="message ref of Toby's written go for a customer image (4.1)")
    ap.add_argument("--path", choices=["platform", "self-serve"], help="the dedicated path (3)")
    ap.add_argument("--direct-guest", help="self-serve path: the owner's direct guest")
    ap.add_argument("--order", help="self-serve path: the owner's ready order id")
    ap.add_argument("--dedicated-since", help="H5: time of the reservation change, YYYY-MM-DDTHH:MM:SSZ")
    ap.add_argument("--h5-ok", help="H5: message ref of Toby's OK for an earlier holder's leftovers")
    ap.add_argument("--h5-holder", help="H5: the earlier holder Toby's OK names")
    ap.add_argument("--reason", help="abort: the error code to record")
    ap.add_argument("--what", choices=["reconcile", "wipe"], default="reconcile", help="sweep: which pass to run")
    ap.add_argument("--since-min", type=int, default=16, help="check: minutes of the sweeper's journal to read")
    ap.add_argument("--where", action="append", default=[])
    ap.add_argument("--commit", action="append", default=[])
    return ap


def main(argv: list[str]) -> int:
    o = parser().parse_args(argv)
    try:
        if o.step == "record-versions":
            step_record_versions(o.hotel, o.where, o.commit)
            return 0
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,58}", o.hotel):
            raise Blocked("custom_guest_request_invalid", "bad --hotel")
        if o.step == "sweep":
            return step_sweep(o)
        if o.step == "check":
            return step_check(o)
        if not o.launch_id:
            raise Blocked("custom_guest_request_invalid", "--launch-id is required")
        with op_lock(o.hotel, wait=True):
            op = Op(o.hotel, o.launch_id, o)
            if o.step == "reconcile":
                return op.step_reconcile()
            printed = getattr(op, "step_" + o.step.replace("-", "_"))() is False
            if o.step != "fetch" and not printed:
                print(json.dumps({"ok": True, "state": op.record()["state"]}))
            return 0
    except Blocked as e:
        print(json.dumps({"ok": False, "error_code": e.code, "detail": e.detail}))
        return 1
    except Transport as e:
        print(json.dumps({"ok": False, "error_code": "custom_guest_journal_behind", "detail": f"no answer: {e}"}))
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

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
  return      held|stopped -> returning -> returned (R0 to R15)
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
CG_H7_WAIT (600 s), CG_ADMIT_WAIT (1800 s), CG_POLL (15 s).
hosts.conf: one line per hotel: <hotel> <ssh target> <repo dir on the host> <public host>.
"""
from __future__ import annotations

import argparse
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
CREDS = os.path.expanduser("~/Documents/TOOLS/.credentials")
ADMIN_KEY_FILE = os.path.expanduser(os.environ.get("CG_ADMIN_KEY_FILE", f"{CREDS}/polaris-admin-key"))
OPERATOR_KEY_FILE = os.path.expanduser(os.environ.get("CG_OPERATOR_KEY_FILE", f"{CREDS}/broker-operator-key"))
PLATFORM_GUEST = os.environ.get("CG_PLATFORM_GUEST", "cathedral-customer-sealed")
SSH = shlex.split(os.environ.get("CG_SSH", "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes"))
SCP = shlex.split(os.environ.get("CG_SCP", "scp -q -o BatchMode=yes -o StrictHostKeyChecking=yes"))
FENCE_WAIT = float(os.environ.get("CG_FENCE_WAIT", "1800"))
H7_WAIT = float(os.environ.get("CG_H7_WAIT", "600"))
ADMIT_WAIT = float(os.environ.get("CG_ADMIT_WAIT", "1800"))
POLL = float(os.environ.get("CG_POLL", "15"))
UA = "cathedral-custom-guest/1"
ADMIN = "/api/admin/cathedral/dedicated/custom-guest"
HOLD_PHASES = ("intent", "drained", "fenced", "inventoried", "kit_stopping", "kit_stopped", "kit_down_set", "baselined")
HOST_DEADLINE = {"intake": 7200, "hold-baseline": 5400, "verify-disks": 5400, "return-kit": 5400, "measure": 1800,
                 "return-finish": 1800}
NOTICE_SECONDS = 72 * 3600


class Blocked(Exception):
    """A step stops here; the record keeps the error for the operator or Toby."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


class Abort(Blocked):
    """A hold step failed while the kit never stopped: undo the hold (11.2)."""


class Transport(Exception):
    """No answer: the effect may or may not have happened. observe() decides."""


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fault(where: str) -> None:
    """Test hook: CG_FAULT=op:<step>:<sub> kills the script right after that act, before the journal."""
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


def tuple_of(view: dict) -> dict:
    return {"generation": view.get("reservation_generation"), "ref": view.get("reservation_ref")}


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
        path = os.path.join(HOME, "hosts.conf")
        try:
            for line in open(path):
                w = line.split("#", 1)[0].split()
                if len(w) == 4 and w[0] == self.hotel:
                    return w[1], w[2], w[3]
        except OSError:
            pass
        raise Blocked("custom_guest_hold_failed", f"{path} has no line for {self.hotel}")

    def host(self, phase: str, data: dict | None = None, **opts: str) -> dict:
        target, repo, _ = self.host_conf()
        argv = [f"{repo}/ops/custom-guest/custom-guest-host.sh", phase, "--hotel", self.hotel, "--launch-id", self.launch]
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
        rec = self.record()
        body = {"from": frm, "to": to, "generation": rec.get("generation", 0) if generation is None else generation,
                "journal_seq": seq, "fields": fields or {}}
        status, doc = self.api.call("PATCH", f"{ADMIN}/{self.launch}", body)
        if status != 200:
            raise Blocked(error_code(doc), f"PATCH {frm} -> {to}: {status}")

    def fence(self, to: str) -> tuple[int, dict]:
        return self.api.call("POST", f"{ADMIN}/{self.launch}/fence", {"to": to}, timeout=60)

    def drain(self, value: bool) -> None:
        status, doc = self.broker.call("PATCH", f"/v1/broker/hotels/{self.hotel}", {"drain": value})
        if status != 200:
            raise Blocked(error_code(doc), f"broker drain {value}: {status}")

    # ---------------- verify before act (5.4)
    def sub(self, step: str, name: str, observe, act=None, generation: int | None = None) -> None:
        """observe() -> True (done) or False (ready), or raises Blocked. act(seq) may lose its reply."""
        if self.j.done(self.launch, step, name):
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

    def reservation(self, **changes) -> dict:
        res = dict(self.record().get("reservation") or {})
        res.update(changes)
        return res

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
        self.sub(step, "inbox", lambda: rec["state"] != "requested" and self.record()["state"] != "requested",
                 lambda seq: self.host_ok("inbox"))
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
            self.patch(seq, "requested", "staged", {
                "reference_initrd_version": req["initrd"]["reference"], "reference_initrd_sha256": req["initrd"]["sha256"],
                "reference_initrd_url": f"{SITE}/dedicated/inputs/{req['initrd']['sha256']}/"
                                        f"cathedral-custom-initrd-{req['initrd']['reference']}.cpio.zst",
                "ovmf_sha256": inputs.get("ovmf_sha256"),
                "ovmf_url": f"{SITE}/dedicated/inputs/{inputs.get('ovmf_sha256')}/OVMF.amdsev.fd"})

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
            req = rec["request"]
            self.patch(seq, "staged", "measured", {
                **{k: r[k] for k in ("manifest", "manifest_sha256", "bootstrap", "bootstrap_sha256", "host_data_hex",
                                     "expected_measurement", "cmdline_hex", "qemu_version", "sev_snp_measure_version")},
                "vcpus": req["vcpus"], "cpu_model": req["cpu_model"], "policy": "0x30000", "chip_id": chip,
                "public_host": public_host, "ports": r["bootstrap"]["ports"]})

        self.sub(step, "measured", lambda: self.record()["state"] != "staged", act)
        self.end(step)

    # ================================================================ hold (11.2)
    def attempt(self) -> int:
        rec = self.record()
        if rec["state"] == "holding":
            return int((rec.get("reservation") or {}).get("attempt") or 1)
        return 1 + len({e["step"] for e in self.j.find(self.launch) if e.get("step", "").startswith("hold#")})

    def step_hold(self) -> None:
        rec = self.record()
        if rec["state"] == "held":
            print(json.dumps({"ok": True, "state": "held"}))
            return
        if rec["state"] not in ("approved", "holding"):
            raise Blocked("custom_guest_state_conflict", f"hold needs approved, the record is {rec['state']}")
        if not rec.get("hold_ack"):
            raise Blocked("custom_guest_hold_ack_required", "the owner has not given hold_ack/v1")
        if not [e for e in self.j.entries() if e.get("step") == "versions" and e.get("phase") == "done"]:
            raise Blocked("custom_guest_hold_unsupported", "record the deployed roll.sh commits first (record-versions, 5.10)")
        n = self.attempt()
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
            if r["state"] == "holding" and (r.get("reservation") or {}).get("attempt") == n:
                return True
            if r["state"] == "approved":
                return False
            raise Blocked("custom_guest_state_conflict", f"record {r['state']}")

        def h1_act(seq: int) -> None:
            v = self.view()
            self.patch(seq, "approved", "holding", {
                "hold_phase": "intent", "drain_before": bool(v.get("drain")), "reservation_guest": v.get("reserved_for"),
                "reservation": {"original": tuple_of(v), "expect": "original", "attempt": n}, "error_code": None})

        self.sub(step, "H1", h1_observe, h1_act)

        # H2 drain.
        self.sub(step, "H2", lambda: bool(self.view().get("drain")), lambda seq: self.drain(True))
        self.set_phase(step, "drained")

        # H3 fence and hold: one PATCH moves the ref and sets the hold.
        def h3_observe() -> bool:
            v, res = self.view(), self.record().get("reservation") or {}
            t, hold = tuple_of(v), v.get("custom_guest_hold") or {}
            orig = res["original"]
            if t == {"generation": orig["generation"] + 1, "ref": ref} and hold.get("launch") == self.launch:
                return True
            if t == orig:
                return False
            raise Blocked("custom_guest_reservation_moved", f"live tuple {t}")

        def h3_act(seq: int) -> None:
            orig = self.record()["reservation"]["original"]
            self.patch(seq, "holding", "holding",
                       {"reservation": self.reservation(fenced={"generation": orig["generation"] + 1, "ref": ref})})
            self.fence_until("fenced", Abort)

        self.sub(step, "H3", h3_observe, h3_act)
        self.set_phase(step, "fenced", {"reservation": self.reservation(expect="fenced")})

        # H4 inventory: zero rooms and zero stored work, from both sides.
        def h4() -> bool:
            rc, v, rows = self.restart_check(), self.view(), self.live_rows()
            if "claims" not in rc:
                raise Abort("custom_guest_hold_unsupported", "restart-check has no claims count (broker below PR 2)")
            counts = {k: rc.get(k) for k in ("rooms", "creating", "queued", "pool_claims", "unreaped", "hotel_rooms", "claims")}
            rooms = sum(len(x) for k, x in rows.items() if isinstance(x, list) and k != "stored_work")
            if not rc.get("count_known") or any(counts.values()) or v.get("rooms_in_use") or rooms:
                raise Abort("custom_guest_rooms_present", f"counts {counts}, rooms_in_use {v.get('rooms_in_use')}, live rows {rooms}")
            if "stored_work" not in rows or rows["stored_work"] is not None:
                raise Abort("custom_guest_stored_work_present", f"stored_work {rows.get('stored_work', 'absent')}")
            self.stash["H4"] = {"restart_check": rc, "rooms_in_use": v.get("rooms_in_use"), "live_rows": rooms,
                                "stored_work": None, "at": now_iso()}
            return True

        self.sub(step, "H4", h4)
        evidence = (self.j.find(self.launch, step, "H4", "done") or [{}])[-1].get("detail")
        self.set_phase(step, "inventoried", {"barrier_evidence": evidence})

        # H5 earlier holders.
        def h5() -> bool:
            f = self.facts()
            start = (f.get("kit_unit") or {}).get("active_enter")
            since = self.o.dedicated_since
            since_t = time.mktime(time.strptime(since, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone if since else None
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
            self.sub("h5", "toby_ok", lambda: bool(self.j.find(self.launch, "h5", "toby_ok", "done")),
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
            res = self.record().get("reservation") or {}
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
                self.patch(seq, "holding", "holding", {"hold_phase": "kit_stopping"})
            r = self.host_ok("hold-stop", part="a")
            self.stash["H6a"] = {"kit_attestation_before": r.get("kit_attestation_before")}

        self.sub(step, "H6a", h6a_observe, h6a_act)

        # H6b: no room list, restart-check or count_known: a stopped kit cannot answer.
        def h6b_observe() -> bool:
            return phase_at_least(self.record(), "kit_stopped") and bool(self.hj(self.facts(), "kit_stopped"))

        def h6b_act(seq: int) -> None:
            v, rec = self.view(), self.record()
            hold = v.get("custom_guest_hold") or {}
            if hold.get("launch") != self.launch or tuple_of(v) != (rec.get("reservation") or {}).get("fenced") \
                    or not rec.get("barrier_evidence"):
                raise Blocked("custom_guest_hold_lost", "H6b needs the hold, the fenced tuple and H4's evidence: Toby decides")
            r = self.host_ok("hold-stop", part="b")
            self.patch(seq, "holding", "holding", {"hold_phase": "kit_stopped",
                                                   "kit_attestation_before": r.get("kit_attestation_before")})

        self.sub(step, "H6b", h6b_observe, h6b_act)

        # H7 kit_down, authorized by the record, not a live room list.
        def h7_observe() -> bool:
            hold = self.view().get("custom_guest_hold") or {}
            return hold.get("launch") == self.launch and hold.get("kit_down") is True

        def h7_act(seq: int) -> None:
            end = time.time() + H7_WAIT
            while True:
                try:
                    status, doc = self.fence("kit_down")
                except Transport:
                    return
                if status == 200:
                    return
                code = error_code(doc)
                # The first attempt closed secret admission; the count can only fall (7.2).
                if status == 409 and code == "secret_calls_in_flight" and time.time() < end:
                    time.sleep(min(POLL, 5))
                    continue
                raise Blocked(code, f"fence kit_down: {status}")

        self.sub(step, "H7", h7_observe, h7_act)
        self.set_phase(step, "kit_down_set", {"broker_hold": {"kit_down_at": now_iso(),
                                                              "read_back": self.view().get("custom_guest_hold")}})

        # H8 host baseline.
        def h8_act(seq: int) -> None:
            self.stash["H8"] = self.host_ok("hold-baseline")

        self.sub(step, "H8", lambda: bool(self.hj(self.facts(), "baselined")), h8_act)
        self.set_phase(step, "baselined")

        # H9 held.
        def h9_act(seq: int) -> None:
            self.patch(seq, "holding", "held")

        self.sub(step, "H9", lambda: self.record()["state"] == "held", h9_act)

    def fence_until(self, to: str, exc: type) -> None:
        """POST fence; on rooms_active wait and retry up to CG_FENCE_WAIT (H3, R12, the abort restore)."""
        end = time.time() + FENCE_WAIT
        while True:
            status, doc = self.fence(to)
            if status == 200:
                return
            code = error_code(doc)
            if status == 409 and code == "rooms_active" and time.time() < end:
                time.sleep(POLL)
                continue
            raise exc("custom_guest_barrier_failed" if code == "rooms_active" else code, f"fence {to}: {status} {code}")

    # ================================================================ abort (11.2)
    def abort(self, n: int, code: str) -> None:
        step = f"abort#{n}"
        self.begin(step)

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
            v, res = self.view(), self.record().get("reservation") or {}
            t, orig = tuple_of(v), res.get("original")
            if v.get("custom_guest_hold") is None and t == orig:
                return True  # H3 never ran
            want = {"generation": orig["generation"] + 2, "ref": orig["ref"]}
            if t == want and v.get("custom_guest_hold") is None and v.get("drain") is True:
                return True
            if t == res.get("fenced"):
                return False
            raise Blocked("custom_guest_reservation_moved", f"live tuple {t}: Toby decides")

        def restored_act(seq: int) -> None:
            orig = self.record()["reservation"]["original"]
            self.patch(seq, "holding", "holding", {"reservation": self.reservation(
                restored={"generation": orig["generation"] + 2, "ref": orig["ref"]})})
            self.fence_until("restored", Blocked)

        self.sub(step, "restore", restored_observe, restored_act)
        before = bool(self.record().get("drain_before"))
        self.sub(step, "drain", lambda: bool(self.view().get("drain")) == before, lambda seq: self.drain(before))

        def approved(seq: int) -> None:
            v = self.view()
            res = self.record().get("reservation") or {}
            self.patch(seq, "holding", "approved", {"error_code": code, "hold_phase": None,
                                                    "reservation": {**res, "expect": None,
                                                                    "final": tuple_of(v)}})

        self.sub(step, "approved", lambda: self.record()["state"] == "approved", approved)
        self.end(step)

    def step_abort(self) -> None:
        rec = self.record()
        if rec["state"] != "holding":
            raise Blocked("custom_guest_state_conflict", f"abort needs holding, the record is {rec['state']}")
        self.abort(int((rec.get("reservation") or {}).get("attempt") or 1), self.o.reason or "custom_guest_hold_failed")

    # ================================================================ boot, stop (11.3, 11.5)
    def step_boot(self) -> None:
        rec = self.record()
        if rec["state"] == "booting":
            gen = int(rec["generation"])
        elif rec["state"] in ("held", "stopped"):
            gen = int(rec.get("generation") or 0) + 1
        elif rec["state"] == "running":
            print(json.dumps({"ok": True, "state": "running"}))
            return
        else:
            raise Blocked("custom_guest_state_conflict", f"boot needs held or stopped, the record is {rec['state']}")
        step = f"boot#{gen}"
        self.begin(step, gen)
        frm = rec["state"]

        def booting(seq: int) -> None:
            self.patch(seq, frm, "booting", {"stop_reason": None, "error_code": None}, generation=gen)

        self.sub(step, "booting", lambda: self.record()["state"] in ("booting", "running")
                 and int(self.record().get("generation") or 0) == gen, booting, gen)
        rec = self.record()
        data = {"generation": gen, "bootstrap_signature_b64": rec["bootstrap_signature_b64"],
                "manifest_sha256": rec["manifest_sha256"], "bootstrap_sha256": rec["bootstrap_sha256"]}
        try:
            self.sub(step, "host_boot", lambda: bool([e for e in self.hj(self.facts(), "booted") if e.get("generation") == gen]),
                     lambda seq: self.host_ok("boot", data), gen)
            self.sub(step, "disks", lambda: False, lambda seq: self.host_ok("verify-disks", context=f"boot{gen}"), gen) \
                if not self.j.done(self.launch, step, "disks") else None
        except Blocked as e:
            if self.record()["state"] == "booting":
                seq = self.j.write(self.launch, gen, step, "boot_failed", "intent", {"error_code": e.code})
                self.patch(seq, "booting", "stopped", {"stop_reason": "boot_failed", "error_code": e.code,
                                                       "error_detail": e.detail[:300]})
                self.j.write(self.launch, gen, step, "boot_failed", "done")
            self.end(step, gen)
            raise

        def running(seq: int) -> None:
            self.patch(seq, "booting", "running")

        self.sub(step, "running", lambda: self.record()["state"] == "running", running, gen)
        self.end(step, gen)

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
        self.sub(step, "host_stop", lambda: False, lambda seq: self.host_ok("stop"), gen) \
            if not self.j.done(self.launch, step, "host_stop") else None
        self.sub(step, "stopped", lambda: self.record()["state"] == "stopped",
                 lambda seq: self.patch(seq, "stopping", "stopped"), gen)
        self.end(step, gen)

    # ================================================================ return (11.6)
    def notice_ok(self, rec: dict) -> bool:
        for r in reversed(rec.get("owner_requests") or []):
            if r.get("action") == "return":
                return bool(r.get("waive_notice"))
        if self.o.notice_sent_at:
            t = time.mktime(time.strptime(self.o.notice_sent_at, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone
            return time.time() - t >= NOTICE_SECONDS
        return False

    def step_return(self) -> None:
        step = "return"
        rec = self.record()
        if not self.open_step(step):
            if rec["state"] not in ("held", "stopped"):
                raise Blocked("custom_guest_state_conflict", f"return needs held or stopped, the record is {rec['state']}")
            if not self.notice_ok(rec):
                raise Blocked("custom_guest_state_conflict", "no owner waiver and no notice 72 h old (--notice-sent-at)")
        self.begin(step)
        if self.record()["state"] == "returned":
            self.return_finish(step)
            self.end(step)
            return
        self.sub(step, "R0", lambda: self.record()["state"] in ("returning", "returned"),
                 lambda seq: self.patch(seq, self.record()["state"], "returning",
                                        {"reservation": self.reservation(expect="fenced")}))

        def kit(seq: int) -> None:
            r = self.host_ok("return-kit")
            self.patch(seq, "returning", "returning", {"kit_boot": r["kit_boot"], "disk_verified": r["disk_verified"]})

        self.sub(step, "R1_R10", lambda: bool(self.record().get("kit_boot")) and
                 (self.record().get("kit_boot") or {}).get("invocation_id") ==
                 (self.facts().get("kit_unit") or {}).get("invocation_id"), kit)

        def r11() -> bool:
            boot = self.record()["kit_boot"]
            end = time.time() + ADMIT_WAIT
            while True:
                v = self.view()
                adm = v.get("admission") or {}
                at = adm.get("attested_at")
                at_t = time.mktime(time.strptime(at, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone if at else 0
                rc = self.restart_check()
                if v.get("up") and adm.get("state") == "admitted" and adm.get("measurement") == boot["measurement"] \
                        and at_t >= (boot.get("active_enter") or 0) and rc.get("count_known") is True:
                    self.stash["R11"] = {"admission": adm, "count_known": True}
                    return True
                if time.time() >= end:
                    seq = self.j.write(self.launch, None, step, "R11_wait", "failed")
                    self.patch(seq, "returning", "returning", {"error_code": "custom_guest_return_not_admitted"})
                    raise Blocked("custom_guest_return_not_admitted", "no admission for the R9 boot")
                time.sleep(POLL)

        self.sub(step, "R11", r11)

        def r12_observe() -> bool:
            v, res = self.view(), self.record().get("reservation") or {}
            t, orig = tuple_of(v), res["original"]
            if t == {"generation": orig["generation"] + 2, "ref": orig["ref"]} and v.get("custom_guest_hold") is None \
                    and v.get("drain") is True:
                return True
            if t == res.get("fenced"):
                return False
            raise Blocked("custom_guest_reservation_moved", f"live tuple {t}: Toby decides")

        def r12_act(seq: int) -> None:
            orig = self.record()["reservation"]["original"]
            self.patch(seq, "returning", "returning", {"reservation": self.reservation(
                restored={"generation": orig["generation"] + 2, "ref": orig["ref"]})})
            self.fence_until("restored", Blocked)

        self.sub(step, "R12", r12_observe, r12_act)
        before = bool(self.record().get("drain_before"))
        self.sub(step, "R13", lambda: bool(self.view().get("drain")) == before, lambda seq: self.drain(before))
        self.sub(step, "R14", lambda: self.record()["state"] == "returned",
                 lambda seq: self.patch(seq, "returning", "returned",
                                        {"reservation": self.reservation(expect="restored"), "error_code": None}))
        self.return_finish(step)
        self.end(step)

    def return_finish(self, step: str) -> None:
        def done() -> bool:
            f = self.facts()
            return f.get("marker") is None and not f.get("launch_dir") and f.get("custom_unit") is None

        self.sub(step, "R15", done, lambda seq: self.host_ok("return-finish", {"record_state": self.record()["state"]}))

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
        self.sub(step, "discard", lambda: not self.facts().get("launch_dir"), lambda seq: self.host_ok("discard"))
        self.sub(step, "cancelled", lambda: self.record()["state"] == "cancelled",
                 lambda seq: self.patch(seq, frm, "cancelled"))
        self.end(step)

    def step_resume(self) -> None:
        opened = []
        for e in self.j.find(self.launch, sub="begin"):
            if self.open_step(e["step"]) and e["step"] not in opened:
                opened.append(e["step"])
        if not opened:
            print(json.dumps({"ok": True, "open": None}))
            return
        step = opened[-1]
        kind = step.split("#", 1)[0]
        {"intake": self.step_intake, "measure": self.step_measure, "hold": self.step_hold, "abort": self.step_abort,
         "boot": self.step_boot, "stop": self.step_stop, "return": self.step_return,
         "cancel": self.step_cancel}[kind]()

    def step_reconcile(self) -> int:
        """Reads only, and projects host facts forward into the record. Starts nothing (5.4)."""
        rec = self.record()
        if int(rec.get("journal_seq") or 0) > self.j.max_seq():
            print(json.dumps({"ok": False, "error_code": "custom_guest_journal_behind",
                              "detail": f"API journal_seq {rec.get('journal_seq')} > local {self.j.max_seq()}"}))
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
        if st == "returned" and (f.get("marker") or f.get("launch_dir")):
            alerts.append("R15 open: the marker or the launch folder is still on the host; run resume")
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
        print(json.dumps({"ok": not alerts, "state": self.record()["state"], "alerts": alerts}))
        return 2 if alerts else 0


def step_record_versions(hotel: str, where: list[str], commits: list[str]) -> None:
    if not where or len(where) != len(commits) or not all(re.fullmatch(r"[0-9a-f]{7,40}", c) for c in commits):
        raise Blocked("custom_guest_request_invalid", "--where NAME --commit SHA, one pair per conveyor or operator machine")
    j = Journal(hotel)
    j.write(None, None, "versions", "roll_sh", "done", dict(zip(where, commits)))
    print(json.dumps({"ok": True, "versions": dict(zip(where, commits))}))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="custom-guest.sh", description=__doc__.splitlines()[0])
    ap.add_argument("step", choices=["fetch", "intake", "measure", "hold", "abort", "boot", "stop", "return", "resume",
                                     "reconcile", "cancel", "record-versions"])
    ap.add_argument("--hotel", required=True)
    ap.add_argument("--launch-id")
    ap.add_argument("--toby-go", help="message ref of Toby's written go for a customer image (4.1)")
    ap.add_argument("--path", choices=["platform", "self-serve"], help="the dedicated path (3)")
    ap.add_argument("--direct-guest", help="self-serve path: the owner's direct guest")
    ap.add_argument("--order", help="self-serve path: the owner's ready order id")
    ap.add_argument("--dedicated-since", help="H5: time of the reservation change, YYYY-MM-DDTHH:MM:SSZ")
    ap.add_argument("--h5-ok", help="H5: message ref of Toby's OK for an earlier holder's leftovers")
    ap.add_argument("--h5-holder", help="H5: the earlier holder Toby's OK names")
    ap.add_argument("--notice-sent-at", help="return: when the 72 h notice went out, YYYY-MM-DDTHH:MM:SSZ")
    ap.add_argument("--reason", help="abort: the error code to record")
    ap.add_argument("--where", action="append", default=[])
    ap.add_argument("--commit", action="append", default=[])
    o = ap.parse_args(argv)
    try:
        if o.step == "record-versions":
            step_record_versions(o.hotel, o.where, o.commit)
            return 0
        if not o.launch_id:
            raise Blocked("custom_guest_request_invalid", "--launch-id is required")
        op = Op(o.hotel, o.launch_id, o)
        if o.step == "reconcile":
            return op.step_reconcile()
        getattr(op, "step_" + o.step.replace("-", "_"))()
        if o.step not in ("fetch",):
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

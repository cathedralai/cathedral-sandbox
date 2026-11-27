"""AB#999 VM6, host side: rebundle (VM runtime spec r3 7.5 step 1) and rewrap (7.5 step 4) in
room-kit/vm/vm_ctl.py, and the mailbox of room-kit/vm/vm_mailbox.py. The fake host of
test_ab991_vm_runtime (no KVM, no root); one test runs as root through sudo -n, as on CI."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

from test_ab991_vm_runtime import CTL, KIT, host  # noqa: F401  (the fixture)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "vm_mailbox_v1.json"
ME = pwd.getpwuid(os.getuid())


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load("vm_mailbox_test", KIT / "vm_mailbox.py")
measure = _load("vm_measure_rebundle_test", KIT / "vm_measure.py")

# sev-snp-measure stand-in whose answer depends on what it measures: a kernel fix moves it.
MEASURE_TOOL = '''#!/usr/bin/env python3
import hashlib, sys
a = sys.argv[1:]
if a == ["--version"]:
    print("sev-snp-measure 0.0.12")
    sys.exit(0)
h = hashlib.sha384()
for flag in ("--ovmf", "--kernel", "--initrd"):
    with open(a[a.index(flag) + 1], "rb") as f:
        h.update(f.read())
h.update(a[a.index("--append") + 1].encode())
h.update(a[a.index("--vcpus") + 1].encode())
print(h.hexdigest())
'''


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def op(n: int) -> str:
    return "%032x" % (0xA5000000 + n)


class Site:
    """The fake host plus what rebundle needs: a second bundle with the same base root (a kernel
    fix), one with another base root, and one that is on disk but not enabled."""

    def __init__(self, host):
        self.h = host
        tool = host.bin / "sev-snp-measure"
        tool.write_text(MEASURE_TOOL)
        tool.chmod(0o755)
        self.b1 = host.bundle
        self.b2 = self.bundle("kernel-fix", kernel_byte=1)
        self.b3 = self.bundle("other-base", verity="cd" * 32)
        self.b4 = self.bundle("not-enabled", kernel_byte=2, enable=False)

    def bundle(self, label: str, kernel_byte: int = 0, verity: str | None = None, enable: bool = True) -> str:
        bundles = self.h.root / "bundles"
        staging = self.h.root.parent / f"staging-{label}"
        shutil.copytree(bundles / self.h.bundle, staging)
        manifest = json.loads((staging / "manifest.json").read_bytes())
        manifest["label"] = label
        if kernel_byte:
            kernel = bytearray((staging / "vmlinuz").read_bytes())
            kernel[-1] ^= kernel_byte
            (staging / "vmlinuz").write_bytes(bytes(kernel))
            manifest["sha256"]["vmlinuz"] = hashlib.sha256(kernel).hexdigest()
        if verity:
            manifest["base_root_verity"] = verity
        raw = measure.canonical(manifest)
        (staging / "manifest.json").write_bytes(raw)
        bundle = hashlib.sha256(raw).hexdigest()
        staging.rename(bundles / bundle)
        if enable:
            cfg = json.loads(self.h.config.read_text())
            cfg["bundles"].append(bundle)
            self.h.config.write_text(json.dumps(cfg))
        return bundle

    @property
    def d(self) -> Path:
        return self.h.root / "vm1"

    def unit(self) -> Path:
        return self.h.units / "cathedral-vm-vm1.service"

    def launch(self) -> dict:
        return json.loads((self.d / "launch.json").read_text())

    def env(self) -> dict:
        return dict(line.split("=", 1) for line in (self.d / "vm.env").read_text().splitlines())

    def files(self) -> dict:
        return {p.name: sha(p) for p in (self.d / "launch.json", self.d / "vm.env", self.unit())}

    def rebundle(self, gen: int, src: str, dst: str, expect: int, op_id: str, extra: dict | None = None):
        return self.h.ctl("rebundle", "vm1", "--generation", str(gen), "--from", src, "--to", dst,
                          "--expect-revision", str(expect), "--op-id", op_id, extra=extra)

    def binds(self, bundle: str) -> bool:
        return any(line.startswith("BindReadOnlyPaths=") and str(self.h.root / "bundles" / bundle) in line.split()
                   for line in self.unit().read_text().splitlines())

    def ran_once(self) -> None:
        """Generation 1 authorized, started and stopped: closed, the state a rebundle needs."""
        assert self.h.ctl("authorize", "vm1", str(2**33), "1")[0] == 0
        assert self.h.ctl("start", "vm1", "--generation", "1")[0] == 0
        assert self.h.ctl("stop", "vm1", "--generation", "1")[0] == 0


@pytest.fixture
def site(host):
    s = Site(host)
    code, vm = host.create()
    assert code == 0, vm
    return s


# ---- rebundle ------------------------------------------------------------------------

def test_rebundle_commits_once_and_a_restore_is_the_same_verb(site):
    before = site.launch()
    assert before["bundle"] == site.b1 and "bundle_selection_revision" not in before
    assert site.h.ctl("status", "vm1")[1]["bundle_selection_revision"] == 0
    code, res = site.rebundle(0, site.b1, site.b2, 0, op(1))  # never started: generation 0
    assert code == 0, res
    assert res["bundle"] == site.b2 and res["bundle_selection_revision"] == 1 and res["op_id"] == op(1)
    assert res["expected_measurement"] != before["expected_measurement"]  # the kernel moved
    after = site.launch()
    assert (after["bundle"], after["expected_measurement"]) == (site.b2, res["expected_measurement"])
    # The identity is unchanged, so HOST_DATA and the identity digest are too (spec 7.5 step 1).
    assert (after["identity_sha256"], after["host_data"], after["vm_id"]) == \
        (before["identity_sha256"], before["host_data"], before["vm_id"])
    assert [o["op_id"] for o in after["selection_ops"]] == [op(1)]
    assert site.env()["VM_BUNDLE"] == f"'{site.b2}'" and site.binds(site.b2) and not site.binds(site.b1)
    assert json.loads((site.d / "selection-synced.json").read_text()) == {"revision": 1}
    assert "daemon-reload" in (site.h.root.parent / "systemd.json.log").read_text()
    status = site.h.ctl("status", "vm1")[1]
    assert (status["bundle"], status["bundle_selection_revision"]) == (site.b2, 1)
    # Restore: the same verb back to B1; the revision goes up like any selection change.
    code, res = site.rebundle(0, site.b2, site.b1, 1, op(2))
    assert code == 0 and res["bundle_selection_revision"] == 2
    assert site.launch()["expected_measurement"] == before["expected_measurement"]
    assert site.env()["VM_BUNDLE"] == f"'{site.b1}'" and site.binds(site.b1)


def test_a_stale_selection_exits_17_and_changes_nothing(site):
    assert site.rebundle(0, site.b1, site.b2, 0, op(1))[0] == 0
    files = site.files()
    # A second caller read revision 0 too: its change is refused, whichever bundle it names.
    code, res = site.rebundle(0, site.b2, site.b1, 0, op(2))
    assert (code, res["error"]) == (17, "stale_selection")
    code, res = site.rebundle(0, site.b2, site.b1, 5, op(3))  # ahead of the host is stale too
    assert (code, res["error"]) == (17, "stale_selection")
    assert site.files() == files and site.launch()["bundle_selection_revision"] == 1


def test_a_replayed_op_id_returns_its_stored_result_unchanged(site):
    code, first = site.rebundle(0, site.b1, site.b2, 0, op(1))
    assert code == 0
    assert site.rebundle(0, site.b2, site.b1, 1, op(2))[0] == 0
    files = site.files()
    # A delayed retry of op 1 after op 2 moved the VM back: op 1's answer, and nothing moves.
    code, again = site.rebundle(0, site.b1, site.b2, 0, op(1))
    assert (code, again) == (0, first)
    assert site.files() == files and site.launch()["bundle"] == site.b1
    # The same op_id for another request is a caller bug, not a retry.
    code, res = site.rebundle(0, site.b1, site.b4, 0, op(1))
    assert (code, res["error"]) == (2, "op_id_conflict")
    assert site.files() == files


def test_the_op_log_keeps_the_last_64(site):
    launch = site.launch()
    ops = [{"op_id": op(i), "request": {"generation": 0, "from": site.b2 if i % 2 else site.b1,
                                        "to": site.b1 if i % 2 else site.b2, "expect_revision": i},
            "result": {"n": i}} for i in range(64)]
    launch.update(bundle_selection_revision=64, selection_ops=ops)
    (site.d / "launch.json").write_text(json.dumps(launch, sort_keys=True) + "\n")
    (site.d / "selection-synced.json").write_text('{"revision": 64}\n')
    assert site.rebundle(0, site.b1, site.b2, 64, op(64))[0] == 0
    kept = [o["op_id"] for o in site.launch()["selection_ops"]]
    assert len(kept) == 64 and kept[0] == op(1) and kept[-1] == op(64)
    # op 0 was evicted: a late retry of it is a new request now, and stale.
    code, res = site.rebundle(0, site.b1, site.b2, 0, op(0))
    assert (code, res["error"]) == (17, "stale_selection")
    assert site.rebundle(0, site.b2, site.b1, 1, op(1)) == (0, {"n": 1})


@pytest.mark.parametrize("case", ["stale_generation", "generation_open", "bundle_changed", "vm_not_stopped",
                                  "bundle_not_enabled", "bundle_incompatible", "no_bundle"])
def test_fences_refuse_and_write_nothing(site, case):
    site.ran_once()  # generation 1 closed
    src, dst, gen, code_want = site.b1, site.b2, 1, 3
    if case == "stale_generation":
        gen = 0
    elif case == "generation_open":
        # Authorizing the next run raises the generation: a delayed rebundle for 1 is stale,
        # and one for 2 waits until run 2 is cancelled (refused while it is open).
        assert site.h.ctl("authorize", "vm1", str(2**33), "2")[0] == 0
        assert site.rebundle(1, src, dst, 0, op(9))[1]["error"] == "stale_generation"
        gen = 2
    elif case == "bundle_changed":
        src, dst = site.b2, site.b1
    elif case == "vm_not_stopped":
        state = site.h.systemd()
        state["cathedral-vm-vm1.service"]["active"] = True
        (site.h.root.parent / "systemd.json").write_text(json.dumps(state))
    elif case == "bundle_not_enabled":
        dst, code_want = site.b4, 1
    elif case == "bundle_incompatible":
        dst, code_want = site.b3, 1
    elif case == "no_bundle":
        # Enabled in the host file, but its directory is gone.
        shutil.rmtree(site.h.root / "bundles" / site.b2)
        code_want = 1
    files = site.files()
    code, res = site.rebundle(gen, src, dst, 0, op(1))
    assert (code, res["error"]) == (code_want, case), res
    assert site.files() == files and "selection_ops" not in site.launch()
    if case == "generation_open":
        # Cancelling run 2 closes it as never started: the rebundle for 2 goes through.
        assert site.h.ctl("cancel", "vm1", "2")[0] == 0
        assert site.rebundle(2, src, dst, 0, op(1))[0] == 0


@pytest.mark.parametrize("args,error", [
    (["--from", "B1", "--to", "B2", "--expect-revision", "0", "--op-id", op(1)], "missing_option"),
    (["--generation", "0", "--from", "B1", "--to", "B1", "--expect-revision", "0", "--op-id", op(1)], "invalid_bundle"),
    (["--generation", "0", "--from", "B1", "--to", "B2x", "--expect-revision", "0", "--op-id", op(1)], "invalid_bundle"),
    (["--generation", "0", "--from", "B1", "--to", "B2", "--expect-revision", "0", "--op-id", op(1)[:-1]], "invalid_op_id"),
    (["--generation", "0", "--from", "B1", "--to", "B2", "--expect-revision", "0", "--op-id", op(1).upper()],
     "invalid_op_id"),
    (["--generation", "0", "--from", "B1", "--to", "B2", "--expect-revision", "-1", "--op-id", op(1)],
     "invalid_expect_revision"),
    (["--generation", "x", "--from", "B1", "--to", "B2", "--expect-revision", "0", "--op-id", op(1)],
     "invalid_generation"),
])
def test_bad_requests_exit_2(site, args, error):
    args = [{"B1": site.b1, "B2": site.b2, "B2x": site.b2[:-1] + "G"}.get(a, a) for a in args]
    files = site.files()
    code, res = site.h.ctl("rebundle", "vm1", *args)
    assert (code, res["error"]) == (2, error)
    assert site.files() == files


# ---- a rebundle cut at every step after its fences ---------------------------------------

class Cut(BaseException):
    """A crash: nothing catches it, as nothing catches SIGKILL."""


def in_process(site, monkeypatch):
    for k, v in site.h.environ.items():
        monkeypatch.setenv(k, v)
    return _load("vm_ctl_cut_test", KIT / "vm_ctl.py")


@pytest.mark.parametrize("cut", ["measure", "launch.json", "vm.env", "unit", "daemon-reload", "marker"])
def test_a_cut_rebundle_is_finished_by_its_retry_or_the_next_start(site, monkeypatch, capsys, cut):
    site.ran_once()
    mod = in_process(site, monkeypatch)
    real_write, real_systemctl = mod.write_atomic, mod.systemctl

    def write(path, data, mode=0o600):
        if {"launch.json": "launch.json", "vm.env": "vm.env", "unit": "cathedral-vm-vm1.service",
                "marker": "selection-synced.json"}.get(cut) == path.name:
            raise Cut()
        return real_write(path, data, mode)

    def systemctl(*args, check=True):
        if cut == "daemon-reload" and args == ("daemon-reload",):
            raise Cut()
        return real_systemctl(*args, check=check)

    def values(*a):
        raise Cut()

    monkeypatch.setattr(mod, "write_atomic", write)
    monkeypatch.setattr(mod, "systemctl", systemctl)
    if cut == "measure":
        monkeypatch.setattr(mod, "selection_values", values)
    argv = ["rebundle", "vm1", "--generation", "1", "--from", site.b1, "--to", site.b2,
            "--expect-revision", "0", "--op-id", op(1)]
    with pytest.raises(Cut):
        mod.main(argv)
    committed = cut not in ("measure", "launch.json")
    assert site.launch()["bundle"] == (site.b2 if committed else site.b1)
    assert site.launch().get("bundle_selection_revision", 0) == (1 if committed else 0)
    if committed:
        # Before the derived files are done, no launch gets through: check-paid refuses (run 2 is
        # authorized and paid, so the selection check is the one that answers).
        assert site.h.ctl("authorize", "vm1", str(2**33), "2")[0] == 0
        code, res = site.h.ctl("check-paid", "vm1")
        assert (code, res["error"]) == (3, "selection_unsynced")
    # The retry (a new process, same op_id) applies it exactly once or returns the stored result,
    # and leaves every derived file and systemd done.
    log = site.h.root.parent / "systemd.json.log"
    log.write_text("")
    code, res = site.h.ctl(*argv)
    assert code == 0 and res["bundle"] == site.b2 and res["bundle_selection_revision"] == 1
    assert [o["op_id"] for o in site.launch()["selection_ops"]] == [op(1)]
    assert site.env()["VM_BUNDLE"] == f"'{site.b2}'" and site.binds(site.b2)
    assert "daemon-reload" in log.read_text()  # also when the cut fell after the unit write
    assert json.loads((site.d / "selection-synced.json").read_text()) == {"revision": 1}


@pytest.mark.parametrize("cut", ["vm.env", "daemon-reload"])
def test_start_finishes_a_cut_rebundle_before_it_launches(site, monkeypatch, cut):
    site.ran_once()
    mod = in_process(site, monkeypatch)
    real_write, real_systemctl = mod.write_atomic, mod.systemctl
    monkeypatch.setattr(mod, "write_atomic",
                        lambda p, data, mode=0o600: (_ for _ in ()).throw(Cut()) if p.name == cut
                        else real_write(p, data, mode))
    monkeypatch.setattr(mod, "systemctl",
                        lambda *a, check=True: (_ for _ in ()).throw(Cut()) if a == (cut,)
                        else real_systemctl(*a, check=check))
    with pytest.raises(Cut):
        mod.main(["rebundle", "vm1", "--generation", "1", "--from", site.b1, "--to", site.b2,
                  "--expect-revision", "0", "--op-id", op(1)])
    assert site.h.ctl("authorize", "vm1", str(2**33), "2")[0] == 0
    log = site.h.root.parent / "systemd.json.log"
    log.write_text("")
    code, vm = site.h.ctl("start", "vm1", "--generation", "2")
    assert code == 0 and vm["bundle"] == site.b2 and vm["state"] == "running"
    lines = log.read_text().splitlines()
    assert lines.index("daemon-reload") < next(i for i, l in enumerate(lines) if l.startswith("start "))
    assert site.env()["VM_BUNDLE"] == f"'{site.b2}'" and site.binds(site.b2)
    assert site.h.ctl("check-paid", "vm1")[0] == 0


def test_a_sigkill_during_daemon_reload_is_finished_by_the_retry(site):
    """A real crash: systemctl daemon-reload kills vm-ctl (its parent) with SIGKILL."""
    site.ran_once()
    killer = site.h.root.parent / "killbin"
    killer.mkdir()
    (killer / "systemctl").write_text(textwrap.dedent(f"""\
        #!/bin/sh
        if [ "$1" = daemon-reload ]; then kill -9 $PPID; exit 1; fi
        exec {site.h.bin / 'systemctl'} "$@"
        """))
    (killer / "systemctl").chmod(0o755)
    argv = ["rebundle", "vm1", "--generation", "1", "--from", site.b1, "--to", site.b2,
            "--expect-revision", "0", "--op-id", op(1)]
    p = subprocess.run([str(CTL), *argv], capture_output=True, text=True, timeout=60,
                       env={**site.h.environ, "PATH": f"{killer}:{site.h.environ['PATH']}"})
    assert p.returncode == -9 and p.stdout == ""
    assert site.launch()["bundle"] == site.b2 and site.binds(site.b2)  # the file is right ...
    assert not (site.d / "selection-synced.json").exists()  # ... systemd is not
    code, res = site.rebundle(1, site.b1, site.b2, 0, op(1))
    assert code == 0 and res["bundle_selection_revision"] == 1
    assert json.loads((site.d / "selection-synced.json").read_text()) == {"revision": 1}


# ---- the mailbox layout ----------------------------------------------------------------

def test_the_mailbox_vectors():
    v = json.loads(FIXTURE.read_text())
    lay = v["layout"]
    assert (lay["mailbox_bytes"], lay["region_bytes"], lay["header_bytes"]) == (1 << 20, 64 << 10, 48)
    assert (lay["status_offset"], lay["offer_offset"], lay["answer_offset"]) == (0, 64 << 10, 128 << 10)
    assert bytes.fromhex(lay["magic_hex"]) == b"CVMMBX1\0" == M.MAGIC
    assert lay["kinds"] == {"status": 1, "offer": 2, "answer": 3} and lay["answer_max"] == 4096
    offer = v["offer"]
    payload = M.canonical(offer["document"])
    assert payload.decode() == offer["payload_utf8"]
    region = M.encode_record(M.KIND_OFFER, payload)
    assert region[:48].hex() == offer["region_head_hex"] and sha_bytes(region) == offer["region_sha256"]
    assert M.read_offer(region) == offer["document"] and M.offer_sha256(offer["document"]) == offer["offer_sha256"]
    answer = v["answer"]
    doc = M.parse_answer(answer["input_utf8"].encode())
    assert M.canonical(doc).decode() == answer["payload_utf8"]
    region = M.answer_region(doc)
    assert region[:48].hex() == answer["region_head_hex"] and sha_bytes(region) == answer["region_sha256"]
    assert M.decode_record(region, M.KIND_ANSWER) == answer["payload_utf8"].encode()
    for case in v["invalid_answers"]:
        with pytest.raises(M.Refusal):
            M.parse_answer(case["input_utf8"].encode())
    for case in v["invalid_offer_regions"]:
        bad = bytearray(M.encode_record(M.KIND_OFFER, payload))
        for off, x in case["xor"]:
            bad[off] ^= x
        assert M.read_offer(bytes(bad)) is None, case["why"]
    assert M.read_offer(bytes(M.REGION_BYTES)) is None  # empty
    with pytest.raises(M.Refusal):
        M.parse_answer(b" " * 4097)
    with pytest.raises(M.Refusal):
        M.encode_record(M.KIND_OFFER, b"x" * (M.PAYLOAD_MAX + 1))


def sha_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# ---- rewrap ------------------------------------------------------------------------------

VEC = json.loads(FIXTURE.read_text())
OFFER = VEC["offer"]["document"]
ANSWER = VEC["answer"]["input_utf8"].encode()
STATUS_REGION = M.encode_record(M.KIND_STATUS, b'{"state":"locked"}')


def put(path: Path, offset: int, data: bytes) -> None:
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(data)


@pytest.fixture
def waiting(site):
    """vm1 running generation 1, its guest waiting with OFFER (the VM user is this test's user)."""
    env = (site.d / "vm.env").read_text().replace("VM_USER='cvm-0'", f"VM_USER='{ME.pw_name}'")
    (site.d / "vm.env").write_text(env)
    assert site.h.ctl("authorize", "vm1", str(2**33), "1")[0] == 0
    assert site.h.ctl("start", "vm1", "--generation", "1")[0] == 0
    box = site.d / "mailbox.raw"
    put(box, M.STATUS_OFFSET, STATUS_REGION)
    put(box, M.OFFER_OFFSET, M.encode_record(M.KIND_OFFER, M.canonical(OFFER)))
    return site


def rewrap(site, answer: bytes, *args: str, gen: str = "1"):
    return site.h.ctl("rewrap", "vm1", "--generation", gen, *args, stdin=answer.decode("latin-1"))


def test_status_shows_the_waiting_offer_and_rewrap_writes_only_the_answer_region(waiting):
    box = waiting.d / "mailbox.raw"
    status = waiting.h.ctl("status", "vm1")[1]
    assert status["rewrap_offer"] == {**OFFER, "offer_sha256": VEC["offer"]["offer_sha256"]}
    before = box.read_bytes()
    code, res = rewrap(waiting, ANSWER)
    assert code == 0 and res == {"name": "vm1", "generation": 1, "offer_sha256": VEC["offer"]["offer_sha256"],
                                 "written": True}
    after = box.read_bytes()
    answer_at = slice(M.ANSWER_OFFSET, M.ANSWER_OFFSET + M.REGION_BYTES)
    assert after[answer_at] == M.answer_region(M.parse_answer(ANSWER))
    assert sha_bytes(after[answer_at]) == VEC["answer"]["region_sha256"]
    assert after[:M.ANSWER_OFFSET] == before[:M.ANSWER_OFFSET]  # status and offer untouched
    assert after[answer_at.stop:] == before[answer_at.stop:]
    # A retry (the broker's answer was lost), in any key order: the same record, not written again.
    code, res = rewrap(waiting, M.canonical(M.parse_answer(ANSWER)))
    assert code == 0 and res["written"] is False and box.read_bytes() == after


@pytest.mark.parametrize("offer_region", ["empty", "bad magic", "another kind", "length past the payload",
                                          "sha256 mismatch", "payload byte changed", "a byte after the payload"])
def test_rewrap_refuses_without_a_valid_offer(waiting, offer_region):
    box = waiting.d / "mailbox.raw"
    region = bytearray(M.encode_record(M.KIND_OFFER, M.canonical(OFFER)))
    if offer_region == "empty":
        region = bytearray(M.REGION_BYTES)
    for case in VEC["invalid_offer_regions"]:
        if case["why"] == offer_region:
            for off, x in case["xor"]:
                region[off] ^= x
    put(box, M.OFFER_OFFSET, bytes(region))
    before = box.read_bytes()
    code, res = rewrap(waiting, ANSWER)
    assert (code, res["error"]) == (3, "no_rewrap_offer")
    assert box.read_bytes() == before
    assert "rewrap_offer" not in waiting.h.ctl("status", "vm1")[1]


def test_rewrap_fences_the_offer_and_the_run(waiting):
    box = waiting.d / "mailbox.raw"
    before = box.read_bytes()
    other = json.loads(ANSWER)
    other["offer_sha256"] = "0" * 64  # wrapped for an offer the guest no longer waits with
    code, res = rewrap(waiting, json.dumps(other).encode())
    assert (code, res["error"]) == (3, "rewrap_offer_changed")
    code, res = rewrap(waiting, ANSWER, gen="2")
    assert (code, res["error"]) == (3, "stale_generation")
    # The unit went down inside the run (the guest powered off after its wait): nothing waits.
    state = waiting.h.systemd()
    state["cathedral-vm-vm1.service"]["active"] = False
    (waiting.h.root.parent / "systemd.json").write_text(json.dumps(state))
    code, res = rewrap(waiting, ANSWER)
    assert (code, res["error"]) == (3, "no_rewrap_offer")
    assert "rewrap_offer" not in waiting.h.ctl("status", "vm1")[1]
    state["cathedral-vm-vm1.service"]["active"] = True
    (waiting.h.root.parent / "systemd.json").write_text(json.dumps(state))
    assert waiting.h.ctl("stop", "vm1", "--generation", "1")[0] == 0
    code, res = rewrap(waiting, ANSWER)
    assert (code, res["error"]) == (3, "generation_closed")
    assert box.read_bytes() == before


@pytest.mark.parametrize("why", [c["why"] for c in VEC["invalid_answers"]] + ["4097 bytes", "empty"])
def test_rewrap_refuses_a_bad_answer_before_it_looks(waiting, why):
    raw = {"4097 bytes": ANSWER + b" " * (4097 - len(ANSWER)), "empty": b""}.get(why)
    if raw is None:
        raw = next(c["input_utf8"] for c in VEC["invalid_answers"] if c["why"] == why).encode()
    before = (waiting.d / "mailbox.raw").read_bytes()
    code, res = rewrap(waiting, raw)
    assert (code, res["error"]) == (2, "invalid_rewrap_answer")
    assert (waiting.d / "mailbox.raw").read_bytes() == before
    # 4096 bytes (the cap) with spaces is still one valid answer.
    assert rewrap(waiting, ANSWER + b" " * (4096 - len(ANSWER)))[0] == 0


@pytest.mark.parametrize("swap", ["symlink", "hardlink", "size", "fifo"])
def test_rewrap_opens_the_mailbox_only_as_the_vm_users_regular_file(waiting, swap):
    box = waiting.d / "mailbox.raw"
    victim = waiting.h.root.parent / "victim"
    victim.write_bytes(box.read_bytes())  # a well-formed 1 MiB file with the offer in it
    box.unlink()
    if swap == "symlink":
        box.symlink_to(victim)
    elif swap == "hardlink":
        os.link(victim, box)
    elif swap == "size":
        box.write_bytes(victim.read_bytes() + b"\0")
    else:
        os.mkfifo(box)
    want = victim.read_bytes()
    code, res = rewrap(waiting, ANSWER)
    assert (code, res["error"]) == (1, "mailbox_invalid")
    assert victim.read_bytes() == want
    assert waiting.h.ctl("status", "vm1")[1]["rewrap_offer_error"] == "mailbox_invalid"


def test_rewrap_takes_the_answer_on_stdin_only(waiting, monkeypatch):
    # From the broker: the forced command, the answer on stdin.
    env = {"SSH_ORIGINAL_COMMAND": "vm-ctl.sh rewrap vm1 --generation 1"}
    p = subprocess.run([str(CTL), "--from-broker"], input=ANSWER, capture_output=True, timeout=60,
                       env={**waiting.h.environ, **env})
    assert p.returncode == 0 and json.loads(p.stdout)["written"] is True
    # No argument can carry an answer: every extra token is refused before stdin matters.
    for cmd in ("vm-ctl.sh rewrap vm1 --generation 1 --answer x", "vm-ctl.sh rewrap vm1 x --generation 1",
                "vm-ctl.sh rewrap vm1 --generation 1 --generation 1"):
        p = subprocess.run([str(CTL), "--from-broker"], input=ANSWER, capture_output=True, timeout=60,
                           env={**waiting.h.environ, "SSH_ORIGINAL_COMMAND": cmd})
        assert p.returncode == 2 and json.loads(p.stdout)["error"] in ("invalid_option", "usage"), cmd
    # The internal writer is never reachable from the broker.
    p = subprocess.run([str(CTL), "--from-broker"], input=b"", capture_output=True, timeout=60,
                       env={**waiting.h.environ, "SSH_ORIGINAL_COMMAND": "mailbox-write-as-vm-user 3 1 1"})
    assert p.returncode == 2 and json.loads(p.stdout)["error"] == "invalid_command"
    # Only create and rewrap read stdin.
    mod = in_process(waiting, monkeypatch)

    class NoRead:
        def read(self, *a):
            raise AssertionError("stdin read")
        buffer = property(lambda self: self)

    monkeypatch.setattr(mod.sys, "stdin", NoRead())
    for verb in ("status vm1", "stop vm1 --generation 1", "rebundle vm1 --generation 1", "list"):
        monkeypatch.setenv("SSH_ORIGINAL_COMMAND", verb)
        assert mod.from_broker()[1] is None
    assert "mailbox-write-as-vm-user" not in mod.COMMANDS


def test_the_answer_writer_refuses_root_and_anything_but_an_answer_record(monkeypatch):
    mod = _load("vm_ctl_writer_test", KIT / "vm_ctl.py")
    monkeypatch.setattr(mod.os, "geteuid", lambda: 0)
    with pytest.raises(mod.Refusal):
        mod.cmd_mailbox_write_as_vm_user(["3", "1", "1"])
    monkeypatch.setattr(mod.os, "geteuid", lambda: 1000)
    for region in (bytes(M.REGION_BYTES), M.encode_record(M.KIND_OFFER, M.canonical(OFFER)), b"x"):
        monkeypatch.setattr(mod.sys, "stdin", type("S", (), {"buffer": __import__("io").BytesIO(region)})())
        with pytest.raises(mod.Refusal) as e:
            mod.cmd_mailbox_write_as_vm_user(["3", "1", "1"])
        assert e.value.error == "invalid_rewrap_answer"


ROOT_SWAP = textwrap.dedent('''
    import importlib.util, json, os, pwd, shutil, sys
    kit, base, region_hex = sys.argv[1], sys.argv[2], sys.argv[3]
    nobody = pwd.getpwnam("nobody")
    region = bytes.fromhex(region_hex)
    try:
        kit_copy = os.path.join(base, "kit")  # world-readable, so the dropped child can run it
        os.mkdir(kit_copy, 0o755)
        for f in ("vm_ctl.py", "vm_measure.py", "vm_mailbox.py"):
            shutil.copy(os.path.join(kit, f), kit_copy)
        vms = os.path.join(base, "vms")
        os.environ["VM_ROOT"] = vms
        spec = importlib.util.spec_from_file_location("vm_ctl_root", os.path.join(kit_copy, "vm_ctl.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        MB = 1 << 20

        def vm(name):
            d = os.path.join(vms, name)
            os.makedirs(d)
            os.chmod(d, 0o700)  # root's, as create makes it
            box = os.path.join(d, "mailbox.raw")
            with open(box, "wb") as f:
                f.truncate(MB)
            os.chown(box, nobody.pw_uid, nobody.pw_gid)
            os.chmod(box, 0o600)
            return d, box
        victim = os.path.join(base, "victim")  # root's own file, 1 MiB, 0600
        with open(victim, "wb") as f:
            f.truncate(MB)
        os.chmod(victim, 0o600)
        out = {}
        # Positive control: the VM user's own mailbox is written, as that user.
        d, box = vm("vm1")
        mod.mailbox_write_answer(mod.Path(d), "nobody", region)
        with open(box, "rb") as f:
            f.seek(128 << 10)
            out["own"] = f.read(len(region)) == region
        # A link swapped in for the mailbox: refused, the victim unchanged.
        d, box = vm("vm2")
        os.unlink(box)
        os.symlink(victim, box)
        try:
            mod.mailbox_write_answer(mod.Path(d), "nobody", region)
            out["symlink"] = "written"
        except mod.Refusal as e:
            out["symlink"] = e.error
        # A hard link to root's file: root's checks refuse it; with them fooled (owner and link
        # count faked), the write still runs as the VM user and the kernel refuses it.
        d, box = vm("vm3")
        os.unlink(box)
        os.link(victim, box)
        try:
            mod.mailbox_write_answer(mod.Path(d), "nobody", region)
            out["hardlink"] = "written"
        except mod.Refusal as e:
            out["hardlink"] = e.error
        real_fstat = os.fstat

        def fake_fstat(fd):
            st = list(real_fstat(fd))
            st[3], st[4] = 1, nobody.pw_uid  # st_nlink, st_uid
            return os.stat_result(st)
        mod.os.fstat = fake_fstat
        try:
            mod.mailbox_write_answer(mod.Path(d), "nobody", region)
            out["hardlink_fooled"] = "written"
        except mod.Refusal as e:
            out["hardlink_fooled"] = e.error
        mod.os.fstat = real_fstat
        with open(victim, "rb") as f:
            out["victim_zero"] = not any(f.read())
        print(json.dumps(out, sort_keys=True))
    finally:
        shutil.rmtree(base, ignore_errors=True)
''')


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs Linux and passwordless sudo")
def test_a_swapped_mailbox_cannot_redirect_the_answer_write_as_root(tmp_path):
    """The answer write as root: a link swapped in for mailbox.raw is refused, and a hard link to a
    root-owned file stays unchanged even with root's checks fooled, because the child that writes
    is the VM user (team-lead VM6 P1, the #789 QMP pattern)."""
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        if os.environ.get("CI"):
            pytest.fail("CI must run this as root (sudo -n)")
        pytest.skip("no passwordless sudo")
    base = tempfile.mkdtemp(prefix="vmb", dir="/tmp")
    os.chmod(base, 0o755)
    script = tmp_path / "swap.py"
    script.write_text(ROOT_SWAP)
    region = M.answer_region(M.parse_answer(ANSWER))
    try:  # the base interpreter, so the dropped child can run it too (not a venv under $HOME)
        p = subprocess.run(["sudo", "-n", os.path.realpath(sys.executable), "-I", "-B", str(script), str(KIT), base,
                            region.hex()], capture_output=True, text=True, timeout=60)
    finally:
        shutil.rmtree(base, ignore_errors=True)  # the script removes what root made
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout.strip().splitlines()[-1]) == {
        "own": True, "symlink": "mailbox_invalid", "hardlink": "mailbox_invalid",
        "hardlink_fooled": "mailbox_write_failed", "victim_zero": True}


def test_rewrap_and_rebundle_are_documented():
    readme = (KIT / "README.md").read_text()
    for word in ("rebundle", "rewrap", "stale_selection", "bundle_selection_revision", "vm_mailbox.py"):
        assert word in readme, word

"""AB#999 VM6, host side: the mailbox (room-kit/vm/vm_mailbox.py) and rewrap (VM runtime spec r3
7.5 Mailbox and step 4) in room-kit/vm/vm_ctl.py. The fake host of test_ab991_vm_runtime (no KVM,
no root), the VM user being this test's user; one test runs as root through sudo -n, as on CI."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pwd
import re
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
OTHER_USER = "nobody"  # exists on every test host, and is not this test's user


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load("vm_mailbox_rewrap_test", KIT / "vm_mailbox.py")
VEC = json.loads(FIXTURE.read_text())
KINDS = {"status": M.KIND_STATUS, "offer": M.KIND_OFFER, "answer": M.KIND_ANSWER}
STATUS_BODY = VEC["status"]["body_utf8"].encode()
OFFER_BODY = VEC["offer"]["body_utf8"].encode()
ANSWER = VEC["answer"]["body_utf8"].encode()
OFFER_SHA = VEC["offer"]["body_sha256"]
VECTORS = json.loads((FIXTURE.parent / "vm_rewrap_answer_v2.json").read_text())


def put(path: Path, offset: int, data: bytes) -> None:
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(data)


def slot_of(path: Path, offset: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read(M.SLOT_BYTES)


def own_vm(host, name: str, user: str = ME.pw_name) -> Path:
    """The VM's user is this test's user, so the mailbox checks pass as on a host."""
    d = host.root / name
    env = (d / "vm.env").read_text()
    (d / "vm.env").write_text(re.sub(r"^VM_USER='[^']*'$", f"VM_USER='{user}'", env, flags=re.M))
    return d / "mailbox.raw"


@pytest.fixture
def waiting(host):
    """vm1 running generation 1, its guest waiting with the vector offer."""
    host.environ["VM_MAILBOX_RETRY_WAIT"] = "0"
    assert host.create()[0] == 0
    box = own_vm(host, "vm1")
    assert host.ctl("authorize", "vm1", str(2**33), "1")[0] == 0
    assert host.ctl("start", "vm1", "--generation", "1")[0] == 0
    put(box, M.STATUS_OFFSET, M.encode_slot(M.KIND_STATUS, STATUS_BODY))
    put(box, M.OFFER_OFFSET, M.encode_slot(M.KIND_OFFER, OFFER_BODY))
    host.box = box
    return host


def rewrap(host, answer: bytes, *args: str, gen: str = "1"):
    return host.ctl("rewrap", "vm1", "--generation", gen, *args, stdin=answer.decode("latin-1"))


# ---- the layout and its vectors ---------------------------------------------------------------

def test_the_mailbox_vectors():
    lay = VEC["layout"]
    assert (lay["mailbox_bytes"], lay["slot_bytes"], lay["header_bytes"]) == (1 << 20, 64 << 10, 45)
    assert (lay["status_offset"], lay["offer_offset"], lay["answer_offset"]) == (0, 64 << 10, 128 << 10)
    assert bytes.fromhex(lay["magic_hex"]) == b"CVMMBX1\0" and lay["body_max"]["answer"] == 4096
    for name, kind in KINDS.items():
        rec = VEC[name]
        body = rec["body_utf8"].encode()
        slot = M.encode_slot(kind, body)
        assert slot[:45].hex() == rec["head_hex"] and hashlib.sha256(slot).hexdigest() == rec["slot_sha256"]
        assert slot[8] == kind and int.from_bytes(slot[9:13], "big") == len(body)  # kind byte, big-endian length
        assert M.decode_slot(slot, kind) == body and M.parse_body(body, kind) == rec["document"]
    # The answer names the offer by its body's sha256, the offer record's header digest.
    assert VEC["answer"]["document"]["offer_sha256"] == OFFER_SHA == M.encode_slot(2, OFFER_BODY)[13:45].hex()
    assert M.decode_slot(bytes(M.SLOT_BYTES), M.KIND_OFFER) is None
    for case in VEC["invalid_bodies"]:
        with pytest.raises(M.Refusal):
            M.parse_body(case["body_utf8"].encode(), KINDS[case["kind"]])
    for case in VEC["torn_offer_slots"]:
        slot = bytearray(M.encode_slot(M.KIND_OFFER, OFFER_BODY))
        for at, hexed in case["edits"]:
            slot[at:at + len(bytes.fromhex(hexed))] = bytes.fromhex(hexed)
        with pytest.raises(M.Torn):
            M.decode_slot(bytes(slot), M.KIND_OFFER)
    with pytest.raises(M.Refusal):
        M.encode_slot(M.KIND_ANSWER, b"{" + b" " * 4095 + b"}")  # over the answer bound


def test_the_prescan_refuses_nesting_before_any_parser_sees_it():
    deep = b'{"a":' + b"[" * 29990 + b"]" * 29990 + b"}"
    with pytest.raises(RecursionError):  # what the parser alone would do with it
        json.loads(deep)
    for body in (deep, b'{"a":{"b":1}}', b'{"a":"[{"}x', b'{"a":"x"}}', b'{"a":"\x01"}', b"[1]", b'{"a":"\\"}'):
        with pytest.raises(M.Refusal):
            M.prescan(body, 1 << 16)
    M.prescan(b'{"a":"[{}]\\"","b":1}', 1 << 16)  # brackets and quotes inside strings are data


# ---- status: the guest's records are data, and isolated per VM ----------------------------------

def test_status_shows_the_guest_records_while_they_check(waiting):
    st = waiting.ctl("status", "vm1")[1]
    assert st["vm_state"] == "open" and st["guest_status"] == VEC["status"]["document"]
    assert st["rewrap_offer"] == {**VEC["offer"]["document"], "offer_sha256": OFFER_SHA}
    # Stopped: the offer is not shown (no guest waits), the last status record still is.
    assert waiting.ctl("stop", "vm1", "--generation", "1")[0] == 0
    st = waiting.ctl("status", "vm1")[1]
    assert st["rewrap_offer"] is None and st["vm_state"] == "open"


def test_a_deep_nested_status_body_is_an_empty_slot_and_list_keeps_every_vm(host):
    """Spec r3 7.5 Isolation: a 60 KB, 30,000-deep nested array with a valid header and sha256."""
    assert host.create("vm1", "22001")[0] == 0 and host.create("vm2", "22002")[0] == 0
    put(own_vm(host, "vm1"), M.STATUS_OFFSET, M.encode_slot(M.KIND_STATUS, b'{"a":' + b"[" * 29990 + b"]" * 29990 + b"}"))
    put(own_vm(host, "vm2"), M.STATUS_OFFSET, M.encode_slot(M.KIND_STATUS, STATUS_BODY))
    code, listed = host.ctl("list")
    assert code == 0
    vms = {v["name"]: v for v in listed["vms"]}
    assert vms["vm1"]["guest_status"] is None and vms["vm1"]["vm_state"] is None
    assert vms["vm2"]["guest_status"] == VEC["status"]["document"]
    assert host.ctl("status", "vm1")[0] == 0


def test_any_exception_in_a_slot_is_an_empty_slot(host, monkeypatch):
    assert host.create()[0] == 0
    put(own_vm(host, "vm1"), M.STATUS_OFFSET, M.encode_slot(M.KIND_STATUS, STATUS_BODY))
    for k, v in host.environ.items():
        monkeypatch.setenv(k, v)
    mod = _load("vm_ctl_isolation_test", KIT / "vm_ctl.py")
    for exc in (MemoryError, RecursionError, KeyError, ZeroDivisionError):
        def boom(*a, exc=exc):
            raise exc()
        monkeypatch.setattr(mod.vm_mailbox, "parse_body", boom)
        st = mod.status_of("vm1")
        assert st["guest_status"] is None and st["name"] == "vm1"


@pytest.mark.parametrize("why", [c["why"] for c in VEC["torn_offer_slots"]])
def test_a_slot_that_never_checks_counts_as_empty(waiting, why):
    case = next(c for c in VEC["torn_offer_slots"] if c["why"] == why)
    slot = bytearray(M.encode_slot(M.KIND_OFFER, OFFER_BODY))
    for at, hexed in case["edits"]:
        slot[at:at + len(bytes.fromhex(hexed))] = bytes.fromhex(hexed)
    put(waiting.box, M.OFFER_OFFSET, bytes(slot))
    code, st = waiting.ctl("status", "vm1")
    assert code == 0 and st["rewrap_offer"] is None and st["guest_status"] == VEC["status"]["document"]
    before = waiting.box.read_bytes()
    code, res = rewrap(waiting, ANSWER)
    assert (code, res["error"]) == (3, "no_rewrap_offer") and waiting.box.read_bytes() == before


def test_status_reads_each_slot_once_and_rewrap_waits_for_a_torn_offer(waiting, monkeypatch):
    """A prefix of the record, then the rest lands while the host waits. status and list read once
    (a torn slot is empty there, with no wait); rewrap reads the offer again until it checks, and
    one that never lands is read MAILBOX_RETRIES more times, then counts as empty."""
    whole = M.encode_slot(M.KIND_OFFER, OFFER_BODY)
    torn = whole[:45 + 700] + bytes(M.SLOT_BYTES - 745)
    put(waiting.box, M.OFFER_OFFSET, torn)
    for k, v in waiting.environ.items():
        monkeypatch.setenv(k, v)
    mod = _load("vm_ctl_torn_test", KIT / "vm_ctl.py")
    sleeps = []
    monkeypatch.setattr(mod.time, "sleep", sleeps.append)
    assert mod.status_of("vm1")["rewrap_offer"] is None and sleeps == []
    assert mod.cmd_list([])["vms"][0]["rewrap_offer"] is None and sleeps == []

    def lands(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            put(waiting.box, M.OFFER_OFFSET, whole)
    monkeypatch.setattr(mod.time, "sleep", lands)
    res = mod.cmd_rewrap(["vm1", "--generation", "1"], ANSWER)
    assert res["written"] is True and len(sleeps) == 2
    assert slot_of(waiting.box, M.ANSWER_OFFSET) == M.encode_slot(M.KIND_ANSWER, ANSWER)
    put(waiting.box, M.OFFER_OFFSET, torn)
    sleeps.clear()
    monkeypatch.setattr(mod.time, "sleep", sleeps.append)
    with pytest.raises(mod.Refusal) as refused:
        mod.cmd_rewrap(["vm1", "--generation", "1"], ANSWER)
    assert refused.value.error == "no_rewrap_offer" and len(sleeps) == mod.MAILBOX_RETRIES


def test_a_slot_that_is_always_torn_costs_list_one_read(waiting, monkeypatch):
    """A guest that keeps rewriting its slots must not slow list for the host: each slot is read
    once, with no wait, and shows as empty."""
    torn = M.encode_slot(M.KIND_OFFER, OFFER_BODY)[:45 + 700] + bytes(M.SLOT_BYTES - 745)
    put(waiting.box, M.OFFER_OFFSET, torn)
    put(waiting.box, M.STATUS_OFFSET, M.encode_slot(M.KIND_STATUS, STATUS_BODY)[:45 + 9] + bytes(M.SLOT_BYTES - 54))
    for k, v in waiting.environ.items():
        monkeypatch.setenv(k, v)
    mod = _load("vm_ctl_list_once_test", KIT / "vm_ctl.py")
    reads, sleeps = [], []
    real_pread = mod.os.pread
    monkeypatch.setattr(mod.os, "pread", lambda fd, n, at: reads.append(at) or real_pread(fd, n, at))
    monkeypatch.setattr(mod.time, "sleep", sleeps.append)
    vm = mod.cmd_list([])["vms"][0]
    assert vm["rewrap_offer"] is None and vm["guest_status"] is None
    assert sorted(reads) == [M.STATUS_OFFSET, M.OFFER_OFFSET] and sleeps == []


# ---- rewrap ------------------------------------------------------------------------------------

def test_rewrap_writes_only_the_answer_slot_once(waiting):
    before = waiting.box.read_bytes()
    code, res = rewrap(waiting, ANSWER)
    assert (code, res) == (0, {"name": "vm1", "generation": 1, "offer_sha256": OFFER_SHA, "written": True})
    after = waiting.box.read_bytes()
    answer_at = slice(M.ANSWER_OFFSET, M.ANSWER_OFFSET + M.SLOT_BYTES)
    assert after[answer_at] == M.encode_slot(M.KIND_ANSWER, ANSWER)
    assert hashlib.sha256(after[answer_at]).hexdigest() == VEC["answer"]["slot_sha256"]
    assert after[:M.ANSWER_OFFSET] == before[:M.ANSWER_OFFSET] and after[answer_at.stop:] == before[answer_at.stop:]
    # A retry (the broker's answer was lost): the same slot, not written again.
    code, res = rewrap(waiting, ANSWER)
    assert code == 0 and res["written"] is False and waiting.box.read_bytes() == after


def test_rewrap_takes_the_largest_signed_answer_whole(waiting):
    """RSA 8192 is the largest key create allows (spec r4 erratum 2.5): the answer with its
    signature is 3173 bytes in the shared vectors, and the host writes it whole. The host checks
    the shape only, so this sig need not verify here; the guest verifies it."""
    rsa = next(c for c in VECTORS["cases"] if c["name"] == "valid-rsa-8192")
    answer = M.vm_measure.canonical(dict(VEC["answer"]["document"], sig=json.loads(rsa["body"])["sig"]))
    assert len(answer) == rsa["body_bytes"] == 3173
    code, res = rewrap(waiting, answer)
    assert (code, res["written"]) == (0, True), res
    assert slot_of(waiting.box, M.ANSWER_OFFSET) == M.encode_slot(M.KIND_ANSWER, answer)


def test_the_host_parser_refuses_exactly_the_shape_cases_of_the_shared_vectors():
    """tests/fixtures/vm_rewrap_answer_v2.json: parse_answer refuses each case the reference
    refuses for its shape or length, and takes every other one, signature refusals included."""
    shape = {"answer_schema", "sig_encoding", "sig_too_long", "answer_too_long"}
    for case in VECTORS["cases"]:
        body = case["body"].encode()
        if case["refusal"] in shape:
            with pytest.raises(M.Refusal):
                M.parse_answer(body)
        else:
            assert M.parse_answer(body) == json.loads(body), case["name"]


def test_the_fixture_answer_is_signed():
    """The mailbox fixture's answer carries a real signature by the vectors' Ed25519 test key."""
    gen = _load("make_vm_rewrap_answer_vectors_rewrap_test",
                FIXTURE.parents[2] / "scripts" / "make_vm_rewrap_answer_vectors.py")
    rec = VEC["answer"]
    assert gen.refusal(rec["body_utf8"].encode(), rec["signed_by_ssh_public_key"]) is None
    assert rec["signed_by_ssh_public_key"] == gen.ed25519_key("ed25519").line


def test_an_answer_for_another_offer_is_refused(waiting):
    """The guest restarted with a new offer: an answer to the old one is stale, and not written."""
    new_offer = dict(VEC["offer"]["document"], nonce=VEC["answer"]["document"]["epk"])
    put(waiting.box, M.OFFER_OFFSET, M.encode_slot(M.KIND_OFFER, M.vm_measure.canonical(new_offer)))
    before = waiting.box.read_bytes()
    code, res = rewrap(waiting, ANSWER)
    assert (code, res["error"]) == (3, "rewrap_offer_changed") and waiting.box.read_bytes() == before


def test_rewrap_is_fenced_to_the_running_open_generation(waiting):
    before = waiting.box.read_bytes()
    assert rewrap(waiting, ANSWER, gen="2")[1]["error"] == "stale_generation"
    assert waiting.ctl("stop", "vm1", "--generation", "1")[0] == 0
    code, res = rewrap(waiting, ANSWER)
    assert (code, res["error"]) == (3, "generation_closed")
    # Authorized, not started: the unit is down, so no guest waits.
    assert waiting.ctl("authorize", "vm1", str(2**33), "2")[0] == 0
    code, res = rewrap(waiting, ANSWER, gen="2")
    assert (code, res["error"]) == (3, "no_rewrap_offer")
    assert slot_of(waiting.box, M.ANSWER_OFFSET) == bytes(M.SLOT_BYTES)
    assert waiting.box.read_bytes()[:M.ANSWER_OFFSET] == before[:M.ANSWER_OFFSET]


@pytest.mark.parametrize("why", [c["why"] for c in VEC["invalid_bodies"] if c["kind"] == "answer"]
                         + ["4097 bytes", "empty", "a trailing newline"])
def test_rewrap_refuses_a_bad_envelope_before_it_looks(waiting, why):
    if why == "4097 bytes":
        answer = ANSWER[:-1] + b" " * (4097 - len(ANSWER)) + b"}"
    elif why == "empty":
        answer = b""
    elif why == "a trailing newline":
        answer = ANSWER + b"\n"
    else:
        answer = next(c for c in VEC["invalid_bodies"] if c["why"] == why)["body_utf8"].encode()
    before = waiting.box.read_bytes()
    code, res = rewrap(waiting, answer)
    assert (code, res["error"]) == (2, "invalid_rewrap_answer")
    assert waiting.box.read_bytes() == before


@pytest.mark.parametrize("swap", ["symlink", "hardlink", "size", "owner", "fifo"])
def test_the_mailbox_is_opened_only_as_the_vm_users_own_file(waiting, swap):
    """Spec r3 7.5 Host access: openat without following a link, then fstat on the open file. The
    host read and the answer write both refuse, and nothing is changed: the file or a link target."""
    box = waiting.box
    victim = waiting.root.parent / "victim"
    victim.write_bytes(bytes(M.MAILBOX_BYTES))
    put(victim, M.OFFER_OFFSET, M.encode_slot(M.KIND_OFFER, OFFER_BODY))  # it even holds the offer
    if swap == "symlink":
        box.unlink()
        box.symlink_to(victim)
    elif swap == "hardlink":
        (waiting.root.parent / "second-name").hardlink_to(box)  # st_nlink 2
        victim = box
    elif swap == "size":
        with open(box, "ab") as f:
            f.write(b"\0")
        victim = box
    elif swap == "owner":
        own_vm(waiting, "vm1", OTHER_USER)  # the file is not the VM user's
        victim = box
    elif swap == "fifo":
        box.unlink()
        os.mkfifo(box)
    before = victim.read_bytes()
    code, st = waiting.ctl("status", "vm1")
    assert code == 0 and st["rewrap_offer"] is None and st["guest_status"] is None
    code, res = rewrap(waiting, ANSWER)
    assert (code, res["error"]) == (3, "mailbox_invalid"), res
    assert victim.read_bytes() == before


def test_rewrap_takes_the_answer_on_stdin_only(waiting):
    """From the broker: the answer on stdin, never as an argument, at most 4097 bytes read."""
    def broker(command: str, stdin: bytes):
        p = subprocess.run([str(CTL), "--from-broker"], capture_output=True, input=stdin, timeout=60,
                           env={**waiting.environ, "SSH_ORIGINAL_COMMAND": command})
        return p.returncode, json.loads(p.stdout)
    code, res = broker("rewrap vm1 --generation 1", ANSWER)
    assert code == 0 and res["written"] is True
    for extra in ("--answer x", "--answer-file x", "x"):
        code, res = broker(f"rewrap vm1 --generation 1 {extra}", ANSWER)
        assert code == 2 and res["error"] in ("invalid_option", "usage"), (extra, res)
    code, res = broker("rewrap vm1 --generation 1", ANSWER + b" " * 8192)
    assert (code, res["error"]) == (2, "invalid_rewrap_answer")


# ---- as root (CI) ------------------------------------------------------------------------------

ROOT_SWAP = textwrap.dedent('''
    import importlib.util, json, os, pwd, shutil, sys
    kit, base = sys.argv[1], sys.argv[2]
    nobody = pwd.getpwnam("nobody")
    MB = 1 << 20
    try:
        os.environ["VM_ROOT"] = os.path.join(base, "vms")
        spec = importlib.util.spec_from_file_location("vm_ctl_root", os.path.join(kit, "vm_ctl.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        def vm(name):
            d = os.path.join(base, "vms", name)
            os.makedirs(d)
            os.chmod(d, 0o700)  # root's, as create makes it
            box = os.path.join(d, "mailbox.raw")
            with open(box, "wb") as f:
                f.truncate(MB)
            os.chown(box, nobody.pw_uid, nobody.pw_gid)
            return mod.Path(d), box

        def opens(d):
            try:
                os.close(mod.mailbox_open(d, "nobody", write=True))
                return "opened"
            except mod.Refusal as e:
                return e.error
        victim = os.path.join(base, "victim")  # root's own file, 1 MiB
        with open(victim, "wb") as f:
            f.truncate(MB)
        os.chmod(victim, 0o600)
        out = {}
        d, box = vm("vm1")
        out["own"] = opens(d)  # positive control
        d, box = vm("vm2")
        os.unlink(box)
        os.symlink(victim, box)
        out["symlink"] = opens(d)
        d, box = vm("vm3")
        os.unlink(box)
        os.link(victim, box)  # root's file under the VM's name: st_uid 0, st_nlink 2
        out["hardlink_root_file"] = opens(d)
        d, box = vm("vm4")
        os.link(box, os.path.join(base, "second-name"))  # the VM user's file, st_nlink 2
        out["hardlink_own_file"] = opens(d)
        with open(victim, "rb") as f:
            out["victim_zero"] = not any(f.read())
        print(json.dumps(out, sort_keys=True))
    finally:
        shutil.rmtree(base, ignore_errors=True)
''')


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs Linux and passwordless sudo")
def test_as_root_a_swapped_mailbox_is_refused_and_its_target_unchanged(tmp_path):
    """Root's open is the one that matters: root passes every permission check, so only O_NOFOLLOW
    and the fstat owner and link count stop a link from turning the answer write onto root's file."""
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        if os.environ.get("CI"):
            pytest.fail("CI must run this as root (sudo -n)")
        pytest.skip("no passwordless sudo")
    base = tempfile.mkdtemp(prefix="vmb", dir="/tmp")
    script = tmp_path / "swap.py"
    script.write_text(ROOT_SWAP)
    try:
        p = subprocess.run(["sudo", "-n", os.path.realpath(sys.executable), "-I", "-B", str(script), str(KIT), base],
                           capture_output=True, text=True, timeout=60)
    finally:
        shutil.rmtree(base, ignore_errors=True)  # the script removes what root made
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout.strip().splitlines()[-1]) == {
        "own": "opened", "symlink": "mailbox_invalid", "hardlink_root_file": "mailbox_invalid",
        "hardlink_own_file": "mailbox_invalid", "victim_zero": True}


def test_rewrap_and_the_mailbox_are_documented():
    readme = (KIT / "README.md").read_text()
    for word in ("rewrap", "vm_mailbox.py", "mailbox_invalid", "rewrap_offer_changed", "guest_status",
                 "pre-scan", "openat"):
        assert word in readme, word

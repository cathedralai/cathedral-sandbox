"""scripts/sealed_data_proof.py: the operator proofs for the sealed data volume (AB#735).

The restart and null-cipher drivers run against a fake hotel on 127.0.0.1 that
follows the real front's shapes (202 create, 503 health_not_ready, 404 after a
confirmed delete, 409 workspace_in_use, the workspace name rule). The LUKS2
header editor is checked against real cryptsetup when it is installed and
against a synthetic header otherwise.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sealed_data_proof.py"
spec = importlib.util.spec_from_file_location("sealed_data_proof", SCRIPT)
sdp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sdp)

KEY = "hotel-key-" + "s3cr3t" * 6
MARK_RE = re.compile(r"CATHEDRAL-DISK-PROOF-[0-9a-f]+")
WORKSPACE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
CRYPTSETUP = shutil.which("cryptsetup") or next(
    (p for p in ("/usr/sbin/cryptsetup", "/sbin/cryptsetup") if os.access(p, os.X_OK)), None)


# --------------------------------------------------------------------------- synthetic LUKS2


def luks2_header(path: Path, size: int = 32 << 20, hdr_size: int = 16384) -> None:
    meta = {
        "keyslots": {"0": {"type": "luks2", "key_size": 64,
                           "area": {"type": "raw", "offset": "32768", "size": "258048",
                                    "encryption": "aes-xts-plain64", "key_size": 64}}},
        "tokens": {},
        "segments": {"0": {"type": "crypt", "offset": "16777216", "size": "dynamic", "iv_tweak": "0",
                           "encryption": "aes-xts-plain64", "sector_size": 4096}},
        "digests": {},
        "config": {"json_size": str(hdr_size - 4096), "keyslots_size": "16744448"},
    }
    salt, uid = os.urandom(64), str(uuid.uuid4()).encode()
    area = b""
    for magic, offset in ((sdp.LUKS2_MAGIC_1, 0), (sdp.LUKS2_MAGIC_2, hdr_size)):
        b = bytearray(hdr_size)
        b[0:6] = magic
        struct.pack_into(">HQQ", b, 6, 2, hdr_size, 1)
        b[24:24 + 21] = b"cathedral-sealed-data"
        b[72:78] = b"sha256"
        b[104:168] = salt
        b[168:168 + len(uid)] = uid
        struct.pack_into(">Q", b, 256, offset)
        area += sdp._render(bytes(b), meta, hdr_size)
    with open(path, "wb") as f:
        f.write(area)
        f.truncate(size)


def real_luks2(path: Path, tmp: Path) -> None:
    key = tmp / "k"
    key.write_bytes(os.urandom(32))
    with open(path, "wb") as f:
        f.truncate(32 << 20)
    subprocess.run([CRYPTSETUP, "luksFormat", "--type", "luks2", "--batch-mode", "--cipher", "aes-xts-plain64",
                    "--key-size", "512", "--sector-size", "4096", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations",
                    "1000", "--hash", "sha256", "--label", "cathedral-sealed-data", "--key-file", str(key),
                    "--keyfile-size", "32", str(path)], check=True, capture_output=True)


def dump_json(path: Path) -> dict:
    out = subprocess.run([CRYPTSETUP, "luksDump", "--dump-json-metadata", str(path)],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out)


# --------------------------------------------------------------------------- fake hotel


class FakeHotel:
    """The hotel front as the proof sees it, plus /_ctl/{restart,stop,start} for the fake unit."""

    def __init__(self, sealed_dir: Path):
        self.dir = sealed_dir
        self.lock = threading.Lock()
        self.up = True
        self.boot = 1
        self.state, self.key_id = "open", "b347e4ae2df1d798"
        self.workspaces: dict[str, dict] = {}
        self.rooms: dict[str, dict] = {}
        self.live = 0              # foreign live rooms
        self.not_ready = 0         # 503 health_not_ready answers left
        # scenario knobs
        self.after_state = "open"
        self.after_key_id = None
        self.lose_data = False
        self.leak_to = None        # (file name, offset): write the marker in clear on the host disk
        self.write_on_boot = False
        self.next_id = 0
        hotel = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def send(self, code, doc=None):
                raw = json.dumps(doc).encode() if doc is not None else b""
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else None

            def do_GET(self):
                hotel.handle(self, "GET")

            def do_POST(self):
                hotel.handle(self, "POST")

            def do_DELETE(self):
                hotel.handle(self, "DELETE")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def ctl(self, what: str) -> str:
        return f"{sys.executable} -c \"import urllib.request; urllib.request.urlopen(urllib.request.Request('{self.url}/_ctl/{what}', method='POST'))\""

    def boot_guest(self):
        self.up = True
        self.boot += 1
        self.not_ready = 2
        self.rooms.clear()
        data = self.dir / "data.raw"
        try:
            _, _, meta = sdp.read_luks2(data)
            c = sdp.ciphers(meta)
            if c["keyslot0"] == sdp.NULL_CIPHER:
                self.state = "locked"
            elif c["segment0"] == sdp.NULL_CIPHER:
                self.state = "tampered"
            else:
                self.state = self.after_state
        except sdp.Luks2Error:
            self.state = self.after_state
        if self.after_key_id:
            self.key_id = self.after_key_id
        if self.lose_data or self.state not in ("new", "open"):
            self.workspaces = {}
        if self.write_on_boot:
            with open(data, "r+b") as f:
                f.seek(20 << 20)
                f.write(b"mkfs was here")

    def handle(self, h, method):
        path = h.path
        with self.lock:
            if path.startswith("/_ctl/"):
                what = path[6:]
                if what in ("restart", "start"):
                    self.boot_guest()
                elif what == "stop":
                    self.up = False
                return h.send(200, {})
            if not self.up:
                return h.send(503, {"error": "down"})
            if path == "/room/attestation" and method == "GET":
                return h.send(200, {"binding": {"boot_id": f"boot-{self.boot}", "measurement": "fa3c" * 24,
                                                "host_data": "8013" * 16}})
            if h.headers.get("Authorization") != f"Bearer {KEY}":
                return h.send(401, {"error": "unauthorized"})
            if path == "/room/health":
                if self.not_ready:
                    self.not_ready -= 1
                    return h.send(503, {"error": "health_not_ready"})
                return h.send(200, {"workspaces_storage": {"state": self.state, "key_id": self.key_id,
                                                           "persistent": self.state in ("new", "open"),
                                                           "detail": f"fake {self.state}"}})
            if path == "/v1/workspaces" and method == "POST":
                name = h.body()["name"]
                if not WORKSPACE_RE.fullmatch(name):
                    return h.send(400, {"error": "invalid_workspace_name"})
                self.workspaces[name] = {}
                return h.send(201, {"name": name, "persistent": self.state in ("new", "open")})
            if path == "/v1/workspaces" and method == "GET":
                return h.send(200, {"workspaces": [{"name": n} for n in self.workspaces]})
            m = re.fullmatch(r"/v1/workspaces/([^/]+)", path)
            if m and method == "DELETE":
                if any(r["workspace"] == m[1] for r in self.rooms.values()):
                    return h.send(409, {"error": "workspace_in_use"})
                self.workspaces.pop(m[1], None)
                return h.send(204)
            if path == "/v1/sandboxes" and method == "GET":
                return h.send(200, {"sandboxes": [{"id": f"x{i}"} for i in range(self.live)] +
                                    [{"id": k} for k in self.rooms]})
            if path == "/v1/sandboxes" and method == "POST":
                b = h.body()
                if b["workspace"] not in self.workspaces:
                    return h.send(404, {"error": "workspace_not_found"})
                self.next_id += 1
                rid = f"room{self.next_id}"
                self.rooms[rid] = {"workspace": b["workspace"], "state": "creating", "deleting": 0}
                return h.send(202, {"id": rid})
            m = re.fullmatch(r"/v1/sandboxes/([^/]+)(/exec)?", path)
            if m:
                room = self.rooms.get(m[1])
                if room is None:
                    return h.send(404, {"error": "sandbox_not_found"})
                if method == "DELETE":
                    room["state"], room["deleting"] = "deleting", 2
                    return h.send(204)
                if method == "GET" and not m[2]:
                    if room["state"] == "deleting":
                        room["deleting"] -= 1
                        if room["deleting"] <= 0:
                            del self.rooms[m[1]]
                    elif room["state"] == "creating":
                        room["state"] = "running"
                    return h.send(200, {"id": m[1], "state": room["state"]})
                if method == "POST" and m[2]:
                    return h.send(200, self.exec_(room, h.body()["cmd"][2]))
            return h.send(404, {"error": "route_not_found"})

    def exec_(self, room, sh):
        ws = self.workspaces.setdefault(room["workspace"], {})
        mark = MARK_RE.search(sh)
        if mark and "> /workspace/marker.txt" in sh:
            ws["marker"], ws["lines"] = mark[0], 20000
            if self.leak_to:
                name, off = self.leak_to
                with open(self.dir / name, "r+b") as f:
                    f.seek(off)
                    f.write(mark[0].encode())
            return {"exit_code": 0, "stdout": f"{mark[0]}\n20000\n968890\n", "stderr": ""}
        if "marker" not in ws:
            return {"exit_code": 1, "stdout": "", "stderr": "cat: can't open '/workspace/marker.txt'"}
        return {"exit_code": 0, "stdout": f"{ws['marker']}\n{ws['lines']}\nscratch-copy-gone\n", "stderr": ""}

    def close(self):
        self.server.shutdown()


@pytest.fixture
def hotel_dir(tmp_path):
    d = tmp_path / "sealed"
    (d / "run").mkdir(parents=True)
    keyf = tmp_path / "hotel.key"
    keyf.write_text(f"  {KEY}\n")
    os.chmod(keyf, 0o600)
    env = tmp_path / "sealed.env"
    env.write_text(f"SEALED_NAME=canary-1\nSEALED_DIR={d}\nSEALED_DATA_GIB=4\nSEALED_ROOM_WORKSPACES=1\n"
                   f"SEALED_MINER=0\nSEALED_API_KEY_FILE={keyf}\nSEALED_OWNER_PUBKEY_FILE=\n")
    # data.raw: a LUKS2 header, then written ciphertext-like sectors past 16 MiB, sparse to 64 MiB
    luks2_header(d / "data.raw", size=64 << 20)
    with open(d / "data.raw", "r+b") as f:
        f.seek(16 << 20)
        f.write(os.urandom(2 << 20))
    with open(d / "scratch.raw", "wb") as f:
        f.seek(40 << 20)
        f.write(os.urandom(1 << 20))
        f.truncate(256 << 20)
    (d / "run" / "serial.log").write_text("[    4.1] [sealed-data] open: LUKS2 volume mounted at /srv/sealed-data (4211081216 bytes)\r\n")
    return env, d


@pytest.fixture
def hotel(hotel_dir):
    _, d = hotel_dir
    h = FakeHotel(d)
    yield h
    h.close()


def run_restart(env, hotel, capsys, *extra):
    rc = sdp.main(["restart", "--env", str(env), "--api", hotel.url, "--settle", "0", "--poll", "0.02",
                   "--timeout", "10", "--restart-cmd", hotel.ctl("restart"), *extra])
    out = capsys.readouterr()
    return rc, out.out, out.err


# --------------------------------------------------------------------------- restart


def test_restart_pass(hotel_dir, hotel, capsys):
    env, _ = hotel_dir
    rc, out, err = run_restart(env, hotel, capsys)
    assert rc == 0, out + err
    assert "Result: **PASS**" in out
    assert "new room reads the marker and 20,000 lines back" in out
    assert "data.raw: marker hits 0" in out and "scratch.raw: marker hits 0" in out
    assert "[sealed-data] open" in out
    assert KEY not in out and KEY not in err
    assert hotel.workspaces == {} and hotel.rooms == {}  # workspace and rooms cleaned up


def test_restart_not_open_after_restart_fails(hotel_dir, hotel, capsys):
    env, _ = hotel_dir
    hotel.after_state = "locked"
    rc, out, _ = run_restart(env, hotel, capsys)
    assert rc == 1
    assert "**FAIL** 9. after" in out
    assert "**FAIL** 10. workspace listed" in out
    assert "workspace_not_found" in out  # a locked volume: the old workspace is gone this boot
    assert hotel.rooms == {}


def test_restart_key_id_changed_fails(hotel_dir, hotel, capsys):
    env, _ = hotel_dir
    hotel.after_key_id = "d8a2826072e119cd"
    rc, out, _ = run_restart(env, hotel, capsys)
    assert rc == 1 and "**FAIL** 9. after" in out


def test_restart_marker_lost_fails(hotel_dir, hotel, capsys):
    env, _ = hotel_dir
    hotel.lose_data = True
    rc, out, _ = run_restart(env, hotel, capsys)
    assert rc == 1
    assert "**FAIL** 10. workspace listed" in out


@pytest.mark.parametrize("disk,offset", [("data.raw", (8 << 20) - 10), ("scratch.raw", (40 << 20) + 5)])
def test_restart_marker_in_clear_on_host_fails(hotel_dir, hotel, capsys, disk, offset):
    env, _ = hotel_dir
    hotel.leak_to = (disk, offset)  # data.raw case straddles the 8 MiB scan chunk edge
    rc, out, _ = run_restart(env, hotel, capsys)
    assert rc == 1
    assert f"**FAIL** {disk}: marker hits 0: 1 hits" in out


def test_restart_refuses_live_rooms(hotel_dir, hotel, capsys):
    env, _ = hotel_dir
    hotel.live = 2
    rc, out, err = run_restart(env, hotel, capsys)
    assert rc == 2 and "2 live room(s)" in err and out == ""
    assert hotel.boot == 1 and hotel.workspaces == {}


@pytest.mark.parametrize("line,why", [
    ("SEALED_MINER=1", "miner hotel"),
    ("SEALED_DATA_GIB=0", "no data volume"),
    ("SEALED_ROOM_WORKSPACES=0", "not used"),
    ("SEALED_OWNER_PUBKEY_FILE=/etc/owner.pub", "dedicated hotel"),
])
def test_restart_refuses_config(hotel_dir, hotel, capsys, line, why):
    env, _ = hotel_dir
    env.write_text(env.read_text() + line + "\n")
    rc, _, err = run_restart(env, hotel, capsys)
    assert rc == 2 and why in err
    assert hotel.boot == 1


def test_restart_refuses_volume_not_open(hotel_dir, hotel, capsys):
    env, _ = hotel_dir
    hotel.state = "locked"
    rc, _, err = run_restart(env, hotel, capsys)
    assert rc == 2 and "not open" in err


def test_guest_constants_override_guest_ip(hotel_dir):
    env, d = hotel_dir
    env.write_text(env.read_text() + "SEALED_GUEST_IP=192.0.2.9\n")
    (d / "guest-constants.sh").write_text("SEALED_GUEST_IP=10.215.0.2\n")
    assert sdp.load_env(env)["SEALED_GUEST_IP"] == "10.215.0.2"


# --------------------------------------------------------------------------- host scans


def test_count_marker_chunk_edges_and_holes(tmp_path):
    f = tmp_path / "disk"
    needle = b"CATHEDRAL-DISK-PROOF-0123456789abcdef"
    with open(f, "wb") as fh:
        fh.truncate(8 << 20)
        for off in (5, 4096 - 7, (1 << 20) - 3, (6 << 20) + 1):
            fh.seek(off)
            fh.write(needle)
    for chunk in (64, 4096, 1 << 20):
        assert sdp.count_marker(f, needle, chunk=chunk)[0] == 4


def test_extents_digest_sees_a_write_into_a_hole(tmp_path):
    f = tmp_path / "disk"
    with open(f, "wb") as fh:
        fh.write(b"x" * 4096)
        fh.truncate(16 << 20)
    d1, _ = sdp.extents_digest(f)
    with open(f, "r+b") as fh:
        fh.seek(8 << 20)
        fh.write(b"y")
    assert sdp.extents_digest(f)[0] != d1


# --------------------------------------------------------------------------- null-cipher


def run_null(env, hotel, capsys, *extra):
    rc = sdp.main(["null-cipher", "--env", str(env), "--api", hotel.url, "--poll", "0.02", "--timeout", "10",
                   "--stop-cmd", hotel.ctl("stop"), "--start-cmd", hotel.ctl("start"), *extra])
    out = capsys.readouterr()
    return rc, out.out, out.err


def test_null_cipher_needs_throwaway(hotel_dir, hotel, capsys):
    env, d = hotel_dir
    before = (d / "data.raw").read_bytes()[:32768]
    rc, _, err = run_null(env, hotel, capsys)
    assert rc == 2 and "--throwaway" in err
    assert (d / "data.raw").read_bytes()[:32768] == before


def test_null_cipher_segment_tampered_passes_and_restores(hotel_dir, hotel, capsys):
    env, d = hotel_dir
    original = (d / "data.raw").read_bytes()[:32768]
    rc, out, err = run_null(env, hotel, capsys, "--throwaway")
    assert rc == 0, out + err
    assert "**PASS** 8. workspaces_storage `tampered`, persistent False" in out
    assert "**PASS** 11. data.raw unchanged" in out
    assert KEY not in out
    backup = next(d.glob("data.raw.luks-header-*"))
    assert backup.read_bytes() == original
    assert sdp.main(["edit-header", str(d / "data.raw"), "--restore", str(backup)]) == 0
    assert (d / "data.raw").read_bytes()[:32768] == original


def test_null_cipher_keyslot_is_a_negative_control(hotel_dir, hotel, capsys):
    env, _ = hotel_dir
    rc, out, _ = run_null(env, hotel, capsys, "--throwaway", "--target", "keyslot")
    assert rc == 0 and "workspaces_storage `locked`" in out and "negative control" in out


def test_null_cipher_guest_write_fails(hotel_dir, hotel, capsys):
    env, _ = hotel_dir
    hotel.write_on_boot = True
    rc, out, _ = run_null(env, hotel, capsys, "--throwaway")
    assert rc == 1 and "**FAIL** 11. data.raw unchanged" in out


def test_null_cipher_refuses_volume_with_workspaces(hotel_dir, hotel, capsys):
    env, _ = hotel_dir
    hotel.workspaces["customer"] = {}
    rc, _, err = run_null(env, hotel, capsys, "--throwaway")
    assert rc == 2 and "holds workspaces" in err and hotel.up


# --------------------------------------------------------------------------- edit-header


def test_edit_header_refuses_non_luks(tmp_path):
    f = tmp_path / "plain"
    f.write_bytes(os.urandom(1 << 16))
    assert sdp.main(["edit-header", str(f)]) == 2


def test_edit_header_refuses_bad_checksum(tmp_path):
    f = tmp_path / "v"
    luks2_header(f)
    with open(f, "r+b") as fh:
        fh.seek(4096 + 3)
        fh.write(b"X")
    with pytest.raises(sdp.Luks2Error, match="checksum"):
        sdp.edit_header(f)


def test_edit_header_synthetic_round_trip(tmp_path):
    f = tmp_path / "v"
    luks2_header(f)
    res = sdp.edit_header(f, "segment")
    assert res["after"]["segment0"] == sdp.NULL_CIPHER and res["after"]["keyslot0"] == "aes-xts-plain64"
    _, _, meta = sdp.read_luks2(f)  # both copies equal, checksums valid
    assert meta["segments"]["0"]["encryption"] == sdp.NULL_CIPHER


@pytest.mark.skipif(CRYPTSETUP is None, reason="needs cryptsetup")
@pytest.mark.parametrize("target", ["segment", "keyslot"])
def test_edit_header_real_cryptsetup_accepts_both_headers(tmp_path, target):
    f = tmp_path / "data.raw"
    real_luks2(f, tmp_path)
    original = f.read_bytes()
    sdp.edit_header(f, target)
    edited = f.read_bytes()
    meta = dump_json(f)
    field = meta["segments"]["0"] if target == "segment" else meta["keyslots"]["0"]["area"]
    assert field["encryption"] == sdp.NULL_CIPHER
    assert f.read_bytes() == edited  # cryptsetup saw no damage to repair
    # the secondary header alone must also be valid: wipe the primary and dump again
    copy = tmp_path / "secondary-only"
    copy.write_bytes(bytes(4096) + edited[4096:])
    assert dump_json(copy)["segments"] == meta["segments"]
    hdr_size = struct.unpack_from(">Q", original, 8)[0]
    assert edited[2 * hdr_size:] == original[2 * hdr_size:]  # nothing past the headers touched

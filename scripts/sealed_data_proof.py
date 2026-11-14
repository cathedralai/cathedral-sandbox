#!/usr/bin/env python3
"""Operator proofs for the sealed data volume (docs/SEALED_DATA_VOLUME.md).

Run as root on the host of a sealed hotel. Standard library only, so this one
file can be copied to the host. It replaces the ad-hoc 7 Nov c48 drivers
(proof.sh, run2.sh in cathedral-sandbox#413) with one command per check that
prints a markdown block to paste on the card.

  restart      Write a marker into a workspace, restart the guest, read it back,
               and show the host disks hold no plaintext. Exit 0 only if all pass.
  null-cipher  On a THROWAWAY guest only: stop it, edit data.raw's LUKS2 header to
               a null cipher, boot, and show the guest refuses the volume
               (state tampered) and writes nothing to data.raw.
  edit-header  Edit (or restore) a LUKS2 header in place, both copies, checksums
               recomputed. Used by null-cipher; also usable on its own.

The hotel key is read from SEALED_API_KEY_FILE and sent as a Bearer header. It
is never printed: every output line is checked for it before it is written.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import math
import os
import secrets
import shlex
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

DEFAULT_ENV = "/srv/sealed-hotel/sealed.env"
API_PORT = 18090
ENV_KEYS = (
    "SEALED_NAME", "SEALED_DIR", "SEALED_DATA_GIB", "SEALED_ROOM_WORKSPACES", "SEALED_MINER",
    "SEALED_API_KEY_FILE", "SEALED_GUEST_IP", "SEALED_OWNER_PUBKEY_FILE",
)
IMAGE = "alpine:3.20"
BULK_LINES = 20000
LUKS_HEADER_AREA = 16 << 20  # sealed-data.sh makes the default LUKS2 layout: data starts at 16 MiB
ENTROPY_SAMPLE = 64 << 20
ENTROPY_MIN = 7.99  # bits per byte over the sampled written sectors; ciphertext is ~8.0

# LUKS2 binary header (cryptsetup docs/on-disk-format-luks2.pdf).
LUKS2_MAGIC_1 = b"LUKS\xba\xbe"
LUKS2_MAGIC_2 = b"SKUL\xba\xbe"
LUKS2_BIN_SIZE = 4096
LUKS2_HDR_SIZES = tuple(16384 << i for i in range(9))  # 16 KiB .. 4 MiB
OFF_VERSION, OFF_HDR_SIZE, OFF_SEQID = 6, 8, 16
OFF_CSUM_ALG, OFF_UUID, OFF_HDR_OFFSET, OFF_CSUM = 72, 168, 256, 448
NULL_CIPHER = "cipher_null-ecb"


class ProofError(Exception):
    """A refusal before anything was changed (exit 2)."""


# --------------------------------------------------------------------------- LUKS2 header


class Luks2Error(ValueError):
    pass


def _csum(hdr: bytes) -> bytes:
    h = bytearray(hdr)
    h[OFF_CSUM:OFF_CSUM + 64] = bytes(64)
    return hashlib.sha256(h).digest()


def _parse_one(raw: bytes, magic: bytes, want_offset: int, hdr_size: int) -> dict:
    if raw[:6] != magic:
        raise Luks2Error(f"no LUKS2 magic at offset {want_offset}")
    (version,) = struct.unpack_from(">H", raw, OFF_VERSION)
    if version != 2:
        raise Luks2Error(f"LUKS version {version}, not 2")
    (size,) = struct.unpack_from(">Q", raw, OFF_HDR_SIZE)
    (seqid,) = struct.unpack_from(">Q", raw, OFF_SEQID)
    (offset,) = struct.unpack_from(">Q", raw, OFF_HDR_OFFSET)
    if size != hdr_size or offset != want_offset:
        raise Luks2Error(f"header at {want_offset}: hdr_size {size}, hdr_offset {offset}")
    alg = raw[OFF_CSUM_ALG:OFF_CSUM_ALG + 32].rstrip(b"\0").decode("ascii", "replace")
    if alg != "sha256":
        raise Luks2Error(f"checksum algorithm {alg!r}, only sha256 is handled")
    if raw[OFF_CSUM:OFF_CSUM + 32] != _csum(raw) or raw[OFF_CSUM + 32:OFF_CSUM + 64] != bytes(32):
        raise Luks2Error(f"header at {want_offset}: checksum does not match")
    text = raw[LUKS2_BIN_SIZE:hdr_size].split(b"\0", 1)[0]
    try:
        meta = json.loads(text)
    except ValueError as exc:
        raise Luks2Error(f"header at {want_offset}: JSON area does not parse: {exc}") from None
    return {"seqid": seqid, "uuid": raw[OFF_UUID:OFF_UUID + 40], "json": meta}


def read_luks2(path: Path) -> tuple[int, bytes, dict]:
    """(hdr_size, both header bytes, metadata). Refuses anything but two valid, equal sha256 headers."""
    with open(path, "rb") as f:
        first = f.read(LUKS2_BIN_SIZE)
        if len(first) < LUKS2_BIN_SIZE or first[:6] != LUKS2_MAGIC_1:
            raise Luks2Error(f"{path} is not a LUKS2 volume (no primary magic)")
        (hdr_size,) = struct.unpack_from(">Q", first, OFF_HDR_SIZE)
        if hdr_size not in LUKS2_HDR_SIZES:
            raise Luks2Error(f"hdr_size {hdr_size} is not a LUKS2 header size")
        f.seek(0)
        area = f.read(2 * hdr_size)
    if len(area) != 2 * hdr_size:
        raise Luks2Error(f"{path} is shorter than two LUKS2 headers")
    one = _parse_one(area[:hdr_size], LUKS2_MAGIC_1, 0, hdr_size)
    two = _parse_one(area[hdr_size:], LUKS2_MAGIC_2, hdr_size, hdr_size)
    # cryptsetup repairs a copy whose seqid or JSON differs, which would write data.raw at boot.
    if one["seqid"] != two["seqid"] or one["uuid"] != two["uuid"] or one["json"] != two["json"]:
        raise Luks2Error("the primary and secondary headers differ; not editing a header cryptsetup would repair")
    return hdr_size, area, one["json"]


def _render(raw: bytes, meta: dict, hdr_size: int) -> bytes:
    text = json.dumps(meta, separators=(",", ":")).encode()
    room = hdr_size - LUKS2_BIN_SIZE
    if len(text) >= room:
        raise Luks2Error(f"edited JSON is {len(text)} bytes, the area holds {room - 1}")
    out = bytearray(raw)
    out[LUKS2_BIN_SIZE:hdr_size] = text + bytes(room - len(text))
    out[OFF_CSUM:OFF_CSUM + 64] = bytes(64)
    out[OFF_CSUM:OFF_CSUM + 32] = _csum(bytes(out))
    return bytes(out)


def ciphers(meta: dict) -> dict:
    return {
        "segment0": meta.get("segments", {}).get("0", {}).get("encryption"),
        "keyslot0": meta.get("keyslots", {}).get("0", {}).get("area", {}).get("encryption"),
    }


def edit_header(path: Path, target: str = "segment", cipher: str = NULL_CIPHER) -> dict:
    """Set segment 0's (or key slot 0's area) cipher in both headers, in place."""
    hdr_size, area, meta = read_luks2(path)
    before = ciphers(meta)
    if target == "segment":
        seg = meta.get("segments", {}).get("0")
        if not isinstance(seg, dict):
            raise Luks2Error("no segment 0")
        seg["encryption"] = cipher
    elif target == "keyslot":
        slot = meta.get("keyslots", {}).get("0")
        if not isinstance(slot, dict) or not isinstance(slot.get("area"), dict):
            raise Luks2Error("no key slot 0 area")
        slot["area"]["encryption"] = cipher
    else:
        raise Luks2Error(f"unknown target {target!r}")
    new = _render(area[:hdr_size], meta, hdr_size) + _render(area[hdr_size:], meta, hdr_size)
    with open(path, "r+b") as f:
        f.write(new)
        f.flush()
        os.fsync(f.fileno())
    read_luks2(path)  # the result must parse with valid checksums
    return {"hdr_size": hdr_size, "before": before, "after": ciphers(meta),
            "header_sha256_before": hashlib.sha256(area).hexdigest(),
            "header_sha256_after": hashlib.sha256(new).hexdigest()}


def restore_header(path: Path, backup: Path) -> dict:
    """Write a saved header area back. The backup must be a valid header pair of the same volume."""
    hdr_size, _, _ = read_luks2(path)
    saved = backup.read_bytes()
    if len(saved) != 2 * hdr_size:
        raise Luks2Error(f"backup is {len(saved)} bytes, expected {2 * hdr_size}")
    a = _parse_one(saved[:hdr_size], LUKS2_MAGIC_1, 0, hdr_size)
    with open(path, "rb") as f:
        cur_uuid = f.read(LUKS2_BIN_SIZE)[OFF_UUID:OFF_UUID + 40]
    if a["uuid"] != cur_uuid:
        raise Luks2Error("backup is from another LUKS2 volume (uuid differs)")
    _parse_one(saved[hdr_size:], LUKS2_MAGIC_2, hdr_size, hdr_size)
    with open(path, "r+b") as f:
        f.write(saved)
        f.flush()
        os.fsync(f.fileno())
    _, _, meta = read_luks2(path)
    return {"hdr_size": hdr_size, "after": ciphers(meta), "header_sha256": hashlib.sha256(saved).hexdigest()}


# --------------------------------------------------------------------------- host disk scans


def data_extents(fd: int, size: int):
    """Allocated ranges of a sparse file (SEEK_DATA/SEEK_HOLE); the whole file if unsupported."""
    off = 0
    while off < size:
        try:
            start = os.lseek(fd, off, os.SEEK_DATA)
        except OSError as exc:
            if exc.errno == errno.ENXIO:
                return
            if exc.errno in (errno.EINVAL, errno.EOPNOTSUPP):
                yield off, size
                return
            raise
        try:
            end = os.lseek(fd, start, os.SEEK_HOLE)
        except OSError:
            end = size
        if end <= start:
            end = size
        yield start, end
        off = end


def _chunks(fd: int, start: int, end: int, chunk: int):
    pos = start
    while pos < end:
        b = os.pread(fd, min(chunk, end - pos), pos)
        if not b:
            return
        yield pos, b
        pos += len(b)


def count_marker(path: Path, needle: bytes, chunk: int = 8 << 20) -> tuple[int, int]:
    """(hits, bytes scanned) over allocated extents. A hole reads as zeros and the
    marker has no NUL, so a hit cannot span a hole; chunk edges overlap."""
    hits = scanned = 0
    keep = len(needle) - 1
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        for start, end in data_extents(fd, size):
            tail = b""
            for _, b in _chunks(fd, start, end, chunk):
                buf = tail + b
                hits += buf.count(needle)
                # the kept tail is shorter than the needle, so no match is counted twice
                tail = buf[-keep:] if keep else b""
                scanned += len(b)
    finally:
        os.close(fd)
    return hits, scanned


def extents_digest(path: Path, chunk: int = 8 << 20) -> tuple[str, int]:
    """sha256 over the extent map and the allocated bytes: any guest write changes it."""
    h = hashlib.sha256()
    total = 0
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        h.update(struct.pack(">Q", size))
        for start, end in data_extents(fd, size):
            h.update(struct.pack(">QQ", start, end))
            for _, b in _chunks(fd, start, end, chunk):
                h.update(b)
                total += len(b)
    finally:
        os.close(fd)
    return h.hexdigest(), total


def entropy_after_header(path: Path) -> tuple[int, float]:
    """(written 4 KiB sectors sampled, bits per byte) past the LUKS2 header area, as on 7 Nov."""
    counts = [0] * 256
    n = sectors = 0
    with open(path, "rb") as f:
        f.seek(LUKS_HEADER_AREA)
        while n < ENTROPY_SAMPLE:
            b = f.read(1 << 20)
            if not b:
                break
            for i in range(0, len(b), 4096):
                s = b[i:i + 4096]
                if s.count(0) == len(s):
                    continue  # a hole or never written
                sectors += 1
                n += len(s)
                for x, c in Counter(s).items():
                    counts[x] += c
    ent = -sum(c / n * math.log2(c / n) for c in counts if c) if n else 0.0
    return sectors, ent


# --------------------------------------------------------------------------- config and hotel API


def load_env(path: Path) -> dict:
    """sealed.env, then $SEALED_DIR/guest-constants.sh (it overrides the guest IP), read by bash."""
    if not path.is_file():
        raise ProofError(f"no sealed.env at {path}")
    script = (
        'set -a; . "$1"; '
        '[ -n "${SEALED_DIR:-}" ] && [ -f "$SEALED_DIR/guest-constants.sh" ] && . "$SEALED_DIR/guest-constants.sh"; '
        'shift; for v in "$@"; do printf "%s=%s\\0" "$v" "${!v-}"; done'
    )
    out = subprocess.run(["bash", "-c", script, "_", str(path), *ENV_KEYS],
                         check=True, capture_output=True).stdout.decode()
    env = dict(kv.split("=", 1) for kv in out.split("\0") if kv)
    if not env.get("SEALED_NAME") or not env.get("SEALED_DIR"):
        raise ProofError("sealed.env sets no SEALED_NAME or SEALED_DIR")
    return env


class Hotel:
    def __init__(self, base: str, key: str, timeout: float = 300):
        self.base = base.rstrip("/")
        self._key = key
        self.timeout = timeout

    def call(self, method: str, path: str, body: dict | None = None, auth: bool = True,
             timeout: float | None = None) -> tuple[int, dict | None]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if auth:
            req.add_header("Authorization", f"Bearer {self._key}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                code, raw = r.status, r.read()
        except urllib.error.HTTPError as exc:
            code, raw = exc.code, exc.read()
        try:
            doc = json.loads(raw) if raw else None
        except ValueError:
            doc = {"raw": raw[:200].decode("utf-8", "replace")}
        return code, doc

    def try_call(self, *a, **kw) -> tuple[int, dict | None]:
        try:
            return self.call(*a, **kw)
        except (OSError, urllib.error.URLError):
            return 0, None


class Report:
    def __init__(self, title: str, key: str):
        self._key = key
        self.lines = [f"## {title}", ""]
        self.failed = False

    def add(self, line: str = "") -> None:
        self.lines.append(line)

    def step(self, name: str, ok: bool | None, detail: str = "") -> bool:
        mark = "PASS" if ok else ("FAIL" if ok is False else "INFO")
        if ok is False:
            self.failed = True
        self.lines.append(f"- **{mark}** {name}" + (f": {detail}" if detail else ""))
        return bool(ok)

    def text(self) -> str:
        out = "\n".join(self.lines) + "\n"
        if self._key and self._key in out:  # last guard: the key never reaches the paste
            out = out.replace(self._key, "[hotel key]")
        return out


def wait_until(fn, timeout: float, every: float = 2.0):
    end = time.monotonic() + timeout
    while True:
        got = fn()
        if got:
            return got
        if time.monotonic() >= end:
            return None
        time.sleep(every)


def run_cmd(cmd: str) -> tuple[int, str]:
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()[-400:]


class Proof:
    def __init__(self, args, report_title: str):
        self.args = args
        self.env = load_env(Path(args.env))
        self.dir = Path(self.env["SEALED_DIR"])
        self.unit = f"room-sealed-{self.env['SEALED_NAME']}.service"
        self._refuse_config()
        key_file = Path(self.env.get("SEALED_API_KEY_FILE") or "")
        try:
            key = "".join(key_file.read_text().split())
        except OSError:
            raise ProofError(f"hotel key file {key_file} is not readable") from None
        if not key:
            raise ProofError(f"hotel key file {key_file} is empty")
        base = args.api or f"http://{self.env.get('SEALED_GUEST_IP') or '10.215.0.2'}:{API_PORT}"
        self.hotel = Hotel(base, key)
        self.r = Report(report_title, key)
        self.rooms: list[str] = []

    def _refuse_config(self) -> None:
        e = self.env
        if e.get("SEALED_MINER", "0") == "1":
            raise ProofError("miner hotel: the host holds no hotel key, so it cannot drive the API; run this on a config hotel")
        if e.get("SEALED_OWNER_PUBKEY_FILE"):
            raise ProofError("dedicated hotel: every room create needs the owner's signature; run this on a shared hotel")
        if e.get("SEALED_DATA_GIB", "0") in ("", "0"):
            raise ProofError("SEALED_DATA_GIB is 0: this build has no data volume")
        if e.get("SEALED_ROOM_WORKSPACES", "0") != "1":
            raise ProofError("SEALED_ROOM_WORKSPACES is not 1: the data volume is not used")
        if not (self.dir / "data.raw").is_file():
            raise ProofError(f"no {self.dir / 'data.raw'}")

    # -- API helpers

    def health(self) -> dict | None:
        code, doc = self.hotel.try_call("GET", "/room/health", timeout=10)
        if code != 200 or not isinstance(doc, dict):
            return None  # includes 503 health_not_ready while the front fills its cache
        return doc

    def storage(self) -> dict | None:
        h = self.health()
        return h.get("workspaces_storage") if h else None

    def binding(self) -> dict | None:
        code, doc = self.hotel.try_call("GET", "/room/attestation", auth=False, timeout=10)
        if code != 200 or not isinstance(doc, dict):
            return None
        b = doc.get("binding") or {}
        return {k: b.get(k) for k in ("boot_id", "measurement", "host_data")}

    def live_rooms(self) -> int | None:
        code, doc = self.hotel.try_call("GET", "/v1/sandboxes", timeout=30)
        if code != 200 or not isinstance(doc, dict):
            return None
        return len(doc.get("sandboxes") or [])

    def refuse_live_rooms(self) -> None:
        live = self.live_rooms()
        if live is None:
            raise ProofError("GET /v1/sandboxes did not answer, so live rooms cannot be counted")
        if live and not self.args.allow_live_rooms:
            raise ProofError(f"{live} live room(s): a restart ends them with no delete receipt. Drain the hotel, or pass --allow-live-rooms")

    def wait_new_boot(self, old_boot: str | None) -> tuple[dict | None, dict | None]:
        b = wait_until(lambda: (lambda x: x if x and x.get("boot_id") and x["boot_id"] != old_boot else None)(self.binding()),
                       self.args.timeout, self.args.poll)
        if not b:
            return None, None
        s = wait_until(self.storage, 120, self.args.poll)
        return b, s

    def create_room(self, workspace: str) -> str:
        code, doc = self.hotel.call("POST", "/v1/sandboxes", {"image": IMAGE, "workspace": workspace, "timeout_seconds": 600})
        if code not in (200, 201, 202) or not isinstance(doc, dict) or not doc.get("id"):
            raise RuntimeError(f"room create answered {code}: {json.dumps(doc)[:300]}")
        rid = doc["id"]
        self.rooms.append(rid)
        st = wait_until(lambda: (lambda d: d if d in ("running", "failed", "error", "deleted") else None)(
            (self.hotel.try_call("GET", f"/v1/sandboxes/{rid}", timeout=30)[1] or {}).get("state")), 300, self.args.poll)
        if st != "running":
            raise RuntimeError(f"room {rid} state {st}")
        return rid

    def exec_(self, rid: str, sh: str) -> dict:
        code, doc = self.hotel.call("POST", f"/v1/sandboxes/{rid}/exec", {"cmd": ["sh", "-c", sh], "timeout_seconds": 120})
        if code != 200 or not isinstance(doc, dict):
            raise RuntimeError(f"exec answered {code}: {json.dumps(doc)[:300]}")
        return doc

    def delete_room(self, rid: str) -> bool:
        self.hotel.try_call("DELETE", f"/v1/sandboxes/{rid}", timeout=60)
        # DELETE answers before the room is gone; its workspace is freed only once removal is confirmed.
        gone = wait_until(lambda: self.hotel.try_call("GET", f"/v1/sandboxes/{rid}", timeout=30)[0] == 404, 180, self.args.poll)
        if gone and rid in self.rooms:
            self.rooms.remove(rid)
        return bool(gone)

    def cleanup_rooms(self) -> None:
        for rid in list(self.rooms):
            try:
                self.delete_room(rid)
            except Exception:  # noqa: BLE001  cleanup is best effort; the paste already says FAIL
                pass

    def serial_lines(self, n: int = 8) -> list[str]:
        log = self.dir / "run" / "serial.log"
        try:
            text = log.read_bytes().decode("utf-8", "replace").replace("\r", "")
        except OSError:
            return []
        return [ln[ln.index("[sealed-data]"):] for ln in text.splitlines() if "[sealed-data]" in ln][-n:]


# --------------------------------------------------------------------------- restart proof


def cmd_restart(args) -> int:
    p = Proof(args, "Sealed data volume: restart proof")
    r, h = p.r, p.hotel
    stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    name = f"proof-{stamp}"  # lowercase and digits only: the API's workspace name rule
    marker = f"CATHEDRAL-DISK-PROOF-{secrets.token_hex(8)}"
    r.add(f"- hotel `{p.env['SEALED_NAME']}`, unit `{p.unit}`, at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    r.add(f"- data.raw `{p.dir / 'data.raw'}` ({p.env['SEALED_DATA_GIB']} GiB), workspace `{name}`, marker `{marker}`")
    r.add("")

    st = p.storage()
    if not st or st.get("state") not in ("new", "open"):
        raise ProofError(f"health workspaces_storage is {json.dumps(st)}: the data volume is not open")
    p.refuse_live_rooms()
    before = p.binding() or {}
    r.step("1. before: workspaces_storage", True,
           f"state `{st.get('state')}`, persistent {st.get('persistent')}, key_id `{st.get('key_id')}`, boot_id `{before.get('boot_id')}`")

    try:
        code, doc = h.call("POST", "/v1/workspaces", {"name": name})
        persistent = (doc or {}).get("persistent")
        if not r.step("2. workspace create", code in (200, 201) and persistent is not False,
                      f"HTTP {code}, persistent {persistent}"):
            raise RuntimeError("workspace create")
        rid = p.create_room(name)
        sh = (
            f"set -e; printf '%s\\n' {marker} > /workspace/marker.txt; "
            f"i=0; while [ $i -lt {BULK_LINES} ]; do echo \"{marker} line $i\"; i=$((i+1)); done > /workspace/bulk.txt; "
            "cp /workspace/bulk.txt /root/scratch-copy.txt; sync; "
            "cat /workspace/marker.txt; grep -c line /workspace/bulk.txt; wc -c < /root/scratch-copy.txt"
        )
        out = p.exec_(rid, sh)
        got = (out.get("stdout") or "").split()
        ok = out.get("exit_code") == 0 and len(got) >= 2 and got[0] == marker and got[1] == str(BULK_LINES)
        if not r.step("3. room writes the marker and 20,000 lines to /workspace, a copy to its root fs (scratch), sync", ok,
                      f"room `{rid}`, exit {out.get('exit_code')}, read back `{' '.join(got)[:120]}`"):
            raise RuntimeError("write")
        r.step("4. room deleted", p.delete_room(rid), rid)

        if args.settle:
            time.sleep(args.settle)  # a unit stop is a power cut for the guest: give writeback time, as on 7 Nov
        r.step(f"5. settle {args.settle:g} s for guest writeback", None)
        try:
            p.refuse_live_rooms()  # the broker may have placed a room since the preflight
        except ProofError as exc:
            raise RuntimeError(str(exc)) from None
        rc, out_text = run_cmd(args.restart_cmd or f"systemctl restart {shlex.quote(p.unit)}")
        if not r.step("6. guest restart", rc == 0, f"`{args.restart_cmd or 'systemctl restart ' + p.unit}` exit {rc}"
                      + (f": {out_text}" if rc else "")):
            raise RuntimeError("restart")
        t0 = time.monotonic()
        after, st2 = p.wait_new_boot(before.get("boot_id"))
        if not r.step("7. new boot answers", bool(after and st2),
                      f"boot_id `{(after or {}).get('boot_id')}` in {time.monotonic() - t0:.0f} s"):
            raise RuntimeError("no new boot")
        same = all(after.get(k) == before.get(k) for k in ("measurement", "host_data"))
        r.step("8. same build: measurement and host_data unchanged", same,
               f"measurement `{str(after.get('measurement'))[:16]}...`")
        ok = st2.get("state") == "open" and st2.get("persistent") is True and st2.get("key_id") == st.get("key_id")
        r.step("9. after: workspaces_storage open, persistent, same key_id", ok,
               f"state `{st2.get('state')}`, persistent {st2.get('persistent')}, key_id `{st2.get('key_id')}`")
        for ln in p.serial_lines(4):
            r.add(f"    `{ln}`")

        code, doc = h.call("GET", "/v1/workspaces")
        names = [w.get("name") for w in (doc or {}).get("workspaces", []) if isinstance(w, dict)]
        r.step("10. workspace listed after restart", name in names, f"HTTP {code}")
        rid = p.create_room(name)
        out = p.exec_(rid, "cat /workspace/marker.txt; grep -c line /workspace/bulk.txt; "
                           "test -e /root/scratch-copy.txt && echo scratch-copy-present || echo scratch-copy-gone")
        got = (out.get("stdout") or "").split()
        ok = len(got) >= 2 and got[0] == marker and got[1] == str(BULK_LINES)
        r.step("11. new room reads the marker and 20,000 lines back", ok,
               f"room `{rid}`, read `{' '.join(got)[:160]}`")
        r.step("12. room deleted", p.delete_room(rid), rid)
        if not args.keep_workspace:
            code = wait_until(lambda: (lambda c: c if c != 409 else None)(h.try_call("DELETE", f"/v1/workspaces/{name}")[0]), 120, args.poll)
            r.step("13. proof workspace deleted", code in (200, 202, 204), f"HTTP {code}")
    except RuntimeError as exc:
        r.step("aborted", False, str(exc))
    finally:
        p.cleanup_rooms()

    if not r.failed:
        host_checks(p, marker.encode())
    return finish(r)


def host_checks(p: Proof, needle: bytes) -> None:
    r = p.r
    r.add("")
    r.add("Host disk:")
    for disk in ("data.raw", "scratch.raw"):
        path = p.dir / disk
        if not path.is_file():
            r.step(f"{disk} marker scan", disk == "scratch.raw" and None, "file missing")
            continue
        t0 = time.monotonic()
        hits, scanned = count_marker(path, needle)
        r.step(f"{disk}: marker hits 0", hits == 0,
               f"{hits} hits; {size_text(path.stat().st_size)} apparent, {size_text(scanned)} allocated scanned in {time.monotonic() - t0:.0f} s")
    data = p.dir / "data.raw"
    with open(data, "rb") as f:
        magic = f.read(6)
    r.step("data.raw starts with the LUKS2 magic", magic == LUKS2_MAGIC_1, magic.hex())
    sectors, ent = entropy_after_header(data)
    r.step("data.raw written sectors after the header look random", sectors > 0 and ent >= ENTROPY_MIN,
           f"{sectors} written 4 KiB sectors sampled, {ent:.4f} bits/byte (8 = random)")
    try:
        _, _, meta = read_luks2(data)
        r.step("data.raw LUKS2 header", None, f"segment 0 `{ciphers(meta)['segment0']}`, "
               f"sector {meta['segments']['0'].get('sector_size')}, key slots {sorted(meta.get('keyslots', {}))}")
    except (Luks2Error, KeyError) as exc:
        r.step("data.raw LUKS2 header", None, f"not read: {exc}")


def size_text(n: int) -> str:
    for unit, shift in (("GiB", 30), ("MiB", 20), ("KiB", 10)):
        if n >= 1 << shift:
            return f"{n / (1 << shift):.1f} {unit}"
    return f"{n} B"


def finish(r: Report) -> int:
    r.add("")
    r.add(f"Result: **{'FAIL' if r.failed else 'PASS'}**")
    sys.stdout.write(r.text())
    return 1 if r.failed else 0


# --------------------------------------------------------------------------- null-cipher check


SEGMENT_VERDICT = {
    "tampered": (True, "verify_header refused the edited header"),
    "locked": (None, "SAFE, verify_header not exercised: cryptsetup refused to activate the edited volume"),
    "broken": (None, "SAFE, verify_header not exercised: cryptsetup refused to load the edited header"),
}


def cmd_null_cipher(args) -> int:
    if not args.throwaway:
        raise ProofError("null-cipher breaks the data volume until the header is restored: run it only on a throwaway "
                         "guest and pass --throwaway")
    p = Proof(args, f"Sealed data volume: real-kernel {NULL_CIPHER} check ({args.target} edit)")
    r = p.r
    data = p.dir / "data.raw"
    r.add(f"- hotel `{p.env['SEALED_NAME']}`, unit `{p.unit}`, at {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    r.add(f"- data.raw `{data}`")
    r.add("")
    st = p.storage()
    if not st or st.get("state") not in ("new", "open"):
        raise ProofError(f"health workspaces_storage is {json.dumps(st)}: boot this build once so its volume is open first")
    code, doc = p.hotel.call("GET", "/v1/workspaces")
    held = [w.get("name") for w in (doc or {}).get("workspaces", []) if isinstance(w, dict)]
    if code != 200:
        raise ProofError(f"GET /v1/workspaces answered {code}")
    if held and not args.allow_workspaces:
        raise ProofError(f"the guest holds workspaces {held}: not a throwaway volume (pass --allow-workspaces to go on)")
    p.refuse_live_rooms()
    read_luks2(data)  # refuse a header we would not edit before the guest is stopped
    before = p.binding() or {}
    r.step("1. before: workspaces_storage", True, f"state `{st.get('state')}`, key_id `{st.get('key_id')}`")

    stop = args.stop_cmd or f"systemctl stop {shlex.quote(p.unit)}"
    start = args.start_cmd or f"systemctl start {shlex.quote(p.unit)}"
    rc, out = run_cmd(stop)
    if not r.step("2. guest stopped", rc == 0, f"`{stop}` exit {rc}" + (f": {out}" if rc else "")):
        return finish(r)
    hdr_size, area, _ = read_luks2(data)
    backup = p.dir / f"data.raw.luks-header-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}"
    backup.write_bytes(area)
    os.chmod(backup, 0o600)
    r.step("3. header saved", True, f"`{backup}` ({len(area)} bytes)")
    res = edit_header(data, args.target)
    r.step("4. header edited, both copies, checksums recomputed", True,
           f"{args.target}: segment0 `{res['before']['segment0']}` -> `{res['after']['segment0']}`, "
           f"keyslot0 `{res['before']['keyslot0']}` -> `{res['after']['keyslot0']}`")
    digest, allocated = extents_digest(data)
    r.step("5. data.raw after edit", None, f"sha256 (allocated extents) `{digest[:16]}`, {size_text(allocated)} allocated")

    rc, out = run_cmd(start)
    if not r.step("6. guest started", rc == 0, f"`{start}` exit {rc}" + (f": {out}" if rc else "")):
        return finish(r)
    t0 = time.monotonic()
    after, st2 = p.wait_new_boot(before.get("boot_id"))
    if r.step("7. new boot answers", bool(after and st2), f"in {time.monotonic() - t0:.0f} s"):
        state = st2.get("state")
        if state in ("new", "open", "unknown", None) or st2.get("persistent") is not False:
            ok, why = False, "the guest used the edited volume"
        elif args.target == "segment":
            ok, why = SEGMENT_VERDICT.get(state, (None, "SAFE, unexpected state"))
        else:
            ok, why = True, "negative control: a null key slot area does not open"
        r.step(f"8. workspaces_storage `{state}`, persistent {st2.get('persistent')}", ok, why)
        r.add(f"    detail: `{st2.get('detail')}`")
        for ln in p.serial_lines(6):
            r.add(f"    `{ln}`")
        code, doc = p.hotel.try_call("GET", "/v1/workspaces")
        r.step("9. workspaces visible this boot", None,
               f"HTTP {code}, {[w.get('name') for w in (doc or {}).get('workspaces', []) if isinstance(w, dict)]}")
    rc, out = run_cmd(stop)
    r.step("10. guest stopped", rc == 0, f"exit {rc}")
    digest2, _ = extents_digest(data)
    r.step("11. data.raw unchanged by the boot (no mkfs, no write)", digest2 == digest, f"`{digest2[:16]}`")
    r.add("")
    r.add(f"Restore: `{os.path.abspath(__file__)} edit-header {data} --restore {backup}`, then `{start}`.")
    return finish(r)


# --------------------------------------------------------------------------- edit-header


def cmd_edit_header(args) -> int:
    path = Path(args.file)
    if args.restore:
        res = restore_header(path, Path(args.restore))
        print(f"restored {path} from {args.restore}: segment0 {res['after']['segment0']}, "
              f"keyslot0 {res['after']['keyslot0']}, header sha256 {res['header_sha256'][:16]}")
        return 0
    res = edit_header(path, args.target, args.cipher)
    print(f"{path}: {args.target} edited; segment0 {res['before']['segment0']} -> {res['after']['segment0']}, "
          f"keyslot0 {res['before']['keyslot0']} -> {res['after']['keyslot0']}; header sha256 "
          f"{res['header_sha256_before'][:16]} -> {res['header_sha256_after'][:16]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--env", default=DEFAULT_ENV, help=f"sealed.env (default {DEFAULT_ENV})")
        sp.add_argument("--api", help="hotel API base URL (default http://$SEALED_GUEST_IP:18090)")
        sp.add_argument("--allow-live-rooms", action="store_true", help="restart even with live rooms (they end with no delete receipt)")
        sp.add_argument("--timeout", type=float, default=900, help="seconds to wait for the new boot (default 900)")
        sp.add_argument("--poll", type=float, default=1, help=argparse.SUPPRESS)

    sp = sub.add_parser("restart", help="workspace survives a guest restart; host disks hold no plaintext")
    common(sp)
    sp.add_argument("--restart-cmd", help="default: systemctl restart room-sealed-$SEALED_NAME.service")
    sp.add_argument("--settle", type=float, default=45, help="seconds between sync and restart (default 45)")
    sp.add_argument("--keep-workspace", action="store_true")
    sp.set_defaults(fn=cmd_restart)

    sp = sub.add_parser("null-cipher", help="throwaway guest: edited header to a null cipher is refused")
    common(sp)
    sp.add_argument("--throwaway", action="store_true", help="required: this breaks the volume until restored")
    sp.add_argument("--target", choices=("segment", "keyslot"), default="segment")
    sp.add_argument("--allow-workspaces", action="store_true")
    sp.add_argument("--stop-cmd", help="default: systemctl stop room-sealed-$SEALED_NAME.service")
    sp.add_argument("--start-cmd", help="default: systemctl start room-sealed-$SEALED_NAME.service")
    sp.set_defaults(fn=cmd_null_cipher)

    sp = sub.add_parser("edit-header", help="edit or restore a LUKS2 header in place")
    sp.add_argument("file")
    sp.add_argument("--target", choices=("segment", "keyslot"), default="segment")
    sp.add_argument("--cipher", default=NULL_CIPHER)
    sp.add_argument("--restore", metavar="BACKUP", help="write a saved header area back")
    sp.set_defaults(fn=cmd_edit_header)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except (ProofError, Luks2Error) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

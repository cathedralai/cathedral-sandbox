"""The room kit installers run against a fake host (review round 6, reader R).

test_room_kit_installer.py and test_room_kit_sealed_kit.py assert on the
script text: they prove lines exist. These tests run install.sh, room-net.sh,
host-net.sh and the restart-and-measure step of install-sealed.sh:

- a PATH of fake host commands that log their argv (systemctl, docker, curl,
  iptables, ip, nft, id, chown, ...) and answer what a host would;
- the real bash, coreutils, tar and sha sums; the real size.py, net_plan.py,
  net_capacity.py, profiles/v1.sh and lib/*.sh from a copy of the kit;
- a directory of files in place of the pinned downloads, pinned in the copy's
  versions.lock with their real sums;
- ROOM_DESTDIR, which points every host path install.sh writes (/etc/pool-room,
  /opt/pool-room, /run/pool-room, /etc/systemd/system) at a temporary root.

No root, no Docker daemon, no network, no host is touched. assess.py is the one
kit file replaced by a stub: the real one reads /proc and /sys of this machine.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
KIT = ROOT / "room-kit"
GIB = 1 << 30
KEY = "ZqTestKey0" * 4  # 40 chars of [A-Za-z0-9]; the trace must never show it
CUSTOMER = "guest-1"
BIN_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def _bash() -> str | None:
    # host-net.sh uses ${TAP^^}, so bash 4 or newer; macOS ships 3.2 at /bin/bash.
    for candidate in ("/opt/homebrew/bin/bash", "/usr/local/bin/bash", shutil.which("bash")):
        if candidate and Path(candidate).exists():
            major = subprocess.run([candidate, "-c", 'echo "${BASH_VERSINFO[0]}"'], capture_output=True, text=True).stdout.strip()
            if major.isdigit() and int(major) >= 4:
                return candidate
    return None


BASH = _bash()
pytestmark = pytest.mark.skipif(BASH is None or shutil.which("bzip2") is None, reason="needs bash 4+ and bzip2")

# A 192-thread, 752 GiB host with nothing else on it: memory limits the room to
# floor(752 * 0.88 / 4) = 165 slots (CPU would give 190, disk 245).
FAKE_MACHINE = {
    "cpu": {"threads": 192},
    "memory": {"total_bytes": 752 * GIB, "hugepages_reserved_bytes": 0},
    "root_fs": {"mount": "/", "total_bytes": 3500 * GIB, "used_bytes": 1500 * GIB},
    "data_dir": {"mount": "DATA_DIR", "total_bytes": 3500 * GIB, "used_bytes": 0},
    "workloads": {
        "host_docker": {"running": 0, "cpu_limit_sum": 0, "mem_limit_sum_bytes": 0, "unlimited_cpu": 0, "unlimited_mem": 0},
        "vms": {"count": 0, "vcpus_sum": 0, "mem_sum_bytes": 0, "items": [],
                "sealed_hotel_count": 0, "sealed_hotel_vcpus_sum": 0, "sealed_hotel_mem_sum_bytes": 0},
    },
}
SLOTS = 165

PROLOGUE = r"""#!@BASH@
# Fake host command for the room kit behaviour tests: logs argv, answers canned.
me=${0##*/}
printf '%s\n' "$me $*" >> "$FAKE_LOG"
count() { local f=$FAKE_STATE/count-$1 n; n=$(cat "$f" 2>/dev/null || echo 0); n=$((n + 1)); echo "$n" > "$f"; echo "$n"; }
pick() { # pick <n> <list>: the n-th word of the list; the last word repeats
  local n=$1; shift; local -a xs; read -r -a xs <<< "$*"
  [ ${#xs[@]} -gt 0 ] || return 0
  local i=$((n - 1)); [ $i -lt ${#xs[@]} ] || i=$((${#xs[@]} - 1)); printf '%s' "${xs[$i]}"; }
"""

FAKES = {
    "id": r"""case "${1:-}" in -u) echo 0 ;; *) exit 0 ;; esac""",
    "systemctl": r"""
ACTIVE=$FAKE_STATE/active-units; touch "$ACTIVE"
args=(); for a in "$@"; do [[ $a == -* ]] || args+=("$a"); done
cmd=${args[0]:-}; units=("${args[@]:1}")
drop() { grep -vxF -- "$1" "$ACTIVE" > "$ACTIVE.tmp" || true; mv "$ACTIVE.tmp" "$ACTIVE"; }
case "$cmd" in
  is-active) grep -qxF -- "${units[0]:-}" "$ACTIVE" && exit 0; exit 3 ;;
  restart|start|enable)
    [ "$cmd" = enable ] && [[ " $* " != *" --now "* ]] && exit 0
    for u in "${units[@]}"; do
      if [ "$u" = "${FAKE_RESTART_KILLS:-}" ]; then drop "$u"; else grep -qxF -- "$u" "$ACTIVE" || echo "$u" >> "$ACTIVE"; fi
    done ;;
  disable|stop) for u in "${units[@]}"; do drop "$u"; done ;;
esac
exit 0""",
    "docker": r"""
args=("$@"); [ "${args[0]:-}" = -H ] && args=("${args[@]:2}")
case "${args[0]:-}" in
  ps) n=$(count docker-ps); spec=$(pick "$n" "${FAKE_DOCKER_PS:-0}")
      [ "$spec" = fail ] && exit 1
      i=0; while [ "$i" -lt "$spec" ]; do printf 'room%03d\n' "$i"; i=$((i + 1)); done ;;
  info) [[ " $* " == *" --format "* ]] && echo "${FAKE_DOCKER_RUNTIME:-runsc}" ;;
esac
exit 0""",
    "curl": r"""
out=""; hdr=""; fmt=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out=$2; shift 2 ;; -H) hdr=$2; shift 2 ;; -w) fmt=$2; shift 2 ;;
    -m|--retry) shift 2 ;; -*) shift ;; *) url=$1; shift ;;
  esac
done
if [ -n "$fmt" ]; then # install.sh's final check: 200 only with the hotel's own key
  n=$(count curl-status)
  if [ -n "${FAKE_API_CODES:-}" ]; then code=$(pick "$n" "$FAKE_API_CODES")
  else code=401; case "$hdr" in @*) [ "$(cat "${hdr#@}")" = "Authorization: Bearer ${FAKE_API_KEY:-}" ] && code=200 ;; esac; fi
  # Like real curl: 000 means no connection, which curl also reports as exit 7.
  printf '%s' "$code"; [ "$code" = 000 ] && exit 7; exit 0
fi
case "$url" in
  */v1/sandboxes) # the sealed installer counts live rooms through the hotel API
    [ "${FAKE_SEALED_API:-up}" = up ] || exit 7
    n=${FAKE_SEALED_ROOMS:-0}; printf '{"sandboxes": ['; i=0
    while [ "$i" -lt "$n" ]; do [ "$i" -gt 0 ] && printf ','; printf '{"id": "sbx%d"}' "$i"; i=$((i + 1)); done
    printf ']}\n'; exit 0 ;;
  */room/attestation)
    n=$(count curl-attestation); [ "$n" -gt "${FAKE_ATT_FAILS:-0}" ] || exit 7
    printf '{"binding": {"measurement": "%s"}}\n' "${FAKE_MEASUREMENT:-}" > "$out"; exit 0 ;;
esac
src=$FAKE_WWW/${url##*/} # a pinned download: a directory of files stands in for the internet
[ -f "$src" ] || { echo "curl: (22) The requested URL returned error: 404" >&2; exit 22; }
cp "$src" "$out"
""",
    "sleep": "exit 0",
    "df": r"""printf '%s\n%s\n' 1B-blocks "${FAKE_DISK_BYTES:-3758096384000}" """,
    "du": r"""printf '0\t%s\n' "${2:-}" """,
    "ufw": r"""[ "${1:-}" = status ] && echo "Status: inactive"; exit 0""",
    "qemu-system-x86_64": r"""[ "${1:-}" = -object ] && printf '%s\n' "List of user creatable objects:" "  sev-snp-guest" "  sev-guest"; exit 0""",
    "iptables": r"""
t=filter; [ "${1:-}" = -t ] && { t=$2; shift 2; }
case "${1:-}" in
  -S) chain=${2:-}
      [ "$chain" = INPUT ] && echo "-P INPUT ${FAKE_INPUT_POLICY:-ACCEPT}"
      if [ -z "$chain" ]; then v=FAKE_IPTABLES_TAGGED_$t; [ -n "${!v:-}" ] && printf '%s\n' "${!v}"; fi
      if [ "${FAKE_IPTABLES_RULES:-}" = present ] && [ -n "$chain" ] && [ "$chain" != INPUT ]; then
        for _ in 1 2 3 4 5; do echo "-A $chain -j DROP"; done
      fi
      exit 0 ;;
  -C) [ "${FAKE_IPTABLES_RULES:-}" = present ]; exit ;;
esac
exit 0""",
    "ip6tables": "exit 0",
    "ip": r"""
case "$*" in
  "-o route show") printf '%s\n' "${FAKE_IP_ROUTES:-}" ;;
  "route show "*) for r in ${FAKE_ROUTED:-}; do [ "$r" = "$3" ] && echo "$3 dev other0 scope link"; done ;;
  "link show "*) for l in ${FAKE_LINKS:-}; do [ "$l" = "$3" ] && exit 0; done; exit 1 ;;
  "-o link show type bridge") for l in ${FAKE_BRIDGES:-}; do echo "7: $l: <BROADCAST,MULTICAST,UP> mtu 1500"; done ;;
esac
exit 0""",
}
for _name in ("chown", "useradd", "apt-get", "mkfs.xfs", "xfs_info", "mountpoint", "nft", "sysctl", "conntrack",
              "dockerd", "mmdebstrap", "zstd", "cpio"):
    FAKES[_name] = "exit 0"

# Wrappers around the real tools: the same bytes go through, two things change.
GREP_WRAPPER = r"""#!@BASH@
# install.sh reads /proc/mounts for the prjquota check; the fake host has its own.
args=(); for a in "$@"; do [ "$a" = /proc/mounts ] && a=$FAKE_STATE/proc-mounts; args+=("$a"); done
exec @REAL@ "${args[@]}"
"""
INSTALL_WRAPPER = r"""#!@BASH@
# install(1) with -o root -g poolroom needs root; the fake host drops the owner.
printf '%s\n' "install $*" >> "$FAKE_LOG"
args=(); while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) args+=("$1"); shift ;; esac; done
exec @REAL@ "${args[@]}"
"""

# Programs the pinned archives carry; install.sh runs them at the end.
FAKE_UV = r"""#!@BASH@
printf '%s\n' "uv $*" >> "$FAKE_LOG"
case "${1:-}" in
  python) mkdir -p "${UV_PYTHON_INSTALL_DIR:?}/cpython-${*: -1}" ;;
  venv) dest=${*: -1}; mkdir -p "$dest/bin"; printf '#!@BASH@\necho "Python 3.12.0 (fake venv)"\n' > "$dest/bin/python"; chmod 0755 "$dest/bin/python" ;;
esac
exit 0
"""
FAKE_RUNSC = "#!@BASH@\n[ \"${1:-}\" = --version ] && echo 'runsc version release-fake'; exit 0\n"
FAKE_CADDY = "#!@BASH@\n[ \"${1:-}\" = version ] && echo 'v2.fake h1:fake'; exit 0\n"

ASSESS_STUB = """#!/usr/bin/env python3
\"\"\"Stand-in for assess.py: a fixed machine.json (the real one reads /proc and /sys).\"\"\"
import argparse, json, pathlib
ap = argparse.ArgumentParser()
ap.add_argument("--data-dir"); ap.add_argument("--room-socket"); ap.add_argument("--out")
a = ap.parse_args()
m = json.loads(%r)
m["data_dir"]["mount"] = a.data_dir
pathlib.Path(a.out).write_text(json.dumps(m, indent=2) + "\\n")
""" % json.dumps(FAKE_MACHINE)


def _tar_bytes(members: dict[str, bytes], mode: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755
            info.uid = info.gid = 1001  # the builders' uid, as in the real archives
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeHost:
    """A kit copy, a fake PATH, a download directory and an empty root."""

    def __init__(self, tmp_path: Path) -> None:
        self.tmp = tmp_path
        self.root = tmp_path / "root"
        for sub in ("etc/systemd/system", "run/pool-room"):
            (self.root / sub).mkdir(parents=True)
        self.state = tmp_path / "state"
        self.state.mkdir()
        self.log = self.state / "calls.log"
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.www = tmp_path / "www"
        self.www.mkdir()
        self.kit = tmp_path / "kit"
        shutil.copytree(KIT, self.kit, ignore=shutil.ignore_patterns("dist", "__pycache__", "*.swp", "room.env", "sealed.env"))
        (self.kit / "assess.py").write_text(ASSESS_STUB)
        # The scripts exec each other through their shebang; Ubuntu's /bin/bash is 5, macOS's is 3.2.
        for script in self.kit.rglob("*.sh"):
            text = script.read_text()
            if text.startswith("#!/bin/bash\n"):
                script.write_text(f"#!{BASH}\n" + text[len("#!/bin/bash\n"):])
        self.key_file = tmp_path / "room-api-key"
        self.key_file.write_text(KEY + "\n")
        self.key_file.chmod(0o600)
        self.data_dir = tmp_path / "srv" / "room-a"
        self.data_img = tmp_path / "var" / "room-a-data.img"
        self.data_img.parent.mkdir()
        self._fakes()
        self._downloads()
        self.proc_mounts(prjquota=True)

    def _script(self, name: str, text: str) -> None:
        path = self.bin / name
        path.write_text(text.replace("@BASH@", BASH or "/bin/bash"))
        path.chmod(0o755)

    def _fakes(self) -> None:
        for name, body in FAKES.items():
            self._script(name, PROLOGUE + body.strip() + "\n")
        self._script("grep", GREP_WRAPPER.replace("@REAL@", shutil.which("grep", path=BIN_PATH) or "/usr/bin/grep"))
        self._script("install", INSTALL_WRAPPER.replace("@REAL@", shutil.which("install", path=BIN_PATH) or "/usr/bin/install"))
        (self.bin / "python3").symlink_to(sys.executable)
        (self.bin / "bzip2").symlink_to(shutil.which("bzip2") or "/usr/bin/bzip2")

    def _downloads(self) -> None:
        # Small archives with the same member layout as the pinned ones, served
        # under the pinned URLs' file names; the copied versions.lock pins them.
        lock = (self.kit / "versions.lock").read_text()
        urls = dict(re.findall(r"^(GVISOR_URL|UV_URL|CADDY_URL)=(\S+)$", lock, re.M))
        bash = BASH or "/bin/bash"
        self.archives = {
            "GVISOR": _tar_bytes({"runsc": FAKE_RUNSC.replace("@BASH@", bash).encode()}, "w:bz2"),
            "UV": _tar_bytes({"uv-x86_64-unknown-linux-gnu/uv": FAKE_UV.replace("@BASH@", bash).encode()}, "w:gz"),
            "CADDY": _tar_bytes({"caddy": FAKE_CADDY.replace("@BASH@", bash).encode(), "LICENSE": b"fake"}, "w:gz"),
        }
        sums = {"GVISOR": ("GVISOR_SHA512", hashlib.sha512), "UV": ("UV_SHA256", hashlib.sha256), "CADDY": ("CADDY_SHA512", hashlib.sha512)}
        for name, data in self.archives.items():
            (self.www / urls[name + "_URL"].rsplit("/", 1)[1]).write_bytes(data)
            var, algo = sums[name]
            lock = re.sub(rf"^{var}=.*$", f"{var}={algo(data).hexdigest()}", lock, flags=re.M)
        # The API tarball is a build product (dist/ is not tracked): a stand-in with the same shape.
        tarball = _tar_bytes({"cathedral-test/pyproject.toml": b"[project]\nname='cathedral'\n", "cathedral-test/cathedral/__init__.py": b""}, "w:gz")
        (self.kit / "dist").mkdir()
        (self.kit / "dist" / "cathedral-test.tar.gz").write_bytes(tarball)
        lock = re.sub(r"^CATHEDRAL_TARBALL=.*$", "CATHEDRAL_TARBALL=dist/cathedral-test.tar.gz", lock, flags=re.M)
        lock = re.sub(r"^CATHEDRAL_TARBALL_SHA256=.*$", f"CATHEDRAL_TARBALL_SHA256={hashlib.sha256(tarball).hexdigest()}", lock, flags=re.M)
        (self.kit / "versions.lock").write_text(lock)
        self.urls = urls

    def tamper(self, name: str) -> str:
        """Serve a different archive under a pinned URL; returns the URL."""
        url = self.urls[name + "_URL"]
        (self.www / url.rsplit("/", 1)[1]).write_bytes(self.archives[name] + b"\n")
        return url

    def proc_mounts(self, prjquota: bool) -> None:
        opts = "rw,relatime,attr2,inode64" + (",prjquota" if prjquota else "")
        (self.state / "proc-mounts").write_text(f"/dev/loop7 {self.data_dir} xfs {opts} 0 0\n")

    def room_env(self, **overrides: str) -> Path:
        # The shipped example, with the paths pointed at this host; later lines win.
        values = {
            "ROOM_API_KEY_FILE": str(self.key_file), "ROOM_CUSTOMER": CUSTOMER, "ROOM_DATA_DIR": str(self.data_dir),
            "ROOM_DATA_IMG": str(self.data_img), "ROOM_DATA_SIZE_GB": "1", **overrides,
        }
        path = self.tmp / "room.env"
        path.write_text((KIT / "room.env.example").read_text() + "\n" + "".join(f'{k}="{v}"\n' for k, v in values.items()))
        return path

    def sealed_env(self, **overrides: str) -> Path:
        sealed = self.tmp / "sealed"
        hotel_key = self.tmp / "hotel.key"
        hotel_key.write_text(KEY + "\n")
        values = {"SEALED_DIR": str(sealed), "SEALED_API_KEY_FILE": str(hotel_key), "SEALED_OVMF": str(self.tmp / "OVMF.amdsev.fd"), **overrides}
        path = self.tmp / "sealed.env"
        path.write_text((KIT / "sealed" / "sealed.env.example").read_text() + "\n" + "".join(f'{k}="{v}"\n' for k, v in values.items()))
        return path

    def live_socket(self) -> Path:
        """The room daemon's socket, so the live-room guard runs (a re-run host)."""
        sock_dir = self.root / "run" / "pool-room"
        cwd = os.getcwd()
        server = socket.socket(socket.AF_UNIX)
        try:
            os.chdir(sock_dir)  # AF_UNIX paths are capped near 104 bytes; bind relative
            server.bind("docker.sock")
        finally:
            os.chdir(cwd)
            server.close()
        return sock_dir / "docker.sock"

    def snapshot(self) -> set[Path]:
        return set(self.root.rglob("*"))

    def run(self, script: Path, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        self.log.write_text("")
        for f in self.state.glob("count-*"):
            f.unlink()
        full_env = {
            "PATH": f"{self.bin}:{BIN_PATH}", "HOME": str(self.tmp), "LC_ALL": "C",
            "ROOM_DESTDIR": str(self.root), "FAKE_LOG": str(self.log), "FAKE_STATE": str(self.state),
            "FAKE_WWW": str(self.www), "FAKE_API_KEY": KEY, **(env or {}),
        }
        return subprocess.run([BASH, "-x", str(script), *args], capture_output=True, text=True, check=False, env=full_env, timeout=600)

    def calls(self, prefix: str = "") -> list[str]:
        return [ln for ln in self.log.read_text().splitlines() if ln.startswith(prefix)]

    def install(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return self.run(self.kit / "install.sh", *args, env=env)

    # Paths of the fake root that install.sh writes.
    @property
    def etc(self) -> Path:
        return self.root / "etc" / "pool-room"

    @property
    def opt(self) -> Path:
        return self.root / "opt" / "pool-room"

    @property
    def units(self) -> Path:
        return self.root / "etc" / "systemd" / "system"

    def unit(self, name: str) -> str:
        return (self.units / name).read_text()


@pytest.fixture
def host(tmp_path: Path) -> FakeHost:
    return FakeHost(tmp_path)


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _clean_install(host: FakeHost, **env: str) -> subprocess.CompletedProcess[str]:
    proc = host.install(str(host.room_env()), env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr[-4000:]
    return proc


# ---------------------------------------------------------------- install.sh: refusals before any write

def test_live_rooms_refuse_the_install_before_any_write(host: FakeHost) -> None:
    host.live_socket()
    before = host.snapshot()
    proc = host.install(str(host.room_env()), env={"FAKE_DOCKER_PS": "2"})
    assert proc.returncode == 1
    assert "2 live room(s)" in proc.stderr and "ROOM_RESTART_WITH_ROOMS=1" in proc.stderr
    # Only the kit's directories exist; no file, no unit, no data image.
    new = host.snapshot() - before
    assert all(p.is_dir() for p in new), sorted(new)
    assert {str(p.relative_to(host.root)) for p in new} == {"etc/pool-room", "opt", "opt/pool-room", "opt/pool-room/cache", "opt/pool-room/bin"}
    assert not host.data_img.exists()
    # The only host commands run were the root check and the room count.
    assert [c.split()[0] for c in host.calls()] == ["id", "docker"]
    assert host.calls("docker") == [f"docker -H unix://{host.root}/run/pool-room/docker.sock ps -q --filter label=cathedral.sandbox.owner"]


def test_a_room_daemon_that_does_not_answer_refuses_with_a_reason(host: FakeHost) -> None:
    host.live_socket()
    proc = host.install(str(host.room_env()), env={"FAKE_DOCKER_PS": "fail"})
    assert proc.returncode == 1
    assert "does not answer" in proc.stderr and "ROOM_RESTART_WITH_ROOMS=1" in proc.stderr
    assert not any(c.startswith("systemctl") for c in host.calls())


def test_the_operator_override_lets_the_install_run_with_live_rooms(host: FakeHost) -> None:
    host.live_socket()
    proc = host.install(str(host.room_env()), env={"FAKE_DOCKER_PS": "2", "ROOM_RESTART_WITH_ROOMS": "1"})
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert "done." in proc.stdout
    assert "ps -q --filter" not in "\n".join(host.calls("docker"))  # the guard did not even count


@pytest.mark.parametrize("key_file", ["missing", "unreadable", "empty-name"])
def test_an_unreadable_key_file_refuses_before_any_write(host: FakeHost, key_file: str) -> None:
    if key_file == "missing":
        host.key_file.unlink()
    elif key_file == "unreadable":
        if os.geteuid() == 0:
            pytest.skip("root reads every file")
        host.key_file.chmod(0)
    env_file = host.room_env(**({"ROOM_API_KEY_FILE": ""} if key_file == "empty-name" else {}))
    before = host.snapshot()
    proc = host.install(str(env_file))
    assert proc.returncode == 1
    assert "ROOM_API_KEY_FILE" in proc.stderr and "must be a readable file" in proc.stderr
    assert host.snapshot() == before
    assert [c.split()[0] for c in host.calls()] == ["id"]


@pytest.mark.parametrize("customer", ["", "a,b", "a:b", "-x", ".x", "a" * 65, "a b"])
def test_a_bad_room_customer_refuses_before_any_write(host: FakeHost, customer: str) -> None:
    # A comma or colon would mint a second key in CATHEDRAL_SANDBOX_KEYS; empty closed the API.
    before = host.snapshot()
    proc = host.install(str(host.room_env(ROOM_CUSTOMER=customer)))
    assert proc.returncode == 1
    assert "ROOM_CUSTOMER must be 1 to 64" in proc.stderr
    assert host.snapshot() == before
    assert [c.split()[0] for c in host.calls()] == ["id"]


# ---------------------------------------------------------------- install.sh: pinned downloads

@pytest.mark.parametrize("archive", ["GVISOR", "UV", "CADDY"])
def test_a_download_with_the_wrong_checksum_is_refused_and_nothing_starts(host: FakeHost, archive: str) -> None:
    url = host.tamper(archive)
    proc = host.install(str(host.room_env()))
    assert proc.returncode == 1
    assert f"checksum mismatch: {url}" in proc.stderr
    cache = host.opt / "cache"
    assert not list(cache.glob("*.part")), "a refused download must not stay in the cache"
    assert not list(cache.glob(f"{archive.lower()}-*"))
    # Nothing that the archive carries is installed, and no unit is loaded or started.
    if archive == "GVISOR":
        assert not list(host.opt.glob("gvisor*"))
    if archive in ("GVISOR", "UV"):
        assert not (host.opt / "bin" / "uv").exists() and not (host.opt / "venv").exists()
    assert not (host.opt / "bin" / "caddy").exists()
    assert not (host.etc / "api.key").exists() and not (host.etc / "secret.env").exists()
    assert not (host.units / "room-a-docker.service").exists() and not (host.units / "room-a.service").exists()
    # Step 0 makes sure containerd runs; no room unit is reloaded, enabled or started.
    assert [c for c in host.calls("systemctl") if "containerd" not in c] == [], host.calls("systemctl")


def test_a_corrupt_pinned_tarball_leaves_the_running_api_source_alone(host: FakeHost) -> None:
    _clean_install(host)
    lock = host.kit / "versions.lock"
    # The pin moves with every hotel API release; read it rather than repeat it.
    pinned = re.search(r"^CATHEDRAL_COMMIT=(\S+)$", lock.read_text(), flags=re.M).group(1)
    assert (host.opt / "src" / "COMMIT").read_text().strip() == pinned
    lock.write_text(re.sub(r"^CATHEDRAL_TARBALL_SHA256=.*$", "CATHEDRAL_TARBALL_SHA256=" + "0" * 64, lock.read_text(), flags=re.M))
    proc = host.install(str(host.room_env()))
    assert proc.returncode != 0
    assert (host.opt / "src" / "COMMIT").read_text().strip() == pinned
    assert (host.opt / "src" / "cathedral" / "__init__.py").exists()
    assert not (host.opt / "src.new").exists()
    assert not any("restart" in c for c in host.calls("systemctl")), host.calls("systemctl")


def test_the_shipped_tarball_matches_the_lock() -> None:
    # dist/ is a build product; where it exists it must be the one the lock pins.
    lock = (KIT / "versions.lock").read_text()
    tarball = KIT / re.search(r"^CATHEDRAL_TARBALL=(.*)$", lock, re.M).group(1)
    if not tarball.exists():
        pytest.skip("no dist tarball in this checkout")
    pinned = re.search(r"^CATHEDRAL_TARBALL_SHA256=(.*)$", lock, re.M).group(1)
    assert hashlib.sha256(tarball.read_bytes()).hexdigest() == pinned


# ---------------------------------------------------------------- install.sh: a clean host

def test_a_clean_host_gets_the_units_the_key_store_and_the_daemon_config(host: FakeHost) -> None:
    proc = _clean_install(host)
    assert KEY not in proc.stderr and KEY not in proc.stdout, "the key reached the trace"
    # The fake API answers 200 only to the installed key in the header file: the
    # final check passing means the key went from ROOM_API_KEY_FILE to reaper.headers.
    assert "API status: 200" in proc.stdout and "done." in proc.stdout
    assert f"size: {SLOTS} slots, quota {SLOTS}:{SLOTS}:{SLOTS * 4}" in proc.stdout

    api = host.unit("room-a.service")
    assert "TimeoutStopSec=600" in api and "KillMode=mixed" in api
    assert "User=poolroom" in api and f"EnvironmentFile={host.etc}/secret.env" in api
    assert re.search(r"^ExecStart=\S+/opt/pool-room/venv/bin/python \S+/opt/pool-room/bin/room_api.py sandbox serve --host 127.0.0.1 --port 18090 --runtime docker$", api, re.M)
    assert re.search(f"^TMPDIR={re.escape(str(host.data_dir))}/work$", (host.etc / "api.env").read_text(), re.M)
    assert (host.etc / "secret.env").read_text() == f"CATHEDRAL_SANDBOX_KEYS={KEY}:{CUSTOMER}:{SLOTS}\n"
    assert (host.etc / "api.key").read_text() == KEY + "\n"
    assert (host.etc / "reaper.headers").read_text() == f"Authorization: Bearer {KEY}\n"
    assert _mode(host.etc / "api.key") == 0o640 and _mode(host.etc / "secret.env") == 0o600 and _mode(host.etc / "reaper.headers") == 0o600
    assert _mode(host.etc / "room.env") == 0o644 and _mode(host.etc / "Caddyfile") == 0o644

    daemon = json.loads((host.etc / "daemon.json").read_text())
    assert daemon["default-runtime"] == "runsc" and daemon["iptables"] is False and daemon["ip6tables"] is False
    assert daemon["hosts"] == [f"unix://{host.root}/run/pool-room/docker.sock"]
    assert daemon["runtimes"]["runsc"]["runtimeArgs"] == ["--platform=systrap", "--overlay2=none", "--net-raw"]
    assert daemon["data-root"] == f"{host.data_dir}/docker"

    for name in ("room-a-data.service", "room-a-docker.service", "room-a-health.service", "room-a-reaper.service",
                 "room-a-reaper.timer", "room-a-egress.service", "room-a-receipts.service", "room-a-caddy.service"):
        assert (host.units / name).exists(), name
    assert "Before=room-a.service" in host.unit("room-a-egress.service")
    assert "KillMode=process" in host.unit("room-a-docker.service")
    caddy = (host.etc / "Caddyfile").read_text()
    assert "reverse_proxy 127.0.0.1:18092" in caddy and "reverse_proxy 127.0.0.1:18091" in caddy

    # Downloads went through the pinned URLs and were extracted; the state file lists what was added.
    downloads = [c for c in host.calls("curl") if "--retry" in c]
    assert [c.rsplit(" ", 1)[1] for c in downloads] == [host.urls["GVISOR_URL"], host.urls["UV_URL"], host.urls["CADDY_URL"]]
    assert (host.opt / "gvisor" / "runsc").exists() and (host.opt / "bin" / "caddy").exists()
    state = (host.etc / "install-state").read_text().splitlines()
    assert f"file:{host.data_img}" in state and "unit:room-a.service" in state and "unit:room-a-caddy.service" in state
    assert "user:poolroom" not in state  # the fake host already had the user

    # systemd: reload before enable, the API restarted once, the daemon never restarted on a first install
    sysd = host.calls("systemctl")
    assert sysd.index("systemctl daemon-reload") < sysd.index("systemctl enable --now room-a-data.service")
    assert sysd.count("systemctl restart room-a.service room-a-health.service") == 1
    assert "systemctl restart room-a-receipts.service" in sysd and "systemctl restart room-a-caddy.service" in sysd
    assert "systemctl start room-a-reaper.timer" in sysd


def test_the_final_check_fails_the_install_when_the_api_never_answers_200(host: FakeHost) -> None:
    proc = host.install(str(host.room_env()), env={"FAKE_API_CODES": "401"})
    assert proc.returncode == 1
    assert "API did not answer 200 on /v1/status with its own key (got 401)" in proc.stderr
    assert "done." not in proc.stdout and "API status" not in proc.stdout
    status = [c for c in host.calls("curl") if "%{http_code}" in c]
    assert len(status) == 60, "the check keeps asking for 60 seconds"
    assert all(f"-H @{host.etc}/reaper.headers http://127.0.0.1:18090/v1/status" in c for c in status)


def test_the_final_check_waits_for_the_api_to_come_up(host: FakeHost) -> None:
    proc = host.install(str(host.room_env()), env={"FAKE_API_CODES": "000 000 200"})
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert len([c for c in host.calls("curl") if "%{http_code}" in c]) == 3


def test_a_data_volume_without_project_quota_is_refused(host: FakeHost) -> None:
    host.proc_mounts(prjquota=False)
    proc = host.install(str(host.room_env()))
    assert proc.returncode == 1
    assert f"prjquota missing on {host.data_dir}" in proc.stderr
    assert not (host.etc / "api.key").exists()
    assert "systemctl enable --now room-a-docker.service" not in host.calls("systemctl")


def test_auto_room_networks_skip_cidrs_other_host_routes_use(host: FakeHost) -> None:
    # 165 rooms do not fit a 100-port bridge: one room network of 1,000 from the
    # pool, past the /22 another device already routes and past this room's own bridge.
    routes = "default via 10.213.4.1 dev eth0\n10.214.0.0/22 dev br-other proto kernel scope link\n10.213.0.0/22 dev pqbr0 proto kernel scope link"
    proc = host.install(str(host.room_env(ROOM_BRIDGE_PORT_CAP="100")), env={"FAKE_IP_ROUTES": routes})
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert f"room networks (auto, {SLOTS} rooms by resources): 10.214.4.0/22" in proc.stdout
    assert 'ROOM_NETS="10.214.4.0/22"' in (host.etc / "room.env").read_text()
    assert (host.etc / "room.env").read_text() == (host.etc / "room.env.applied").read_text()
    api_env = (host.etc / "api.env").read_text()
    assert "CATHEDRAL_ROOM_NETWORKS=1\n" in api_env and "CATHEDRAL_ROOM_NETWORK_SUBNETS=10.214.4.0/22\n" in api_env
    assert "CATHEDRAL_ROOM_NETWORK_BRIDGE_PREFIX=rmnet\n" in api_env and 'CATHEDRAL_ROOM_NETWORK_DNS="1.1.1.1 8.8.8.8"\n' in api_env


# ---------------------------------------------------------------- install.sh: a re-run on an installed hotel (stage H)

def test_a_rerun_downloads_nothing_and_restarts_only_the_api(host: FakeHost) -> None:
    _clean_install(host)
    host.live_socket()
    proc = host.install(str(host.room_env()), env={"FAKE_DOCKER_PS": "0"})
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert not [c for c in host.calls("curl") if "--retry" in c], "cached archives with the pinned sums are not fetched again"
    assert "room daemon config changed" not in proc.stdout
    sysd = host.calls("systemctl")
    assert "systemctl restart room-a-docker.service" not in sysd
    assert sysd.count("systemctl restart room-a.service room-a-health.service") == 1
    assert len(_room_counts(host)) == 2  # at the top and right before the API restart


def _room_counts(host: FakeHost) -> list[str]:
    return [c for c in host.calls("docker") if "ps -q --filter label=cathedral.sandbox.owner" in c]


def test_a_changed_bridge_setting_restarts_the_room_daemon_once(host: FakeHost) -> None:
    _clean_install(host)
    host.live_socket()
    proc = host.install(str(host.room_env(ROOM_BRIDGE_CIDR="10.213.8.1/22")), env={"FAKE_DOCKER_PS": "0"})
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert "room daemon config changed" in proc.stdout
    assert host.calls("systemctl").count("systemctl restart room-a-docker.service") == 1
    assert len(_room_counts(host)) == 3  # the daemon restart gets its own count


def test_rooms_that_open_before_a_daemon_restart_stop_it(host: FakeHost) -> None:
    _clean_install(host)
    host.live_socket()
    proc = host.install(str(host.room_env(ROOM_BRIDGE_CIDR="10.213.8.1/22")), env={"FAKE_DOCKER_PS": "0 1"})
    assert proc.returncode == 1 and "1 live room(s)" in proc.stderr
    assert not any("restart" in c for c in host.calls("systemctl")), host.calls("systemctl")
    assert len(_room_counts(host)) == 2


def test_a_refused_daemon_restart_is_done_by_the_next_run(host: FakeHost) -> None:
    # B150: room.env.applied used to be written before the restart guard
    # could refuse, so the next run saw no change and never restarted.
    # A bridge setting changed and a room opened before step 8: the daemon
    # restart is refused. The setting never reached the daemon, so the next
    # run with no rooms must restart it.
    _clean_install(host)
    host.live_socket()
    refused = host.install(str(host.room_env(ROOM_BRIDGE_CIDR="10.213.8.1/22")), env={"FAKE_DOCKER_PS": "0 1"})
    assert refused.returncode == 1 and "systemctl restart room-a-docker.service" not in host.calls("systemctl")
    proc = host.install(str(host.room_env(ROOM_BRIDGE_CIDR="10.213.8.1/22")), env={"FAKE_DOCKER_PS": "0"})
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert "systemctl restart room-a-docker.service" in host.calls("systemctl")


def test_a_first_install_does_not_restart_the_daemon_it_just_started(host: FakeHost) -> None:
    # B151: `enable --now` starts the daemon with the new config; a restart
    # seconds later served nothing and printed "config changed" on every
    # first install, because the no-previous-config guard could never be false.
    proc = host.install(str(host.room_env()))
    assert proc.returncode == 0, proc.stderr[-3000:]
    sysd = host.calls("systemctl")
    assert "systemctl enable --now room-a-docker.service" in sysd, sysd
    assert "systemctl restart room-a-docker.service" not in sysd, sysd
    assert "room daemon config changed" not in proc.stdout + proc.stderr


def test_rooms_that_open_during_the_install_stop_the_api_restart(host: FakeHost) -> None:
    # The guard at the top is minutes old by step 13: the room count is taken
    # again, and a room that opened since stops the restart.
    _clean_install(host)
    host.live_socket()
    proc = host.install(str(host.room_env()), env={"FAKE_DOCKER_PS": "0 1"})
    assert proc.returncode == 1
    assert "1 live room(s)" in proc.stderr
    sysd = host.calls("systemctl")
    assert not any("restart" in c for c in sysd), sysd
    assert "done." not in proc.stdout


# ---------------------------------------------------------------- room-net.sh

def _net_env(host: FakeHost, nets: str = "10.214.0.0/22 10.214.4.0/22") -> Path:
    env = host.tmp / "net.env"
    env.write_text(f'ROOM_ID=room-a\nROOM_BRIDGE=pqbr0\nROOM_BRIDGE_CIDR=10.213.0.1/22\nROOM_NETS="{nets}"\n'
                   f'ROOM_DATA_DIR={host.data_dir}\nROOM_NET_BRIDGE_PREFIX=rmnet\n')
    return env


def test_room_net_up_builds_every_bridge_guard_before_the_chain_is_reachable(host: FakeHost) -> None:
    kv = host.data_dir / "docker" / "network" / "files" / "local-kv.db"
    kv.parent.mkdir(parents=True)
    kv.write_text("stale subnet")
    proc = host.run(host.kit / "lib" / "room-net.sh", "up", str(_net_env(host)))
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert not kv.exists(), "the daemon's stored bridge subnet is dropped so a new CIDR takes effect"
    ipt = host.calls("iptables")
    assert ipt[-1] == "iptables -I FORWARD 1 -j ROOM-ROOM-A -m comment --comment pool-room:room-a", ipt[-1]
    for br, net in (("pqbr0", "10.213.0.0/22"), ("rmnet0", "10.214.0.0/22"), ("rmnet1", "10.214.4.0/22")):
        drops = [c for c in ipt if c.startswith(f"iptables -A ROOM-ROOM-A -i {br} -d ") and c.endswith("-j DROP")]
        assert [c.split()[6] for c in drops] == ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"], br
        spoof = ipt.index(f"iptables -A ROOM-ROOM-A -i {br} ! -s {net} -j DROP")
        assert ipt.index(drops[-1]) < spoof < ipt.index(f"iptables -A ROOM-ROOM-A -i {br} ! -o {br} -j ACCEPT")
        assert f"iptables -A ROOM-ROOM-A -o {br} -j DROP" in ipt and f"iptables -A ROOM-ROOM-A -i {br} -j DROP" in ipt
        assert f"iptables -I ROOM-ROOM-A-IN 1 -i {br} -p udp --dport 15353 -j ACCEPT" in ipt
        assert f"iptables -I ROOM-ROOM-A-IN 1 -i {br} -p tcp -m multiport --dports 15353,15080,15443 -j ACCEPT" in ipt
        assert f"iptables -I INPUT 1 -i {br} -j ROOM-ROOM-A-IN -m comment --comment pool-room:room-a" in ipt
        assert f"iptables -t nat -A POSTROUTING -s {net} ! -o {br} -j MASQUERADE -m comment --comment pool-room:room-a" in ipt
        assert f"ip6tables -I FORWARD 1 -i {br} -j DROP -m comment --comment pool-room:room-a" in host.calls("ip6tables")
        assert f"nft add rule bridge pool_room_room_a forward meta ibrname {br} drop" in host.calls("nft")
    assert "ip link add pqbr0 type bridge" in host.calls("ip") and "ip addr add 10.213.0.1/22 dev pqbr0" in host.calls("ip")
    assert "sysctl -q -w net.ipv4.ip_forward=1" in host.calls("sysctl")
    # up runs down first: the old table goes, then the table and chain come before any rule.
    nft = host.calls("nft")
    assert nft[0] == "nft delete table bridge pool_room_room_a"
    assert host.calls("nft add")[:2] == ["nft add table bridge pool_room_room_a",
                                         "nft add chain bridge pool_room_room_a forward { type filter hook forward priority 0; policy accept; }"]


@pytest.mark.parametrize("routed, message", [("10.213.0.0/22", "room CIDR 10.213.0.0/22 already routed"),
                                             ("10.214.4.0/22", "room network 10.214.4.0/22 already routed")])
def test_room_net_up_refuses_a_cidr_another_route_uses(host: FakeHost, routed: str, message: str) -> None:
    proc = host.run(host.kit / "lib" / "room-net.sh", "up", str(_net_env(host)), env={"FAKE_ROUTED": routed})
    assert proc.returncode == 1
    assert message in proc.stderr
    assert "iptables -I FORWARD 1 -j ROOM-ROOM-A -m comment --comment pool-room:room-a" not in host.calls("iptables")


def test_room_net_down_removes_only_tagged_rules_and_room_bridges(host: FakeHost) -> None:
    tagged = ('-A FORWARD -j ROOM-ROOM-A -m comment --comment "pool-room:room-a"\n'
              '-A INPUT -i pqbr0 -j ROOM-ROOM-A-IN -m comment --comment "pool-room:room-a"\n'
              '-A FORWARD -i docker0 -j DOCKER-USER -m comment --comment "someone else"')
    proc = host.run(host.kit / "lib" / "room-net.sh", "down", str(_net_env(host)),
                    env={"FAKE_IPTABLES_TAGGED_filter": tagged, "FAKE_LINKS": "pqbr0", "FAKE_BRIDGES": "rmnet0 rmnet1 br-other"})
    assert proc.returncode == 0, proc.stderr[-3000:]
    ipt = host.calls("iptables")
    assert "iptables -t filter -D FORWARD -j ROOM-ROOM-A -m comment --comment pool-room:room-a" in ipt
    assert "iptables -t filter -D INPUT -i pqbr0 -j ROOM-ROOM-A-IN -m comment --comment pool-room:room-a" in ipt
    assert not any("DOCKER-USER" in c and " -D " in c for c in ipt), "another owner's rule was deleted"
    assert "iptables -F ROOM-ROOM-A" in ipt and "iptables -X ROOM-ROOM-A-IN" in ipt
    assert "nft delete table bridge pool_room_room_a" in host.calls("nft")
    deleted = [c.split()[-1] for c in host.calls("ip link del")]
    assert deleted == ["pqbr0", "rmnet0", "rmnet1"]


# ---------------------------------------------------------------- host-net.sh (sealed host link)

def _run_host_net(host: FakeHost, action: str, **env: str) -> subprocess.CompletedProcess[str]:
    return host.run(host.kit / "sealed" / "host-net.sh", action, str(host.sealed_env()), env=env)


def test_host_net_up_orders_the_guest_rules_and_down_removes_them(host: FakeHost) -> None:
    proc = _run_host_net(host, "up")
    assert proc.returncode == 0, proc.stderr[-3000:]
    ipt = host.calls("iptables")
    fwd = [c for c in ipt if c.startswith("iptables -A SEALED-SNP0-FWD ")]
    assert [c.split("SEALED-SNP0-FWD ")[1] for c in fwd] == [
        "-i snp0 -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16 -j DROP",
        "-i snp0 -s 10.215.0.2 -j ACCEPT", "-i snp0 -j DROP",
        "-o snp0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT", "-o snp0 -j DROP"]
    assert ipt.index(fwd[-1]) < ipt.index("iptables -I FORWARD 1 -m comment --comment sealed-hotel:sealed-1 -j SEALED-SNP0-FWD")
    assert "iptables -I INPUT 1 -m comment --comment sealed-hotel:sealed-1 -j SEALED-SNP0-IN" in ipt
    assert "iptables -t nat -A POSTROUTING -s 10.215.0.2/32 ! -o snp0 -m comment --comment sealed-hotel:sealed-1 -j MASQUERADE" in ipt
    assert "ip tuntap add dev snp0 mode tap" in host.calls("ip") and "ip addr replace 10.215.0.1/30 dev snp0" in host.calls("ip")

    proc = _run_host_net(host, "down")
    assert proc.returncode == 0, proc.stderr[-3000:]
    ipt = host.calls("iptables")
    assert "iptables -D FORWARD -m comment --comment sealed-hotel:sealed-1 -j SEALED-SNP0-FWD" in ipt
    assert "iptables -t nat -D POSTROUTING -s 10.215.0.2/32 ! -o snp0 -m comment --comment sealed-hotel:sealed-1 -j MASQUERADE" in ipt
    assert "iptables -X SEALED-SNP0-FWD" in ipt and "iptables -X SEALED-SNP0-IN" in ipt
    assert host.calls("ip link del") == ["ip link del snp0"]


def test_host_net_check_restores_missing_rules_and_leaves_present_ones(host: FakeHost) -> None:
    proc = _run_host_net(host, "check", FAKE_IPTABLES_RULES="present")
    assert proc.returncode == 0 and proc.stdout == ""
    assert not [c for c in host.calls("iptables") if " -A " in c or " -I " in c], "present rules were rewritten"
    proc = _run_host_net(host, "check")
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert "host link rules for snp0 were missing; restoring" in proc.stderr
    assert "iptables -I FORWARD 1 -m comment --comment sealed-hotel:sealed-1 -j SEALED-SNP0-FWD" in host.calls("iptables")


# ---------------------------------------------------------------- install-sealed.sh

def test_sealed_install_on_a_host_without_snp_refuses_at_the_first_check(host: FakeHost) -> None:
    # install.sh --sealed hands off to the sealed installer, which must stop at
    # its hardware check before it makes any directory.
    sealed_env = host.sealed_env()
    before = host.snapshot()
    proc = host.install("--sealed", str(sealed_env))
    assert proc.returncode == 1
    assert "SEV-SNP is not enabled in kvm_amd" in proc.stderr
    assert host.snapshot() == before and not (host.tmp / "sealed").exists()


def _sealed_step5(host: FakeHost, measurement: str, expected: str = "ab" * 48, prev: bool = True, **env: str):
    """Run step 5 of install-sealed.sh (restart guard, attestation, measurement) verbatim.

    Steps 1 to 4 need /dev/sev (a builtin test on a device path), the guest
    build and sev-snp-measure; the slice sets the three values they produce.
    """
    text = (host.kit / "sealed" / "install-sealed.sh").read_text()
    head = text[:text.index("# ---------------------------------------------------------------- 1. assess")]
    tail = text[text.index("# ---------------------------------------------------------------- 5. start and check"):]
    script = host.kit / "sealed" / "step5-slice.sh"
    script.write_text(head + 'PREV_IMG=${SLICE_PREV_IMG}\nIMG=${SLICE_IMG}\nEXPECTED=${SLICE_EXPECTED}\n' + tail)
    sealed_env = host.sealed_env()
    sealed = host.tmp / "sealed"
    shutil.rmtree(sealed, ignore_errors=True)
    images = sealed / "images"
    (images / "20260101T000000Z").mkdir(parents=True)
    (images / "20260102T000000Z").mkdir()
    (images / "current").symlink_to("20260102T000000Z")
    (sealed / "run").mkdir()
    prev_img = str(images / "20260101T000000Z") if prev else ""
    proc = host.run(script, str(sealed_env), env={
        "SLICE_PREV_IMG": prev_img, "SLICE_IMG": str(images / "20260102T000000Z"), "SLICE_EXPECTED": expected,
        "FAKE_MEASUREMENT": measurement, **env})
    return proc, images


def test_sealed_restart_with_live_rooms_is_refused_unless_overridden(host: FakeHost) -> None:
    (host.state / "active-units").write_text("room-sealed-sealed-1.service\n")
    proc, images = _sealed_step5(host, "ab" * 48, FAKE_SEALED_ROOMS="3")
    assert proc.returncode == 1
    assert "3 live room(s)" in proc.stderr and "SEALED_RESTART_WITH_ROOMS=1" in proc.stderr
    assert "systemctl restart room-sealed-sealed-1.service" not in host.calls("systemctl")
    assert os.readlink(images / "current") == "20260102T000000Z"
    assert KEY not in proc.stdout  # the key goes into the header of one curl call only
    (host.state / "active-units").write_text("room-sealed-sealed-1.service\n")
    proc, images = _sealed_step5(host, "ab" * 48, FAKE_SEALED_ROOMS="3", SEALED_RESTART_WITH_ROOMS="1")
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert "systemctl restart room-sealed-sealed-1.service" in host.calls("systemctl")
    assert "measurement matches the build" in proc.stdout and "done." in proc.stdout
    assert (host.tmp / "sealed" / "run" / "attestation.json").exists()
    assert list((images / "20260102T000000Z").glob("attestation-*.json"))


def test_sealed_hotel_api_that_does_not_answer_refuses_the_restart(host: FakeHost) -> None:
    (host.state / "active-units").write_text("room-sealed-sealed-1.service\n")
    proc, _ = _sealed_step5(host, "ab" * 48, FAKE_SEALED_API="down")
    assert proc.returncode == 1
    assert "did not answer, so live rooms cannot be counted" in proc.stderr
    assert not host.calls("systemctl restart")


def test_sealed_first_start_asks_no_api_and_restarts(host: FakeHost) -> None:
    proc, _ = _sealed_step5(host, "ab" * 48, prev=False, FAKE_ATT_FAILS="2")
    assert proc.returncode == 0, proc.stderr[-3000:]
    assert not [c for c in host.calls("curl") if "/v1/sandboxes" in c], "no guest runs yet: nothing to count"
    assert len([c for c in host.calls("curl") if "/room/attestation" in c]) == 3, "the attestation is polled until the guest answers"


def test_sealed_measurement_mismatch_disables_the_unit_and_restores_the_previous_image(host: FakeHost) -> None:
    proc, images = _sealed_step5(host, "cd" * 48)
    assert proc.returncode == 1
    assert "MEASUREMENT DIFFERS: report " + "cd" * 48 + ", build " + "ab" * 48 in proc.stdout
    sysd = host.calls("systemctl")
    assert sysd.index("systemctl restart room-sealed-sealed-1.service") < sysd.index("systemctl disable --now room-sealed-sealed-1.service")
    assert os.readlink(images / "current") == str(images / "20260101T000000Z")
    assert "done." not in proc.stdout
    assert list((images / "20260102T000000Z").glob("attestation-*.json")), "the differing report is kept with the build"


def test_sealed_guest_that_stops_fails_the_install_at_once(host: FakeHost) -> None:
    proc, _ = _sealed_step5(host, "ab" * 48, FAKE_ATT_FAILS="999", FAKE_RESTART_KILLS="room-sealed-sealed-1.service")
    assert proc.returncode == 1
    assert "guest stopped" in proc.stderr
    assert len([c for c in host.calls("curl") if "/room/attestation" in c]) == 1

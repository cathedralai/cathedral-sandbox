"""Local development fakes for the TEE box harness. NEVER used on the TD.

A developer machine has docker (runc only, no root), no TDX and no dm-crypt.
To exercise the harness logic end to end anyway, ``serve_worker.py`` with
``E2E_LOCAL=1`` passes ``build_tee_box_api`` these replacements:

- RTMR3: ``FileRtmr3``, a file that extends like TDG.MR.RTMR.EXTEND;
- storage: a probe that reports the central state directory as tmpfs, no
  swap, and Docker's data root as dm-crypt with integrity (or not, with
  ``E2E_LOCAL_SCRATCH=plain``, to exercise the refusal path);
- the guest's tools: ``LocalGuest``, a runner that passes docker and ``ip``
  through (rewriting ``--runtime=runsc`` to runc and reporting a runsc
  runtime entry), and fakes nft, tc and nsenter, which need root. The veth
  lookup stays real: the peer index comes from the container itself and the
  bridge ports from the real ``ip -o link show master cathsbx0``.

So locally the egress table is NOT enforced; the harness reports the egress
probes as INFO there.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import subprocess

from cathedral.tee_box.enforce import NFT_QUARANTINE_TABLE, NFT_TABLE
from cathedral.tee_box.storage import TMPFS_MAGIC, StorageProbe, default_storage_probe

RUNSC_ENTRY = {
    "path": "/usr/local/bin/runsc",
    "runtimeArgs": ["--platform=systrap", "--network=sandbox"],
}
SWAPS_HEADER = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"
FAKE_DEVICE = (253, 250)


class FileRtmr3:
    """RTMR3 in a file: read returns 48 bytes, extend sets SHA-384(old || data)."""

    def __init__(self, path: str) -> None:
        self.path = path

    def read(self) -> bytes:
        with open(self.path, "rb") as handle:
            value = handle.read(49)
        if len(value) != 48:
            raise OSError("fake RTMR3 file is not 48 bytes")
        return value

    def extend(self, digest: bytes) -> None:
        value = hashlib.sha384(self.read() + digest).digest()
        with open(self.path, "wb") as handle:
            handle.write(value)


def nft_listing(policy) -> bytes:  # noqa: ANN001
    """What ``nft --json list table`` prints for the policy (as the sandbox tests model it)."""

    def elements(networks):  # noqa: ANN001, ANN202
        out = []
        for net in ipaddress.collapse_addresses(networks):
            if net.num_addresses == 1:
                out.append(str(net.network_address))
            else:
                out.append({"prefix": {"addr": str(net.network_address), "len": net.prefixlen}})
        return out

    base = {"family": "inet", "table": NFT_TABLE}
    iif = {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": policy.bridge}}
    counter = {"counter": {"packets": 0, "bytes": 0}}
    entries = [
        {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": NFT_TABLE, "handle": 3}},
        {
            "set": {
                **base,
                "name": "deny4",
                "type": "ipv4_addr",
                "handle": 3,
                "flags": ["interval"],
                "elem": elements(policy.denied_ipv4),
            }
        },
        {
            "set": {
                **base,
                "name": "deny6",
                "type": "ipv6_addr",
                "handle": 4,
                "flags": ["interval"],
                "elem": elements(policy.denied_ipv6),
            }
        },
        {
            "chain": {
                **base,
                "name": "forward",
                "handle": 1,
                "type": "filter",
                "hook": "forward",
                "prio": -1,
                "policy": "accept",
            }
        },
        {
            "chain": {
                **base,
                "name": "input",
                "handle": 2,
                "type": "filter",
                "hook": "input",
                "prio": -1,
                "policy": "accept",
            }
        },
    ]
    for protocol, name in (("ip", "@deny4"), ("ip6", "@deny6")):
        daddr = {"payload": {"protocol": protocol, "field": "daddr"}}
        entries.append(
            {
                "rule": {
                    **base,
                    "chain": "forward",
                    "handle": 5,
                    "expr": [
                        iif,
                        {"match": {"op": "==", "left": daddr, "right": name}},
                        counter,
                        {"drop": None},
                    ],
                }
            }
        )
    entries.append(
        {"rule": {**base, "chain": "input", "handle": 7, "expr": [iif, counter, {"drop": None}]}}
    )
    return json.dumps({"nftables": entries}).encode()


class LocalGuest:
    """The guest's docker/ip (real) and nft/tc/nsenter (faked) for a rootless machine."""

    def __init__(self, policy) -> None:  # noqa: ANN001
        self.policy = policy
        self.table: bytes | None = None
        self.quarantine = False
        self.qdiscs: dict[str, list[dict]] = {}
        self.filters: dict[str, str] = {}
        self.sandbox_keys: dict[str, str] = {}
        self.log = os.environ.get("E2E_LOCAL_GUEST_LOG")

    @staticmethod
    def _done(argv, stdout=b"", code=0, stderr=b""):  # noqa: ANN001, ANN205
        return subprocess.CompletedProcess(argv, code, stdout, stderr)

    def __call__(self, argv, **kwargs):  # noqa: ANN001, ANN204
        if self.log:
            with open(self.log, "a") as handle:
                handle.write(json.dumps(argv) + "\n")
        tool = argv[0].rsplit("/", 1)[-1]
        if tool == "docker":
            return self._docker(list(argv), kwargs)
        if tool == "nft":
            return self._nft(argv, kwargs.get("input"))
        if tool == "tc":
            return self._tc(argv)
        if tool == "nsenter":
            return self._nsenter(argv, kwargs)
        return subprocess.run(argv, **kwargs)

    def _docker(self, argv, kwargs):  # noqa: ANN001, ANN202
        if argv[1:3] == ["info", "--format"] and argv[3] == "{{json .Runtimes}}":
            result = subprocess.run(argv, **kwargs)
            runtimes = json.loads(result.stdout or b"{}")
            runtimes["runsc"] = RUNSC_ENTRY
            return self._done(argv, json.dumps(runtimes).encode())
        if argv[1:3] == ["info", "--format"] and "DockerRootDir" in argv[3]:
            root = (
                subprocess.run([argv[0], "info", "--format", "{{json .DockerRootDir}}"], **kwargs)
                .stdout.decode()
                .strip()
            )
            status = [["Backing Filesystem", "extfs"]]
            return self._done(argv, f'{root} "overlay2" {json.dumps(status)}'.encode())
        if argv[1:3] == ["info", "--format"] and "Driver" in argv[3]:
            return self._done(argv, b'"overlay2" [["Backing Filesystem","extfs"]]')
        if argv[1] == "run":
            argv = ["--runtime=runc" if item.startswith("--runtime=") else item for item in argv]
            return subprocess.run(argv, **kwargs)
        result = subprocess.run(argv, **kwargs)
        if argv[1:4] == ["container", "inspect", "--format"] and "SandboxKey" in argv[4]:
            key = (result.stdout or b"").decode().strip()
            if key:
                self.sandbox_keys[key] = argv[5]
        return result

    def _nft(self, argv, stdin):  # noqa: ANN001, ANN202
        quarantine_head = (
            f"table inet {NFT_QUARANTINE_TABLE}\ndelete table inet {NFT_QUARANTINE_TABLE}\n"
        )
        if argv[1:] == ["-f", "-"] and stdin.decode().startswith(quarantine_head):
            self.quarantine = True
            return self._done(argv)
        if argv[1:] == ["list", "table", "inet", NFT_QUARANTINE_TABLE]:
            if not self.quarantine:
                return self._done(argv, code=1, stderr=b"Error: No such file or directory")
            return self._done(argv, b"table inet cathedral_tee_box_lapse {}\n")
        if argv[1:] == ["delete", "table", "inet", NFT_QUARANTINE_TABLE]:
            if not self.quarantine:
                return self._done(argv, code=1, stderr=b"Error: No such file or directory")
            self.quarantine = False
            return self._done(argv)
        if argv[1:] == ["-f", "-"]:
            if not stdin.decode().startswith(f"table inet {NFT_TABLE}\n"):
                return self._done(argv, code=1, stderr=b"Error: unexpected ruleset")
            self.table = nft_listing(self.policy)
            return self._done(argv)
        if argv[1:] == ["--json", "list", "table", "inet", NFT_TABLE]:
            if self.table is None:
                return self._done(argv, code=1, stderr=b"Error: No such file or directory")
            return self._done(argv, self.table)
        return self._done(argv, code=1, stderr=b"Error: unsupported in the local fake")

    def _nsenter(self, argv, kwargs):  # noqa: ANN001, ANN202
        key = argv[1].removeprefix("--net=")
        name = self.sandbox_keys.get(key)
        if name is None:
            return self._done(argv, code=1, stderr=b"nsenter: unknown namespace (local fake)")
        docker = "/usr/bin/docker"
        result = subprocess.run(
            [docker, "exec", name, "cat", "/sys/class/net/eth0/iflink"],
            capture_output=True,
            timeout=kwargs.get("timeout", 15),
            check=False,
        )
        index = (result.stdout or b"").decode().strip()
        if result.returncode != 0 or not index.isdigit():
            return self._done(argv, code=1, stderr=b"cannot read the peer index (local fake)")
        return self._done(argv, f"2: eth0@if{index}: <BROADCAST,MULTICAST,UP> mtu 1500\n".encode())

    def _tc(self, argv):  # noqa: ANN001, ANN202
        if argv[1:3] == ["qdisc", "replace"] and "root" in argv:
            rate = int(argv[argv.index("rate") + 1].removesuffix("mbit")) * 125_000
            self.qdiscs.setdefault(argv[4], []).append(
                {"kind": "tbf", "handle": "8001:", "root": True, "options": {"rate": rate}}
            )
        elif argv[1:3] == ["qdisc", "replace"]:
            self.qdiscs.setdefault(argv[4], []).append(
                {"kind": "ingress", "handle": "ffff:", "parent": "ffff:fff1", "options": {}}
            )
        elif argv[1:3] == ["filter", "replace"]:
            rate = argv[argv.index("rate") + 1]
            self.filters[argv[4]] = (
                "filter parent ffff: protocol all pref 49152 matchall chain 0 handle 0x1\n"
                f"\taction order 1:  police 0x1 rate {rate.replace('mbit', 'Mbit')} "
                "burst 1250000b mtu 2Kb action drop overhead 0b\n"
            )
        elif argv[1:4] == ["-json", "qdisc", "show"]:
            return self._done(argv, json.dumps(self.qdiscs.get(argv[5], [])).encode())
        elif argv[1:3] == ["filter", "show"]:
            return self._done(argv, self.filters.get(argv[4], "").encode())
        elif argv[1:3] == ["qdisc", "del"]:
            if argv[4] not in self.qdiscs:
                return self._done(
                    argv, code=1, stderr=b'Cannot find device "%s"' % argv[4].encode()
                )
            kind = "tbf" if argv[5] == "root" else "ingress"
            self.qdiscs[argv[4]] = [q for q in self.qdiscs[argv[4]] if q["kind"] != kind]
        else:
            return self._done(argv, code=1, stderr=b"unsupported in the local fake")
        return self._done(argv)


def local_storage_probe(tmpfs_dir: str, docker_root: str, *, plain: bool) -> StorageProbe:
    real = default_storage_probe()
    tmpfs_dir = os.path.realpath(tmpfs_dir)

    def fs_type(path: str) -> int:
        resolved = os.path.realpath(path)
        if resolved == tmpfs_dir or resolved.startswith(tmpfs_dir + "/"):
            return TMPFS_MAGIC
        return real.fs_type(path)

    def mountinfo() -> str:
        major, minor = FAKE_DEVICE
        return (
            "1 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n"
            f"900 1 {major}:{minor} / {docker_root} rw,relatime - ext4 /dev/mapper/e2e-local rw\n"
        )

    def crypt_integrity(major: int, minor: int) -> tuple[bool, str]:
        if plain:
            return False, f"block device {major}:{minor} is not a device-mapper device (local fake)"
        return True, "e2e-local: dm-crypt aes-xts-plain64 integrity hmac(sha256) (local fake)"

    return StorageProbe(
        fs_type=fs_type,
        mountinfo=mountinfo,
        swaps=lambda: SWAPS_HEADER,
        crypt_integrity=crypt_integrity,
        device_of=lambda path: FAKE_DEVICE,
    )


def local_build_kwargs(config, kwargs: dict) -> dict:  # noqa: ANN001
    from cathedral.tee_box import configure

    policy = configure.box_policy(config, public_endpoint=kwargs.get("public_endpoint"))
    docker_root = (
        subprocess.run(
            [config.docker_path, "info", "--format", "{{.DockerRootDir}}"],
            capture_output=True,
            check=True,
            timeout=60,
        )
        .stdout.decode()
        .strip()
    )
    kwargs = dict(kwargs)
    kwargs["runner"] = LocalGuest(policy)
    kwargs["storage_probe"] = local_storage_probe(
        os.environ["E2E_LOCAL_TMPFS_DIR"],
        os.path.realpath(docker_root),
        plain=os.environ.get("E2E_LOCAL_SCRATCH") == "plain",
    )
    kwargs["boot_options"] = {"rtmr": FileRtmr3(os.environ["E2E_LOCAL_RTMR3"])}
    return kwargs

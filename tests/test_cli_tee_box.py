"""Worker flags for the TEE box API: off by default, all or nothing, TLS only.

The callers' root keys are not a flag: they come from the fixed image path and
must match the launch's measured binding (cathedral/tee_box/measured_root.py).
"""

from __future__ import annotations

import base64
import json
import re
import subprocess
from pathlib import Path

import pytest

from cathedral import cli
from cathedral.cli import DEFAULT_WORKER_BEARER_ENV, build_parser, cmd_worker_serve
from cathedral.policy_registry import canonical_json
from cathedral.tee_box import TeeBoxSandboxApi, measured_root
from cathedral.tee_box import configure as configure_module
from cathedral.tee_box import boot as boot_module
from cathedral.tee_box.boot import RTMR3_CONSUMED, BootError, BootGuard, RelaunchRequired
from cathedral.tee_box.configure import OPTIONAL, REQUIRED, tee_box_config
from cathedral.tee_box.storage import TMPFS_MAGIC, StorageProbe
from tests.test_cli import _tls_material
from tests.test_tee_box_service import (
    BOOTED_AT,
    NETUID,
    NETWORK,
    _FakeRtmr,
    OTHER_ROOT_SEED,
    ROOT_KEYS,
    ROOT_SEED,
    _public,
)
from tests.test_validator_access import WORKER_HOTKEY

RUNSC = '{"runsc":{"path":"/usr/local/bin/runsc","runtimeArgs":["--platform=systrap"]}}'


class _FakeServer:
    host = "127.0.0.1"
    port = 8081
    calls: list[dict] = []

    def __init__(self, *_args, **kwargs):
        _FakeServer.calls.append(kwargs)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def serve_forever(self):
        return None


class _Guest:
    """The guest's docker, nft, ip and tc, answering the startup checks."""

    def __init__(self, *, storage: bytes = b'"overlay2" [["Backing Filesystem","xfs"]]'):
        self.storage = storage
        self.docker_root = "/var/lib/docker"
        self.driver_status = [["Backing Filesystem", "xfs"]]
        self.nft_fails = False
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        assert kwargs["shell"] is False
        self.calls.append(argv)
        tool = argv[0].rsplit("/", 1)[-1]
        if tool == "docker" and argv[1] == "info":
            out = RUNSC.encode() if "Runtimes" in argv[-1] else self.storage
            if "DockerRootDir" in argv[-1]:
                parts = (self.docker_root, "overlay2", self.driver_status)
                out = " ".join(json.dumps(part) for part in parts).encode()
            return subprocess.CompletedProcess(argv, 0, out, b"")
        if tool == "docker" and argv[1:3] == ["network", "inspect"]:
            network = {
                "Driver": "bridge",
                "Options": {
                    "com.docker.network.bridge.name": "cathsbx0",
                    "com.docker.network.bridge.enable_icc": "false",
                },
            }
            return subprocess.CompletedProcess(argv, 0, json.dumps(network).encode(), b"")
        if tool == "nft":
            if self.nft_fails:
                return subprocess.CompletedProcess(argv, 1, b"", b"Error: permission denied")
            if argv[1] == "-f":
                return subprocess.CompletedProcess(argv, 0, b"", b"")
            if argv[1] == "list":  # no quarantine table left from an earlier run
                return subprocess.CompletedProcess(argv, 1, b"", b"Error: No such file")
            from tests.test_tee_box_enforce import _listing

            policy = configure_module.build_egress_policy(["34.120.1.2"])
            return subprocess.CompletedProcess(argv, 0, _listing(policy), b"")
        if tool == "ip":
            listing = [{"ifname": "eth0", "addr_info": [{"local": "10.128.0.5"}]}]
            return subprocess.CompletedProcess(argv, 0, json.dumps(listing).encode(), b"")
        raise AssertionError(argv)


EXT4_MAGIC = 0xEF53
SWAPS_HEADER = "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n"


class _Storage:
    """The guest's storage as the TEE box checks read it; each part is a lever.

    By default the state directory is tmpfs, there is no swap, and Docker's
    data root is an ext4 filesystem on dm-crypt with AEAD integrity.
    """

    def __init__(self, docker_root: Path) -> None:
        self.docker_root = docker_root
        self.disk_paths: set[str] = set()  # statfs says ext4 for these
        self.root_fstype = "ext4"
        self.extra_mounts: list[str] = []
        self.root_device = (253, 3)
        self.crypt_devices = {
            "253:3": (True, "cathedral-scratch: dm-crypt capi:authenc integrity aead")
        }
        self.swap_lines: list[str] = []
        self.probed: list[str] = []

    def fs_type(self, path: str) -> int:
        self.probed.append(path)
        return EXT4_MAGIC if path in self.disk_paths else TMPFS_MAGIC

    def mountinfo(self) -> str:
        self.probed.append("mountinfo")
        lines = [
            "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw",
            f"90 22 253:3 / {self.docker_root} rw,relatime - {self.root_fstype} "
            "/dev/mapper/cathedral-scratch rw",
            *self.extra_mounts,
        ]
        return "\n".join(lines) + "\n"

    def swaps(self) -> str:
        self.probed.append("swaps")
        return SWAPS_HEADER + "".join(line + "\n" for line in self.swap_lines)

    def crypt_integrity(self, major: int, minor: int):
        self.probed.append(f"crypt {major}:{minor}")
        device = f"{major}:{minor}"
        return self.crypt_devices.get(device, (False, f"{device} is not a device-mapper device"))

    def device_of(self, path: str):
        self.probed.append(f"stat {path}")
        return self.root_device

    def probe(self) -> StorageProbe:
        return StorageProbe(
            self.fs_type, self.mountinfo, self.swaps, self.crypt_integrity, self.device_of
        )


def _root_key_file(seed: bytes = ROOT_SEED) -> bytes:
    return canonical_json({"cathedral-root-1": base64.b64encode(_public(seed)).decode("ascii")})


def _full_flags(tmp_path: Path) -> list[str]:
    return [
        "--tee-box-central-state",
        str(tmp_path / "tee-box-central.sqlite"),
        "--tee-box-executor",
        "runsc",
        "--tee-box-address",
        "34.120.1.2",
        "--tee-box-capacity",
        "8,32768,204800",
        "--tee-box-default-shape",
        "2,4096,10240",
    ]


def _args(
    tmp_path: Path, *extra: str, tls: bool = True, command: str = "serve", subnet: bool = True
):
    # The box takes the subnet from the flags; neither has a default.
    base = ["worker", command, "--hotkey", WORKER_HOTKEY]
    if subnet:
        base += ["--validator-network", NETWORK, "--validator-netuid", str(NETUID)]
    if tls:
        certificate, private_key = _tls_material(tmp_path)
        base += ["--tls-certificate", str(certificate), "--tls-private-key", str(private_key)]
    return build_parser().parse_args([*base, *extra])


@pytest.fixture
def guest(monkeypatch, tmp_path: Path):
    """A TDX guest whose image holds the root key file its MRCONFIGID names."""

    _FakeServer.calls = []
    monkeypatch.setenv(DEFAULT_WORKER_BEARER_ENV, "worker-token")
    monkeypatch.setattr("cathedral.cli.WorkerServer", _FakeServer)
    image_root = tmp_path / "image-central-root-keys.json"
    image_root.write_bytes(_root_key_file())
    monkeypatch.setattr(measured_root, "CENTRAL_ROOT_KEYS_PATH", str(image_root))
    box = _Guest()
    box.mrconfigid = measured_root.mrconfigid_for_root_keys(_root_key_file())
    box.image_root = image_root
    docker_root = tmp_path / "docker-root"
    docker_root.mkdir()
    box.docker_root = str(docker_root.resolve())
    box.disk = _Storage(docker_root.resolve())
    box.boot_id = "0f2d6c5e-1b7a-4c8e-9d3f-2a6b8c0e4f11"
    box.rtmr = _FakeRtmr()
    real_build = configure_module.build_tee_box_api

    def build(config, **kwargs):
        def read_binding():
            if isinstance(box.mrconfigid, Exception):
                raise box.mrconfigid
            return box.mrconfigid

        def read_boot_id():
            if isinstance(box.boot_id, Exception):
                raise box.boot_id
            return box.boot_id

        return real_build(
            config,
            runner=box,
            read_binding=read_binding,
            storage_probe=box.disk.probe(),
            boot_options={
                **({} if box.rtmr is None else {"rtmr": box.rtmr}),
                "read_boot_id": read_boot_id,
                "read_booted_at": lambda: BOOTED_AT,
            },
            **kwargs,
        )

    monkeypatch.setattr(cli, "build_tee_box_api", build)
    return box


def test_no_tee_box_flags_mean_no_sandbox_api(tmp_path: Path, guest, capsys):
    assert cmd_worker_serve(_args(tmp_path, subnet=False)) == 0
    assert _FakeServer.calls[0]["tee_box_api"] is None
    assert guest.calls == []
    assert guest.disk.probed == []  # no TEE box, no storage rules
    startup = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert startup["tee_box"] is None


def test_the_flags_are_off_by_default_on_every_serve_command():
    parser = build_parser()
    for command in ("serve", "serve-snp"):
        args = parser.parse_args(["worker", command, "--hotkey", "miner"])
        assert tee_box_config(args) is None
    # Development, migration and GPU postures do not offer the flags at all.
    for command in ("develop", "migrate", "serve-gpu"):
        with pytest.raises(SystemExit):
            parser.parse_args(["worker", command, "--hotkey", "m", "--tee-box-executor", "runsc"])


def test_the_full_flag_set_serves_the_sandbox_api(tmp_path: Path, guest, capsys):
    assert cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path))) == 0
    api = _FakeServer.calls[0]["tee_box_api"]
    assert isinstance(api, TeeBoxSandboxApi)
    assert api.authorizer.worker_hotkey == WORKER_HOTKEY
    assert api.authorizer.channel_binding == _FakeServer.calls[0]["channel_binding"]
    assert api.authorizer.root_keys == ROOT_KEYS
    assert (api.authorizer.network, api.authorizer.netuid) == (NETWORK, NETUID)
    assert api.executor.network_modes == ("internet", "deny_all")
    assert api.executor.storage_quota is True
    assert [str(net) for net in api.egress.box_addresses] == ["34.120.1.2/32"]
    startup = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert startup["tee_box"]["egress"]["enforced"] is True
    assert startup["tee_box"]["network_modes"] == ["internet", "deny_all"]
    assert startup["tee_box"]["capacity"] == {"vcpus": 8, "memory_mib": 32768, "disk_mib": 204800}
    assert startup["tee_box"]["central_root_digest"] == measured_root.root_digest_from_mrconfigid(
        guest.mrconfigid
    )
    assert startup["tee_box"]["central_root_key_ids"] == ["cathedral-root-1"]
    assert startup["tee_box"]["storage"] == {
        "central_state": "central state on tmpfs",
        "swap": "no swap",
        "docker_root": guest.docker_root,
        "scratch": f"{guest.docker_root}: cathedral-scratch: dm-crypt capi:authenc integrity aead",
    }
    assert "crypt 253:3" in guest.disk.probed


@pytest.mark.parametrize("missing", ["--validator-network", "--validator-netuid"])
def test_the_box_has_no_default_network_or_netuid(tmp_path: Path, guest, missing):
    flags = [*_full_flags(tmp_path), "--validator-network", NETWORK, "--validator-netuid", "7"]
    with pytest.raises(
        ValueError,
        match=r"^the TEE box sandbox API requires --validator-network and --validator-netuid$",
    ):
        cmd_worker_serve(_args(tmp_path, *_without(flags, missing), subnet=False))
    # Refused before any storage probe, guest command or listener.
    assert _FakeServer.calls == [] and guest.calls == [] and guest.disk.probed == []


def test_the_box_binds_the_network_and_netuid_it_is_given(tmp_path: Path, guest, capsys):
    args = _args(
        tmp_path,
        *_full_flags(tmp_path),
        "--validator-network",
        "test",
        "--validator-netuid",
        "2",
        subnet=False,
    )
    assert cmd_worker_serve(args) == 0
    api = _FakeServer.calls[0]["tee_box_api"]
    assert (api.authorizer.network, api.authorizer.netuid) == ("test", 2)
    # The pair serves the box alone; it does not turn on signed validator access.
    assert _FakeServer.calls[0]["validator_authorizer"] is None


@pytest.mark.parametrize("network,netuid", [("Finney", "94"), ("finney", "-1")])
def test_the_box_refuses_a_malformed_network_or_netuid(tmp_path: Path, guest, network, netuid):
    args = _args(
        tmp_path,
        *_full_flags(tmp_path),
        "--validator-network",
        network,
        "--validator-netuid",
        netuid,
        subnet=False,
    )
    with pytest.raises(ValueError, match="network must be|netuid must be"):
        cmd_worker_serve(args)
    assert _FakeServer.calls == []


def test_a_network_and_netuid_without_the_box_still_ask_for_signed_access(
    tmp_path: Path, guest
):
    with pytest.raises(ValueError, match="^signed validator access requires"):
        cmd_worker_serve(_args(tmp_path))
    assert _FakeServer.calls == [] and guest.calls == []


def test_the_box_does_not_relax_a_partial_signed_access_set(tmp_path: Path, guest):
    snapshot = str(tmp_path / "validator-access.json")
    with pytest.raises(ValueError, match="^signed validator access requires"):
        cmd_worker_serve(
            _args(tmp_path, *_full_flags(tmp_path), "--validator-access-snapshot", snapshot)
        )
    assert _FakeServer.calls == [] and guest.calls == []


def test_serve_snp_takes_the_same_flags(tmp_path: Path, guest):
    args = _args(tmp_path, *_full_flags(tmp_path), command="serve-snp")
    assert tee_box_config(args) is not None


def test_serve_snp_refuses_without_a_measured_root_binding(tmp_path: Path, monkeypatch):
    # The real SNP reader, not the guest fixture's: HOST_DATA is not read yet.
    monkeypatch.setenv(DEFAULT_WORKER_BEARER_ENV, "worker-token")
    monkeypatch.setattr("cathedral.cli.WorkerServer", _FakeServer)
    monkeypatch.setattr(cli, "build_tee_box_api", _with_runner(_Guest()))
    _FakeServer.calls = []
    args = _args(tmp_path, *_full_flags(tmp_path), command="serve-snp")
    args.worker_posture = "development"  # skip SNP production's signed access requirement
    with pytest.raises(ValueError, match="HOST_DATA"):
        cmd_worker_serve(args)
    assert _FakeServer.calls == []


def _with_runner(box):
    real_build = configure_module.build_tee_box_api

    def build(config, **kwargs):
        return real_build(config, runner=box, **kwargs)

    return build


def test_a_root_key_file_that_does_not_match_mrconfigid_refuses(tmp_path: Path, guest):
    guest.image_root.write_bytes(_root_key_file(OTHER_ROOT_SEED))
    with pytest.raises(ValueError, match="does not match MRCONFIGID"):
        cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path)))
    assert _FakeServer.calls == [] and guest.calls == []


@pytest.mark.parametrize(
    ("binding", "match"),
    [
        (bytes(48), "MRCONFIGID is zero"),
        (b"\x01" * 48, "16 zero bytes"),
        (b"\x01" * 32, "48 bytes"),
        (measured_root.MeasuredRootError("the TD report device is unavailable"), "unavailable"),
        (OSError("ioctl failed"), "unreadable"),
    ],
)
def test_an_unusable_measured_binding_refuses(tmp_path: Path, guest, binding, match):
    guest.mrconfigid = binding
    with pytest.raises(ValueError, match=match):
        cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path)))
    assert _FakeServer.calls == [] and guest.calls == []


def test_a_missing_root_key_file_refuses(tmp_path: Path, guest):
    guest.image_root.unlink()
    with pytest.raises(ValueError, match="central root"):
        cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path)))
    assert _FakeServer.calls == []


@pytest.mark.parametrize(
    "flag",
    [
        "--tee-box-caller-snapshot",
        "--tee-box-caller-keys",
        "--tee-box-caller-keys-digest",
        "--tee-box-caller-state",
        "--tee-box-caller-max-age-seconds",
        "--tee-box-central-root-keys",
        "--tee-box-central-root-keys-digest",
        "--tee-box-root-keys",
        "--tee-box-mrconfigid",
    ],
)
def test_no_flag_names_the_callers_or_their_root(tmp_path: Path, flag, capsys):
    for command in ("serve", "serve-snp"):
        with pytest.raises(SystemExit):
            build_parser().parse_args(
                ["worker", command, "--hotkey", WORKER_HOTKEY, *_full_flags(tmp_path), flag, "x"]
            )
    assert "unrecognized arguments" in capsys.readouterr().err


def test_no_environment_variable_changes_the_root(tmp_path: Path, guest, monkeypatch):
    other_keys = tmp_path / "other-root.json"
    other_keys.write_bytes(_root_key_file(OTHER_ROOT_SEED))
    for name in (
        "CATHEDRAL_CENTRAL_ROOT_KEYS",
        "CATHEDRAL_TEE_BOX_ROOT_KEYS",
        "CATHEDRAL_TDX_TSM_REPORT_ROOT",
        "CATHEDRAL_MRCONFIGID",
    ):
        monkeypatch.setenv(name, str(other_keys))
    assert cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path))) == 0
    assert _FakeServer.calls[0]["tee_box_api"].authorizer.root_keys == ROOT_KEYS
    # The module that loads the root reads no environment at all.
    source = Path(measured_root.__file__).read_text()
    assert "os.environ" not in source and "getenv" not in source
    assert measured_root.CENTRAL_ROOT_KEYS_PATH == str(guest.image_root)


def _without(flags: list[str], flag: str) -> list[str]:
    at = flags.index(flag)
    return flags[:at] + flags[at + 2 :]


@pytest.mark.parametrize("flag", [*REQUIRED.values(), "--tee-box-address"])
def test_a_partial_flag_set_refuses_to_start(tmp_path: Path, guest, flag):
    with pytest.raises(ValueError, match="TEE box API requires"):
        cmd_worker_serve(_args(tmp_path, *_without(_full_flags(tmp_path), flag)))
    assert _FakeServer.calls == [] and guest.calls == []


@pytest.mark.parametrize(
    "lonely",
    [
        ["--tee-box-bandwidth-mbit", "50"],
        ["--tee-box-no-disk-quota"],
        ["--tee-box-detect-addresses"],
        ["--tee-box-address", "34.120.1.2"],
        ["--tee-box-runtime-path", "/opt/runsc"],
        ["--tee-box-docker-path", "/usr/local/bin/docker"],
    ],
)
def test_an_optional_flag_alone_is_a_partial_set(tmp_path: Path, guest, lonely):
    with pytest.raises(ValueError, match="TEE box API requires"):
        cmd_worker_serve(_args(tmp_path, *lonely))
    assert _FakeServer.calls == []


def test_every_flag_is_part_of_the_group():
    parser = build_parser()
    actions = {
        action.dest
        for action in parser._subparsers._group_actions[0]
        .choices["worker"]  # noqa: SLF001
        ._subparsers._group_actions[0]
        .choices["serve"]
        ._actions  # noqa: SLF001
        if action.dest.startswith("tee_box_")
    }
    assert actions == set(REQUIRED) | set(OPTIONAL)


def test_both_address_sources_refuse(tmp_path: Path, guest):
    with pytest.raises(ValueError, match="exactly one"):
        cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path), "--tee-box-detect-addresses"))


def test_the_flags_require_the_attested_tls_listener(tmp_path: Path, guest):
    with pytest.raises(ValueError, match="attested worker TLS"):
        cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path), tls=False))
    assert guest.calls == []


def test_a_default_shape_larger_than_capacity_refuses(tmp_path: Path, guest):
    flags = _without(_full_flags(tmp_path), "--tee-box-default-shape")
    with pytest.raises(ValueError, match="fit"):
        cmd_worker_serve(_args(tmp_path, *flags, "--tee-box-default-shape", "16,4096,10240"))


def test_unsupported_disk_quota_refuses_unless_opted_out(tmp_path: Path, guest):
    guest.storage = b'"overlay2" [["Backing Filesystem","extfs"]]'
    with pytest.raises(ValueError, match="--tee-box-no-disk-quota"):
        cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path)))
    assert _FakeServer.calls == []
    flags = [*_full_flags(tmp_path), "--tee-box-no-disk-quota"]
    assert cmd_worker_serve(_args(tmp_path, *flags)) == 0
    assert _FakeServer.calls[0]["tee_box_api"].executor.storage_quota is False


def test_an_unapplied_egress_table_starts_deny_all_only(tmp_path: Path, guest, capsys):
    guest.nft_fails = True
    assert cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path))) == 0
    api = _FakeServer.calls[0]["tee_box_api"]
    assert api.executor.network_modes == ("deny_all",)
    startup = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert startup["tee_box"]["egress"]["enforced"] is False
    assert startup["tee_box"]["egress"]["error"] == "nft apply failed"
    assert startup["tee_box"]["network_modes"] == ["deny_all"]


def test_detected_addresses_include_interfaces_and_an_ip_endpoint(tmp_path: Path, guest):
    config = tee_box_config(
        _args(
            tmp_path,
            *_without(_full_flags(tmp_path), "--tee-box-address"),
            "--tee-box-detect-addresses",
        )
    )
    policy = configure_module.box_policy(
        config, public_endpoint="https://34.120.1.2:8081", runner=guest
    )
    assert [str(net) for net in policy.box_addresses] == ["34.120.1.2/32", "10.128.0.5/32"]
    named = configure_module.box_policy(
        config, public_endpoint="https://miner.example:8081", runner=guest
    )
    assert [str(net) for net in named.box_addresses] == ["10.128.0.5/32"]


@pytest.mark.parametrize("other", ["--validator-access-state", "--central-access-state"])
def test_the_central_state_must_be_separate(tmp_path: Path, guest, other):
    flags = _full_flags(tmp_path)
    args = _args(tmp_path, *flags, other, flags[1])
    with pytest.raises(ValueError, match="separate"):
        tee_box_config(args)


def _refused(tmp_path: Path, match: str, *flags: str) -> None:
    with pytest.raises(ValueError, match=match):
        cmd_worker_serve(_args(tmp_path, *(flags or _full_flags(tmp_path))))
    assert _FakeServer.calls == []


def test_central_state_off_tmpfs_refuses_before_the_state_is_created(tmp_path: Path, guest):
    guest.disk.disk_paths |= {str(tmp_path), str(tmp_path.resolve())}
    _refused(
        tmp_path,
        r"^TEE box storage: the TEE box central state must be on tmpfs or ramfs \(guest "
        r"memory\); .* is on filesystem type 0xef53$",
    )
    assert not (tmp_path / "tee-box-central.sqlite").exists()
    assert not (tmp_path / "tee-box-central.sqlite.lock").exists()
    # Refused before any docker call.
    assert not any(call[0].endswith("docker") for call in guest.calls)


def test_the_startup_line_reports_the_boot_and_its_record(tmp_path: Path, guest, capsys):
    assert cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path))) == 0
    startup = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert startup["tee_box"]["boot"] == {
        "boot_id": guest.boot_id,
        "booted_at": BOOTED_AT,
        "consumed": False,
        "rtmr3_extended": False,
        "record": str(tmp_path / "tee-box-central.sqlite.boot"),
    }
    api = _FakeServer.calls[0]["tee_box_api"]
    assert api.boot.marker_path == str(tmp_path / "tee-box-central.sqlite.boot")


def test_an_unreadable_boot_id_refuses_to_start(tmp_path: Path, guest):
    guest.boot_id = BootError("cannot read the boot id")
    _refused(tmp_path, r"^TEE box boot identity: cannot read the boot id$")


def test_an_unreadable_rtmr3_refuses_to_start(tmp_path: Path, guest):
    guest.rtmr.unreadable = True
    _refused(tmp_path, r"^TEE box boot identity: RTMR3 is unavailable: no such file$")


def test_the_box_uses_the_kernel_rtmr3_interface_by_default(tmp_path: Path, guest, monkeypatch):
    seen = []

    class _Recording(boot_module.SysfsRtmr3):
        def read(self) -> bytes:
            seen.append(self.path)
            return bytes(48)

    monkeypatch.setattr(configure_module, "SysfsRtmr3", _Recording)
    guest.rtmr = None  # no test double: build_tee_box_api picks the interface
    assert cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path))) == 0
    assert seen == ["/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384"]
    assert isinstance(_FakeServer.calls[0]["tee_box_api"].boot._rtmr, _Recording)  # noqa: SLF001


def test_a_box_on_sev_snp_has_no_rtmr3_to_extend(tmp_path: Path, guest, monkeypatch):
    # SEV-SNP is refused earlier for want of a measured root binding; were
    # that added, the missing RTMR would still refuse.
    monkeypatch.setattr(
        measured_root,
        "load_measured_root_keys",
        lambda tee, read_binding=None: (ROOT_KEYS, "sha256:" + "0" * 64),
    )
    config = tee_box_config(_args(tmp_path, *_full_flags(tmp_path)))
    with pytest.raises(ValueError, match=r"^TEE box boot identity: TEE 'snp' has no RTMR3"):
        configure_module.build_tee_box_api(
            config,
            tee="snp",
            hotkey=WORKER_HOTKEY,
            channel_binding=None,
            network="finney",
            netuid=NETUID,
            public_endpoint=None,
            runner=guest,
            read_binding=lambda: guest.mrconfigid,
            storage_probe=guest.disk.probe(),
        )


def test_a_restarted_worker_keeps_this_boots_customer(tmp_path: Path, guest, capsys):
    # The first worker of this boot leased the box to one customer.
    marker = tmp_path / "tee-box-central.sqlite.boot"
    first = BootGuard(
        str(marker),
        rtmr=guest.rtmr,
        read_boot_id=lambda: guest.boot_id,
        read_booted_at=lambda: BOOTED_AT,
    )
    first.consume("central:" + "a" * 64, 1_900_000_000.0)
    assert guest.rtmr.value == RTMR3_CONSUMED
    assert cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path))) == 0
    startup = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert startup["tee_box"]["boot"]["consumed"] is True
    assert startup["tee_box"]["boot"]["rtmr3_extended"] is True
    assert len(guest.rtmr.extends) == 1  # the restarted worker does not extend again
    api = _FakeServer.calls[0]["tee_box_api"]
    with pytest.raises(RelaunchRequired):
        api.boot.check("central:" + "b" * 64)
    api.boot.check("central:" + "a" * 64)


def test_central_state_on_tmpfs_is_accepted_and_reported(tmp_path: Path, guest, capsys):
    assert cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path))) == 0
    assert str(tmp_path.resolve()) in guest.disk.probed
    startup = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert startup["tee_box"]["storage"]["central_state"] == "central state on tmpfs"


@pytest.mark.parametrize(
    "detail",
    [
        "253:3 is not a device-mapper device",
        "cathedral-scratch: crypt cipher aes-xts-plain64 has no integrity (no AEAD or HMAC tags)",
    ],
)
def test_scratch_that_is_not_encrypted_with_integrity_refuses(tmp_path: Path, guest, detail):
    guest.disk.crypt_devices["253:3"] = (False, detail)
    _refused(
        tmp_path,
        "^TEE box storage: TEE box scratch must be in guest memory or on dm-crypt with "
        rf"integrity; {guest.docker_root} \(ext4 on 253:3\) under the Docker data root is "
        rf"not: {re.escape(detail)}$",
    )


def test_a_plain_disk_mounted_below_the_docker_root_refuses(tmp_path: Path, guest):
    guest.disk.extra_mounts.append(
        f"91 90 8:2 / {guest.docker_root}/overlay2 rw - xfs /dev/sda2 rw,pquota"
    )
    _refused(tmp_path, rf"{guest.docker_root}/overlay2 \(xfs on 8:2\)")


def test_a_docker_root_in_guest_memory_needs_no_device(tmp_path: Path, guest, capsys):
    guest.disk.root_fstype = "tmpfs"
    guest.disk.crypt_devices.clear()
    assert cmd_worker_serve(_args(tmp_path, *_full_flags(tmp_path))) == 0
    assert not any(item.startswith("crypt") for item in guest.disk.probed)
    startup = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert startup["tee_box"]["storage"]["scratch"] == f"{guest.docker_root}: tmpfs"


def test_a_docker_root_shadowed_by_a_plain_disk_refuses(tmp_path: Path, guest):
    # The dm-crypt mount on the data root is hidden by a disk mounted later
    # over its parent; stat reports the disk.
    parent = str(Path(guest.docker_root).parent)
    guest.disk.extra_mounts.append(f"95 22 8:2 / {parent} rw - xfs /dev/sda2 rw")
    guest.disk.root_device = (8, 2)
    _refused(tmp_path, rf"{re.escape(parent)} \(xfs on 8:2\)")


def test_the_containerd_image_store_refuses(tmp_path: Path, guest):
    guest.driver_status = [["driver-type", "io.containerd.snapshotter.v1"]]
    _refused(tmp_path, "containerd image store")


@pytest.mark.parametrize(
    "line",
    [
        "/dev/sda2                               partition\t8388604\t0\t-2",
        "/swapfile                               file\t\t2097148\t0\t-3",
        "/dev/dm-4                               partition\t8388604\t0\t-2",
        # zram too: a backing_dev writes its pages to a disk in the clear.
        "/dev/zram0                              partition\t4194300\t0\t100",
        "/var/zram.img                           file\t\t2097148\t0\t-3",
    ],
)
def test_any_swap_refuses(tmp_path: Path, guest, line):
    guest.disk.swap_lines = [line]
    _refused(tmp_path, r"^TEE box storage: swap is on \(/\S+\); swap can write guest memory")
    assert not (tmp_path / "tee-box-central.sqlite").exists()

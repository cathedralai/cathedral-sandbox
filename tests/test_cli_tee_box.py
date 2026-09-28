"""T6b1 worker flags for the TEE box API: off by default, all or nothing, TLS only."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from cathedral import cli
from cathedral.cli import DEFAULT_WORKER_BEARER_ENV, build_parser, cmd_worker_serve
from cathedral.tee_box import TeeBoxSandboxApi
from cathedral.tee_box import configure as configure_module
from cathedral.tee_box.configure import OPTIONAL, REQUIRED, tee_box_config
from tests.test_cli import _tls_material
from tests.test_tee_box_service import NETUID, TRUSTED, _snapshot_bytes
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
        self.nft_fails = False
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kwargs):
        assert kwargs["shell"] is False
        self.calls.append(argv)
        tool = argv[0].rsplit("/", 1)[-1]
        if tool == "docker" and argv[1] == "info":
            out = RUNSC.encode() if "Runtimes" in argv[-1] else self.storage
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


def _full_flags(tmp_path: Path) -> list[str]:
    snapshot = tmp_path / "callers.json"
    snapshot.write_bytes(_snapshot_bytes())
    return [
        "--tee-box-caller-snapshot",
        str(snapshot),
        "--tee-box-caller-keys",
        str(tmp_path / "caller-keys.json"),
        "--tee-box-caller-keys-digest",
        "sha256:" + "cd" * 32,
        "--tee-box-caller-state",
        str(tmp_path / "callers.sqlite"),
        "--tee-box-executor",
        "runsc",
        "--tee-box-address",
        "34.120.1.2",
        "--tee-box-capacity",
        "8,32768,204800",
        "--tee-box-default-shape",
        "2,4096,10240",
    ]


def _args(tmp_path: Path, *extra: str, tls: bool = True, command: str = "serve"):
    base = ["worker", command, "--hotkey", WORKER_HOTKEY, "--validator-netuid", str(NETUID)]
    if tls:
        certificate, private_key = _tls_material(tmp_path)
        base += ["--tls-certificate", str(certificate), "--tls-private-key", str(private_key)]
    return build_parser().parse_args([*base, *extra])


@pytest.fixture
def guest(monkeypatch):
    _FakeServer.calls = []
    monkeypatch.setenv(DEFAULT_WORKER_BEARER_ENV, "worker-token")
    monkeypatch.setattr("cathedral.cli.WorkerServer", _FakeServer)
    monkeypatch.setattr(
        "cathedral.admission_policy.load_policy_keys", lambda *_a, **_k: dict(TRUSTED)
    )
    box = _Guest()
    real_build = configure_module.build_tee_box_api

    def build(config, **kwargs):
        return real_build(config, runner=box, **kwargs)

    monkeypatch.setattr(cli, "build_tee_box_api", build)
    return box


def test_no_tee_box_flags_mean_no_sandbox_api(tmp_path: Path, guest, capsys):
    assert cmd_worker_serve(_args(tmp_path)) == 0
    assert _FakeServer.calls[0]["tee_box_api"] is None
    assert guest.calls == []
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
    assert api.executor.network_modes == ("internet", "deny_all")
    assert api.executor.storage_quota is True
    assert [str(net) for net in api.egress.box_addresses] == ["34.120.1.2/32"]
    startup = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert startup["tee_box"]["egress"]["enforced"] is True
    assert startup["tee_box"]["network_modes"] == ["internet", "deny_all"]
    assert startup["tee_box"]["capacity"] == {"vcpus": 8, "memory_mib": 32768, "disk_mib": 204800}


def test_serve_snp_takes_the_same_flags(tmp_path: Path, guest):
    args = _args(tmp_path, *_full_flags(tmp_path), command="serve-snp")
    assert tee_box_config(args) is not None


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


def test_a_stale_caller_snapshot_refuses(tmp_path: Path, guest):
    flags = _full_flags(tmp_path)
    Path(flags[1]).write_bytes(b"{}")
    with pytest.raises(ValueError, match="caller snapshot"):
        cmd_worker_serve(_args(tmp_path, *flags))


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


def test_the_caller_state_must_be_separate(tmp_path: Path, guest):
    flags = _full_flags(tmp_path)
    args = _args(tmp_path, *flags, "--validator-access-state", flags[7])
    with pytest.raises(ValueError, match="separate"):
        tee_box_config(args)

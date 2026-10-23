"""Room egress policy through the sandbox API (fake docker CLI) and the real
hotel egress daemon control socket (room_egress.py with fake docker facts and
a recording nftables runner)."""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from cathedral.sandbox_api import (
    CreateSandboxRequest,
    ImageSource,
    NetworkPatch,
    NetworkSpec,
    Resources,
    SandboxContractError,
    canonical_network_policy,
    network_policy_sha256,
    normalize_allow_entry,
)
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import SandboxOpError
from cathedral.sandbox_server import SandboxApplication
from tests.fake_docker_cli import FakeDocker, install

SCRIPT = Path(__file__).resolve().parents[1] / "room-kit" / "room_egress.py"


def _load():
    spec = importlib.util.spec_from_file_location("room_egress", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["room_egress"] = mod
    spec.loader.exec_module(mod)
    return mod


eg = _load()


class Facts:
    """Docker facts for the egress daemon: one address per container id."""

    def __init__(self):
        self.ips: dict[str, str] = {}
        self.pool = ipaddress.ip_network("10.214.0.0/22").hosts()
        next(self.pool)  # the gateway

    def facts(self, cid):
        if cid not in self.ips:
            self.ips[cid] = str(next(self.pool))
        return self.ips[cid], "02:42:0a:d6:00:02", "veth" + cid[:6]

    def running(self):
        return set(self.ips)


class Daemon:
    def __init__(self, monkeypatch):
        monkeypatch.setattr(eg, "flush_conntrack", lambda ip: None)
        self.scripts: list[str] = []
        self.refuse = False
        self.facts = Facts()
        rules = eg.Rules("room-test", ["10.214.0.0/22"], 15353, 15080, 15443, run=self._run)
        self.table = eg.Table(rules, self.facts, None)
        self.table.load()
        self.path = tempfile.mktemp(prefix="egt", suffix=".sock", dir="/tmp")
        self.srv = eg.ControlServer(self.path, eg.Control)
        self.srv.table = self.table
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        monkeypatch.setenv("CATHEDRAL_ROOM_EGRESS_SOCKET", self.path)

    def _run(self, script):
        if self.refuse:
            raise RuntimeError("nft failed: refused by the test")
        self.scripts.append(script)

    def close(self):
        self.srv.shutdown()
        Path(self.path).unlink(missing_ok=True)


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    f = install(tmp_path, monkeypatch)
    f.add_image("alpine:3.20")
    return f


@pytest.fixture
def daemon(fake, monkeypatch):
    d = Daemon(monkeypatch)
    yield d
    d.close()


ALLOW = ("pypi.org", "files.pythonhosted.org")


def _create(provider, mode="allowlist", allow=ALLOW, digest="a"):
    req = CreateSandboxRequest(
        image=ImageSource(image="alpine:3.20"),
        resources=Resources(vcpu=1, memory_gib=1, disk_gib=5),
        network=NetworkSpec(mode=mode, allow=allow),
    )
    return provider.create(req, api_key="k", idempotency=None, body_digest=digest)


def _run_network(fake):
    run = fake.calls_of("run")[-1]
    return run[run.index("--network") + 1] if "--network" in run else None


# ---------------------------------------------------------------- contract

def test_canonical_policy_and_sha() -> None:
    p = canonical_network_policy("allowlist", ["PyPI.org.", "*.Pythonhosted.org", "1.2.3.4", "9.9.8.7/8", "pypi.org"])
    assert p == {"mode": "allowlist", "allow": ["*.pythonhosted.org", "1.2.3.4", "9.0.0.0/8", "pypi.org"]}
    assert canonical_network_policy("public") == {"mode": "internet", "allow": []}
    assert canonical_network_policy("deny_all", ["ignored.example"]) == {"mode": "deny_all", "allow": []}
    sha = network_policy_sha256(p)
    assert sha == network_policy_sha256({"allow": p["allow"], "mode": "allowlist"}) and len(sha) == 64
    # The daemon writes the same canonical policy.
    assert eg.Policy.parse(p).document() == p


@pytest.mark.parametrize("bad", ["::1", "fe80::/10", "https://pypi.org", "pypi.org:8080", "1.2.3.4:443", "pypi.org/simple", "*", "*.", "*.10.0.0.1", "local", "a_b.example"])
def test_bad_allowlist_entries_are_refused(bad) -> None:
    with pytest.raises(SandboxContractError):
        normalize_allow_entry(bad)
    with pytest.raises(SandboxContractError):
        NetworkSpec(mode="allowlist", allow=(bad,))
    with pytest.raises(SandboxContractError):
        NetworkPatch(mode="allowlist", allow=(bad,))


def test_new_and_old_mode_names() -> None:
    for mode in ("internet", "deny_all", "public", "none"):
        NetworkSpec(mode=mode)
        NetworkPatch(mode=mode)
    with pytest.raises(SandboxContractError):
        NetworkSpec(mode="open")


# ---------------------------------------------------------------- provider with the daemon

def test_allowlist_room_gets_an_interface_and_the_policy(fake, daemon) -> None:
    provider = DockerGuestProvider()
    try:
        doc = _create(provider)
        assert _run_network(fake) is None  # default bridge: the room has an interface
        policy = {"mode": "allowlist", "allow": ["files.pythonhosted.org", "pypi.org"]}
        assert doc["network"]["policy"] == policy
        assert doc["network"]["policy_sha256"] == network_policy_sha256(policy)
        assert doc["network"]["enforced_by"] == "hotel_egress"
        assert doc["guest"]["allowlist_fail_closed"] is False and doc["guest"]["network_switchable"] is True
        cid = doc["guest"]["container_id"]
        ip = daemon.table.by_cid[cid].ip
        assert daemon.table.policy_of(ip).document() == policy
        assert f"add element ip pool_room_egress_room_test named {{ {ip} }}" in daemon.scripts[-1]
        assert provider.status().to_document()["network_allowlist_enforced"] is True
    finally:
        provider.close()


def test_live_switch_deny_all_internet_and_back(fake, daemon) -> None:
    provider = DockerGuestProvider()
    try:
        doc = _create(provider)
        sid, cid = doc["id"], doc["guest"]["container_id"]
        ip = daemon.table.by_cid[cid].ip
        for mode, allow in (("deny_all", ()), ("internet", ()), ("allowlist", ALLOW), ("none", ())):
            out = provider.set_network(sid, NetworkPatch(mode=mode, allow=allow))
            want = canonical_network_policy("deny_all" if mode == "none" else mode, allow)
            assert out["network"]["policy"] == want
            assert out["network"]["policy_sha256"] == network_policy_sha256(want)
            assert daemon.table.policy_of(ip).document() == want
        # No docker network connect or disconnect: only the rules outside the room change.
        assert fake.calls_of("network", "connect") == [] and fake.calls_of("network", "disconnect") == []
    finally:
        provider.close()


def test_internet_room_is_registered_too(fake, daemon) -> None:
    provider = DockerGuestProvider()
    try:
        doc = _create(provider, mode="public", allow=())
        assert doc["network"]["policy"] == {"mode": "internet", "allow": []}
        ip = daemon.table.by_cid[doc["guest"]["container_id"]].ip
        assert daemon.table.policy_of(ip).mode == "internet"
    finally:
        provider.close()


def test_room_created_with_none_cannot_switch(fake, daemon) -> None:
    provider = DockerGuestProvider()
    try:
        doc = _create(provider, mode="none", allow=())
        assert _run_network(fake) == "none"
        assert doc["network"]["policy"] == {"mode": "deny_all", "allow": []}
        assert doc["network"]["enforced_by"] == "no_interface"
        with pytest.raises(SandboxOpError) as exc:
            provider.set_network(doc["id"], NetworkPatch(mode="internet"))
        assert exc.value.code == "network_not_switchable" and exc.value.http_status == 409
        assert daemon.table.by_cid == {}
    finally:
        provider.close()


def test_delete_forgets_the_policy(fake, daemon) -> None:
    provider = DockerGuestProvider()
    try:
        doc = _create(provider)
        cid = doc["guest"]["container_id"]
        assert cid in daemon.table.by_cid
        provider.delete(doc["id"])
        assert cid not in daemon.table.by_cid
    finally:
        provider.close()


def test_daemon_failure_fails_the_create_and_removes_the_room(fake, daemon) -> None:
    provider = DockerGuestProvider()
    try:
        daemon.refuse = True
        with pytest.raises(SandboxOpError) as exc:
            _create(provider)
        assert exc.value.code == "egress_unavailable" and exc.value.http_status == 503
        assert fake.containers == {} or all(c.get("removed") for c in fake.containers.values())
    finally:
        provider.close()


def test_daemon_down_fails_closed(fake, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_ROOM_EGRESS_SOCKET", "/tmp/no-such-egress.sock")
    provider = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError) as exc:
            _create(provider, mode="internet", allow=())
        assert exc.value.code == "egress_unavailable"
    finally:
        provider.close()


# ---------------------------------------------------------------- no daemon: old behaviour

def test_without_daemon_allowlist_and_deny_all_fail_closed(fake) -> None:
    provider = DockerGuestProvider()
    try:
        for i, mode in enumerate(("allowlist", "deny_all")):
            doc = _create(provider, mode=mode, allow=ALLOW if mode == "allowlist" else (), digest=str(i))
            assert _run_network(fake) == "none"
            assert doc["guest"]["allowlist_fail_closed"] is True
            assert doc["network"]["policy"] == {"mode": "deny_all", "allow": []}
        doc = _create(provider, mode="internet", allow=(), digest="i")
        assert _run_network(fake) is None and doc["network"]["policy"] == {"mode": "internet", "allow": []}
        assert provider.status().to_document()["network_allowlist_enforced"] is False
    finally:
        provider.close()


# ---------------------------------------------------------------- HTTP route

def test_put_network_route(fake, daemon) -> None:
    provider = DockerGuestProvider()
    app = SandboxApplication(provider)
    try:
        auth = {"Authorization": "Bearer k"}
        created = app.dispatch("POST", "/v1/sandboxes", auth, json.dumps({
            "image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5},
            "network": "allowlist", "network_allow": ["pypi.org"]}).encode())
        assert created.status in (200, 201, 202), created.body
        sid = json.loads(created.body)["id"]
        res = app.dispatch("PUT", f"/v1/sandboxes/{sid}/network", auth, json.dumps({"mode": "deny_all"}).encode())
        assert res.status == 200, res.body
        net = json.loads(res.body)["network"]
        assert net["policy"] == {"mode": "deny_all", "allow": []} and net["policy_sha256"] == network_policy_sha256(net["policy"])
        bad = app.dispatch("PUT", f"/v1/sandboxes/{sid}/network", auth, json.dumps({"mode": "allowlist", "allow": ["::1"]}).encode())
        assert bad.status == 400 and json.loads(bad.body)["error"]["code"] == "invalid_network_allowlist"
    finally:
        provider.close()


@pytest.mark.parametrize("entry", ["pypi.org:443", "pypi.org:80", "PyPI.org:443"])
def test_web_ports_on_hostnames_are_accepted(entry) -> None:
    # The proxy only carries 80 and 443, so the port is accepted and dropped.
    assert normalize_allow_entry(entry) == "pypi.org"
    NetworkSpec(mode="allowlist", allow=(entry,))


@pytest.mark.parametrize("bad", ["169.254.169.254", "169.254.169.254/32", "127.0.0.1/32", "10.0.0.0/8",
                                 "192.168.1.0/24", "0.0.0.0/0", "100.64.0.0/10", "8.0.0.0/4"])
def test_allowlist_refuses_non_public_ranges(bad) -> None:
    # A host firewall rule drops these today, so they never worked; refusing
    # them keeps the policy honest if that rule is ever missing.
    with pytest.raises(SandboxContractError):
        normalize_allow_entry(bad)


def test_allowlist_keeps_public_ranges() -> None:
    assert normalize_allow_entry("1.1.1.1") == "1.1.1.1"
    assert normalize_allow_entry("140.82.112.0/20") == "140.82.112.0/20"

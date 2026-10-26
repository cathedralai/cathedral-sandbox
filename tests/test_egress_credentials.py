"""Egress credentials (#304): the hotel egress proxy attaches a secret to
plain HTTP requests from a room to one allowed host. The room never holds
the value.

Three layers:
- the hotel API with the fake docker CLI and the real egress daemon control
  socket (secret routes, policy with credential references, owners);
- the egress proxy for real on 127.0.0.1, with a TLS upstream that has a
  test certificate (header added, rotation, missing secret, bad certificate);
- the secret store on disk (AES-GCM, key file, associated data).

Most tests are negative. A test value must never appear in an answer, a
docker argument, a receipt or a log line.
"""

from __future__ import annotations

import asyncio
import datetime
import http.client
import importlib.util
import json
import os
import socket
import ssl
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from cathedral.sandbox_api import (
    NetworkPatch,
    NetworkSpec,
    SandboxContractError,
    canonical_network_policy,
    network_policy_sha256,
)
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_owner import owner_hash, owner_id
from cathedral.sandbox_server import SandboxApplication, serve
from tests.fake_docker_cli import FakeDocker, install
from tests.test_sandbox_egress import Daemon, eg

VALUE = "Bearer test-secret-value-1"
VALUE2 = "Bearer test-secret-value-2"
KEY = "hotel-key"
A = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "guest-a"}
B = {"Authorization": f"Bearer {KEY}", "X-Cathedral-Guest": "guest-b"}
CRED = {"host": "pypi.example", "header": "Authorization", "secret": "PIP_TOKEN"}
NET = {"mode": "allowlist", "allow": ["pypi.example"], "credentials": [CRED]}
ROOM = {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}


@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    f = install(tmp_path, monkeypatch)
    f.add_image("alpine:3.20")
    return f


@pytest.fixture
def daemon(fake, monkeypatch):
    d = Daemon(monkeypatch)
    d.srv.secrets = eg.SecretStore()
    yield d
    d.close()
    d.srv.server_close()


@pytest.fixture
def app(daemon):
    provider = DockerGuestProvider()
    yield SandboxApplication(provider)
    provider.close()


def call(app, method, path, headers, body=None):
    raw = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    res = app.dispatch(method, path, headers, raw)
    return res.status, res.body.decode() if res.body else ""


def code(text: str) -> str:
    return json.loads(text)["error"]["code"]


# ---------------------------------------------------------------- policy contract

def test_policy_without_credentials_keeps_its_document_and_hash() -> None:
    doc = canonical_network_policy("allowlist", ["pypi.example"])
    assert doc == {"mode": "allowlist", "allow": ["pypi.example"]}
    assert network_policy_sha256(doc) == network_policy_sha256({"allow": ["pypi.example"], "mode": "allowlist"})


def test_policy_with_credentials_has_names_only_and_matches_the_daemon() -> None:
    doc = NetworkSpec(mode="allowlist", allow=("pypi.example",), credentials=(CRED,)).policy
    assert doc["credentials"] == [{"host": "pypi.example", "header": "authorization", "secret": "PIP_TOKEN"}]
    assert eg.Policy.parse(doc).document() == doc


@pytest.mark.parametrize("bad", [
    {"mode": "internet", "allow": (), "credentials": (CRED,)},
    {"mode": "allowlist", "allow": ("other.example",), "credentials": (CRED,)},
    {"mode": "allowlist", "allow": ("*.pkgs.example",), "credentials": ({**CRED, "host": "*.pkgs.example"},)},
    {"mode": "allowlist", "allow": ("1.2.3.4",), "credentials": ({**CRED, "host": "1.2.3.4"},)},
    {"mode": "allowlist", "allow": ("pypi.example",), "credentials": ({**CRED, "header": "Host"},)},
    {"mode": "allowlist", "allow": ("pypi.example",), "credentials": ({**CRED, "header": "Proxy-Authorization"},)},
    {"mode": "allowlist", "allow": ("pypi.example",), "credentials": ({**CRED, "header": "X-A\r\nX-B"},)},
    {"mode": "allowlist", "allow": ("pypi.example",), "credentials": ({**CRED, "secret": "pip_token"},)},
    {"mode": "allowlist", "allow": ("pypi.example",), "credentials": ({**CRED, "value": "x"},)},
    {"mode": "allowlist", "allow": ("pypi.example",), "credentials": (CRED, CRED)},
])
def test_bad_credential_references_fail(bad) -> None:
    with pytest.raises(SandboxContractError) as exc:
        NetworkSpec(**bad)
    assert exc.value.code in ("invalid_credentials", "invalid_secret_name")
    with pytest.raises(SandboxContractError):
        NetworkPatch(**bad)


def test_wildcard_allow_covers_an_exact_credential_host() -> None:
    doc = NetworkSpec(mode="allowlist", allow=("*.pkgs.example",),
                      credentials=({**CRED, "host": "a.pkgs.example"},)).policy
    assert doc["credentials"][0]["host"] == "a.pkgs.example"
    assert eg.Policy.parse(doc).document() == doc


# ---------------------------------------------------------------- secret routes

def test_put_list_delete_never_return_the_value(app) -> None:
    status, out = call(app, "PUT", "/v1/secrets/PIP_TOKEN", A, {"value": VALUE})
    assert status == 200 and VALUE not in out and json.loads(out)["name"] == "PIP_TOKEN"
    status, out = call(app, "GET", "/v1/secrets", A)
    assert status == 200 and VALUE not in out
    assert [s["name"] for s in json.loads(out)["secrets"]] == ["PIP_TOKEN"]
    assert set(json.loads(out)["secrets"][0]) == {"name", "updated_at"}
    status, _ = call(app, "DELETE", "/v1/secrets/PIP_TOKEN", A)
    assert status == 204
    status, out = call(app, "DELETE", "/v1/secrets/PIP_TOKEN", A)
    assert (status, code(out)) == (404, "secret_not_found")


def test_other_guest_cannot_list_or_delete(app, daemon) -> None:
    call(app, "PUT", "/v1/secrets/PIP_TOKEN", A, {"value": VALUE})
    status, out = call(app, "GET", "/v1/secrets", B)
    assert status == 200 and json.loads(out)["secrets"] == []
    status, out = call(app, "DELETE", "/v1/secrets/PIP_TOKEN", B)
    assert (status, code(out)) == (404, "secret_not_found")
    assert daemon.srv.secrets.get(owner_hash(owner_id(KEY, "guest-a")), "PIP_TOKEN") == VALUE
    # Another hotel key with the same guest id is another owner.
    other = {"Authorization": "Bearer other-key", "X-Cathedral-Guest": "guest-a"}
    assert json.loads(call(app, "GET", "/v1/secrets", other)[1])["secrets"] == []


@pytest.mark.parametrize("value", [
    VALUE + "\r\nX-Injected: 1", VALUE + "\n", "", "x" * 8193, 42, None, "café", "a\x00b",
])
def test_bad_values_are_refused_and_not_echoed(app, value) -> None:
    status, out = call(app, "PUT", "/v1/secrets/PIP_TOKEN", A, {"value": value})
    assert (status, code(out)) == (400, "invalid_secret_value")
    if isinstance(value, str) and value:
        assert value not in out and VALUE not in out


def test_broken_json_is_not_echoed(app) -> None:
    status, out = call(app, "PUT", "/v1/secrets/PIP_TOKEN", A, b'{"value": "' + VALUE.encode())
    assert status == 400 and VALUE not in out


@pytest.mark.parametrize("name", ["pip_token", "..", "A-B", "A" * 65, "%2e%2e", "1ABC"])
def test_bad_names_fail(app, name) -> None:
    status, out = call(app, "PUT", f"/v1/secrets/{name}", A, {"value": VALUE})
    assert (status, code(out)) == (400, "invalid_secret_name")


def test_secret_limit(app, monkeypatch) -> None:
    monkeypatch.setattr(eg, "SECRETS_PER_OWNER", 2)
    assert call(app, "PUT", "/v1/secrets/ONE", A, {"value": "1"})[0] == 200
    assert call(app, "PUT", "/v1/secrets/TWO", A, {"value": "2"})[0] == 200
    status, out = call(app, "PUT", "/v1/secrets/THREE", A, {"value": "3"})
    assert (status, code(out)) == (409, "secret_limit")
    assert call(app, "PUT", "/v1/secrets/TWO", A, {"value": "2b"})[0] == 200  # an update is not new
    assert call(app, "PUT", "/v1/secrets/THREE", B, {"value": "3"})[0] == 200  # per owner


def test_no_egress_daemon_means_501(fake) -> None:
    provider = DockerGuestProvider()
    app = SandboxApplication(provider)
    try:
        status, out = call(app, "PUT", "/v1/secrets/PIP_TOKEN", A, {"value": VALUE})
        assert (status, code(out)) == (501, "secrets_unavailable")
        status, out = call(app, "POST", "/v1/sandboxes", A, {**ROOM, "network": NET})
        assert (status, code(out)) == (501, "credentials_unavailable")
        assert fake.calls_of("run") == []
    finally:
        provider.close()


# ---------------------------------------------------------------- rooms

def test_room_with_credentials_never_holds_the_value(app, fake, daemon) -> None:
    call(app, "PUT", "/v1/secrets/PIP_TOKEN", A, {"value": VALUE})
    status, out = call(app, "POST", "/v1/sandboxes", A, {**ROOM, "network": NET, "env": {"PIP_INDEX_URL": "http://pypi.example/simple"}})
    assert status == 202, out
    doc = json.loads(out)
    sid = doc["id"]
    policy = doc["network"]["policy"]
    assert policy["credentials"] == [{"host": "pypi.example", "header": "authorization", "secret": "PIP_TOKEN"}]
    assert doc["network"]["policy_sha256"] == network_policy_sha256(policy)
    # Not in the docker run arguments (env, mounts, labels).
    assert VALUE not in json.dumps(fake.calls)
    # Not in any API answer.
    answers = [out]
    for method, path in (("GET", f"/v1/sandboxes/{sid}"), ("GET", "/v1/sandboxes"), ("GET", "/v1/quota"),
                         ("GET", "/v1/status"), ("GET", f"/v1/sandboxes/{sid}/logs")):
        answers.append(call(app, method, path, A)[1])
    answers.append(call(app, "PUT", f"/v1/sandboxes/{sid}/network", A, NET)[1])
    assert all(VALUE not in a for a in answers)
    # The daemon table names the owner hash and the secret name only.
    room = daemon.table.by_cid[next(iter(daemon.table.by_cid))]
    assert room.owner == owner_hash(owner_id(KEY, "guest-a"))
    rooms_doc = json.dumps([r.policy.document() for r in daemon.table.by_cid.values()])
    assert VALUE not in rooms_doc and "PIP_TOKEN" in rooms_doc


def test_switch_to_credentials_keeps_the_room_owner(app, daemon) -> None:
    plain = {"Authorization": f"Bearer {KEY}"}
    status, out = call(app, "POST", "/v1/sandboxes", plain,
                       {**ROOM, "network": {"mode": "deny_all"}, "labels": {"broker_guest": "guest-a"}})
    assert status == 202, out
    sid = json.loads(out)["id"]
    status, out = call(app, "PUT", f"/v1/sandboxes/{sid}/network", plain, NET)
    assert status == 200, out
    room = next(iter(daemon.table.by_cid.values()))
    assert room.owner == owner_hash(owner_id(KEY, "guest-a"))
    assert room.policy.credential_for("pypi.example") == ("authorization", "PIP_TOKEN")


def test_receipt_records_names_and_policy_hash_not_values() -> None:
    spec = importlib.util.spec_from_file_location(
        "room_receipts", Path(__file__).resolve().parents[1] / "room-kit" / "room_receipts.py")
    rr = importlib.util.module_from_spec(spec)
    sys.modules["room_receipts"] = rr
    spec.loader.exec_module(rr)
    policy = NetworkSpec(mode="allowlist", allow=("pypi.example",), credentials=(CRED,)).policy
    got = rr.Handler.network_policy("create", 202, {"network": {"policy": policy}})
    assert got == policy
    assert rr.sha(rr.canonical(got)) == network_policy_sha256(policy)
    old = rr.Handler.network_policy("create", 202, {"network": {"policy": {"mode": "deny_all", "allow": []}}})
    assert old == {"mode": "deny_all", "allow": []}
    # Secret routes are not signed: their bodies never reach a receipt.
    assert not any(pat.match("/v1/secrets/PIP_TOKEN") for _, pat, _ in rr.SIGNED)


def test_hotel_access_log_has_no_value(fake, daemon, monkeypatch, capfd) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_ACCESS_LOG", "1")
    provider = DockerGuestProvider()
    srv = serve(SandboxApplication(provider), "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=10)
        conn.request("PUT", "/v1/secrets/PIP_TOKEN", body=json.dumps({"value": VALUE}), headers=A)
        assert conn.getresponse().read() and True
        conn.request("PUT", "/v1/secrets/PIP_TOKEN", body=json.dumps({"value": VALUE + "\n"}), headers=A)
        conn.getresponse().read()
    finally:
        srv.shutdown()
        provider.close()
    captured = capfd.readouterr()
    assert "PIP_TOKEN" in captured.err  # the log is on
    assert "test-secret-value" not in captured.out + captured.err


# ---------------------------------------------------------------- proxy with TLS upstream

def _cert(tmp: Path, name: str) -> tuple[str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp / f"{name}.crt", tmp / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return str(cert_path), str(key_path)


OWNER_A = "a" * 64
OWNER_B = "b" * 64
ROOM_IP = "10.214.0.40"


@pytest.fixture
def proxy_env(tmp_path, monkeypatch):
    """A table with one room of owner A that has the credential policy."""
    from tests.test_room_kit_egress import FakeDocker as EgFacts, Runner

    monkeypatch.setattr(eg, "flush_conntrack", lambda ip: None)
    rules = eg.Rules("room-test", ["10.214.0.0/22"], 15353, 15080, 15443, run=Runner())
    facts = EgFacts()
    facts.add("1" * 64, ROOM_IP)
    table = eg.Table(rules, facts, None)
    table.load()
    table.put("1" * 64, "s1", eg.Policy.parse(NET | {"credentials": [CRED]}), OWNER_A)
    return table, eg.SecretStore(), tmp_path


async def _through_proxy(table, store, tmp: Path, request: bytes, *, cert_name: str = "pypi.example",
                         repeat: int = 1, tls: bool = False):
    cert, key = _cert(tmp, cert_name)
    server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    server_ctx.load_cert_chain(cert, key)
    seen: list[bytes] = []

    async def upstream(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, ConnectionResetError):
            writer.close()
            return
        seen.append(head)
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        await writer.drain()
        writer.close()

    up = await asyncio.start_server(upstream, "127.0.0.1", 0, ssl=server_ctx)
    client_ctx = ssl.create_default_context(cafile=cert)
    resolved: list[str] = []

    async def resolve(name, port):
        resolved.append(f"{name}:{port}")
        return ["127.0.0.1"]

    proxy = eg.Proxy(table, resolve=resolve, addr_ok=lambda a: True, secrets=store,
                     tls_context=client_ctx, tls_port=up.sockets[0].getsockname()[1])

    async def handler(reader, writer):
        real = writer.get_extra_info
        writer.get_extra_info = lambda k, d=None: (ROOM_IP, 1) if k == "peername" else real(k, d)
        await proxy.handle(reader, writer, 80, tls)

    front = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = front.sockets[0].getsockname()[1]
    answers = []
    for i in range(repeat):
        if callable(request):
            payload = request(i)
        else:
            payload = request
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(payload)
        await w.drain()
        answers.append(await asyncio.wait_for(r.read(65536), 10))
        w.close()
    up.close()
    front.close()
    return answers, seen, resolved


REQ = (b"GET /simple/pkg/ HTTP/1.1\r\nHost: pypi.example\r\nAuthorization: Basic forged-by-room\r\n"
       b"Connection: keep-alive\r\nProxy-Authorization: x\r\n\r\n")


def test_proxy_adds_the_header_over_tls_and_the_room_sees_no_value(proxy_env, capfd) -> None:
    table, store, tmp = proxy_env
    store.put(OWNER_A, "PIP_TOKEN", VALUE)
    answers, seen, resolved = asyncio.run(_through_proxy(table, store, tmp, REQ))
    head = seen[0].decode()
    assert f"authorization: {VALUE}\r\n" in head
    assert "forged-by-room" not in head and "Proxy-Authorization" not in head
    assert "Connection: close" in head and "keep-alive" not in head
    assert head.startswith("GET /simple/pkg/ HTTP/1.1\r\n")
    assert answers[0].endswith(b"ok") and VALUE.encode() not in answers[0]
    assert resolved[0].startswith("pypi.example:")
    out = capfd.readouterr()
    assert "test-secret-value" not in out.out + out.err


def test_rotation_takes_effect_on_the_next_request_without_a_restart(proxy_env) -> None:
    table, store, tmp = proxy_env
    store.put(OWNER_A, "PIP_TOKEN", VALUE)

    def request(i):
        if i == 1:
            store.put(OWNER_A, "PIP_TOKEN", VALUE2)
        return REQ

    _, seen, _ = asyncio.run(_through_proxy(table, store, tmp, request, repeat=2))
    assert f"authorization: {VALUE}\r\n" in seen[0].decode()
    assert f"authorization: {VALUE2}\r\n" in seen[1].decode()


def test_missing_or_deleted_secret_gives_502_with_the_name_only(proxy_env) -> None:
    table, store, tmp = proxy_env
    answers, seen, resolved = asyncio.run(_through_proxy(table, store, tmp, REQ))
    assert answers[0].startswith(b"HTTP/1.1 502") and b"PIP_TOKEN" in answers[0]
    assert seen == [] and resolved == []  # nothing went upstream
    store.put(OWNER_A, "PIP_TOKEN", VALUE)
    store.delete(OWNER_A, "PIP_TOKEN")
    answers, seen, _ = asyncio.run(_through_proxy(table, store, tmp, REQ))
    assert answers[0].startswith(b"HTTP/1.1 502") and seen == []


def test_secret_of_another_owner_is_never_used(proxy_env) -> None:
    table, store, tmp = proxy_env
    store.put(OWNER_B, "PIP_TOKEN", VALUE)  # same name, other owner
    answers, seen, _ = asyncio.run(_through_proxy(table, store, tmp, REQ))
    assert answers[0].startswith(b"HTTP/1.1 502") and seen == []


def test_wrong_upstream_certificate_fails_closed(proxy_env) -> None:
    table, store, tmp = proxy_env
    store.put(OWNER_A, "PIP_TOKEN", VALUE)
    answers, seen, _ = asyncio.run(_through_proxy(table, store, tmp, REQ, cert_name="other.example"))
    assert answers[0].startswith(b"HTTP/1.1 502") and b"TLS to pypi.example failed" in answers[0]
    assert seen == []
    assert VALUE.encode() not in answers[0]


def test_other_allowed_host_gets_no_credential(proxy_env) -> None:
    table, store, tmp = proxy_env
    table.put("1" * 64, "s1", eg.Policy.parse({"mode": "allowlist", "allow": ["pypi.example", "files.example"],
                                               "credentials": [CRED]}), OWNER_A)
    store.put(OWNER_A, "PIP_TOKEN", VALUE)

    got = {}

    async def run():
        async def upstream(reader, writer):
            got["head"] = await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            writer.close()

        up = await asyncio.start_server(upstream, "127.0.0.1", 0)

        async def resolve(name, port):
            return ["127.0.0.1"]

        proxy = eg.Proxy(table, resolve=resolve, addr_ok=lambda a: True, secrets=store)

        async def handler(reader, writer):
            real = writer.get_extra_info
            writer.get_extra_info = lambda k, d=None: (ROOM_IP, 1) if k == "peername" else real(k, d)
            # The proxy checks the policy on the room's real port (80), so hand
            # it that port and send its upstream dial to the fake server.
            await proxy.handle(reader, writer, 80, False)

        up_port = up.sockets[0].getsockname()[1]
        real_open = asyncio.open_connection

        async def open_upstream(host, port, *args, **kwargs):
            if host == "127.0.0.1" and port == 80:
                port = up_port
            return await real_open(host, port, *args, **kwargs)

        front = await asyncio.start_server(handler, "127.0.0.1", 0)
        r, w = await asyncio.open_connection("127.0.0.1", front.sockets[0].getsockname()[1])
        asyncio.open_connection = open_upstream
        try:
            w.write(b"GET / HTTP/1.1\r\nHost: files.example\r\n\r\n")
            await w.drain()
            await asyncio.wait_for(r.read(65536), 5)
        finally:
            asyncio.open_connection = real_open
        w.close()
        up.close()
        front.close()

    asyncio.run(run())
    assert VALUE.encode() not in got["head"] and b"authorization" not in got["head"].lower()


def test_tls_from_the_room_is_passed_through_without_a_credential(proxy_env) -> None:
    table, store, tmp = proxy_env
    calls = []

    class Spy(eg.SecretStore):
        def get(self, owner, name):
            calls.append(name)
            return VALUE

    from tests.test_room_kit_egress import _client_hello

    asyncio.run(_through_proxy(table, Spy(), tmp, _client_hello("pypi.example"), tls=True))
    assert calls == []


def test_add_credential_cannot_be_split_by_the_room() -> None:
    head = b"GET / HTTP/1.1\r\nHost: pypi.example\r\nAUTHORIZATION: room\r\nupgrade: h2c\r\nTE: trailers\r\n\r\n"
    out = eg.add_credential(head, "authorization", "Bearer v")
    lines = out.split(b"\r\n")
    assert [ln for ln in lines if ln.lower().startswith(b"authorization")] == [b"authorization: Bearer v"]
    assert not any(ln.lower().startswith((b"upgrade", b"te:")) for ln in lines)
    assert out.endswith(b"Connection: close\r\n\r\n")


# ---------------------------------------------------------------- store on disk

def test_store_on_disk_is_encrypted_and_bound_to_owner_and_name(tmp_path) -> None:
    path = tmp_path / "state" / "secrets.json"
    store = eg.SecretStore(str(path), str(tmp_path / "state" / "secrets.key"))
    store.put(OWNER_A, "PIP_TOKEN", VALUE)
    raw = path.read_text()
    assert "test-secret-value" not in raw
    assert oct((tmp_path / "state" / "secrets.key").stat().st_mode & 0o777) == "0o600"
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    again = eg.SecretStore(str(path), str(tmp_path / "state" / "secrets.key"))
    assert again.get(OWNER_A, "PIP_TOKEN") == VALUE
    # Move the entry to another owner on disk: it does not decrypt.
    entries = json.loads(raw)
    entries[0]["owner"] = OWNER_B
    path.write_text(json.dumps(entries))
    moved = eg.SecretStore(str(path), str(tmp_path / "state" / "secrets.key"))
    assert moved.get(OWNER_B, "PIP_TOKEN") is None and moved.get(OWNER_A, "PIP_TOKEN") is None


def test_memory_only_store_writes_nothing(tmp_path) -> None:
    before = set(os.listdir(tmp_path))
    store = eg.SecretStore(None)
    store.put(OWNER_A, "PIP_TOKEN", VALUE)
    assert store.get(OWNER_A, "PIP_TOKEN") == VALUE
    assert set(os.listdir(tmp_path)) == before


def test_control_socket_secret_routes(tmp_path) -> None:
    path = tempfile.mktemp(prefix="egs", suffix=".sock", dir="/tmp")
    srv = eg.ControlServer(path, eg.Control)
    srv.secrets = eg.SecretStore()
    srv.table = None
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    class Conn(http.client.HTTPConnection):
        def connect(self):
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(path)

    def req(method, url, body=None):
        c = Conn("localhost")
        c.request(method, url, body=json.dumps(body).encode() if body is not None else None)
        r = c.getresponse()
        return r.status, r.read().decode()

    try:
        status, out = req("PUT", f"/secrets/{OWNER_A}/PIP_TOKEN", {"value": VALUE})
        assert status == 200 and VALUE not in out
        status, out = req("GET", f"/secrets/{OWNER_A}")
        assert status == 200 and VALUE not in out and "PIP_TOKEN" in out
        status, out = req("GET", f"/secrets/{OWNER_B}")
        assert json.loads(out)["secrets"] == []
        status, out = req("PUT", f"/secrets/{OWNER_A}/PIP_TOKEN", {"value": VALUE + "\r\n"})
        assert status == 400 and "test-secret-value" not in out
        for bad in (f"/secrets/{OWNER_A}/pip", "/secrets/xyz/PIP_TOKEN", f"/secrets/{OWNER_A}/../x"):
            assert req("PUT", bad, {"value": VALUE})[0] == 404
        assert req("DELETE", f"/secrets/{OWNER_B}/PIP_TOKEN")[0] == 404
        assert req("DELETE", f"/secrets/{OWNER_A}/PIP_TOKEN")[0] == 200
    finally:
        srv.shutdown()
        Path(path).unlink(missing_ok=True)


def test_one_owner_for_the_workspace_and_the_secrets_of_a_room(fake, daemon, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("CATHEDRAL_WORKSPACE_MOUNT_CHECK", "0")
    provider = DockerGuestProvider()
    app = SandboxApplication(provider)
    try:
        assert call(app, "POST", "/v1/workspaces", A, {"name": "repo"})[0] == 201
        assert call(app, "PUT", "/v1/secrets/PIP_TOKEN", A, {"value": VALUE})[0] == 200
        status, out = call(app, "POST", "/v1/sandboxes", A, {**ROOM, "network": NET, "workspace": "repo"})
        assert status == 202, out
        room = next(iter(daemon.table.by_cid.values()))
        assert room.owner == owner_hash(owner_id(KEY, "guest-a"))
        assert VALUE not in json.dumps(fake.calls) and VALUE not in out
        status, out = call(app, "POST", "/v1/sandboxes", B, {**ROOM, "network": NET, "workspace": "repo"})
        assert (status, code(out)) == (404, "workspace_not_found")
    finally:
        provider.close()

"""AB#789: guest volume agent, lease-holder signing route, volume-key-install and the storage gateway.

The restic round trip runs only where the pinned restic is on hand (RESTIC_BIN or restic on PATH at
0.19.1); everything else runs offline.
"""
from __future__ import annotations

import base64
import os
import shutil
import urllib.error
import urllib.request

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from cathedral import volume_agent as va
from cathedral import volume_chain as vc
from cathedral import volume_gateway as vg
from cathedral import volume_subtoken as vs

NOW = 1_800_000_000


class Boot:
    """One sealed guest boot: receipt key and binding."""

    def __init__(self, name: str, registry_keys: list[str]):
        self.key = Ed25519PrivateKey.generate()
        self.binding = {"schema": vc.SEALED_BINDING_SCHEMA, "hotel": name,
                        "receipt_key_ed25519_b64": vc.public_b64(self.key), "measurement": "m-" + name}
        self.signer = va.HolderSigner(self.key, self.binding, registry_keys, now=lambda: NOW)
        self.keys = va.VolumeKeys(self.signer)


@pytest.fixture
def world():
    registry_key = Ed25519PrivateKey.generate()
    registry = vc.VolumeRegistry(registry_key, now=lambda: NOW)
    keys = [vc.public_b64(registry_key)]
    return registry, registry_key, keys


def test_signer_signs_commit_the_registry_accepts_only_on_its_own_lease(world):
    registry, _, keys = world
    a, b = Boot("a", keys), Boot("b", keys)
    genesis = registry.create("vol1", "owner")
    lease = registry.grant("vol1", a.binding)
    commit = a.signer.sign_commit(lease, generation=1, parent_sha256=vc.statement_sha256(genesis),
                                  restic_repo_id="r", restic_snapshot_id="a" * 64)
    assert registry.accept(commit)["statement"]["generation"] == 1
    # b's route refuses to sign on a's lease: it is not a general signing oracle.
    with pytest.raises(vc.VolumeRefused, match="lease_not_ours"):
        b.signer.sign_commit(lease, generation=2, parent_sha256="x", restic_repo_id="r", restic_snapshot_id="b" * 64)
    with pytest.raises(vc.VolumeRefused, match="lease_not_ours"):
        b.signer.subtoken_request(lease)
    # A lease a caller made up is not the registry's.
    fake = vc.sign_statement(a.key, lease["statement"])
    with pytest.raises(vc.VolumeRefused, match="lease_not_signed_by_registry"):
        a.signer.sign_commit(fake, generation=2, parent_sha256="x", restic_repo_id="r", restic_snapshot_id="c" * 64)


def test_non_lease_holder_commit_refused_at_head_plus_one(world):
    registry, _, keys = world
    a, b = Boot("a", keys), Boot("b", keys)
    genesis = registry.create("vol1", "owner")
    lease = registry.grant("vol1", a.binding)
    forged = vc.sign_statement(b.key, vc.make_commit(a.key, lease, generation=1,
                                                     parent_sha256=vc.statement_sha256(genesis),
                                                     restic_repo_id="r", restic_snapshot_id="d" * 64)["statement"])
    with pytest.raises(vc.VolumeRefused, match="signature_not_lease_holder"):
        registry.accept(forged)
    assert registry.head("vol1")["statement"]["generation"] == 0


def test_holder_requests_use_their_own_label():
    keys = [vc.public_b64(Ed25519PrivateKey.generate())]
    a = Boot("a", keys)
    request = a.signer.lease_request("vol1")
    statement = request["statement"]
    assert statement["binding_sha256"] == vc.sha(vc.canonical(a.binding))
    a.key.public_key().verify(base64.b64decode(request["signature_b64"]),
                              va.HOLDER_REQUEST_LABEL + vc.canonical(statement))
    # Never a plain receipt signature (room_receipts.py signs canonical(statement) with no label).
    with pytest.raises(Exception):
        a.key.public_key().verify(base64.b64decode(request["signature_b64"]), vc.canonical(statement))


def test_volume_key_install_opens_only_on_its_boot():
    keys = [vc.public_b64(Ed25519PrivateKey.generate())]
    a, b = Boot("a", keys), Boot("b", keys)
    doc = a.keys.install_key_document()
    envelope = va.seal_volume_key(doc, a.binding, volume_id="vol1", key_id="k1", secret=os.urandom(32))
    assert a.keys.install(envelope) == {"volume_id": "vol1", "key_id": "k1", "installed": True}
    assert len(a.keys.password("vol1")) == 64
    with pytest.raises(vc.VolumeRefused, match="envelope_not_for_this_boot"):
        b.keys.install(envelope)
    # The owner refuses an install key the binding's receipt key did not sign.
    with pytest.raises(vc.VolumeRefused, match="install_key_not_signed_by_receipt_key"):
        va.seal_volume_key(b.keys.install_key_document(), a.binding, volume_id="vol1", key_id="k1", secret=b"x" * 32)
    tampered = dict(envelope, volume_id="vol2")
    with pytest.raises(vc.VolumeRefused, match="envelope_does_not_open"):
        a.keys.install(tampered)


def _call(url, method="GET", token=None, data=None):
    headers = {}
    if token is not None:
        headers["Authorization"] = "Basic " + base64.b64encode(b"v:" + vg.encode_token(token).encode()).decode()
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def test_gateway_enforces_subtoken_per_request(world, tmp_path):
    registry, registry_key, keys = world
    a = Boot("a", keys)
    registry.create("vol1", "owner")
    registry.create("vol2", "owner")
    lease = registry.grant("vol1", a.binding)
    token = vs.issue(registry_key, lease, prefix=vs.volume_prefix("vol1"), source_ip="127.0.0.1", ttl_seconds=600)
    wrong_ip = vs.issue(registry_key, lease, prefix=vs.volume_prefix("vol1"), source_ip="10.9.9.9", ttl_seconds=600)
    server, gateway = vg.serve(tmp_path, keys[0])
    base = f"http://127.0.0.1:{server.server_address[1]}"
    name = "ab" * 32
    try:
        assert _call(f"{base}/volumes/vol1/data/{name}", "POST", token, b"pack")[0] == 200
        assert _call(f"{base}/volumes/vol1/data/{name}", "GET", token) == (200, b"pack")
        assert _call(f"{base}/volumes/vol1/data/{name}", "GET")[0] == 401
        assert _call(f"{base}/volumes/vol1/data/{name}", "GET", wrong_ip)[0] == 403
        assert _call(f"{base}/volumes/vol2/data/{name}", "POST", token, b"x")[0] == 403
        assert _call(f"{base}/volumes/vol1/data/{name}", "DELETE", token)[0] == 403
        assert (tmp_path / "volumes/vol1/data" / name).read_bytes() == b"pack"
        # Content-addressed objects are never rewritten.
        assert _call(f"{base}/volumes/vol1/data/{name}", "POST", token, b"other")[0] == 403
        assert {r["code"] for r in gateway.refusals} >= {"no_token", "wrong_source_ip", "outside_prefix",
                                                          "op_not_allowed"}
    finally:
        server.shutdown()


@pytest.mark.parametrize("path", ["/volumes/v1/../v2/config", "/data/x", "/volumes/v1/data/zz", "/volumes//config"])
def test_gateway_paths_outside_a_repo_refused(path):
    with pytest.raises(vc.VolumeRefused):
        vg.parse_path(path)


def _restic() -> str | None:
    found = os.environ.get("RESTIC_BIN") or shutil.which("restic")
    return found if found and va.restic_version(found) == va.RESTIC_VERSION else None


class InMemoryRegistryClient:
    """The API's holder routes over the in-memory contract registry (the API is tested in polariscomputer)."""

    def __init__(self, registry, registry_key):
        self.registry, self.registry_key = registry, registry_key
        self.commits: list[dict] = []  # what the API's chain route returns

    def subtoken(self, volume_id, request_doc):
        lease = self.registry.volumes[volume_id].lease.doc
        assert request_doc["statement"]["lease_id"] == lease["statement"]["lease_id"]
        return vs.issue(self.registry_key, lease, prefix=vs.volume_prefix(volume_id), source_ip="127.0.0.1",
                        ttl_seconds=600, now=lambda: NOW)

    def commit(self, volume_id, commit_doc):
        head = self.registry.accept(commit_doc)
        self.commits.append(commit_doc)
        return head


@pytest.mark.skipif(_restic() is None, reason="pinned restic 0.19.1 not available")
def test_two_host_restore_round_trip_with_pinned_restic(world, tmp_path, monkeypatch):
    registry, registry_key, keys = world
    monkeypatch.setattr(vs.time, "time", lambda: NOW)  # gateway checks token expiry against the same clock
    server, _ = vg.serve(tmp_path / "store", keys[0])
    gateway = f"http://127.0.0.1:{server.server_address[1]}"
    client = InMemoryRegistryClient(registry, registry_key)
    secret = os.urandom(32)

    def host(name):
        boot = Boot(name, keys)
        boot.keys.install(va.seal_volume_key(boot.keys.install_key_document(), boot.binding, volume_id="vol1",
                                             key_id="k1", secret=secret))
        agent = va.VolumeAgent(boot.signer, boot.keys, client, gateway, _restic(), str(tmp_path / name / "cache"))
        return boot, agent

    def grant(boot):
        volume = registry.volumes["vol1"]
        return {"volume": volume.doc, "commits": list(client.commits), "head": volume.head_doc,
                "lease": registry.grant("vol1", boot.binding)}

    try:
        registry.create("vol1", "owner")
        a, agent_a = host("a")
        work_a = tmp_path / "a" / "ws"
        assert agent_a.attach(grant(a), str(work_a))["restored"] is None
        (work_a / "notes.txt").write_text("written on host a\n")
        head = agent_a.commit("vol1")
        assert head["statement"]["generation"] == 1
        registry.release("vol1", registry.volumes["vol1"].lease.statement["lease_id"])

        b, agent_b = host("b")
        work_b = tmp_path / "b" / "ws"
        attached = agent_b.attach(grant(b), str(work_b))
        assert attached["restored"]["generation"] == 1
        assert (work_b / "notes.txt").read_text() == "written on host a\n"
        # b commits generation 2 on its lease; a, no longer the holder, is refused at head + 1.
        (work_b / "notes.txt").write_text("edited on host b\n")
        assert agent_b.commit("vol1")["statement"]["generation"] == 2
        late = vc.make_commit(a.key, registry.volumes["vol1"].lease.doc, generation=3,
                              parent_sha256=registry.volumes["vol1"].head_sha256, restic_repo_id="r",
                              restic_snapshot_id="e" * 64)
        with pytest.raises(vc.VolumeRefused, match="signature_not_lease_holder"):
            registry.accept(late)
        assert registry.head("vol1")["statement"]["generation"] == 2
    finally:
        server.shutdown()


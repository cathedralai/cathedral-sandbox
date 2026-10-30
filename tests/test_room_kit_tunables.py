"""Per-room start-up tunables on a hotel ("option 2"): create, isolation, refusal, receipts, attest."""

from __future__ import annotations

import base64
import http.client
import importlib.util
import json
import threading
from pathlib import Path

import pytest

from cathedral import room_tunables as rt
from cathedral.sandbox_api import CreateSandboxRequest, ImageSource, Resources, SandboxContractError
from cathedral.sandbox_guest import DockerGuestProvider
from cathedral.sandbox_provider import InMemorySandboxProvider, SandboxOpError
from cathedral.sandbox_server import SandboxApplication
from cathedral.tee_box.tunables import default_tunables, parse_tunables
from tests.fake_docker_cli import FakeDocker, install

KIT = Path(__file__).resolve().parents[1] / "room-kit"
RUNSC = "/opt/pool-room/gvisor/runsc"
HOTEL_FLAGS = "--platform=systrap --overlay2=none --net-raw"  # room.env.example and the sealed guest
DEFAULT_SHA = "e187a847a2c9d715078c086429fe1f29bc2eb4447aa47d89b628fd08e7caa547"
COLD = {"schema": 1, "runsc": {"directfs": False, "overlay2": "all:self"}}  # gt-challenge baselines/cold


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


kit_runtimes = _load("tunable_runtimes_t", KIT / "lib" / "tunable_runtimes.py")
rr = _load("room_receipts_tunables_t", KIT / "room_receipts.py")
vr = _load("verify_receipts_tunables_t", KIT / "verify_receipts.py")


# ---------------------------------------------------------------- validation (same set and bounds as the TEE box)
def test_default_document_has_the_challenge_sha() -> None:
    assert rt.parse_room_tunables({"schema": 1}).sha256 == DEFAULT_SHA == default_tunables().sha256


def test_valid_per_room_document_is_accepted() -> None:
    t = rt.parse_room_tunables({**COLD, "docker": {"log_driver": "none"}, "image": {"prime": "page_cache"}})
    assert t["runsc.directfs"] is False and t["runsc.overlay2"] == "all:self" and t["docker.log_driver"] == "none"
    assert t.sha256 == parse_tunables(json.dumps({**COLD, "docker": {"log_driver": "none"},
                                                  "image": {"prime": "page_cache"}})).sha256


@pytest.mark.parametrize("doc", [
    {"schema": 1, "runsc": {"platform": "ptrace"}},          # pinned, not a tunable
    {"schema": 1, "runsc": {"net_channels": 5}},              # out of bounds
    {"schema": 1, "runsc": {"net_channels": 0}},
    {"schema": 1, "runsc": {"net_channels": 2.0}},            # float
    {"schema": 1, "runsc": {"directfs": "yes"}},              # wrong type
    {"schema": 1, "runsc": {"overlay2": "root:memory"}},      # not offered
    {"schema": 1, "docker": {"log_driver": "syslog"}},
    {"schema": 1, "network": {"mode": "host"}},               # unknown section
    {"schema": 2},
    {"runsc": {"directfs": False}},                           # no schema
    "{\"schema\": 1}",                                        # not an object
    [1],
])
def test_invalid_tunables_are_a_400(doc) -> None:
    with pytest.raises(SandboxContractError) as exc:
        CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), tunables=doc)
    assert exc.value.code == "invalid_tunables"


@pytest.mark.parametrize("doc", [
    {"schema": 1, "pool": {"warm_size": 4}},
    {"schema": 1, "pool": {"idle_seconds": 60}},
    {"schema": 1, "pool": {"refill_parallelism": 2}},
    {"schema": 1, "boot": {"create_concurrency": 4}},
])
def test_hotel_wide_tunables_are_refused_per_room(doc) -> None:
    with pytest.raises(SandboxContractError) as exc:
        CreateSandboxRequest(image=ImageSource(image="alpine:3.20"), tunables=doc)
    assert exc.value.code == "tunables_not_per_room"


def test_hotel_wide_tunables_at_their_defaults_are_accepted() -> None:
    doc = {"schema": 1, "pool": {"warm_size": 0, "idle_seconds": 300}, "boot": {"create_concurrency": 1}}
    assert rt.parse_room_tunables(doc).sha256 == DEFAULT_SHA


# ---------------------------------------------------------------- the kit registers what the API checks
def test_kit_variants_are_the_ones_the_api_checks() -> None:
    runtimes = kit_runtimes.runtimes(RUNSC, HOTEL_FLAGS)
    assert runtimes["runsc"] == {"path": RUNSC, "runtimeArgs": HOTEL_FLAGS.split()}
    names = {rt.runtime_name(t) for t in rt.variants()}
    assert len(names) == 16 and set(runtimes) == names | {"runsc"}
    for t in rt.variants():
        args = rt.check_runtime(runtimes, "runsc", t)
        assert args[:2] == ["--platform=systrap", "--net-raw"]  # pinned flags kept, the hotel's overlay2 replaced
        assert args[2:] == rt.runsc_flags(t)


def test_a_variant_that_drops_a_pinned_flag_is_refused() -> None:
    runtimes = kit_runtimes.runtimes(RUNSC, HOTEL_FLAGS)
    t = rt.parse_room_tunables(COLD)
    runtimes[rt.runtime_name(t)]["runtimeArgs"].remove("--platform=systrap")
    with pytest.raises(rt.RoomTunablesError) as exc:
        rt.check_runtime(runtimes, "runsc", t)
    assert exc.value.code == "tunables_unavailable"


# ---------------------------------------------------------------- the hotel API applies them to one room
@pytest.fixture
def fake(tmp_path, monkeypatch) -> FakeDocker:
    fake = install(tmp_path, monkeypatch)
    fake.set(default_runtime="runsc", runtimes=kit_runtimes.runtimes(RUNSC, HOTEL_FLAGS))
    return fake


def _req(tunables=None, image="alpine:3.20") -> CreateSandboxRequest:
    return CreateSandboxRequest(image=ImageSource(image=image), resources=Resources(vcpu=1, memory_gib=1, disk_gib=5),
                                tunables=tunables)


def _argv(fake: FakeDocker, sandbox_id: str) -> list[str]:
    return next(c["argv"] for c in fake.state["containers"].values()
                if c["labels"].get("cathedral.sandbox.id") == sandbox_id)


def _opt(argv: list[str], flag: str) -> str | None:
    return argv[argv.index(flag) + 1] if flag in argv else None


def test_tunables_apply_to_their_room_only(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        plain = provider.create(_req(), api_key="k", idempotency=None, body_digest="a")
        cold = provider.create(_req(COLD), api_key="k", idempotency=None, body_digest="b")
        fast = provider.create(_req({"schema": 1, "runsc": {"net_channels": 4}, "docker": {"log_driver": "local"}}),
                               api_key="k", idempotency=None, body_digest="c")
        plain_argv, cold_argv, fast_argv = (_argv(fake, d["id"]) for d in (plain, cold, fast))
        # The room without tunables starts exactly as before: daemon default runtime, daemon log driver.
        assert "--runtime" not in plain_argv and "--log-driver" not in plain_argv and "tunables" not in plain
        assert _opt(cold_argv, "--runtime") == "runsc-tun-d0-all-n1" and _opt(cold_argv, "--log-driver") == "json-file"
        assert _opt(fast_argv, "--runtime") == "runsc-tun-d1-root-n4" and _opt(fast_argv, "--log-driver") == "local"
        assert cold["tunables"]["sha256"] == rt.parse_room_tunables(COLD).sha256
        assert cold["tunables"]["status"] == "applied" and cold["tunables"]["runtime"] == "runsc-tun-d0-all-n1"
        assert cold["tunables"]["runtime_args"] == ["--platform=systrap", "--net-raw", "--directfs=false",
                                                     "--overlay2=all:self", "--num-network-channels=1"]
        assert fast["tunables"]["values"]["runsc"]["net_channels"] == 4
        # AB#238: every runsc room, tuned or not, keeps its sentry out of the host OOM killer's reach.
        assert all(_opt(argv, "--oom-score-adj") == "-1000" for argv in (plain_argv, cold_argv, fast_argv))
        # A read reports each room's own tunables; the plain room still has none.
        assert provider.get(cold["id"])["tunables"] == cold["tunables"]
        assert provider.get(fast["id"])["tunables"] == fast["tunables"]
        assert "tunables" not in provider.get(plain["id"])
        # No daemon-wide change: nothing touched daemon.json or reloaded the daemon.
        assert not [c for c in fake.state["calls"] if c[:1] in (["restart"], ["kill"])]
    finally:
        provider.close()


def test_two_rooms_with_different_tunables_stay_isolated_under_concurrency(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    docs: dict[str, dict] = {}
    sides = {"challenger": COLD, "king": {"schema": 1}}

    def make(side: str, i: int) -> None:
        docs[f"{side}{i}"] = provider.create(_req(sides[side]), api_key="k", idempotency=None, body_digest=f"{side}{i}")

    try:
        threads = [threading.Thread(target=make, args=(s, i)) for i in range(4) for s in sides]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(docs) == 8, "a create failed"
        for key, doc in docs.items():
            want = rt.parse_room_tunables(sides[key.rstrip("0123456789")])
            assert doc["tunables"]["sha256"] == want.sha256
            assert _opt(_argv(fake, doc["id"]), "--runtime") == rt.runtime_name(want)
    finally:
        provider.close()


def test_a_hotel_without_the_variant_refuses_and_keeps_no_room(fake: FakeDocker) -> None:
    fake.set(runtimes={"runsc": {"path": RUNSC, "runtimeArgs": HOTEL_FLAGS.split()}})  # a kit before this change
    provider = DockerGuestProvider()
    try:
        with pytest.raises(SandboxOpError) as exc:
            provider.create(_req(COLD), api_key="k", idempotency=None, body_digest="a")
        assert exc.value.code == "tunables_unavailable" and exc.value.http_status == 409
        assert fake.state["containers"] == {}
        assert provider.quota()["usage"]["resident_sandboxes"] == 0
    finally:
        provider.close()


def test_image_prime_reads_the_image_before_that_room_starts(fake: FakeDocker) -> None:
    provider = DockerGuestProvider()
    try:
        doc = provider.create(_req({"schema": 1, "image": {"prime": "page_cache"}}), api_key="k",
                              idempotency=None, body_digest="a")
        assert fake.state["saved"] == ["alpine:3.20"] and doc["tunables"]["image_prime"] == "done"
        calls = [c[0] for c in fake.state["calls"]]
        assert calls.index("save") < calls.index("run")
        provider.create(_req(), api_key="k", idempotency=None, body_digest="b")
        assert fake.state["saved"] == ["alpine:3.20"]  # a room without the tunable does not prime
    finally:
        provider.close()


def _app_create(app: SandboxApplication, body: dict):
    raw = json.dumps(body).encode()
    return app.dispatch("POST", "/v1/sandboxes", {"Authorization": "Bearer k", "Content-Type": "application/json"}, raw)


def test_the_api_answers_400_for_bad_tunables_and_409_where_it_cannot_apply_them(fake: FakeDocker, monkeypatch) -> None:
    monkeypatch.setenv("CATHEDRAL_SANDBOX_KEYS", "k:p:4")
    base = {"image": "alpine:3.20", "resources": {"vcpu": 1, "memory_gib": 1, "disk_gib": 5}}
    docker_app = SandboxApplication(provider=DockerGuestProvider())
    memory_app = SandboxApplication(provider=InMemorySandboxProvider(), require_auth=False)
    try:
        bad = _app_create(docker_app, {**base, "tunables": {"schema": 1, "runsc": {"net_channels": 9}}})
        assert bad.status == 400 and json.loads(bad.body)["error"]["code"] == "invalid_tunables"
        wide = _app_create(docker_app, {**base, "tunables": {"schema": 1, "pool": {"warm_size": 2}}})
        assert wide.status == 400 and json.loads(wide.body)["error"]["code"] == "tunables_not_per_room"
        ok = _app_create(docker_app, {**base, "tunables": COLD})
        assert ok.status == 202 and json.loads(ok.body)["tunables"]["sha256"] == rt.parse_room_tunables(COLD).sha256
        # A runtime that cannot start a room under them refuses; it never ignores them.
        mem = _app_create(memory_app, {**base, "tunables": COLD})
        assert mem.status == 409 and json.loads(mem.body)["error"]["code"] == "tunables_unavailable"
    finally:
        docker_app.provider.close()


# ---------------------------------------------------------------- receipts and attest bind them
def test_create_receipt_carries_the_tunables_and_their_sha() -> None:
    t = rt.parse_room_tunables(COLD)
    view = rt.room_view(t, runtime=rt.runtime_name(t), runtime_args=["--directfs=false"], image_prime="none")
    fields = rr.Handler.room_tunables("create", 202, {"id": "r1", "tunables": view})
    assert fields["tunables"] == t.nested()
    assert fields["tunables_sha256"] == t.sha256 == rr.sha(rr.canonical(t.nested()))
    assert fields["tunables_runtime"] == "runsc-tun-d0-all-n1"
    assert rr.Handler.room_tunables("create", 400, {"tunables": view}) is None
    assert rr.Handler.room_tunables("exec", 200, {"tunables": view}) is None
    assert rr.Handler.room_tunables("create", 202, {"id": "r2"}) is None


def test_verifier_lists_room_tunables_and_catches_a_wrong_sha() -> None:
    t = rt.parse_room_tunables(COLD)
    good = {"statement": {"sequence": 1, "action": "create", "sandbox_id": "r1", "tunables": t.nested(),
                          "tunables_sha256": t.sha256}}
    assert vr.room_tunables([good]) == {"r1": t.sha256}
    bad = json.loads(json.dumps(good))
    bad["statement"]["tunables"]["runsc"]["directfs"] = True
    with pytest.raises(vr.Fail):
        vr.room_tunables([bad])


def _sealed_front(tmp_path, monkeypatch, api_answer: dict):
    """A sealed receipt front (fake TSM) over a fake API that answers every create with api_answer."""
    from tests.test_room_kit_attest import FakeTsm

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Api(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            out = json.dumps(api_answer).encode()
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=api.serve_forever, daemon=True).start()
    tsm = FakeTsm()
    monkeypatch.setattr(rr, "tsm_provider", lambda: tsm.provider)
    monkeypatch.setattr(rr, "_read_tsm_aux", tsm)
    monkeypatch.setattr(rr, "read", lambda path, default="": "boot-1" if "boot_id" in path else default)
    monkeypatch.setattr(rr.Server, "health_loop", lambda self: None)
    ledger = rr.Ledger("sealed-1", str(tmp_path))
    front = rr.Server(("127.0.0.1", 0), ledger, api.server_address[1], 1, b"k" * 32, "/nonexistent.sock")
    monkeypatch.setattr(front, "image_digest", lambda ref: None)
    threading.Thread(target=front.serve_forever, daemon=True).start()
    return front, api, ledger


def _call(port: int, method: str, path: str, body: dict) -> tuple[int, dict, dict]:
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request(method, path, body=json.dumps(body).encode(),
              headers={"Authorization": "Bearer " + "k" * 32, "Content-Type": "application/json"})
    r = c.getresponse()
    out = r.read()
    return r.status, dict(r.getheaders()), json.loads(out)


def test_sealed_attest_returns_the_rooms_signed_create_receipt_with_its_tunables(tmp_path, monkeypatch) -> None:
    t = rt.parse_room_tunables(COLD)
    view = rt.room_view(t, runtime=rt.runtime_name(t), runtime_args=[], image_prime="none")
    front, api, ledger = _sealed_front(tmp_path, monkeypatch, {"id": "r1", "tunables": view})
    port = front.server_address[1]
    try:
        status, headers, _doc = _call(port, "POST", "/v1/sandboxes", {"image": "alpine:3.20", "tunables": COLD})
        assert status == 202
        header = json.loads(base64.urlsafe_b64decode(headers["X-Room-Receipt"]))
        assert header["statement"]["tunables_sha256"] == t.sha256
        status, _h, out = _call(port, "POST", "/room/attest", {"report_data_hex": "ab" * 64, "sandbox_id": "r1"})
        assert status == 200
        receipt = out["room"]["create_receipt"]
        assert receipt == header and receipt["statement"]["binding_sha256"] == out["binding_sha256"]
        # The receipt verifies under the receipt key that the boot report's binding names.
        att = ledger.attestation()
        assert vr.verify_receipts(att, [receipt], None)["signatures_ok"] == 1
        assert vr.room_tunables([receipt]) == {"r1": t.sha256}
        # A room this boot never created has no receipt; a malformed id is a 400.
        assert _call(port, "POST", "/room/attest", {"report_data_hex": "ab" * 64, "sandbox_id": "nope"})[2]["room"] == {
            "sandbox_id": "nope", "create_receipt": None}
        assert _call(port, "POST", "/room/attest", {"report_data_hex": "ab" * 64, "sandbox_id": 7})[0] == 400
    finally:
        front.shutdown()
        api.shutdown()

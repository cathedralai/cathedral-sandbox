"""Tests for cathedral/worker.py and cathedral/remote.py.

Covers:
- Good round trips (evidence + SAT work)
- Wrong IDs / hotkey / nonce → RemoteError
- Malformed / unknown / missing keys → 400
- Oversized request → 413 / oversized response → RemoteError
- Busy semaphore → 503
- Timeout / connection-failure isolation
- work_units never trusted (recomputed from instance)
- Optional bearer token DoS filter
- Returned certificate passes SatLane.verify()

All networking is loopback-only (127.0.0.1, OS-assigned port). No hardware.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from cathedral.common import (
    MAX_CPU_EVIDENCE_RESPONSE_BODY,
    ChannelBinding,
    ChannelBindingType,
    Evidence,
    EvidenceKind,
)
from cathedral.lanes.sat import (
    MAX_N_VARS,
    SatLane,
    _canonical_instance,
    _compute_challenge_id,
    solve_sat,
)
from cathedral.lanes.sat_types import SatCertificate, SatInstance, SatWorkItem
from cathedral.remote import (
    MAX_RESPONSE_BODY,
    MAX_SAT_RESPONSE_BODY,
    RemoteError,
)
from cathedral.remote import (
    RemoteMiner as _RemoteMiner,
)
from cathedral.worker import (
    WorkerServer as _WorkerServer,
)
from cathedral.worker import (
    _solve_customer_sat_bounded,
)
import cathedral.worker as worker_module

# ---------------------------------------------------------------------------
# Test fixtures / helpers
# ---------------------------------------------------------------------------

HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
OTHER_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
TEST_BEARER = "test-worker-token"
TEST_BINDING = ChannelBinding(ChannelBindingType.APPLICATION_KEY_SHA256, b"t" * 32)


def WorkerServer(*args, **kwargs):
    kwargs.setdefault("configured_hotkey", HOTKEY)
    kwargs.setdefault("allow_noncanonical_sat", True)
    kwargs.setdefault("bearer_token", TEST_BEARER)
    kwargs.setdefault("channel_binding", TEST_BINDING)
    return _WorkerServer(*args, **kwargs)


def RemoteMiner(endpoint, hotkey, **kwargs):
    kwargs.setdefault("allow_insecure_http", True)
    kwargs.setdefault("bearer_token", TEST_BEARER)
    return _RemoteMiner(endpoint, hotkey, **kwargs)


def test_remote_default_retains_cpu_specific_response_limit():
    assert MAX_RESPONSE_BODY == MAX_CPU_EVIDENCE_RESPONSE_BODY == 128 * 1024


@pytest.mark.parametrize("drip_phase", ["headers", "body"])
def test_remote_response_uses_one_total_deadline_and_closes_drip_connection(
    drip_phase,
):
    handler_done = threading.Event()
    handler_saw_disconnect = threading.Event()
    force_stop = threading.Event()

    class DripHandler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            request_length = int(self.headers["Content-Length"])
            self.rfile.read(request_length)
            headers = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: 512\r\n"
                b"Connection: close\r\n\r\n"
            )
            try:
                if drip_phase == "body":
                    self.connection.sendall(headers)
                    dripping = b" " * 512
                else:
                    dripping = headers
                for byte in dripping:
                    self.connection.sendall(bytes((byte,)))
                    if force_stop.wait(0.05):
                        return
            except OSError:
                handler_saw_disconnect.set()
            finally:
                handler_done.set()

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), DripHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        endpoint = f"http://127.0.0.1:{server.server_address[1]}"
        remote = RemoteMiner(endpoint, HOTKEY, timeout=0.3)
        started = time.monotonic()
        with pytest.raises(RemoteError) as raised:
            remote.supports_customer_sat()
        elapsed = time.monotonic() - started

        assert str(raised.value) == "worker request timed out"
        assert 0.2 < elapsed < 1.25
        assert handler_done.wait(1.0), "client timeout left the drip handler running"
        assert handler_saw_disconnect.is_set()
    finally:
        force_stop.set()
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1)

    assert not server_thread.is_alive()


def _fake_evidence(nonce: bytes, hotkey: str) -> Evidence:
    """Deterministic mock collector — no hardware needed."""
    return Evidence(
        kind=EvidenceKind.TDX,
        quote=b"fakequote:" + nonce[:4],
        nonce=nonce,
        miner_hotkey=hotkey,
        cert_chain=[b"fakecert"],
    )


def _make_sat_item(n_vars: int = 3, seed: int = 0) -> SatWorkItem:
    clauses = [[1, 2], [-1, 3], [-2, -3]]
    inst = SatInstance(n_vars=n_vars, clauses=clauses)
    cid = _compute_challenge_id(inst, seed)
    return SatWorkItem(instance=inst, seed=seed, challenge_id=cid)


def _canonical_sat_payload(seed: int) -> bytes:
    """The public audit instance, framed exactly as the wire expects it."""
    instance = _canonical_instance(seed)
    return json.dumps(
        {
            "challenge_id": _compute_challenge_id(instance, seed),
            "assigned_hotkey": HOTKEY,
            "instance": {"n_vars": instance.n_vars, "clauses": instance.clauses},
            "seed": seed,
        }
    ).encode()


def _must_not_solve(_instance):
    raise AssertionError("unauthorized work reached solve_sat")


def _must_not_solve_customer(_instance, _timeout):
    raise AssertionError("unauthorized work reached the customer solver")


def _start_server(server: _WorkerServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


def _post_raw(url: str, body: bytes, *, bearer: str | None = TEST_BEARER) -> tuple[int, bytes]:
    """Return (status_code, body_bytes) without raising on 4xx/5xx."""
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
    )
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _stall_post_connection(
    port: int,
    *,
    path: str = "/v1/evidence",
    declared_length: int = 4096,
    bearer: str | None = None,
) -> socket.socket:
    """Open a POST whose complete headers promise a body that never arrives."""
    conn = socket.create_connection(("127.0.0.1", port), timeout=10)
    headers = (
        f"POST {path} HTTP/1.1\r\nHost: localhost\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {declared_length}\r\n"
    )
    if bearer is not None:
        headers += f"Authorization: Bearer {bearer}\r\n"
    conn.sendall((headers + "\r\n").encode("ascii"))
    return conn


def _stall_connection(port: int, declared_length: int = 4096) -> socket.socket:
    return _stall_post_connection(
        port,
        path="/v1/evidence",
        declared_length=declared_length,
    )


def _wait_for_active_connections(
    server: _WorkerServer,
    expected: int,
    timeout: float = 2.0,
) -> None:
    deadline = time.monotonic() + timeout
    while (
        server._server.active_connection_count != expected
        and time.monotonic() < deadline
    ):
        time.sleep(0.01)
    assert server._server.active_connection_count == expected


def _status_of(response: bytes) -> int:
    return int(response.split(b"\r\n", 1)[0].split(b" ")[1])


def _raw_http_status(port: int, headers: bytes, body: bytes = b"") -> int:
    request = b"POST /v1/evidence HTTP/1.0\r\nHost: localhost\r\n" + headers + b"\r\n" + body
    with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
        conn.sendall(request)
        conn.shutdown(socket.SHUT_WR)
        response = conn.recv(4096)
    return int(response.split(b" ", 2)[1])


def _connection_gate_response(port: int) -> bytes:
    """Return bytes observed when the pre-HTTP gate refuses one connection."""
    request = (
        b"POST /v1/evidence HTTP/1.0\r\nHost: localhost\r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    chunks: list[bytes] = []
    with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
        try:
            conn.sendall(request)
            conn.shutdown(socket.SHUT_WR)
        except OSError:
            return b""
        while True:
            try:
                chunk = conn.recv(4096)
            except OSError:
                break
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks)


def _raw_post(
    port: int, path: str, body: bytes, extra_headers: bytes = b""
) -> tuple[int, bytes]:
    """POST one path with raw header bytes, including non-ASCII Authorization."""
    request = (
        f"POST {path} HTTP/1.0\r\nHost: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
    ).encode("ascii") + extra_headers + b"\r\n" + body
    with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
        conn.sendall(request)
        conn.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    response = b"".join(chunks)
    head, _, payload = response.partition(b"\r\n\r\n")
    return int(head.split(b" ", 2)[1]), payload


# ---------------------------------------------------------------------------
# Good round trips
# ---------------------------------------------------------------------------


def test_evidence_good_round_trip():
    nonce = os.urandom(32)
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        ev = remote.fetch_evidence(nonce)

    assert isinstance(ev, Evidence)
    assert ev.kind == EvidenceKind.TDX
    assert ev.nonce == nonce
    assert ev.miner_hotkey == HOTKEY
    assert ev.quote == b"fakequote:" + nonce[:4]
    assert ev.cert_chain == [b"fakecert"]


def test_sat_work_good_round_trip():
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        cert = remote.do_sat_work(item)

    assert isinstance(cert, SatCertificate)
    assert cert.satisfiable is True
    assert cert.challenge_id == item.challenge_id
    assert cert.assigned_hotkey == HOTKEY
    # Verify the assignment is actually satisfying
    true_lits = set(cert.assignment)
    for clause in item.instance.clauses:
        assert any(lit in true_lits for lit in clause), f"clause {clause} not satisfied"


def test_canonical_sat_happy_path_with_production_default():
    seed = 17
    instance = _canonical_instance(seed)
    item = SatWorkItem(
        instance=instance,
        seed=seed,
        challenge_id=_compute_challenge_id(instance, seed),
    )
    with _WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_fake_evidence,
    ) as srv:
        _start_server(srv)
        cert = RemoteMiner(srv.base_url, HOTKEY).do_sat_work(item)
    assert cert.assigned_hotkey == HOTKEY
    assert cert.satisfiable is True


def test_worker_api_cannot_enable_customer_sat_without_auth_and_binding():
    with pytest.raises(ValueError, match="bearer authentication"):
        _WorkerServer(
            configured_hotkey=HOTKEY,
            evidence_collector=_fake_evidence,
            allow_noncanonical_sat=True,
        )


def test_default_worker_rejects_valid_hash_noncanonical_instance(monkeypatch):
    item = _make_sat_item()

    def must_not_solve(instance):
        raise AssertionError("noncanonical work reached solver")

    monkeypatch.setattr("cathedral.worker.solve_sat", must_not_solve)
    with _WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_fake_evidence,
    ) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": item.challenge_id,
                "assigned_hotkey": HOTKEY,
                "instance": {
                    "n_vars": item.instance.n_vars,
                    "clauses": item.instance.clauses,
                },
                "seed": item.seed,
            }
        ).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400
    assert b"noncanonical" in body


def test_customer_sat_resource_exhaustion_returns_retryable_failure(monkeypatch):
    item = _make_sat_item()
    monkeypatch.setattr(
        "cathedral.worker._solve_customer_sat_bounded",
        lambda _instance, _timeout: (False, None),
    )
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": item.challenge_id,
                "assigned_hotkey": HOTKEY,
                "instance": {
                    "n_vars": item.instance.n_vars,
                    "clauses": item.instance.clauses,
                },
                "seed": item.seed,
            }
        ).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 503
    assert b"resource limits" in body


def test_customer_sat_solver_process_handles_maximum_branch_depth():
    instance = SatInstance(
        n_vars=MAX_N_VARS,
        clauses=[[variable, variable] for variable in range(1, MAX_N_VARS + 1)],
    )
    completed, assignment = _solve_customer_sat_bounded(instance, 5.0)
    assert completed is True
    assert assignment is not None
    assert len(assignment) == MAX_N_VARS


def test_worker_capability_negotiation_tracks_customer_sat_mode():
    with _WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_fake_evidence,
    ) as default_server:
        _start_server(default_server)
        assert RemoteMiner(default_server.base_url, HOTKEY).supports_customer_sat() is False

    with WorkerServer(evidence_collector=_fake_evidence) as customer_server:
        _start_server(customer_server)
        assert RemoteMiner(customer_server.base_url, HOTKEY).supports_customer_sat() is True


def test_evidence_with_bearer_good_round_trip():
    nonce = os.urandom(32)
    token = "s3cr3t-t0ken"
    with WorkerServer(evidence_collector=_fake_evidence, bearer_token=token) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY, bearer_token=token)
        ev = remote.fetch_evidence(nonce)
    assert ev.miner_hotkey == HOTKEY


# ---------------------------------------------------------------------------
# Hotkey / nonce / challenge_id verification
# ---------------------------------------------------------------------------


def test_evidence_wrong_hotkey_in_response_rejected():
    """Worker using wrong-hotkey collector; RemoteMiner must detect mismatch."""
    nonce = os.urandom(32)

    def wrong_hotkey_collector(nonce: bytes, hotkey: str) -> Evidence:
        return _fake_evidence(nonce, OTHER_HOTKEY)  # returns wrong hotkey

    with WorkerServer(evidence_collector=wrong_hotkey_collector) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        with pytest.raises(RemoteError, match="HTTP 500"):
            remote.fetch_evidence(nonce)


def test_evidence_wrong_nonce_in_response_rejected():
    """Collector that returns a different nonce; RemoteMiner must detect it."""
    nonce = os.urandom(32)
    other_nonce = os.urandom(32)

    def wrong_nonce_collector(nonce: bytes, hotkey: str) -> Evidence:
        return _fake_evidence(other_nonce, hotkey)

    with WorkerServer(evidence_collector=wrong_nonce_collector) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        with pytest.raises(RemoteError, match="HTTP 500"):
            remote.fetch_evidence(nonce)


def test_sat_wrong_challenge_id_response_rejected():
    """A fake server that echoes a different challenge_id; RemoteMiner rejects."""
    item = _make_sat_item()

    # Spin a one-off server that returns wrong challenge_id in response.
    class _FakeHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps(
                {
                    "satisfiable": True,
                    "assignment": [1, -2, 3],
                    "work_units": 3.0,
                    "challenge_id": "wrong-id-000",
                    "assigned_hotkey": HOTKEY,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fake_srv = HTTPServer(("127.0.0.1", 0), _FakeHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY)
        with pytest.raises(RemoteError, match="challenge_id mismatch"):
            remote.do_sat_work(item)
    finally:
        fake_srv.shutdown()


def test_sat_wrong_challenge_id_request_rejected():
    """challenge_id that doesn't match instance+seed → 400 from worker."""
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": "badbadbadbad",  # wrong
                "assigned_hotkey": HOTKEY,
                "instance": {"n_vars": item.instance.n_vars, "clauses": item.instance.clauses},
                "seed": item.seed,
            }
        ).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400
    assert b"challenge_id" in body


# ---------------------------------------------------------------------------
# Malformed / unknown / missing keys
# ---------------------------------------------------------------------------


def test_evidence_malformed_json_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", b"{not valid json")
    assert code == 400
    assert b"invalid JSON" in body


def test_evidence_unknown_key_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "nonce_hex": os.urandom(32).hex(),
                "assigned_hotkey": HOTKEY,
                "extra_field": "surprise",  # unknown
            }
        ).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 400
    assert b"schema" in body.lower() or b"extra" in body.lower()


def test_evidence_missing_key_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {"nonce_hex": os.urandom(32).hex()}
        ).encode()  # missing assigned_hotkey
        code, _body = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 400


def test_sat_work_unknown_key_rejected():
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": item.challenge_id,
                "assigned_hotkey": HOTKEY,
                "instance": {"n_vars": item.instance.n_vars, "clauses": item.instance.clauses},
                "seed": item.seed,
                "injected": "evil",  # unknown
            }
        ).encode()
        code, _body = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400


def test_sat_work_missing_key_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": "someid",
                "assigned_hotkey": HOTKEY,
                # missing instance and seed
            }
        ).encode()
        code, _body = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400


def test_sat_work_instance_unknown_key_rejected():
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": item.challenge_id,
                "assigned_hotkey": HOTKEY,
                "instance": {
                    "n_vars": item.instance.n_vars,
                    "clauses": item.instance.clauses,
                    "surprise": True,  # unknown instance key
                },
                "seed": item.seed,
            }
        ).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400


@pytest.mark.parametrize(
    "instance",
    [
        {"n_vars": 0, "clauses": []},
        {"n_vars": True, "clauses": []},
        {"n_vars": 1, "clauses": [[0]]},
        {"n_vars": 1, "clauses": [[2]]},
        {"n_vars": 4097, "clauses": []},
    ],
)
def test_sat_work_rejects_invalid_variable_and_literal_bounds(instance):
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": "0" * 64,
                "assigned_hotkey": HOTKEY,
                "instance": instance,
                "seed": 0,
            }
        ).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400


def test_sat_work_rejects_zero_clause_instance():
    # The bounds table above uses a fixed, deliberately mismatched
    # challenge_id: every genuinely invalid instance there is caught by
    # _parse_instance before the challenge_id binding is even checked. A
    # zero-clause instance needs its OWN request with a matching challenge_id,
    # because a bug that lets validate_sat_instance accept clauses=[] would
    # let this request reach solve_sat and return 200, not 400.
    instance = SatInstance(n_vars=1, clauses=[])
    seed = 0
    challenge_id = _compute_challenge_id(instance, seed)
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": challenge_id,
                "assigned_hotkey": HOTKEY,
                "instance": {"n_vars": instance.n_vars, "clauses": instance.clauses},
                "seed": seed,
            }
        ).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/sat-work", payload)
    assert code == 400


def test_unknown_path_returns_404():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        code, _ = _post_raw(f"{srv.base_url}/v1/unknown", b"{}")
    assert code == 404


def test_evidence_invalid_nonce_hex_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "nonce_hex": "not-hex!",
                "assigned_hotkey": HOTKEY,
            }
        ).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 400
    assert b"hex" in body.lower()


@pytest.mark.parametrize("version", [True, 1.0, 2.0, "2"])
def test_worker_rejects_non_integer_report_data_version(version):
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"a" * 32)
    called = False

    def must_not_collect(*_args, **_kwargs):
        nonlocal called
        called = True
        raise AssertionError("invalid version reached collector")

    with WorkerServer(evidence_collector=must_not_collect, channel_binding=binding) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "nonce_hex": os.urandom(32).hex(),
                "assigned_hotkey": HOTKEY,
                "report_data_version": version,
                "channel_binding_type": binding.binding_type.value,
                "channel_binding_digest_hex": binding.digest.hex(),
            }
        ).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/evidence", payload)

    assert code == 400
    assert called is False


def test_evidence_empty_hotkey_rejected():
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "nonce_hex": os.urandom(32).hex(),
                "assigned_hotkey": "",
            }
        ).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 400


def test_assigned_hotkey_mismatch_rejected_at_both_endpoints():
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        evidence = json.dumps(
            {
                "nonce_hex": os.urandom(32).hex(),
                "assigned_hotkey": OTHER_HOTKEY,
            }
        ).encode()
        sat = json.dumps(
            {
                "challenge_id": item.challenge_id,
                "assigned_hotkey": OTHER_HOTKEY,
                "instance": {"n_vars": item.instance.n_vars, "clauses": item.instance.clauses},
                "seed": item.seed,
            }
        ).encode()
        evidence_code, _ = _post_raw(f"{srv.base_url}/v1/evidence", evidence)
        sat_code, _ = _post_raw(f"{srv.base_url}/v1/sat-work", sat)
    assert evidence_code == 403
    assert sat_code == 403


def test_nonce_must_be_exactly_32_bytes_on_client_and_worker():
    remote = RemoteMiner("http://127.0.0.1:1", HOTKEY)
    with pytest.raises(RemoteError, match="exactly 32 bytes"):
        remote.collect_evidence(b"short")

    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        payload = json.dumps({"nonce_hex": "aa" * 31, "assigned_hotkey": HOTKEY}).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 400


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        (b"", 411),
        (b"Content-Length: nope\r\n", 400),
        (b"Content-Length: -1\r\n", 400),
        (b"Content-Length: 999999\r\n", 413),
    ],
)
def test_worker_rejects_absent_invalid_negative_and_oversized_lengths(headers, expected):
    with WorkerServer(evidence_collector=_fake_evidence, max_body=64) as srv:
        _start_server(srv)
        assert _raw_http_status(srv.port, headers) == expected


# ---------------------------------------------------------------------------
# Oversized request / response
# ---------------------------------------------------------------------------


def test_oversized_request_rejected():
    """Body exceeding max_body → 413."""
    with WorkerServer(evidence_collector=_fake_evidence, max_body=64) as srv:
        _start_server(srv)
        big_payload = json.dumps(
            {
                "nonce_hex": "aa" * 32,
                "assigned_hotkey": "A" * 200,  # push it over 64 bytes
            }
        ).encode()
        assert len(big_payload) > 64
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", big_payload)
    assert code == 413
    assert b"large" in body.lower()


def test_oversized_response_rejected():
    """Server returning >max_response_body bytes → RemoteError."""

    class _BigHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            # Return a valid-looking but enormous response
            big = json.dumps(
                {
                    "kind": "tdx",
                    "quote_hex": "aa" * 70_000,  # ~140KB hex
                    "nonce_hex": "bb" * 32,
                    "assigned_hotkey": HOTKEY,
                    "cert_chain_hex": [],
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(big)))
            self.end_headers()
            self.wfile.write(big)

    fake_srv = HTTPServer(("127.0.0.1", 0), _BigHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY, max_response_body=1024)  # tiny cap
        with pytest.raises(RemoteError, match="body limit"):
            remote.fetch_evidence(os.urandom(32))
    finally:
        fake_srv.shutdown()


def test_sat_response_keeps_small_cap_when_evidence_limit_is_large():
    """A malicious SAT peer cannot consume the evidence response budget."""
    item = _make_sat_item()

    class _OversizedSatHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            body = b"{" + b"x" * MAX_SAT_RESPONSE_BODY + b"}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

    server = HTTPServer(("127.0.0.1", 0), _OversizedSatHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        remote = RemoteMiner(
            f"http://127.0.0.1:{server.server_address[1]}",
            HOTKEY,
        )
        with pytest.raises(RemoteError, match="body limit"):
            remote.do_sat_work(item)
    finally:
        server.shutdown()


def test_actual_response_body_over_cap_rejected_without_content_length():
    class _UndeclaredBigHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{" + b"x" * 4096 + b"}")

    server = HTTPServer(("127.0.0.1", 0), _UndeclaredBigHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        remote = RemoteMiner(
            f"http://127.0.0.1:{server.server_address[1]}",
            HOTKEY,
            max_response_body=128,
        )
        with pytest.raises(RemoteError, match="body limit"):
            remote.fetch_evidence(os.urandom(32))
    finally:
        server.shutdown()


def test_worker_caps_generated_response_and_hides_collector_error():
    secret = "private collector failure"

    def failing_collector(nonce, hotkey):
        raise RuntimeError(secret)

    with WorkerServer(evidence_collector=failing_collector) as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "nonce_hex": os.urandom(32).hex(),
                "assigned_hotkey": HOTKEY,
            }
        ).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/evidence", payload)
    assert code == 500
    assert secret.encode() not in body


# ---------------------------------------------------------------------------
# Busy (semaphore / 503)
# ---------------------------------------------------------------------------


def test_busy_returns_503():
    """When the server is processing one request, a second gets 503."""
    hold = threading.Event()
    unblock = threading.Event()

    def blocking_collector(nonce: bytes, hotkey: str) -> Evidence:
        hold.set()  # signal: request is in flight
        unblock.wait(5.0)  # hold the semaphore
        return _fake_evidence(nonce, hotkey)

    with WorkerServer(
        evidence_collector=blocking_collector,
        max_concurrent=1,
        max_challenge_concurrent=1,
    ) as srv:
        _start_server(srv)

        nonce_hex = os.urandom(32).hex()
        payload = json.dumps({"nonce_hex": nonce_hex, "assigned_hotkey": HOTKEY}).encode()
        url = f"{srv.base_url}/v1/evidence"

        # First request — runs in background, holds semaphore.
        results: list[tuple[int, bytes]] = []

        def first_request():
            results.append(_post_raw(url, payload))

        t1 = threading.Thread(target=first_request)
        t1.start()

        # Wait until first request is inside the handler.
        hold.wait(timeout=5.0)

        # Second request — should get 503 immediately.
        code2, body2 = _post_raw(url, payload)
        assert code2 == 503
        assert b"busy" in body2.lower()

        # Let first request finish.
        unblock.set()
        t1.join(timeout=5.0)
        assert results[0][0] == 200


# ---------------------------------------------------------------------------
# Slot exhaustion by unauthenticated callers (issue #65)
# ---------------------------------------------------------------------------


def test_partial_bodies_are_bounded_before_handler_threads_can_grow():
    """Every long-lived partial-body thread consumes one finite admission slot."""
    evidence_payload = json.dumps(
        {"nonce_hex": os.urandom(32).hex(), "assigned_hotkey": HOTKEY}
    ).encode()
    with WorkerServer(
        evidence_collector=_fake_evidence,
        max_concurrent=1,
        max_challenge_concurrent=2,
        max_sat_challenge_concurrent=1,
        max_connection_concurrent=4,
        timeout=30.0,
    ) as srv:
        _start_server(srv)
        stalled = [
            _stall_post_connection(srv.port, path="/v1/evidence"),
            _stall_post_connection(srv.port, path="/v1/evidence"),
            _stall_post_connection(srv.port, path="/v1/sat-work"),
            _stall_post_connection(
                srv.port,
                path="/v1/sat-work",
                bearer=TEST_BEARER,
            ),
        ]
        try:
            _wait_for_active_connections(srv, 4)
            for _ in range(20):
                # The pre-handler gate has no parsed HTTP request and closes
                # immediately. Class-pool saturation, tested separately,
                # remains the point that returns a deterministic HTTP 503.
                assert _connection_gate_response(srv.port) == b""
                assert srv._server.active_connection_count == 4
        finally:
            for conn in stalled:
                conn.close()
        _wait_for_active_connections(srv, 0)
        assert _post_raw(f"{srv.base_url}/v1/evidence", evidence_payload)[0] == 200


def test_saturated_class_pool_returns_503_before_body_framing():
    """Admission wins over framing detail once the request class is saturated."""
    hold = threading.Event()
    unblock = threading.Event()

    def blocking_collector(nonce: bytes, hotkey: str) -> Evidence:
        hold.set()
        unblock.wait(5.0)
        return _fake_evidence(nonce, hotkey)

    with WorkerServer(
        evidence_collector=blocking_collector,
        max_challenge_concurrent=1,
    ) as srv:
        _start_server(srv)
        url = f"{srv.base_url}/v1/evidence"
        payload = json.dumps(
            {"nonce_hex": os.urandom(32).hex(), "assigned_hotkey": HOTKEY}
        ).encode()
        holder = threading.Thread(target=lambda: _post_raw(url, payload))
        holder.start()
        try:
            assert hold.wait(5.0)
            assert _raw_http_status(srv.port, b"") == 503
            assert _raw_http_status(srv.port, b"Content-Length: nope\r\n") == 503
            assert _raw_http_status(srv.port, b"Content-Length: 999999\r\n") == 503
            assert _raw_http_status(srv.port, b"Transfer-Encoding: chunked\r\n") == 503
        finally:
            unblock.set()
            holder.join(timeout=5.0)

        assert _raw_http_status(srv.port, b"") == 411
        assert _raw_http_status(srv.port, b"Content-Length: nope\r\n") == 400
        assert _raw_http_status(srv.port, b"Content-Length: 999999\r\n") == 413
        assert _raw_http_status(srv.port, b"Transfer-Encoding: chunked\r\n") == 400


def test_total_request_deadline_ends_a_trickled_body():
    """A body slower than the body limit but faster than each recv still ends."""
    stop = threading.Event()
    with WorkerServer(evidence_collector=_fake_evidence, timeout=1.0) as srv:
        _start_server(srv)
        conn = _stall_connection(srv.port)
        started = time.monotonic()

        def trickle() -> None:
            while not stop.wait(0.3):
                try:
                    conn.sendall(b" ")
                except OSError:
                    return

        sender = threading.Thread(target=trickle, daemon=True)
        sender.start()
        try:
            conn.settimeout(10.0)
            response = conn.recv(4096)
            elapsed = time.monotonic() - started
        finally:
            stop.set()
            sender.join(timeout=5.0)
            conn.close()
    assert _status_of(response) == 400
    # Without a total deadline this request never ends: 4096 bytes at one
    # byte per 0.3s outlives any per-recv timeout.
    assert elapsed < 5.0


def test_shutdown_cancels_partial_body_and_releases_connection_slot():
    """Operator shutdown must not wait for the attacker's request deadline."""
    srv = WorkerServer(
        evidence_collector=_fake_evidence,
        max_concurrent=1,
        max_challenge_concurrent=1,
        max_sat_challenge_concurrent=1,
        max_connection_concurrent=3,
        timeout=30.0,
    )
    server_thread = _start_server(srv)
    stalled = _stall_connection(srv.port)
    try:
        _wait_for_active_connections(srv, 1)
        shutdown_thread = threading.Thread(target=srv.shutdown)
        started = time.monotonic()
        shutdown_thread.start()
        shutdown_thread.join(timeout=2.0)
        elapsed = time.monotonic() - started

        assert not shutdown_thread.is_alive()
        assert elapsed < 2.0
        _wait_for_active_connections(srv, 0)
        server_thread.join(timeout=1.0)
        assert not server_thread.is_alive()
    finally:
        stalled.close()
        if server_thread.is_alive():
            srv.shutdown()


def test_a_client_that_stops_reading_cannot_keep_the_challenge_slot():
    """The response gets a deadline too, or stalling the read holds a slot."""

    def big_collector(nonce: bytes, hotkey: str) -> Evidence:
        return Evidence(
            kind=EvidenceKind.TDX,
            quote=b"q" * (512 * 1024),
            nonce=nonce,
            miner_hotkey=hotkey,
            cert_chain=[b"fakecert"],
        )

    payload = json.dumps({"nonce_hex": os.urandom(32).hex(), "assigned_hotkey": HOTKEY}).encode()
    with WorkerServer(
        evidence_collector=big_collector,
        max_challenge_concurrent=1,
        timeout=1.0,
    ) as srv:
        _start_server(srv)
        url = f"{srv.base_url}/v1/evidence"
        stalled = socket.socket()
        # A tiny receive buffer stops the response fitting in the socket, so
        # the handler is genuinely blocked in send rather than already done.
        stalled.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2048)
        stalled.settimeout(10.0)
        stalled.connect(("127.0.0.1", srv.port))
        try:
            stalled.sendall(
                b"POST /v1/evidence HTTP/1.1\r\nHost: localhost\r\n"
                b"Content-Type: application/json\r\n"
                b"Content-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n" + payload
            )
            time.sleep(0.3)
            # Whether the handler is still blocked in send at this instant
            # depends on how the kernel sized and drained the socket buffers,
            # so a 503 here is expected but not guaranteed and must not be
            # asserted. The invariant that matters is the recovery below: a
            # client that stops reading cannot hold the slot indefinitely.
            # Without the response deadline the handler blocks forever and
            # this loop never sees a 200.
            code = 0
            deadline = time.monotonic() + 8.0
            while code != 200 and time.monotonic() < deadline:
                code, _ = _post_raw(url, payload)
            assert code == 200
        finally:
            stalled.close()


def test_saturated_challenge_pool_does_not_starve_authenticated_work():
    """Three pools: evidence, credential-free SAT, and authenticated work.

    A saturated evidence pool must not starve either of the other two. Since
    #168 the credential-free SAT path has its own pool rather than sharing the
    evidence pool, so a blocked evidence request no longer 503s the public
    canonical audit; a SAT POST carrying the configured bearer is customer
    work and runs on the authenticated pool as before.
    """
    hold = threading.Event()
    unblock = threading.Event()

    def blocking_collector(nonce: bytes, hotkey: str) -> Evidence:
        hold.set()
        unblock.wait(5.0)
        return _fake_evidence(nonce, hotkey)

    item = _make_sat_item()
    with WorkerServer(
        evidence_collector=blocking_collector,
        max_concurrent=1,
        max_challenge_concurrent=1,
    ) as srv:
        _start_server(srv)
        url = f"{srv.base_url}/v1/evidence"
        payload = json.dumps(
            {"nonce_hex": os.urandom(32).hex(), "assigned_hotkey": HOTKEY}
        ).encode()
        holder = threading.Thread(target=lambda: _post_raw(url, payload))
        holder.start()
        try:
            assert hold.wait(5.0)
            assert _post_raw(url, payload)[0] == 503
            # #168: the public canonical audit is on its own pool now, so a
            # full evidence pool must NOT refuse it.
            assert _post_raw(
                f"{srv.base_url}/v1/sat-work",
                _canonical_sat_payload(23),
                bearer=None,
            )[0] == 200
            cert = RemoteMiner(srv.base_url, HOTKEY, timeout=5).do_sat_work(item)
            assert cert.challenge_id == item.challenge_id
            assert RemoteMiner(srv.base_url, HOTKEY, timeout=5).supports_customer_sat() is True
        finally:
            unblock.set()
            holder.join(timeout=5.0)


# ---------------------------------------------------------------------------
# Timeout / connection-failure isolation
# ---------------------------------------------------------------------------


def test_timeout_raises_remote_error():
    """RemoteMiner wraps socket timeout as RemoteError; other operations unaffected."""
    # Find a free port then close the socket so nothing is listening.
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]

    remote = RemoteMiner(f"http://127.0.0.1:{dead_port}", HOTKEY, timeout=0.5)
    with pytest.raises(RemoteError):
        remote.fetch_evidence(os.urandom(32))


def test_read_timeout_is_typed_and_does_not_leak_details():
    secret = "internal-secret-that-must-not-leak"

    class _SlowHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            time.sleep(0.2)
            try:
                self.wfile.write(secret.encode())
            except OSError:
                pass

    server = HTTPServer(("127.0.0.1", 0), _SlowHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        remote = RemoteMiner(f"http://127.0.0.1:{server.server_address[1]}", HOTKEY, timeout=0.02)
        with pytest.raises(RemoteError) as caught:
            remote.fetch_evidence(os.urandom(32))
        assert str(caught.value) == "worker request timed out"
        assert secret not in str(caught.value)
    finally:
        server.shutdown()


def test_redirect_is_rejected_without_following_location():
    followed = threading.Event()

    class _RedirectHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            if self.path == "/followed":
                followed.set()
                self.send_response(200)
            else:
                self.send_response(307)
                self.send_header("Location", "/followed")
            self.end_headers()

    server = HTTPServer(("127.0.0.1", 0), _RedirectHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        remote = RemoteMiner(f"http://127.0.0.1:{server.server_address[1]}", HOTKEY)
        with pytest.raises(RemoteError, match="redirect rejected"):
            remote.fetch_evidence(os.urandom(32))
        assert not followed.is_set()
    finally:
        server.shutdown()


def test_https_required_without_explicit_test_flag():
    with pytest.raises(ValueError, match="HTTPS"):
        _RemoteMiner("http://127.0.0.1:8080", HOTKEY)


def test_connection_error_does_not_leak_exception_type():
    """RemoteError wraps urllib errors; callers never see raw urllib exceptions."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]

    remote = RemoteMiner(f"http://127.0.0.1:{dead_port}", HOTKEY, timeout=0.5)
    with pytest.raises(RemoteError):
        remote.do_sat_work(_make_sat_item())


def test_one_failure_does_not_affect_next_request():
    """Failure on one call does not break the RemoteMiner for subsequent calls."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead_port = s.getsockname()[1]

    remote_dead = RemoteMiner(f"http://127.0.0.1:{dead_port}", HOTKEY, timeout=0.3)
    with pytest.raises(RemoteError):
        remote_dead.fetch_evidence(os.urandom(32))

    # A second client to a live server should still work.
    nonce = os.urandom(32)
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote_live = RemoteMiner(srv.base_url, HOTKEY)
        ev = remote_live.fetch_evidence(nonce)
    assert ev.nonce == nonce


# ---------------------------------------------------------------------------
# work_units never trusted
# ---------------------------------------------------------------------------


def test_work_units_not_trusted():
    """RemoteMiner discards server work_units and recomputes from the instance."""
    item = _make_sat_item()
    expected_wu = float(len(item.instance.clauses))

    # Fake server that returns an inflated work_units.
    class _InflatedHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps(
                {
                    "satisfiable": True,
                    "assignment": [1, 2, 3],
                    "work_units": 1e300,  # forged / inflated
                    "challenge_id": item.challenge_id,
                    "assigned_hotkey": HOTKEY,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fake_srv = HTTPServer(("127.0.0.1", 0), _InflatedHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY)
        cert = remote.do_sat_work(item)
        # Must equal the validator-recomputed value, not the forged 1e300.
        assert cert.work_units == expected_wu
    finally:
        fake_srv.shutdown()


# ---------------------------------------------------------------------------
# Bearer token DoS filter
# ---------------------------------------------------------------------------


def test_bearer_token_missing_returns_401(monkeypatch):
    item = _make_sat_item()
    monkeypatch.setattr("cathedral.worker.solve_sat", _must_not_solve)
    monkeypatch.setattr(
        "cathedral.worker._solve_customer_sat_bounded", _must_not_solve_customer
    )
    with WorkerServer(evidence_collector=_fake_evidence, bearer_token="tok") as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": item.challenge_id,
                "assigned_hotkey": HOTKEY,
                "instance": {
                    "n_vars": item.instance.n_vars,
                    "clauses": item.instance.clauses,
                },
                "seed": item.seed,
            }
        ).encode()
        code, body = _post_raw(f"{srv.base_url}/v1/sat-work", payload, bearer=None)
    assert code == 401
    assert b"unauthorized" in body.lower()


def test_bearer_token_wrong_returns_401(monkeypatch):
    item = _make_sat_item()
    monkeypatch.setattr("cathedral.worker.solve_sat", _must_not_solve)
    monkeypatch.setattr(
        "cathedral.worker._solve_customer_sat_bounded", _must_not_solve_customer
    )
    with WorkerServer(evidence_collector=_fake_evidence, bearer_token="correct") as srv:
        _start_server(srv)
        payload = json.dumps(
            {
                "challenge_id": item.challenge_id,
                "assigned_hotkey": HOTKEY,
                "instance": {
                    "n_vars": item.instance.n_vars,
                    "clauses": item.instance.clauses,
                },
                "seed": item.seed,
            }
        ).encode()
        code, _ = _post_raw(f"{srv.base_url}/v1/sat-work", payload, bearer="wrong")
    assert code == 401


def test_bearer_token_correct_accepted():
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence, bearer_token="mysecret") as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY, bearer_token="mysecret")
        cert = remote.do_sat_work(item)
    assert cert.assigned_hotkey == HOTKEY


def test_canonical_sat_is_answered_without_any_authorization_header():
    """An independent validator holds no bearer, and must still be audited.

    A production worker configures a bearer for customer work. While the gate
    rejected every unauthenticated POST to /v1/sat-work, the canonical audit
    an unenrolled validator sends 401'd, so a worker that serves the protocol
    correctly could never be shown to be serving it.
    """
    seed = 23
    instance = _canonical_instance(seed)
    with _WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_fake_evidence,
        bearer_token="production-worker-token",
    ) as srv:
        _start_server(srv)
        code, body = _post_raw(
            f"{srv.base_url}/v1/sat-work", _canonical_sat_payload(seed), bearer=None
        )
    assert code == 200
    response = json.loads(body)
    assert response["satisfiable"] is True
    assert response["challenge_id"] == _compute_challenge_id(instance, seed)
    true_literals = set(response["assignment"])
    for clause in instance.clauses:
        assert any(literal in true_literals for literal in clause), f"clause {clause} unsatisfied"


def test_canonical_sat_is_answered_despite_a_wrong_authorization_header():
    """A stale or foreign credential must not turn the public audit into a 401."""
    seed = 41
    instance = _canonical_instance(seed)
    with _WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_fake_evidence,
        bearer_token="production-worker-token",
    ) as srv:
        _start_server(srv)
        code, body = _post_raw(
            f"{srv.base_url}/v1/sat-work",
            _canonical_sat_payload(seed),
            bearer="some-other-subnets-token",
        )
    assert code == 200
    response = json.loads(body)
    true_literals = set(response["assignment"])
    for clause in instance.clauses:
        assert any(literal in true_literals for literal in clause), f"clause {clause} unsatisfied"


def test_evidence_challenge_never_sends_or_requires_bearer_token():
    nonce = os.urandom(32)
    with WorkerServer(evidence_collector=_fake_evidence, bearer_token="secret") as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY, bearer_token="wrong-on-purpose")
        evidence = remote.fetch_evidence(nonce)
    assert evidence.nonce == nonce


def test_non_ascii_authorization_does_not_crash_evidence():
    """hmac.compare_digest TypeError must not take down /v1/evidence.

    Pool selection used to call _check_auth on every path, including the
    credential-free quote. A Latin-1 Authorization value then raised
    TypeError before the request try block, so a public challenge failed
    hard instead of ignoring the header.
    """
    nonce = os.urandom(32)
    payload = json.dumps(
        {"nonce_hex": nonce.hex(), "assigned_hotkey": HOTKEY}
    ).encode()
    with _WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_fake_evidence,
        bearer_token="production-worker-token",
    ) as srv:
        _start_server(srv)
        code, body = _raw_post(
            srv.port,
            "/v1/evidence",
            payload,
            extra_headers="Authorization: Bearer café\r\n".encode("latin-1"),
        )
    assert code == 200
    assert json.loads(body)["nonce_hex"] == nonce.hex()


def test_non_ascii_authorization_does_not_crash_canonical_sat():
    seed = 23
    with _WorkerServer(
        configured_hotkey=HOTKEY,
        evidence_collector=_fake_evidence,
        bearer_token="production-worker-token",
    ) as srv:
        _start_server(srv)
        code, body = _raw_post(
            srv.port,
            "/v1/sat-work",
            _canonical_sat_payload(seed),
            extra_headers="Authorization: Bearer café\r\n".encode("latin-1"),
        )
    assert code == 200
    assert json.loads(body)["satisfiable"] is True


# ---------------------------------------------------------------------------
# Response schema violations (extra / missing keys in server response)
# ---------------------------------------------------------------------------


def test_extra_key_in_evidence_response_raises_remote_error():
    """If the server adds an unexpected key, RemoteMiner raises RemoteError."""

    class _ExtraKeyHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(length))
            body = json.dumps(
                {
                    "kind": "tdx",
                    "quote_hex": "aa" * 4,
                    "nonce_hex": req["nonce_hex"],
                    "assigned_hotkey": req["assigned_hotkey"],
                    "cert_chain_hex": [],
                    "surprise_field": "evil",  # extra
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fake_srv = HTTPServer(("127.0.0.1", 0), _ExtraKeyHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY)
        with pytest.raises(RemoteError, match="schema"):
            remote.fetch_evidence(os.urandom(32))
    finally:
        fake_srv.shutdown()


def test_missing_key_in_sat_response_raises_remote_error():
    """If the server omits a required key, RemoteMiner raises RemoteError."""
    item = _make_sat_item()

    class _MissingKeyHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps(
                {
                    "satisfiable": True,
                    "assignment": [1, 2, 3],
                    # missing: work_units, challenge_id, assigned_hotkey
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    fake_srv = HTTPServer(("127.0.0.1", 0), _MissingKeyHandler)
    t = threading.Thread(target=fake_srv.serve_forever, daemon=True)
    t.start()
    try:
        url = f"http://127.0.0.1:{fake_srv.server_address[1]}"
        remote = RemoteMiner(url, HOTKEY)
        with pytest.raises(RemoteError, match="schema"):
            remote.do_sat_work(item)
    finally:
        fake_srv.shutdown()


def test_malformed_assignment_response_is_rejected():
    item = _make_sat_item()

    class _BadAssignmentHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps(
                {
                    "satisfiable": True,
                    "assignment": [1, -1, 3],
                    "work_units": 3.0,
                    "challenge_id": item.challenge_id,
                    "assigned_hotkey": HOTKEY,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = HTTPServer(("127.0.0.1", 0), _BadAssignmentHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        remote = RemoteMiner(f"http://127.0.0.1:{server.server_address[1]}", HOTKEY)
        with pytest.raises(RemoteError, match="invalid assignment"):
            remote.do_sat_work(item)
    finally:
        server.shutdown()


# ---------------------------------------------------------------------------
# Compatibility: returned certificate passes SatLane.verify()
# ---------------------------------------------------------------------------


def test_certificate_passes_sat_lane_verify():
    """Certificate from RemoteMiner is accepted by SatLane.verify()."""
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        cert = remote.do_sat_work(item)

    lane = SatLane()
    # Simulate lane having dispatched this item.
    lane._issued_ids.add(item.challenge_id)
    lane._challenge_owner[item.challenge_id] = HOTKEY

    verified = lane.verify(item, cert)
    assert verified is not None
    assert verified.satisfiable is True
    assert verified.challenge_id == item.challenge_id


def test_certificate_scores_correctly_in_lane():
    """SatLane.score() sums verified work for the correct miner."""
    item = _make_sat_item()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        remote = RemoteMiner(srv.base_url, HOTKEY)
        cert = remote.do_sat_work(item)

    lane = SatLane()
    lane._issued_ids.add(item.challenge_id)
    lane._challenge_owner[item.challenge_id] = HOTKEY
    verified = lane.verify(item, cert)
    assert verified is not None

    score = lane.score(HOTKEY, [verified])
    # sat_work_units_v1: a non-canonical (customer-shaped) item earns the
    # fixed CUSTOMER_SAT_WORK_UNITS, never a clause-count claim.
    assert score == 20.0
    # Other miner gets zero.
    assert lane.score(OTHER_HOTKEY, [verified]) == 0.0


def test_sat_lane_rejects_certificate_owned_by_another_hotkey():
    item = _make_sat_item()
    lane = SatLane()
    lane._issued_ids.add(item.challenge_id)
    lane._challenge_owner[item.challenge_id] = HOTKEY
    forged = SatCertificate(
        satisfiable=True,
        assignment=[1, -2, 3],
        work_units=3.0,
        challenge_id=item.challenge_id,
        assigned_hotkey=OTHER_HOTKEY,
    )
    assert lane.verify(item, forged) is None


def test_sat_lane_rejects_legacy_empty_owner():
    lane = SatLane()
    item = lane.dispatch(HOTKEY, 0)
    assignment = solve_sat(item.instance)
    assert assignment is not None
    cert = SatCertificate(
        satisfiable=True,
        assignment=assignment,
        work_units=float(len(item.instance.clauses)),
        challenge_id=item.challenge_id,
    )
    assert cert.assigned_hotkey == ""
    assert lane.verify(item, cert) is None


def test_remote_miner_empty_hotkey_raises():
    with pytest.raises(ValueError, match="hotkey"):
        RemoteMiner("http://127.0.0.1:9999", "")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": 0},
        {"timeout": float("nan")},
        {"max_response_body": 0},
    ],
)
def test_remote_miner_rejects_invalid_limits(kwargs):
    with pytest.raises(ValueError):
        RemoteMiner("http://127.0.0.1:9999", HOTKEY, **kwargs)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"timeout": 0},
        {"max_body": 0},
        {"max_response_body": 0},
        {"max_concurrent": 0},
        {"max_challenge_concurrent": 0},
        {"max_sat_challenge_concurrent": 0},
        {"max_connection_concurrent": 0},
        {"max_connection_concurrent": True},
        {"max_connection_concurrent": 1.5},
        {"max_connection_concurrent": 7},
    ],
)
def test_worker_server_rejects_invalid_limits(kwargs):
    with pytest.raises(ValueError):
        WorkerServer(evidence_collector=_fake_evidence, **kwargs)


# ---------------------------------------------------------------------------
# Credential-free SAT must not be able to starve evidence collection (#168)
# ---------------------------------------------------------------------------


def test_partial_unauthenticated_sat_does_not_starve_valid_bearer_sat(monkeypatch):
    """A valid bearer routes to work capacity before either body is read."""
    body_read_started = threading.Event()
    real_readinto = worker_module._DeadlineReader.readinto

    def observed_readinto(reader, buffer):
        body_read_started.set()
        return real_readinto(reader, buffer)

    monkeypatch.setattr(worker_module._DeadlineReader, "readinto", observed_readinto)
    payload = _canonical_sat_payload(23)
    with WorkerServer(
        evidence_collector=_fake_evidence,
        max_concurrent=1,
        max_challenge_concurrent=2,
        max_sat_challenge_concurrent=1,
        max_connection_concurrent=4,
        timeout=30.0,
    ) as srv:
        _start_server(srv)
        stalled = _stall_post_connection(srv.port, path="/v1/sat-work")
        try:
            assert body_read_started.wait(timeout=2.0)

            public_code, public_body = _post_raw(
                f"{srv.base_url}/v1/sat-work",
                payload,
                bearer=None,
            )
            assert public_code == 503
            assert b"busy" in public_body.lower()

            authenticated_code, authenticated_body = _post_raw(
                f"{srv.base_url}/v1/sat-work",
                payload,
                bearer=TEST_BEARER,
            )
            assert authenticated_code == 200
            assert json.loads(authenticated_body)["satisfiable"] is True
        finally:
            stalled.close()


def test_inflight_unauthenticated_sat_cannot_503_evidence(monkeypatch):
    """#168: hold the credential-free SAT pool open and prove evidence survives.

    Canonical classification needs the parsed instance, so an unauthenticated
    noncanonical request holds its slot through json.loads and _parse_instance
    before it can 401. While it is parked there this test fires BOTH a second
    SAT request (must 503, proving the SAT pool really is exhausted) and an
    evidence request (must 200, proving the pools are separate). Sharing one
    pool would 503 the evidence request, and a validator that cannot collect a
    quote scores the miner zero.
    """
    entered = threading.Event()
    release = threading.Event()
    real_parse = worker_module._parse_instance

    def parked_parse(raw):
        entered.set()
        release.wait(timeout=10.0)
        return real_parse(raw)

    monkeypatch.setattr(worker_module, "_parse_instance", parked_parse)

    item = _make_sat_item()
    sat_payload = json.dumps(
        {
            "challenge_id": item.challenge_id,
            "assigned_hotkey": HOTKEY,
            "instance": {
                "n_vars": item.instance.n_vars,
                "clauses": item.instance.clauses,
            },
            "seed": item.seed,
        }
    ).encode()
    evidence_payload = json.dumps(
        {"nonce_hex": os.urandom(32).hex(), "assigned_hotkey": HOTKEY}
    ).encode()

    with WorkerServer(
        evidence_collector=_fake_evidence,
        max_sat_challenge_concurrent=1,
        max_challenge_concurrent=1,
    ) as srv:
        _start_server(srv)
        held: list[int] = []

        def hold_the_slot():
            code, _ = _post_raw(f"{srv.base_url}/v1/sat-work", sat_payload, bearer=None)
            held.append(code)

        parker = threading.Thread(target=hold_the_slot, daemon=True)
        parker.start()
        try:
            assert entered.wait(timeout=10.0), "parked SAT request never reached parse"

            # The SAT pool is genuinely full: a second SAT request is refused.
            busy_code, _ = _post_raw(
                f"{srv.base_url}/v1/sat-work", sat_payload, bearer=None
            )
            assert busy_code == 503, f"SAT pool not exhausted, got {busy_code}"

            # ...and evidence, on its own pool, is unaffected.
            code, _ = _post_raw(
                f"{srv.base_url}/v1/evidence", evidence_payload, bearer=None
            )
            assert code == 200, f"evidence was starved by unauthenticated SAT: {code}"
        finally:
            release.set()
            parker.join(timeout=10.0)
        assert held == [401]


def test_near_canonical_mutation_is_rejected_without_a_bearer(monkeypatch):
    """#168: exact equality, not shape. One flipped literal must still 401.

    A regression from exact SatInstance equality to a shape-only comparison
    would expose altered 8-variable, 20-clause work to any unauthenticated
    caller while every accept-direction test still passed.
    """
    seed = 11
    instance = _canonical_instance(seed)
    clauses = [list(clause) for clause in instance.clauses]
    clauses[0][0] = -clauses[0][0]
    mutated = SatInstance(n_vars=instance.n_vars, clauses=clauses)
    assert mutated != instance

    monkeypatch.setattr("cathedral.worker.solve_sat", _must_not_solve)
    monkeypatch.setattr(
        "cathedral.worker._solve_customer_sat_bounded",
        lambda _i, _t: (_ for _ in ()).throw(
            AssertionError("mutated work reached the customer solver")
        ),
    )
    payload = json.dumps(
        {
            # recomputed, so only the instance differs from canonical
            "challenge_id": _compute_challenge_id(mutated, seed),
            "assigned_hotkey": HOTKEY,
            "instance": {"n_vars": mutated.n_vars, "clauses": mutated.clauses},
            "seed": seed,
        }
    ).encode()
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        for bearer in (None, "wrong-token", "nön-ascii-tökén"):
            code, _ = _post_raw(f"{srv.base_url}/v1/sat-work", payload, bearer=bearer)
            assert code == 401, f"bearer={bearer!r} should 401, got {code}"


def test_oversized_integer_literal_is_a_client_error_not_a_server_error():
    """A JSON integer past CPython's 4300-digit limit must 400, not 500.

    json.loads raises a BARE ValueError for this, not a JSONDecodeError, so
    the decode guard misses it and the request falls through to the generic
    500 handler. That reports a malformed client request as a worker fault:
    an operator watching 5xx sees a worker bug, and any 5xx alerting fires on
    traffic the worker actually rejected correctly.
    """
    body = b'{"challenge_id": "' + b"0" * 64 + b'", "assigned_hotkey": "' \
        + HOTKEY.encode() + b'", "instance": {"n_vars": 1, "clauses": [[1]]}, "seed": ' \
        + b"1" * 5000 + b"}"
    assert len(body) < worker_module.MAX_REQUEST_BODY
    with WorkerServer(evidence_collector=_fake_evidence) as srv:
        _start_server(srv)
        code, payload = _post_raw(f"{srv.base_url}/v1/sat-work", body)
    assert code == 400, f"expected 400 for an unparseable integer, got {code}"
    assert b"invalid JSON" in payload

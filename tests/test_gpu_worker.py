"""Short acceptance for GPU wire/auth/execution failure behavior; no live GPU claim."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import socket
import subprocess
import threading

import pytest
import sr25519

from cathedral.cli import build_parser, cmd_worker_serve
from cathedral.common import Evidence, EvidenceKind
from cathedral.gpu_work import (
    CudaWorkExecutor, ELEMENTS, EVIDENCE_SCHEMA, GpuWorkError, RESULT_SCHEMA,
    WORKLOAD_ID, WORK_SCHEMA, challenge_id, completion_nonce, expected_output_digest,
    parse_composite, request_digest, validate_request,
)
from cathedral.remote import RemoteError, RemoteMiner
from cathedral.validator_access import (
    ValidatorAccessState, ValidatorRequestAuthorizer, load_sr25519_verifier,
)
from cathedral.worker import WorkerServer
import cathedral.gpu_work as gpu_work
import cathedral.validator_access as access_module
from test_validator_access import (
    VALIDATOR_HOTKEY, VALIDATOR_PAIR, WORKER_HOTKEY, _snapshot, _tls_contexts,
)

UUID = "GPU-11111111-1111-4111-8111-111111111111"


def work_request(executor):
    request = {
        "schema": WORK_SCHEMA, "assigned_hotkey": WORKER_HOTKEY,
        "nonce": "a" * 64, "seed": "b" * 64, "profile_id": executor.profile_id,
        "device_identity_digests": list(executor.device_identity_digests),
        "elements": ELEMENTS, "workload_id": WORKLOAD_ID,
    }
    request["challenge_id"] = challenge_id(request)
    return request


def test_gpu_work_is_exact_bounded_and_completion_commits_all_inputs():
    executor = CudaWorkExecutor("tdx-h100-v1", (UUID,))
    request = work_request(executor)
    validate_request(request)
    expected = expected_output_digest(request)
    nonce = completion_nonce(request, expected)
    for key, value in (("seed", "c" * 64), ("nonce", "d" * 64),
                       ("profile_id", "other-v1"), ("assigned_hotkey", "other")):
        changed = {**request, key: value}
        changed["challenge_id"] = challenge_id(changed)
        assert completion_nonce(changed, expected) != nonce
    with pytest.raises(GpuWorkError):
        validate_request({**request, "elements": True})
    with pytest.raises(GpuWorkError):
        validate_request({**request, "seed": "f" * 64})
    with pytest.raises(GpuWorkError):
        CudaWorkExecutor("tdx-h100-v1", (UUID, UUID))


def test_gpu_child_unavailable_timeout_or_wrong_output_never_falls_back(monkeypatch):
    executor = CudaWorkExecutor("tdx-h100-v1", (UUID,))
    request = work_request(executor)
    for result in (subprocess.CompletedProcess([], 1, b""),
                   subprocess.CompletedProcess([], 0, b"sha256:" + b"0" * 64)):
        monkeypatch.setattr(subprocess, "run", lambda *a, **k: result)
        with pytest.raises(GpuWorkError):
            executor.execute(request)
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], kwargs["timeout"])
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(GpuWorkError):
        executor.execute(request)
    assert executor._slot.acquire(blocking=False)
    executor._slot.release()


def test_missing_native_cuda_does_not_execute_cpu_result(monkeypatch):
    monkeypatch.setattr(gpu_work.sys, "platform", "linux")
    def no_cuda(*_args):
        raise OSError("no CUDA driver")
    monkeypatch.setattr(gpu_work.C, "CDLL", no_cuda)
    with pytest.raises(OSError):
        gpu_work._cuda_execute(work_request(CudaWorkExecutor("tdx-h100-v1", (UUID,))))


def test_serve_gpu_is_explicit_requires_signed_access_and_keeps_cpu_posture():
    args = build_parser().parse_args([
        "worker", "serve-gpu", "--hotkey", WORKER_HOTKEY,
        "--gpu-profile-id", "tdx-h100-v1", "--gpu-device-uuid", UUID,
    ])
    assert args.worker_posture == "gpu-production"
    with pytest.raises(ValueError, match="signed validator-access"):
        cmd_worker_serve(args)
    with pytest.raises(SystemExit):
        build_parser().parse_args(["worker", "serve", "--hotkey", WORKER_HOTKEY,
                                  "--gpu-profile-id", "tdx-h100-v1"])


def test_gpu_service_requires_native_signed_auth():
    with pytest.raises(ValueError, match="signed validator access"):
        WorkerServer(configured_hotkey=WORKER_HOTKEY,
                     gpu_executor=CudaWorkExecutor("tdx-h100-v1", (UUID,)),
                     gpu_evidence_collector=lambda *_a, **_k: ())


def test_gpu_signed_endpoints_bind_completion_and_leave_cpu_wire_unchanged(tmp_path, monkeypatch):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    monkeypatch.setattr(access_module, "is_globally_routable", lambda _a: True)
    now = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(generated_at=now, expires_at=now + timedelta(minutes=10), verify_at=now),
        worker_hotkey=WORKER_HOTKEY, channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "access.sqlite")),
        signature_verifier=load_sr25519_verifier(),
    )
    executor = CudaWorkExecutor("tdx-h100-v1", (UUID,))
    # Test seam only. This verifies transport/control logic, not GPU qualification.
    monkeypatch.setattr(executor, "execute", expected_output_digest)
    def collector(nonce, hotkey, **kwargs):
        return tuple(Evidence(kind=kind, quote=b"test-only", nonce=nonce,
                              miner_hotkey=hotkey, report_data_version=2,
                              channel_binding=kwargs["channel_binding"])
                     for kind in (EvidenceKind.TDX, EvidenceKind.GPU_CC))
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with WorkerServer(
        port=port, configured_hotkey=WORKER_HOTKEY, channel_binding=binding,
        tls_context=server_context, validator_authorizer=authorizer,
        fleet_endpoints=(f"https://127.0.0.1:{port}",),
        gpu_executor=executor, gpu_evidence_collector=collector,
        evidence_collector=lambda nonce, hotkey, **kwargs: collector(nonce, hotkey, **kwargs)[0],
    ) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(server.base_url, WORKER_HOTKEY, ssl_context=client_context,
                             validator_hotkey=VALIDATOR_HOTKEY,
                             validator_signer=lambda m: sr25519.sign(VALIDATOR_PAIR, m))
        def post(path, body, signed=True):
            return remote._post_tls(path, lambda _b: body, expected_binding=binding,
                                    include_auth=False, include_validator_auth=signed)[0]
        for path in ("/v1/gpu-capabilities", "/v1/gpu-evidence", "/v1/gpu-work"):
            with pytest.raises(RemoteError) as denied:
                post(path, {}, signed=False)
            assert denied.value.status_code == 401
        assert post("/v1/capabilities", {}) == {"customer_sat": False}
        capability = post("/v1/gpu-capabilities", {})
        assert capability["status"] == "registered" and capability["verified"] is False
        request = work_request(executor)
        evidence_request = {"nonce_hex": request["nonce"], "assigned_hotkey": WORKER_HOTKEY,
                            "report_data_version": 2,
                            "channel_binding_type": binding.binding_type.value,
                            "channel_binding_digest_hex": binding.digest.hex()}
        evidence = post("/v1/gpu-evidence", evidence_request)
        assert evidence["schema"] == EVIDENCE_SCHEMA
        assert len(parse_composite(evidence["evidence"], bytes.fromhex(request["nonce"]),
                                   WORKER_HOTKEY, binding)) == 2
        cpu = post("/v1/evidence", evidence_request)
        assert cpu["kind"] == "tdx" and "evidence" not in cpu
        result = post("/v1/gpu-work", request)
        assert result["schema"] == RESULT_SCHEMA
        assert result["request_digest"] == request_digest(request)
        assert result["output_digest"] == expected_output_digest(request)
        nonce = completion_nonce(request, result["output_digest"])
        parse_composite(result["completion_evidence"], nonce, WORKER_HOTKEY, binding)
        with pytest.raises(RemoteError):
            parse_composite(result["completion_evidence"], bytes.fromhex(request["nonce"]),
                            WORKER_HOTKEY, binding)
        def fail(_request):
            raise GpuWorkError("CUDA unavailable")
        monkeypatch.setattr(executor, "execute", fail)
        with pytest.raises(RemoteError) as unavailable:
            post("/v1/gpu-work", request)
        assert unavailable.value.status_code == 503

"""Code-only G4 identity acceptance. Injected NVIDIA/CUDA are not hardware proof."""
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import socket
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import pytest
import sr25519

from cathedral.cli import build_parser, cmd_worker_serve
from cathedral.common import ChannelBinding, ChannelBindingType
from cathedral.gpu_provider import (ENDORSEMENT_SCHEMA, G4ProviderCollector, G4ProviderVerifier,
    G4_WORKER_PROFILE_ID, GpuWorkError, PROVIDER_EVIDENCE_SCHEMA, cpu_evidence_unavailable,
    sign_endorsement, verify_provider_evidence)
from cathedral.gpu_work import CudaWorkExecutor, completion_nonce, expected_output_digest
from cathedral.remote import RemoteError, RemoteMiner
from cathedral.validator_access import ValidatorAccessState, ValidatorRequestAuthorizer, load_sr25519_verifier
from cathedral.worker import WorkerServer
import cathedral.gpu_provider as provider
import cathedral.validator_access as access_module
from test_gpu_worker import UUID, work_request
from test_validator_access import VALIDATOR_HOTKEY, VALIDATOR_PAIR, WORKER_HOTKEY, _snapshot, _tls_contexts


def fixture(binding):
    operator, worker = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    def public(key):
        return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    now = int(time.time())
    claims = {"schema": ENDORSEMENT_SCHEMA, "profile_id": G4_WORKER_PROFILE_ID,
              "provider_instance_id": "projects/123456/zones/us-central1-a/instances/7654321",
              "hotkey": WORKER_HOTKEY, "machine_type": "g4-standard-48", "provisioning_model": "SPOT",
              "confidential_compute_type": "SEV", "cpu_attestation": "unattested",
              "guest_control": "approved_operator", "private_customer_work": False,
              "image_digest": "sha256:" + "1" * 64, "worker_public_key_hex": public(worker).hex(),
              "tls_spki_sha256": binding.digest.hex(), "gpu_uuid": UUID,
              "issued_at": now - 10, "expires_at": now + 600}
    endorsement = sign_endorsement(claims, "operator-test-only", operator)
    trusted = {"operator-test-only": public(operator)}
    collector = G4ProviderCollector(endorsement, worker, trusted, WORKER_HOTKEY, binding)
    return collector, trusted, operator


def test_provider_endorsement_binds_instance_worker_key_tls_hotkey_and_freshness(monkeypatch):
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"t" * 32)
    collector, trusted, _operator = fixture(binding)
    monkeypatch.setattr(provider, "_local_nvidia_checks", lambda *_a: b"GPU Attestation is Successful. TEST ONLY")
    nonce = b"n" * 32
    document = collector(nonce, WORKER_HOTKEY, channel_binding=binding, report_data_version=2)
    verifier = G4ProviderVerifier(trusted)
    verdict = verifier.verify(document, nonce, WORKER_HOTKEY, binding.digest, G4_WORKER_PROFILE_ID)
    assert verdict["cpu_attestation"] == "unattested" and verdict["private_customer_work"] is False
    assert verdict["worker_key_digest"].startswith("sha256:")
    for changed_nonce, changed_hotkey, changed_binding in (
        (b"x" * 32, WORKER_HOTKEY, binding.digest), (nonce, "another", binding.digest),
        (nonce, WORKER_HOTKEY, b"u" * 32),
    ):
        with pytest.raises(GpuWorkError):
            verifier.verify(document, changed_nonce, changed_hotkey, changed_binding, G4_WORKER_PROFILE_ID)
    changed = deepcopy(document)
    changed["endorsement"]["claims"]["provider_instance_id"] += "1"
    with pytest.raises(GpuWorkError):
        verifier.verify(changed, nonce, WORKER_HOTKEY, binding.digest, G4_WORKER_PROFILE_ID)
    with pytest.raises(GpuWorkError):
        verify_provider_evidence(document, nonce, WORKER_HOTKEY, binding, trusted_operators={}, now=int(time.time()))
    with pytest.raises(GpuWorkError):
        verify_provider_evidence(document, nonce, WORKER_HOTKEY, binding, trusted_operators=trusted,
                                 now=collector.endorsement["claims"]["expires_at"] + 1)


def test_operator_cannot_endorse_unsupported_profile_or_customer_secrets():
    binding = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, b"t" * 32)
    collector, _, operator = fixture(binding)
    for field, value in (("machine_type", "g4-standard-384"), ("private_customer_work", True),
                         ("cpu_attestation", "snp"), ("guest_control", "miner"),
                         ("provisioning_model", "STANDARD")):
        claims = {**collector.endorsement["claims"], field: value}
        with pytest.raises(GpuWorkError):
            sign_endorsement(claims, "operator-test-only", operator)


def test_serve_g4_is_distinct_requires_signed_access_and_cannot_select_cpu_evidence():
    args = build_parser().parse_args(["worker", "serve-g4", "--hotkey", WORKER_HOTKEY,
        "--gpu-operator-endorsement", "/test-only/endorsement", "--gpu-operator-keys", "/test-only/keys",
        "--gpu-worker-private-key", "/test-only/worker-key"])
    assert args.worker_posture == "g4-prelaunch" and args.tee == "unattested"
    with pytest.raises(ValueError, match="signed validator-access"):
        cmd_worker_serve(args)
    native = build_parser().parse_args(["worker", "serve-gpu", "--hotkey", WORKER_HOTKEY,
        "--gpu-profile-id", G4_WORKER_PROFILE_ID, "--gpu-device-uuid", UUID])
    with pytest.raises(ValueError, match="never TDX"):
        cmd_worker_serve(native)


def test_signed_tls_g4_evidence_work_and_cpu_denial(tmp_path, monkeypatch):
    server_context, client_context, binding = _tls_contexts(tmp_path)
    monkeypatch.setattr(access_module, "is_globally_routable", lambda _a: True)
    now = datetime.now(UTC).replace(microsecond=0)
    authorizer = ValidatorRequestAuthorizer(
        _snapshot(generated_at=now, expires_at=now + timedelta(minutes=10), verify_at=now),
        worker_hotkey=WORKER_HOTKEY, channel_binding=binding,
        state=ValidatorAccessState(str(tmp_path / "access.sqlite")), signature_verifier=load_sr25519_verifier())
    collector, trusted, _operator = fixture(binding)
    calls = []
    def synthetic_nvidia(nonce, _uuid):
        calls.append(nonce)
        return b"GPU Attestation is Successful. TEST ONLY"
    monkeypatch.setattr(provider, "_local_nvidia_checks", synthetic_nvidia)
    executor = CudaWorkExecutor(G4_WORKER_PROFILE_ID, (UUID,))
    monkeypatch.setattr(executor, "execute", expected_output_digest)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with WorkerServer(port=port, configured_hotkey=WORKER_HOTKEY, channel_binding=binding,
        tls_context=server_context, validator_authorizer=authorizer,
        fleet_endpoints=(f"https://127.0.0.1:{port}",), gpu_executor=executor,
        gpu_evidence_collector=collector, evidence_collector=cpu_evidence_unavailable) as server:
        threading.Thread(target=server.serve_forever, daemon=True).start()
        remote = RemoteMiner(server.base_url, WORKER_HOTKEY, ssl_context=client_context,
            validator_hotkey=VALIDATOR_HOTKEY, validator_signer=lambda m: sr25519.sign(VALIDATOR_PAIR, m))
        def post(path, body, signed=True):
            return remote._post_tls(path, lambda _b: body, expected_binding=binding,
                include_auth=False, include_validator_auth=signed)[0]
        with pytest.raises(RemoteError):
            post("/v1/gpu-capabilities", {}, False)
        assert post("/v1/gpu-capabilities", {})["verified"] is False
        request = work_request(executor)
        evidence_request = {"nonce_hex": request["nonce"], "assigned_hotkey": WORKER_HOTKEY,
            "report_data_version": 2, "channel_binding_type": binding.binding_type.value,
            "channel_binding_digest_hex": binding.digest.hex()}
        evidence = post("/v1/gpu-evidence", evidence_request)
        assert evidence["schema"] == PROVIDER_EVIDENCE_SCHEMA
        verifier = G4ProviderVerifier(trusted)
        admission = verifier.verify(evidence["evidence"], bytes.fromhex(request["nonce"]),
            WORKER_HOTKEY, binding.digest, G4_WORKER_PROFILE_ID)
        with pytest.raises(RemoteError):
            post("/v1/evidence", evidence_request)
        result = post("/v1/gpu-work", request)
        nonce = completion_nonce(request, result["output_digest"])
        completion = verifier.verify(result["completion_evidence"], nonce,
            WORKER_HOTKEY, binding.digest, G4_WORKER_PROFILE_ID)
        assert completion["provider_instance_id"] == admission["provider_instance_id"]
        assert completion["worker_key_digest"] == admission["worker_key_digest"]
        assert calls == [bytes.fromhex(request["nonce"]), bytes.fromhex(request["nonce"]), nonce]
        def bad_nvidia(*_a):
            raise GpuWorkError("TEST ONLY failure")
        monkeypatch.setattr(provider, "_local_nvidia_checks", bad_nvidia)
        with pytest.raises(RemoteError) as failed:
            post("/v1/gpu-work", request)
        assert failed.value.status_code == 503

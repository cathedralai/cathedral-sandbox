"""Tests for Cathedral compute sandbox workload extensions in cathedral-sandbox.

Validates:
- Custom disk size on create (§3.1, §3.6): disk_gib 5-1000 GiB
- Network policies (§3.7): public, none, allowlist (CIDRs and domain names)
- Dynamic runtime network policy change (§3.7): update_network_policy
- Port exposure (§3.7): expose_port
- Interactive process attach (§3.2): open_process / WebSocket attach
- Docker-in-Docker capability (§3.17): dind_enabled
"""

from __future__ import annotations

import pytest

from cathedral.workload import (
    AdmittedWorkload,
    ImageReference,
    RecordingExecutionAdapter,
    SignatureVerdict,
    WorkloadAdmissionController,
    WorkloadAdmissionError,
    WorkloadAdmissionPolicy,
    WorkloadManifest,
    WorkloadRequest,
)
from cathedral.provider_contract import parse_workload_manifest_document

IMAGE = "registry.cathedral.computer/cathedral/worker@sha256:" + "a" * 64
SIGNER = "sigstore://cathedral/worker-release"
ROOT = "cathedral-workload-root-v1"
ARGUMENTS_DIGEST = "sha256:" + "1" * 64
CONFIG_DIGEST = "sha256:" + "2" * 64
SIGNATURE_DIGEST = "sha256:" + "3" * 64
ARTIFACT_A = "sha256:" + "4" * 64


class LocalSignatureVerifier:
    production_capable = False

    def __init__(self, verdict: SignatureVerdict):
        self._verdict = verdict

    def preflight(self, trusted_root_ids: frozenset[str]) -> None:
        pass

    def verify(
        self,
        image: ImageReference,
        *,
        required_signer: str,
        trusted_root_ids: frozenset[str],
    ) -> SignatureVerdict:
        return self._verdict


def _policy() -> WorkloadAdmissionPolicy:
    return WorkloadAdmissionPolicy(
        policy_id="cathedral-cpu-v1",
        allowed_registries=frozenset({"registry.cathedral.computer"}),
        allowed_signers=frozenset({SIGNER}),
        trusted_root_ids=frozenset({ROOT}),
        allowed_resource_profiles=frozenset({"cpu-small", "cpu-large"}),
        allowed_runtime_profiles=frozenset({"confidential-cpu-v1"}),
    )


def _request(**overrides) -> WorkloadRequest:
    values = {
        "image_reference": IMAGE,
        "required_signer": SIGNER,
        "arguments_digest": ARGUMENTS_DIGEST,
        "config_digest": CONFIG_DIGEST,
        "resource_profile": "cpu-small",
        "runtime_profile": "confidential-cpu-v1",
        "artifact_digests": (ARTIFACT_A,),
        "disk_gib": 20,
        "network_policy": "public",
        "network_allowlist": (),
        "dind_enabled": False,
    }
    values.update(overrides)
    return WorkloadRequest(**values)


def _verdict() -> SignatureVerdict:
    return SignatureVerdict(
        image_reference=IMAGE,
        signer_identity=SIGNER,
        trust_root_id=ROOT,
        signature_digest=SIGNATURE_DIGEST,
    )


def test_workload_request_disk_gib_validation() -> None:
    # Valid disk sizes
    req5 = _request(disk_gib=5)
    assert req5.disk_gib == 5

    req100 = _request(disk_gib=100)
    assert req100.disk_gib == 100

    req1000 = _request(disk_gib=1000)
    assert req1000.disk_gib == 1000

    # Invalid disk sizes
    with pytest.raises(WorkloadAdmissionError, match="disk_gib"):
        _request(disk_gib=4)

    with pytest.raises(WorkloadAdmissionError, match="disk_gib"):
        _request(disk_gib=1001)

    with pytest.raises(WorkloadAdmissionError, match="disk_gib"):
        _request(disk_gib=True)

    with pytest.raises(WorkloadAdmissionError, match="disk_gib"):
        _request(disk_gib="50")  # type: ignore[arg-type]


def test_workload_request_network_policy_validation() -> None:
    # Valid policies
    req_pub = _request(network_policy="public")
    assert req_pub.network_policy == "public"

    req_none = _request(network_policy="none")
    assert req_none.network_policy == "none"

    req_allow = _request(
        network_policy="allowlist",
        network_allowlist=("api.cathedral.computer", "pypi.org", "10.0.0.0/8"),
    )
    assert req_allow.network_policy == "allowlist"
    assert req_allow.network_allowlist == ("api.cathedral.computer", "pypi.org", "10.0.0.0/8")

    # Invalid policy
    with pytest.raises(WorkloadAdmissionError, match="network_policy"):
        _request(network_policy="invalid_mode")

    # Invalid allowlist entries
    with pytest.raises(WorkloadAdmissionError, match="network_allowlist"):
        _request(network_allowlist=("",))

    with pytest.raises(WorkloadAdmissionError, match="network_allowlist"):
        _request(network_allowlist="not-a-tuple")  # type: ignore[arg-type]


def test_workload_request_dind_validation() -> None:
    req_dind = _request(dind_enabled=True)
    assert req_dind.dind_enabled is True

    req_nodind = _request(dind_enabled=False)
    assert req_nodind.dind_enabled is False

    with pytest.raises(WorkloadAdmissionError, match="dind_enabled"):
        _request(dind_enabled="yes")  # type: ignore[arg-type]


def test_workload_manifest_document_and_roundtrip() -> None:
    req = _request(
        disk_gib=50,
        network_policy="allowlist",
        network_allowlist=("api.cathedral.computer", "10.0.0.0/8"),
        dind_enabled=True,
    )
    controller = WorkloadAdmissionController(
        policy=_policy(),
        verifier=LocalSignatureVerifier(_verdict()),
        production_mode=False,
    )
    admitted = controller.development_bypass(req, reason="test Cathedral manifest fields")
    manifest = admitted.manifest

    assert manifest.disk_gib == 50
    assert manifest.network_policy == "allowlist"
    assert manifest.network_allowlist == ("api.cathedral.computer", "10.0.0.0/8")
    assert manifest.dind_enabled is True

    doc = manifest.document()
    assert doc["disk_gib"] == 50
    assert doc["network_policy"] == "allowlist"
    assert doc["network_allowlist"] == ["api.cathedral.computer", "10.0.0.0/8"]
    assert doc["dind_enabled"] is True

    # Roundtrip via provider contract parser
    parsed = parse_workload_manifest_document(doc)
    assert parsed.disk_gib == 50
    assert parsed.network_policy == "allowlist"
    assert parsed.network_allowlist == ("api.cathedral.computer", "10.0.0.0/8")
    assert parsed.dind_enabled is True


def test_recording_adapter_network_policy_update() -> None:
    adapter = RecordingExecutionAdapter()
    exec_id = "execution-" + "a" * 64

    res = adapter.update_network_policy(
        exec_id, policy="allowlist", allowlist=("pypi.org", "api.cathedral.computer")
    )
    assert res["status"] == "applied"
    assert res["policy"] == "allowlist"
    assert res["allowlist"] == ["pypi.org", "api.cathedral.computer"]
    assert adapter.network_policies[exec_id] == res

    with pytest.raises(WorkloadAdmissionError, match="policy must be"):
        adapter.update_network_policy(exec_id, policy="invalid")


def test_recording_adapter_port_exposure() -> None:
    adapter = RecordingExecutionAdapter()
    exec_id = "execution-" + "b" * 64

    res = adapter.expose_port(exec_id, port=8080)
    assert res["status"] == "exposed"
    assert res["port"] == 8080
    assert f"{exec_id}-8080.cathedral.computer" in str(res["url"])
    assert len(adapter.exposed_ports[exec_id]) == 1

    with pytest.raises(ValueError, match="port must be"):
        adapter.expose_port(exec_id, port=0)

    with pytest.raises(ValueError, match="port must be"):
        adapter.expose_port(exec_id, port=70000)


def test_recording_adapter_interactive_process() -> None:
    adapter = RecordingExecutionAdapter()
    exec_id = "execution-" + "c" * 64

    res = adapter.open_process(exec_id, process_id="proc-123")
    assert res["status"] == "ready"
    assert res["process_id"] == "proc-123"
    assert f"/sandboxes/{exec_id}/processes/proc-123/attach" in str(res["websocket_url"])


def test_controller_helpers() -> None:
    controller = WorkloadAdmissionController(
        policy=_policy(),
        verifier=LocalSignatureVerifier(_verdict()),
        production_mode=False,
    )
    req = _request(disk_gib=25)
    admitted = controller.development_bypass(req, reason="test controller helpers")
    adapter = RecordingExecutionAdapter()
    exec_id = "execution-" + "d" * 64

    # Network policy helper
    net_res = controller.update_network_policy(
        admitted, adapter, execution_id=exec_id, policy="none"
    )
    assert net_res["policy"] == "none"

    # Port expose helper
    port_res = controller.expose_port(admitted, adapter, execution_id=exec_id, port=3000)
    assert port_res["port"] == 3000

    # Interactive process attach helper
    proc_res = controller.open_process(
        admitted, adapter, execution_id=exec_id, process_id="pid-1"
    )
    assert proc_res["process_id"] == "pid-1"

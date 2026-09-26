"""G4 evidence from an explicitly trusted guest operator, not CPU attestation.

The operator must retain guest/root and provisioning control. Its endorsement
binds a per-instance worker key to the cloud instance and TLS key. Distributing
that private key to a miner invalidates this trust model. NVIDIA verification is
performed locally by that trusted controller; signatures do not turn its log
into independently replayable vendor evidence. Private customer work is denied.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess
import threading
import time
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from cathedral.common import ChannelBinding, ChannelBindingType
from cathedral.gpu import gpu_identity_policy_digest
from cathedral.gpu_work import CudaWorkExecutor, GpuWorkError, canonical, completion_nonce

G4_WORKER_PROFILE_ID = "gcp-g4-rtx-pro-6000-sev-v1"
G4_BUNDLE_PROFILE_ID = "gcp-g4-rtx-pro-6000-8gpu-v1"
PROVIDER_EVIDENCE_SCHEMA = "cathedral_gpu_provider_evidence_v1"
ENDORSEMENT_SCHEMA = "cathedral_g4_operator_endorsement_v1"
STATEMENT_SCHEMA = "cathedral_g4_worker_statement_v1"
TRUST_MODEL = "approved_operator_guest_cpu_unattested"
MODEL = "NVIDIA RTX PRO 6000 Blackwell Server Edition"
VERIFIER = "nv-local-gpu-verifier"
VERIFIER_VERSION = "2.7.3"
VERIFIER_PYTHON = "/opt/cathedral/nv-verifier/bin/python"
MAX_LOG_BYTES = 65536
MAX_EVIDENCE_BYTES = 131072
MAX_ENDORSEMENT_SECONDS = 86400
MAX_STATEMENT_SECONDS = 300
LOCAL_CHECK_SECONDS = 45
_HEX = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_INSTANCE = re.compile(r"projects/[1-9][0-9]{0,19}/zones/[a-z][a-z0-9-]{1,62}/instances/[1-9][0-9]{0,19}")
_CLAIM_FIELDS = frozenset({"schema", "profile_id", "provider_instance_id", "hotkey",
    "machine_type", "provisioning_model", "confidential_compute_type", "cpu_attestation",
    "guest_control", "private_customer_work", "image_digest", "worker_public_key_hex",
    "tls_spki_sha256", "gpu_uuid", "issued_at", "expires_at"})
_STATEMENT_FIELDS = frozenset({"schema", "endorsement_digest", "nonce_hex", "hotkey",
    "tls_spki_sha256", "issued_at", "gpu_uuid", "gpu_model", "cc_mode", "ready_state",
    "verifier", "verifier_version", "verifier_log_b64", "verifier_log_digest"})


def _require(condition, message):
    if not condition:
        raise GpuWorkError(message)


def _digest(value):
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _public_bytes(key):
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _signed_bytes(domain, value):
    return domain.encode("ascii") + b"\0" + canonical(value)


def _verify_signature(key, signature, domain, value):
    _require(isinstance(signature, str) and len(signature) == 128, "invalid G4 signature")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(
            bytes.fromhex(signature), _signed_bytes(domain, value))
    except Exception as exc:
        raise GpuWorkError("G4 signature verification failed") from exc


def validate_endorsement_claims(claims, now=None):
    now = int(time.time()) if now is None else now
    _require(isinstance(claims, dict) and set(claims) == _CLAIM_FIELDS,
             "invalid G4 endorsement claims")
    expected = {"schema": ENDORSEMENT_SCHEMA, "profile_id": G4_WORKER_PROFILE_ID,
                "machine_type": "g4-standard-48", "provisioning_model": "SPOT",
                "confidential_compute_type": "SEV", "cpu_attestation": "unattested",
                "guest_control": "approved_operator"}
    _require(all(claims[k] == v for k, v in expected.items())
             and claims["private_customer_work"] is False, "unsupported G4 trust profile")
    _require(isinstance(claims["provider_instance_id"], str)
             and _INSTANCE.fullmatch(claims["provider_instance_id"]), "invalid cloud instance identity")
    _require(isinstance(claims["hotkey"], str) and 1 <= len(claims["hotkey"]) <= 256
             and claims["hotkey"].isascii(), "invalid G4 hotkey")
    for field in ("worker_public_key_hex", "tls_spki_sha256"):
        _require(isinstance(claims[field], str) and _HEX.fullmatch(claims[field]),
                 "invalid G4 key binding")
    _require(isinstance(claims["image_digest"], str)
             and _DIGEST.fullmatch(claims["image_digest"]), "invalid G4 image digest")
    gpu_identity_policy_digest(claims["gpu_uuid"])
    issued, expires = claims["issued_at"], claims["expires_at"]
    _require(type(issued) is int and type(expires) is int
             and issued <= now < expires and 0 < expires - issued <= MAX_ENDORSEMENT_SECONDS,
             "G4 endorsement expired or invalid")
    return claims


def sign_endorsement(claims, operator_key_id, operator_key):
    """Call only after operator provisioning/custody checks; never auto-endorse metadata."""
    validate_endorsement_claims(claims)
    _require(isinstance(operator_key_id, str) and 1 <= len(operator_key_id) <= 128,
             "invalid operator key id")
    return {"claims": claims, "operator_key_id": operator_key_id,
            "signature_hex": operator_key.sign(_signed_bytes(ENDORSEMENT_SCHEMA, claims)).hex()}


def verify_endorsement(endorsement, trusted_operators, now=None):
    _require(isinstance(endorsement, dict)
             and set(endorsement) == {"claims", "operator_key_id", "signature_hex"},
             "invalid G4 endorsement")
    key_id = endorsement["operator_key_id"]
    _require(isinstance(key_id, str) and key_id in trusted_operators, "untrusted G4 operator")
    _verify_signature(trusted_operators[key_id], endorsement["signature_hex"],
                      ENDORSEMENT_SCHEMA, endorsement["claims"])
    return validate_endorsement_claims(endorsement["claims"], now)


def verify_provider_evidence(document, nonce, hotkey, binding, *, trusted_operators, now=None):
    """Verify explicit operator trust; do not call this hardware CPU attestation."""
    now = int(time.time()) if now is None else now
    _require(isinstance(document, dict)
             and set(document) == {"endorsement", "statement", "signature_hex"}
             and len(canonical(document)) <= MAX_EVIDENCE_BYTES, "invalid G4 evidence")
    claims = verify_endorsement(document["endorsement"], trusted_operators, now)
    _require(isinstance(binding, ChannelBinding)
             and binding.binding_type is ChannelBindingType.TLS_SPKI_SHA256,
             "G4 requires TLS SPKI binding")
    _require(isinstance(nonce, bytes) and len(nonce) == 32, "invalid G4 evidence nonce")
    _require(claims["hotkey"] == hotkey and claims["tls_spki_sha256"] == binding.digest.hex(),
             "G4 endorsement hotkey or TLS mismatch")
    statement = document["statement"]
    _require(isinstance(statement, dict) and set(statement) == _STATEMENT_FIELDS,
             "invalid G4 worker statement")
    _verify_signature(bytes.fromhex(claims["worker_public_key_hex"]), document["signature_hex"],
                      STATEMENT_SCHEMA, statement)
    _require(statement["schema"] == STATEMENT_SCHEMA
             and statement["endorsement_digest"] == _digest(document["endorsement"])
             and statement["nonce_hex"] == nonce.hex() and statement["hotkey"] == hotkey
             and statement["tls_spki_sha256"] == binding.digest.hex()
             and statement["gpu_uuid"] == claims["gpu_uuid"], "G4 statement binding mismatch")
    _require(type(statement["issued_at"]) is int
             and claims["issued_at"] <= statement["issued_at"] <= now
             and now - statement["issued_at"] <= MAX_STATEMENT_SECONDS,
             "G4 statement is stale")
    _require(statement["gpu_model"] == MODEL and statement["cc_mode"] == "ON"
             and statement["ready_state"] == "ready" and statement["verifier"] == VERIFIER
             and statement["verifier_version"] == VERIFIER_VERSION,
             "G4 NVIDIA verification posture differs")
    log = statement["verifier_log_b64"]
    _require(isinstance(log, str) and len(log) <= 4 * ((MAX_LOG_BYTES + 2) // 3),
             "G4 verifier transcript too large")
    try:
        raw = base64.b64decode(log, validate=True)
    except Exception as exc:
        raise GpuWorkError("invalid G4 verifier transcript") from exc
    _require(0 < len(raw) <= MAX_LOG_BYTES
             and "sha256:" + hashlib.sha256(raw).hexdigest() == statement["verifier_log_digest"]
             and b"GPU Attestation is Successful." in raw, "G4 verifier transcript mismatch")
    instance = claims["provider_instance_id"]
    return {"device_identity_digests": (gpu_identity_policy_digest(claims["gpu_uuid"]),),
            "provider_instance_id": instance, "machine_id": _digest({"gcp_instance": instance}),
            "worker_key_digest": "sha256:" + hashlib.sha256(
                b"cathedral-g4-worker-key-v1\0" + bytes.fromhex(claims["worker_public_key_hex"])).hexdigest(),
            "component_digest": _digest(document), "trust_model": TRUST_MODEL,
            "cpu_attestation": "unattested", "private_customer_work": False}


class G4ProviderVerifier:
    def __init__(self, trusted_operators):
        _require(isinstance(trusted_operators, dict) and 1 <= len(trusted_operators) <= 32
                 and all(isinstance(k, str) and 1 <= len(k) <= 128
                         and isinstance(v, bytes) and len(v) == 32
                         for k, v in trusted_operators.items()), "invalid G4 trusted operators")
        self.trusted_operators = dict(trusted_operators)
        self.registry_digest = _digest({k: v.hex() for k, v in trusted_operators.items()})
        self.profiles = {G4_WORKER_PROFILE_ID: SimpleNamespace(
            profile_id=G4_WORKER_PROFILE_ID, expected_device_identity_digests=(),
            allowed_models=(MODEL,))}

    def verify(self, document, nonce, hotkey, binding, profile_id):
        _require(profile_id == G4_WORKER_PROFILE_ID, "unsupported provider profile")
        channel = ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, binding)
        return verify_provider_evidence(document, nonce, hotkey, channel,
                                        trusted_operators=self.trusted_operators)


def _local_nvidia_checks(nonce, expected_uuid):
    """Pinned NVIDIA verifier, one device, CC ON and Ready. No CPU quote is invented."""
    deadline = time.monotonic() + LOCAL_CHECK_SECONDS
    def run(arguments):
        remaining = deadline - time.monotonic()
        _require(remaining > 0, "NVIDIA verification timed out")
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=remaining, check=False, cwd="/",
                                env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        _require(result.returncode == 0 and len(result.stdout) <= MAX_LOG_BYTES,
                 "NVIDIA verification command failed")
        return result.stdout
    version = run([VERIFIER_PYTHON, "-c", "from importlib.metadata import version; "
                   "print(version('nv-local-gpu-verifier'))"])
    _require(version.strip() == VERIFIER_VERSION.encode(), "NVIDIA verifier version mismatch")
    status = run(["/usr/bin/nvidia-smi", "conf-compute", "-f"])
    _require(b"CC status: ON" in status, "GPU confidential compute is not ON")
    transcript = run([VERIFIER_PYTHON, "-m", "verifier.cc_admin", "--nonce", nonce.hex()])
    _require(b"GPU Attestation is Successful." in transcript, "NVIDIA attestation failed")
    run(["/usr/bin/nvidia-smi", "conf-compute", "-srs", "1"])
    ready = run(["/usr/bin/nvidia-smi", "conf-compute", "-grs"])
    _require(b"Ready state: ready" in ready, "GPU is not ready")
    query = run(["/usr/bin/nvidia-smi", "--query-gpu=name,uuid", "--format=csv,noheader,nounits"])
    rows = query.decode("ascii").strip().splitlines()
    _require(len(rows) == 1 and [v.strip() for v in rows[0].split(",")] == [MODEL, expected_uuid],
             "G4 requires its exact single GPU")
    return transcript


class G4ProviderCollector:
    """Run only inside an approved operator-controlled G4 guest."""
    def __init__(self, endorsement, private_key, trusted_operators, hotkey, binding):
        self.endorsement = endorsement
        self.private_key = private_key
        self.trusted_operators = dict(trusted_operators)
        self.hotkey, self.binding = hotkey, binding
        self._slot = threading.Lock()
        claims = verify_endorsement(endorsement, trusted_operators)
        _require(claims["hotkey"] == hotkey and claims["tls_spki_sha256"] == binding.digest.hex()
                 and claims["worker_public_key_hex"] == _public_bytes(private_key.public_key()).hex(),
                 "G4 local key, hotkey or TLS differs from endorsement")
        self.gpu_uuid = claims["gpu_uuid"]

    @classmethod
    def from_files(cls, endorsement_path, private_key_path, operator_keys_path, hotkey, binding):
        def read(path, limit):
            with Path(path).open("rb") as stream:
                value = stream.read(limit + 1)
            _require(len(value) <= limit, "G4 configuration too large")
            return value
        key_file = Path(private_key_path)
        _require(key_file.stat().st_mode & 0o077 == 0, "G4 private key must be owner-only")
        key = serialization.load_pem_private_key(read(key_file, 4096), password=None)
        _require(isinstance(key, Ed25519PrivateKey), "G4 worker key must be Ed25519")
        keys = json.loads(read(operator_keys_path, 16384))
        _require(isinstance(keys, dict), "G4 operator keys must be a map")
        trusted = {k: bytes.fromhex(v) for k, v in keys.items()}
        G4ProviderVerifier(trusted)
        return cls(json.loads(read(endorsement_path, 16384)), key, trusted, hotkey, binding)

    def _collect(self, nonce):
        verify_endorsement(self.endorsement, self.trusted_operators)
        transcript = _local_nvidia_checks(nonce, self.gpu_uuid)
        statement = {"schema": STATEMENT_SCHEMA, "endorsement_digest": _digest(self.endorsement),
                     "nonce_hex": nonce.hex(), "hotkey": self.hotkey,
                     "tls_spki_sha256": self.binding.digest.hex(), "issued_at": int(time.time()),
                     "gpu_uuid": self.gpu_uuid, "gpu_model": MODEL, "cc_mode": "ON",
                     "ready_state": "ready", "verifier": VERIFIER,
                     "verifier_version": VERIFIER_VERSION,
                     "verifier_log_b64": base64.b64encode(transcript).decode("ascii"),
                     "verifier_log_digest": "sha256:" + hashlib.sha256(transcript).hexdigest()}
        document = {"endorsement": self.endorsement, "statement": statement,
                    "signature_hex": self.private_key.sign(
                        _signed_bytes(STATEMENT_SCHEMA, statement)).hex()}
        verify_provider_evidence(document, nonce, self.hotkey, self.binding,
                                 trusted_operators=self.trusted_operators)
        return document

    def __call__(self, nonce, hotkey, *, channel_binding, report_data_version):
        _require(hotkey == self.hotkey and channel_binding == self.binding
                 and report_data_version == 2, "G4 collection binding mismatch")
        _require(self._slot.acquire(blocking=False), "G4 worker busy")
        try:
            return self._collect(nonce)
        finally:
            self._slot.release()

    def execute(self, executor, request):
        _require(isinstance(executor, CudaWorkExecutor)
                 and executor.profile_id == G4_WORKER_PROFILE_ID
                 and executor.device_identity_digests == (gpu_identity_policy_digest(self.gpu_uuid),),
                 "G4 executor differs from endorsed device")
        _require(self._slot.acquire(blocking=False), "G4 worker busy")
        try:
            # NVIDIA verification and Ready precede actual CUDA execution.
            self._collect(bytes.fromhex(request["nonce"]))
            output = executor.execute(request)
            return output, self._collect(completion_nonce(request, output))
        finally:
            self._slot.release()


def cpu_evidence_unavailable(*_args, **_kwargs):
    raise GpuWorkError("G4 plain SEV has no guest CPU attestation; provider trust is GPU-only")

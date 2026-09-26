"""Hardware-free command and per-worker size acceptance; no provider admission."""
import subprocess

import pytest

from cathedral.gpu_provider import MODEL, VERIFIER_PYTHON, _local_nvidia_checks
from cathedral.gpu_work import (CudaWorkExecutor, G4_BUNDLE_PROFILE_ID,
                                G4_WORKER_PROFILE_ID, GpuWorkError)

UUID = "GPU-11111111-1111-4111-8111-111111111111"
SECOND_UUID = "GPU-22222222-2222-4222-8222-222222222222"


def test_g4_is_one_gpu_per_worker_never_one_eight_gpu_confidential_vm():
    assert len(CudaWorkExecutor(G4_WORKER_PROFILE_ID, (UUID,)).device_identity_digests) == 1
    with pytest.raises(GpuWorkError, match="one device"):
        CudaWorkExecutor(G4_WORKER_PROFILE_ID, (UUID, SECOND_UUID))
    with pytest.raises(GpuWorkError, match="eight workers"):
        CudaWorkExecutor(G4_BUNDLE_PROFILE_ID, (UUID,))


def outputs():
    return [b"2.7.3\n", b"CC status: ON\n", b"GPU Attestation is Successful.\n",
            b"", b"Ready state: ready\n", f"{MODEL}, {UUID}\n".encode()]


def test_g4_local_verifier_uses_pinned_binary_fresh_nonce_and_exact_device(monkeypatch):
    values, calls = iter(outputs()), []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, next(values))
    monkeypatch.setattr(subprocess, "run", run)
    nonce = bytes.fromhex("ab" * 32)
    transcript = _local_nvidia_checks(nonce, UUID)
    assert b"GPU Attestation is Successful." in transcript
    assert calls[2][0] == [VERIFIER_PYTHON, "-m", "verifier.cc_admin", "--nonce", nonce.hex()]
    assert all(0 < kw["timeout"] <= 45 and "LD_PRELOAD" not in kw["env"] for _, kw in calls)
    assert calls[3][0][-2:] == ["-srs", "1"]


@pytest.mark.parametrize("index,replacement", [
    (0, b"2.7.2\n"), (1, b"CC status: OFF\n"), (2, b"attestation failed\n"),
    (4, b"Ready state: not ready\n"), (5, f"{MODEL}, {SECOND_UUID}\n".encode()),
    (5, (f"{MODEL}, {UUID}\n" * 2).encode()),
])
def test_g4_bad_version_mode_verification_readiness_or_device_fails_closed(monkeypatch, index, replacement):
    sequence = outputs()
    sequence[index] = replacement
    values = iter(sequence)
    monkeypatch.setattr(subprocess, "run", lambda args, **_k: subprocess.CompletedProcess(args, 0, next(values)))
    with pytest.raises(GpuWorkError):
        _local_nvidia_checks(b"a" * 32, UUID)


def test_g4_missing_verifier_or_timeout_never_returns_success(monkeypatch):
    for error in (FileNotFoundError(), subprocess.TimeoutExpired("verifier", 45)):
        def unavailable(*_a, **_k):
            raise error
        monkeypatch.setattr(subprocess, "run", unavailable)
        with pytest.raises(type(error)):
            _local_nvidia_checks(b"a" * 32, UUID)

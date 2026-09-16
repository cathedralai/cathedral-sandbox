"""Fixed CUDA work contract. Correct output alone is not attested GPU execution.

Admission must verify the measured worker and its composite device/session
evidence. This module supplies deterministic correctness and completion binding;
it never substitutes a software claim for vendor verification.
"""
from __future__ import annotations

import ctypes as C
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import threading
import uuid

from cathedral.common import ChannelBinding, Evidence, EvidenceKind
from cathedral.gpu import gpu_identity_policy_digest

WORK_SCHEMA = "cathedral_gpu_work_v1"
RESULT_SCHEMA = "cathedral_gpu_result_v1"
EVIDENCE_SCHEMA = "cathedral_gpu_evidence_v1"
WORKLOAD_ID = "cuda_i32_vector_v1"
ELEMENTS = 4096
MAX_DEVICES = 8
MAX_EXECUTION_SECONDS = 30
G4_WORKER_PROFILE_ID = "gcp-g4-rtx-pro-6000-sev-v1"
G4_BUNDLE_PROFILE_ID = "gcp-g4-rtx-pro-6000-8gpu-v1"
_HEX = re.compile(r"[0-9a-f]{64}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_PROFILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_FIELDS = frozenset({"schema", "challenge_id", "nonce", "assigned_hotkey", "profile_id",
                     "device_identity_digests", "seed", "elements", "workload_id"})


class GpuWorkError(ValueError):
    """An invalid request or unavailable GPU never produces a successful result."""


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def challenge_id(request: dict[str, object]) -> str:
    return hashlib.sha256(b"cathedral-gpu-work-v1\0" + canonical(
        {k: v for k, v in request.items() if k != "challenge_id"}
    )).hexdigest()


def validate_request(request: object) -> dict[str, object]:
    if not isinstance(request, dict) or set(request) != _FIELDS:
        raise GpuWorkError("invalid GPU work schema")
    if request["schema"] != WORK_SCHEMA or request["workload_id"] != WORKLOAD_ID:
        raise GpuWorkError("unsupported GPU workload")
    if type(request["elements"]) is not int or request["elements"] != ELEMENTS:
        raise GpuWorkError("invalid GPU work size")
    for name in ("nonce", "seed", "challenge_id"):
        if not isinstance(request[name], str) or not _HEX.fullmatch(request[name]):
            raise GpuWorkError(f"invalid GPU {name}")
    hotkey, profile = request["assigned_hotkey"], request["profile_id"]
    if not isinstance(hotkey, str) or not 1 <= len(hotkey) <= 256 or not hotkey.isascii():
        raise GpuWorkError("invalid GPU hotkey")
    if not isinstance(profile, str) or not _PROFILE.fullmatch(profile):
        raise GpuWorkError("invalid GPU profile")
    identities = request["device_identity_digests"]
    if (not isinstance(identities, list) or not 1 <= len(identities) <= MAX_DEVICES
            or any(not isinstance(v, str) or not _DIGEST.fullmatch(v) for v in identities)
            or identities != sorted(set(identities))):
        raise GpuWorkError("invalid GPU device set")
    if profile == G4_BUNDLE_PROFILE_ID or (profile == G4_WORKER_PROFILE_ID and len(identities) != 1):
        raise GpuWorkError("G4 requires one device per worker; eight workers form a fleet")
    if request["challenge_id"] != challenge_id(request):
        raise GpuWorkError("GPU challenge digest mismatch")
    return request


def vectors(seed: str) -> tuple[list[int], list[int]]:
    # Exact integer products avoid cross-driver floating-point differences.
    seed_bytes = bytes.fromhex(seed)
    words = [hashlib.sha256(b"cathedral-gpu-vector-v1\0" + seed_bytes
                           + struct.pack("<I", i)).digest() for i in range(ELEMENTS)]
    return ([int.from_bytes(v[:2], "little") & 32767 for v in words],
            [int.from_bytes(v[2:4], "little") & 32767 for v in words])


def expected_output_digest(request: dict[str, object]) -> str:
    validate_request(request)
    left, right = vectors(request["seed"])
    output = struct.pack("<" + "i" * ELEMENTS, *(a * b for a, b in zip(left, right)))
    return "sha256:" + hashlib.sha256(
        output * len(request["device_identity_digests"])
    ).hexdigest()


def request_digest(request: dict[str, object]) -> str:
    validate_request(request)
    return "sha256:" + hashlib.sha256(canonical(request)).hexdigest()


def completion_nonce(request: dict[str, object], output_digest: str) -> bytes:
    validate_request(request)
    if not isinstance(output_digest, str) or not _DIGEST.fullmatch(output_digest):
        raise GpuWorkError("invalid GPU output digest")
    return hashlib.sha256(b"cathedral-gpu-completion-v1\0" + canonical({
        "request": request, "output_digest": output_digest,
        "device_identity_digests": request["device_identity_digests"],
    })).digest()


def serialize_composite(evidences: object, nonce: bytes, hotkey: str,
                        binding: ChannelBinding) -> list[dict[str, object]]:
    from cathedral.worker import _evidence_fits_transport
    if (not isinstance(evidences, (tuple, list)) or len(evidences) != 2
            or any(not isinstance(e, Evidence) for e in evidences)
            or {e.kind for e in evidences} != {EvidenceKind.TDX, EvidenceKind.GPU_CC}):
        raise GpuWorkError("exact composite evidence required")
    if any(e.nonce != nonce or e.miner_hotkey != hotkey or e.report_data_version != 2
           or e.channel_binding != binding or not _evidence_fits_transport(e)
           for e in evidences):
        raise GpuWorkError("GPU evidence binding mismatch")
    return [{"kind": e.kind.value, "quote_hex": e.quote.hex(),
             "nonce_hex": nonce.hex(), "assigned_hotkey": hotkey,
             "cert_chain_hex": [c.hex() for c in e.cert_chain],
             "report_data_version": 2, "channel_binding_type": binding.binding_type.value,
             "channel_binding_digest_hex": binding.digest.hex(),
             "composite_jwt": e.composite_jwt} for e in evidences]


def parse_composite(items: object, nonce: bytes, hotkey: str,
                    binding: ChannelBinding) -> tuple[Evidence, Evidence]:
    """Parse the bounded existing wire grammar without relaxing CPU parsing."""
    from cathedral.remote import _evidence_from_response
    if not isinstance(items, list) or len(items) != 2 or any(
        not isinstance(item, dict) for item in items
    ):
        raise GpuWorkError("exact composite evidence required")
    evidences = tuple(_evidence_from_response(item, nonce, hotkey, binding, bundle_item=True)
                      for item in items)
    serialize_composite(evidences, nonce, hotkey, binding)
    return evidences


# PTX JIT is performed by the installed CUDA driver on each actual device.
_PTX = b""".version 7.0
.target sm_80
.address_size 64
.visible .entry multiply(.param .u64 a, .param .u64 b, .param .u64 out) {
 .reg .pred p;
 .reg .b32 r<8>;
 .reg .b64 rd<8>;
 ld.param.u64 rd1, [a]; ld.param.u64 rd2, [b]; ld.param.u64 rd3, [out];
 mov.u32 r1, %ctaid.x; mov.u32 r2, %ntid.x; mov.u32 r3, %tid.x;
 mad.lo.s32 r4, r1, r2, r3;
 setp.ge.u32 p, r4, 4096; @p bra done;
 mul.wide.u32 rd4, r4, 4;
 add.u64 rd5, rd1, rd4; add.u64 rd6, rd2, rd4; add.u64 rd7, rd3, rd4;
 ld.global.u32 r5, [rd5]; ld.global.u32 r6, [rd6];
 mul.lo.s32 r7, r5, r6; st.global.u32 [rd7], r7;
done: ret;
}
"""


def _cuda_execute(request: dict[str, object]) -> str:
    """Child-only CUDA driver path. Missing CUDA and every API error fail closed."""
    validate_request(request)
    if sys.platform != "linux":
        raise GpuWorkError("CUDA requires Linux")
    cuda = C.CDLL("libcuda.so.1")

    def call(name, *args):
        status = getattr(cuda, name)(*args)
        if status != 0:
            raise GpuWorkError(f"CUDA operation failed: {name}")

    call("cuInit", C.c_uint(0))
    count = C.c_int()
    call("cuDeviceGetCount", C.byref(count))
    if not 1 <= count.value <= MAX_DEVICES:
        raise GpuWorkError("unsupported CUDA device count")
    devices = {}
    for index in range(count.value):
        device, raw_uuid = C.c_int(), (C.c_ubyte * 16)()
        call("cuDeviceGet", C.byref(device), C.c_int(index))
        call("cuDeviceGetUuid_v2", C.byref(raw_uuid), device)
        identity = gpu_identity_policy_digest("GPU-" + str(uuid.UUID(bytes=bytes(raw_uuid))))
        if identity in devices:
            raise GpuWorkError("duplicate CUDA device identity")
        devices[identity] = device
    if sorted(devices) != request["device_identity_digests"]:
        raise GpuWorkError("CUDA devices differ from requested profile")
    left, right = vectors(request["seed"])
    buffers = [(C.c_int32 * ELEMENTS)(*v) for v in (left, right)]
    digest = hashlib.sha256()
    for identity in sorted(devices):
        context, module, function = C.c_void_p(), C.c_void_p(), C.c_void_p()
        allocations = []
        call("cuCtxCreate_v2", C.byref(context), C.c_uint(0), devices[identity])
        try:
            call("cuModuleLoadData", C.byref(module), C.c_char_p(_PTX))
            call("cuModuleGetFunction", C.byref(function), module, C.c_char_p(b"multiply"))
            for _ in range(3):
                ptr = C.c_uint64()
                call("cuMemAlloc_v2", C.byref(ptr), C.c_size_t(ELEMENTS * 4))
                allocations.append(ptr)
            for ptr, source in zip(allocations[:2], buffers):
                call("cuMemcpyHtoD_v2", ptr, C.cast(source, C.c_void_p),
                     C.c_size_t(ELEMENTS * 4))
            parameters = (C.c_void_p * 3)(*[C.cast(C.byref(p), C.c_void_p)
                                          for p in allocations])
            call("cuLaunchKernel", function, C.c_uint(ELEMENTS // 128), C.c_uint(1),
                 C.c_uint(1), C.c_uint(128), C.c_uint(1), C.c_uint(1), C.c_uint(0),
                 C.c_void_p(), parameters, C.c_void_p())
            call("cuCtxSynchronize")
            output = (C.c_int32 * ELEMENTS)()
            call("cuMemcpyDtoH_v2", C.cast(output, C.c_void_p), allocations[2],
                 C.c_size_t(ELEMENTS * 4))
            digest.update(struct.pack("<" + "i" * ELEMENTS, *output))
        finally:
            # Context destruction reclaims allocations if an earlier API failed.
            for ptr in allocations:
                cuda.cuMemFree_v2(ptr)
            if module.value:
                cuda.cuModuleUnload(module)
            cuda.cuCtxDestroy_v2(context)
    actual = "sha256:" + digest.hexdigest()
    if actual != expected_output_digest(request):
        raise GpuWorkError("CUDA result is incorrect")
    return actual


class CudaWorkExecutor:
    """One bounded GPU job at a time; child exit destroys its CUDA contexts."""
    def __init__(self, profile_id: str, device_uuids: tuple[str, ...]):
        if not isinstance(profile_id, str) or not _PROFILE.fullmatch(profile_id):
            raise GpuWorkError("invalid GPU profile")
        identities = tuple(sorted(gpu_identity_policy_digest(v) for v in device_uuids))
        if not 1 <= len(identities) <= MAX_DEVICES or len(set(identities)) != len(identities):
            raise GpuWorkError("invalid configured GPU set")
        if profile_id == G4_BUNDLE_PROFILE_ID or (profile_id == G4_WORKER_PROFILE_ID and len(identities) != 1):
            raise GpuWorkError("G4 requires one device per worker; eight workers form a fleet")
        self.profile_id = profile_id
        self.device_identity_digests = identities
        self._slot = threading.Lock()

    def capabilities(self) -> dict[str, object]:
        return {"schema": "cathedral_gpu_capability_v1", "profile_id": self.profile_id,
                "device_identity_digests": list(self.device_identity_digests),
                "workload_id": WORKLOAD_ID, "elements": ELEMENTS,
                "status": "registered", "verified": False}

    def execute(self, request: dict[str, object]) -> str:
        validate_request(request)
        if (request["profile_id"] != self.profile_id
                or tuple(request["device_identity_digests"]) != self.device_identity_digests):
            raise GpuWorkError("GPU request differs from configured profile")
        if not self._slot.acquire(blocking=False):
            raise GpuWorkError("GPU worker busy")
        try:
            # Never inherit miner credentials, dynamic-library injection, or CUDA
            # visibility overrides. Source and driver belong to measured image.
            result = subprocess.run(
                [sys.executable, "-m", "cathedral.gpu_work"], input=canonical(request),
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=MAX_EXECUTION_SECONDS,
                cwd="/", env={"PATH": "/usr/bin:/bin", "LANG": "C",
                              "PYTHONPATH": str(Path(__file__).resolve().parent.parent)},
                check=False,
            )
            if result.returncode != 0 or len(result.stdout) > 128:
                raise GpuWorkError("CUDA execution unavailable")
            actual = result.stdout.decode("ascii").strip()
            if actual != expected_output_digest(request):
                raise GpuWorkError("CUDA output mismatch")
            return actual
        except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
            raise GpuWorkError("CUDA execution failed or timed out") from exc
        finally:
            self._slot.release()


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise GpuWorkError("GPU work request too large")
        print(_cuda_execute(json.loads(raw)))
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

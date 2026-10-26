"""Pinned Affine verify artifacts — production digests, not always-PASS mocks.

A pin is the exact verify code + inputs bytes Affine validators would re-run.
Cathedral hashes those bytes into ``cathedral_affine_claim_v1`` digests.
"""

from __future__ import annotations

import importlib.util
import json
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from cathedral.affine_claim import (
    AffineClaimError,
    canonical_affine_claim_json,
    digest_affine_verify_bundle,
    run_tiny_affine_verify,
    sha256_hex,
)


@dataclass(frozen=True)
class AffineVerifyPin:
    """Content-addressed Affine verify artifact."""

    verify_code: bytes
    verify_inputs: bytes
    source: str
    entrypoint: str = "verify"

    @property
    def code_sha256(self) -> str:
        return sha256_hex(self.verify_code)

    @property
    def inputs_sha256(self) -> str:
        return sha256_hex(self.verify_inputs)

    def digests_for(self, *, miner_payload: bytes, verify_result: bytes) -> dict[str, str]:
        return digest_affine_verify_bundle(
            verify_code=self.verify_code,
            verify_inputs=self.verify_inputs,
            miner_payload=miner_payload,
            verify_result=verify_result,
        )

    def run(self, miner_payload: bytes) -> bytes:
        """Execute the pinned verify artifact; returns canonical result JSON bytes."""

        if self.source == "tiny_builtin":
            return run_tiny_affine_verify(miner_payload=miner_payload)
        if self.source.startswith("module:"):
            return _run_module_entrypoint(
                self.verify_code,
                entrypoint=self.entrypoint,
                miner_payload=miner_payload,
                verify_inputs=self.verify_inputs,
            )
        raise AffineClaimError("policy", f"unsupported verify pin source {self.source!r}")


def load_verify_pin_from_paths(
    *,
    verify_code_path: Path,
    verify_inputs_path: Path,
    entrypoint: str = "verify",
) -> AffineVerifyPin:
    code = verify_code_path.read_bytes()
    inputs = verify_inputs_path.read_bytes()
    if not code:
        raise AffineClaimError("schema", "verify code file is empty")
    # Validate inputs are JSON object for production pins.
    try:
        parsed = json.loads(inputs.decode("utf-8"))
    except Exception as exc:
        raise AffineClaimError("schema", "verify inputs must be UTF-8 JSON") from exc
    if not isinstance(parsed, dict):
        raise AffineClaimError("schema", "verify inputs must be a JSON object")
    return AffineVerifyPin(
        verify_code=code,
        verify_inputs=canonical_affine_claim_json(parsed),
        source=f"module:{verify_code_path.name}",
        entrypoint=entrypoint,
    )


def tiny_builtin_pin() -> AffineVerifyPin:
    """CI pin — real logic, not always-PASS; not Affine production code."""

    from cathedral import affine_claim as mod

    code = Path(mod.__file__).read_bytes()
    inputs = canonical_affine_claim_json({"task": "tiny-affine-v1", "prefix": "AFFINE"})
    return AffineVerifyPin(
        verify_code=code,
        verify_inputs=inputs,
        source="tiny_builtin",
        entrypoint="run_tiny_affine_verify",
    )


def _load_module_from_bytes(code: bytes, *, name: str = "affine_verify_pin_mod") -> ModuleType:
    path = f"<affine_verify_pin:{sha256_hex(code)[:12]}>"
    spec = importlib.util.spec_from_loader(name, loader=None)
    if spec is None:
        raise AffineClaimError("policy", "unable to build module spec for verify pin")
    module = importlib.util.module_from_spec(spec)
    compiled = compile(code, path, "exec")
    exec(compiled, module.__dict__)  # noqa: S102 — pinned bytes only; caller trusts the pin
    return module


def _run_module_entrypoint(
    code: bytes,
    *,
    entrypoint: str,
    miner_payload: bytes,
    verify_inputs: bytes,
) -> bytes:
    module = _load_module_from_bytes(code)
    fn = getattr(module, entrypoint, None)
    if not callable(fn):
        raise AffineClaimError("policy", f"verify pin missing entrypoint {entrypoint!r}")
    inputs = json.loads(verify_inputs.decode("ascii"))
    result = fn(miner_payload, inputs)
    if isinstance(result, (bytes, bytearray)):
        raw = bytes(result)
        # Must be canonical JSON object.
        parsed = json.loads(raw.decode("ascii"))
        if not isinstance(parsed, dict):
            raise AffineClaimError("schema", "verify entrypoint bytes must be a JSON object")
        return canonical_affine_claim_json(parsed)
    if isinstance(result, dict):
        if "passed" not in result:
            raise AffineClaimError("schema", "verify result must include boolean passed")
        return canonical_affine_claim_json(result)
    raise AffineClaimError("schema", "verify entrypoint must return dict or JSON bytes")

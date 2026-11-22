"""AB#825: the unmounted shred request handler (cathedral/volume_shred.py)."""
from __future__ import annotations

import json
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cathedral import volume_chain as vc
from cathedral import volume_log as vl
from cathedral import volume_shred as vs

T0 = 1_800_000_000
SECRET = "kms says arn:aws:kms:eu-west-1:123:key/abc is busy"


def binding(key: Ed25519PrivateKey) -> dict:
    return {"schema": vc.SEALED_BINDING_SCHEMA, "hotel": "hotel-a", "boot_id": "b1",
            "receipt_key_ed25519_b64": vc.public_b64(key), "measurement": "aa" * 48}


class KeyService:
    def __init__(self, result=True, error: Exception | None = None):
        self.calls: list[str] = []
        self.result = result
        self.error = error

    def __call__(self, volume_id: str, key_id: str):
        self.calls.append(key_id)
        if self.error is not None:
            raise self.error
        return self.result


class UntouchedRegistry:
    """Fails the test if the handler reaches the registry."""

    def __getattr__(self, name):
        raise AssertionError(f"registry.{name} touched")


@pytest.fixture
def registry():
    registry = vc.VolumeRegistry(Ed25519PrivateKey.generate(), now=lambda: T0, lease_seconds=600)
    registry.create("vol-1", "customer-1", key_id="vk:vol-1")
    holder = Ed25519PrivateKey.generate()
    lease = registry.grant("vol-1", binding(holder))
    head = registry.head("vol-1")["statement"]
    commit = vc.make_commit(holder, lease, generation=1, parent_sha256=head["head_sha256"],
                            restic_repo_id="repo-1", restic_snapshot_id="s1")
    registry.accept(commit)
    registry.commit = commit  # for the restore check
    return registry


def body(volume_id="vol-1", key_id="vk:vol-1", **extra) -> dict:
    return {"schema": vs.REQUEST_SCHEMA, "key_id": key_id, "confirm_volume_id": volume_id, **extra}


DEFAULT = object()


def call(registry, *, enabled=True, caller_owner="customer-1", volume_id="vol-1", request=DEFAULT,
         destroy_key=None, **kw):
    return vs.handle_shred(registry, enabled=enabled, caller_owner=caller_owner, volume_id=volume_id,
                           body=body(volume_id) if request is DEFAULT else request,
                           destroy_key=KeyService() if destroy_key is None else destroy_key, **kw)


def refusal(status: int, code: str, retryable: bool):
    return status, {"status": "refused", "code": code, "retryable": retryable}


def test_disabled_route_is_404_and_never_touches_the_registry():
    keys = KeyService()
    assert call(UntouchedRegistry(), enabled=False, destroy_key=keys) == refusal(404, "not_found", False)
    assert call(UntouchedRegistry(), enabled=None, caller_owner=None, request="x", destroy_key=keys) == \
        refusal(404, "not_found", False)
    assert keys.calls == []


@pytest.mark.parametrize("owner", [None, "", 7])
def test_missing_caller_is_401(owner):
    assert call(UntouchedRegistry(), caller_owner=owner, request="not a body") == \
        refusal(401, "unauthenticated", False)


@pytest.mark.parametrize("volume_id, request_body", [
    ("vol-1", body(extra_field=1)),
    ("vol-1", {"schema": vs.REQUEST_SCHEMA, "key_id": "vk:vol-1"}),
    ("vol-1", body() | {"schema": "cathedral_volume_shred_request_v2"}),
    ("vol-1", body(volume_id="vol-2") | {"key_id": "vk:vol-1"}),
    ("vol-1", body(key_id="k/1")),
    ("vol-1", body(key_id=None)),
    ("vol-1", body(key_id="")),
    ("vol-1", None),
    ("vol-1", [body()]),
    ("vol-1", json.dumps(body())),
    ("vol.1", body(volume_id="vol.1")),
    ("", body(volume_id="")),
    (None, body(volume_id=None)),
])
def test_bad_request_is_400_and_never_touches_the_registry(volume_id, request_body):
    keys = KeyService()
    assert call(UntouchedRegistry(), volume_id=volume_id, request=request_body, destroy_key=keys) == \
        refusal(400, "bad_request", False)
    assert keys.calls == []


def test_unknown_volume_and_wrong_owner_answer_the_same_bytes(registry):
    keys = KeyService()
    unknown = call(registry, volume_id="vol-9", destroy_key=keys)
    wrong_owner = call(registry, caller_owner="customer-2", destroy_key=keys)
    assert unknown == refusal(404, "volume_not_found", False)
    assert json.dumps(unknown, sort_keys=True).encode() == json.dumps(wrong_owner, sort_keys=True).encode()
    assert keys.calls == []


def test_happy_path_returns_a_verifiable_receipt_and_resends_are_identical(registry):
    keys = KeyService()
    status, answer = call(registry, destroy_key=keys)
    assert status == 200
    assert answer["status"] == "shredded"
    public = {registry.log_signing_key_id: registry.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)}
    vl.verify_shred_receipt(answer["receipt"], public_keys_by_id=public, entries=registry.log_entries())
    resend_keys = KeyService()
    again = call(registry, destroy_key=resend_keys)
    assert json.dumps(again, sort_keys=True) == json.dumps((status, answer), sort_keys=True)
    assert keys.calls == ["vk:vol-1"]
    assert resend_keys.calls == []
    # Another key id after the shred is gone for good.
    assert call(registry, request=body(key_id="vk:other")) == refusal(410, "volume_shredded", False)


def test_restore_after_a_handler_shred_is_refused(registry):
    assert call(registry)[0] == 200
    with pytest.raises(vl.VolumeLogError, match="volume_shredded"):
        vl.check_restore(registry.log_entries(), volume_id="vol-1", generation=1,
                         manifest_sha256=vc.manifest_sha256(registry.commit["statement"]))


@pytest.mark.parametrize("keys", [KeyService(error=RuntimeError(SECRET)), KeyService(result=SECRET)])
def test_key_service_refusal_is_502_retryable_and_hides_its_text(registry, keys):
    answer = call(registry, destroy_key=keys)
    assert answer == refusal(502, "key_not_destroyed", True)
    assert "kms" not in json.dumps(answer)
    assert call(registry)[0] == 200  # retry finishes


def test_timeout_is_504_and_in_progress_is_409_both_retryable(registry):
    release = threading.Event()

    def blocked(volume_id, key_id):
        release.wait(5)
        raise RuntimeError(SECRET)

    try:
        timeout = call(registry, destroy_key=blocked, timeout_seconds=0.1)
        assert timeout == refusal(504, "key_service_timeout", True)
        assert call(registry) == refusal(409, "shred_in_progress", True)
        assert "kms" not in json.dumps(timeout)
    finally:
        release.set()


def test_registry_conflicts_are_409_with_the_registry_code(registry):
    registry.create("vol-2", "customer-1")
    assert call(registry, volume_id="vol-2") == refusal(409, "nothing_to_shred", False)
    assert call(registry, request=body(key_id="vk:vol-2")) == refusal(409, "shred_key_mismatch", False)


def test_other_registry_refusals_are_500_internal(registry):
    assert call(registry, timeout_seconds=0) == refusal(500, "internal", True)

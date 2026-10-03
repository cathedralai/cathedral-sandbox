"""Ditto SN118 sandbox profile — additive; does not alter Affline §3.8 constants.

Operators size Ditto via ``CATHEDRAL_SANDBOX_KEYS`` / ``CATHEDRAL_KEY_QUOTAS`` only.
These helpers document and validate the 2–8 concurrent slot contract for tests
and docs. Affline ``MIN_RUNNING_SANDBOXES`` / ``customer_mvp_quota()`` stay untouched.
"""

from __future__ import annotations

DITTO_CUSTOMER_LABEL = "ditto"
DITTO_MIN_SLOTS = 2
DITTO_MAX_SLOTS = 8
DITTO_DEFAULT_SLOTS = 8
DITTO_DEFAULT_TTL_SECONDS = 600
DITTO_NETWORK_MODE = "none"


def ditto_key_env(
    *,
    key: str = "ditto-demo-key",
    project: str = "ditto",
    max_running: int = DITTO_DEFAULT_SLOTS,
) -> dict[str, str]:
    """Env fragment for a Ditto-shaped keyed boot (project key + small ceiling)."""
    if not DITTO_MIN_SLOTS <= max_running <= DITTO_MAX_SLOTS:
        raise ValueError(
            f"Ditto max_running must be in [{DITTO_MIN_SLOTS}, {DITTO_MAX_SLOTS}], got {max_running}"
        )
    return {
        "CATHEDRAL_SANDBOX_KEYS": f"{key}:{project}:{max_running}",
        "CATHEDRAL_KEY_QUOTAS": f"{key}:{max_running}",
        # Project ceiling for Ditto only — never Affline 500:1000:3000.
        "CATHEDRAL_SANDBOX_QUOTA": f"{max_running}:{max_running * 2}:{max_running * 8}",
    }


def ditto_create_labels(*, trial: str | None = None) -> dict[str, str]:
    labels = {"customer": DITTO_CUSTOMER_LABEL, "job": "ditto-harness"}
    if trial:
        labels["trial"] = trial
    return labels


def ditto_create_body(
    *,
    image: str = "python:3.12-alpine",
    ttl_seconds: int = DITTO_DEFAULT_TTL_SECONDS,
    trial: str | None = None,
    **over: object,
) -> dict[str, object]:
    """Canonical Ditto harness create payload (deny-all egress, short TTL)."""
    body: dict[str, object] = {
        "image": image,
        "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 10},
        "network": {"mode": DITTO_NETWORK_MODE, "allow": []},
        "labels": ditto_create_labels(trial=trial),
        "ttl_seconds": ttl_seconds,
        "entrypoint": ["sleep", "infinity"],
    }
    body.update(over)
    return body


__all__ = [
    "DITTO_CUSTOMER_LABEL",
    "DITTO_DEFAULT_SLOTS",
    "DITTO_DEFAULT_TTL_SECONDS",
    "DITTO_MAX_SLOTS",
    "DITTO_MIN_SLOTS",
    "DITTO_NETWORK_MODE",
    "ditto_create_body",
    "ditto_create_labels",
    "ditto_key_env",
]

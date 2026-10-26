"""Agent IDE sandbox profile — additive; does not alter Affline or Ditto defaults."""

from __future__ import annotations

AGENT_CUSTOMER_LABEL = "agent"
AGENT_DEFAULT_NETWORK_MODE = "public"
AGENT_DEFAULT_TTL_SECONDS = 3600


def agent_create_labels(*, trial: str | None = None) -> dict[str, str]:
    labels = {"customer": AGENT_CUSTOMER_LABEL, "job": "agent-ide"}
    if trial:
        labels["trial"] = trial
    return labels


def agent_create_body(
    *,
    image: str = "python:3.12-alpine",
    ttl_seconds: int = AGENT_DEFAULT_TTL_SECONDS,
    trial: str | None = None,
    **over: object,
) -> dict[str, object]:
    """Canonical Agent IDE create payload (public network; freeze/thaw enabled via API)."""
    body: dict[str, object] = {
        "image": image,
        "resources": {"vcpu": 1, "memory_gib": 2, "disk_gib": 10},
        "network": {"mode": AGENT_DEFAULT_NETWORK_MODE, "allow": []},
        "labels": agent_create_labels(trial=trial),
        "ttl_seconds": ttl_seconds,
        "entrypoint": ["sleep", "infinity"],
    }
    body.update(over)
    return body


__all__ = [
    "AGENT_CUSTOMER_LABEL",
    "AGENT_DEFAULT_NETWORK_MODE",
    "AGENT_DEFAULT_TTL_SECONDS",
    "agent_create_body",
    "agent_create_labels",
]

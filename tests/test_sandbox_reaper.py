"""Background reaper: TTL expiry must not depend on API traffic (defect 8)."""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from cathedral.sandbox_api import CreateSandboxRequest, ImageSource
from cathedral.sandbox_provider import InMemorySandboxProvider
from cathedral.sandbox_server import (
    REAPER_INTERVAL_DEFAULT_SECONDS,
    SandboxApplication,
    reaper_interval_from_env,
)


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_reaper_collects_expired_sandbox_without_requests() -> None:
    provider = InMemorySandboxProvider()
    app = SandboxApplication(provider)
    try:
        doc = provider.create(CreateSandboxRequest(image=ImageSource(image="alpine:3.20")), api_key="k", idempotency=None, body_digest="b")
        with provider._lock:  # noqa: SLF001
            provider._sandboxes[doc["id"]].expires_at = datetime.now(timezone.utc) - timedelta(hours=1)  # noqa: SLF001
        app.start_reaper(0.05)
        assert app.reaper_running
        # No list/get/quota call: only the reaper can collect it.
        assert _wait_for(lambda: doc["id"] not in provider._sandboxes)  # noqa: SLF001
    finally:
        app.stop_reaper()
        provider.close()
    assert not app.reaper_running


class _CountingProvider:
    def __init__(self, *, fail_first: bool = False) -> None:
        self.sweeps = 0
        self.marks = 0
        self.fail_first = fail_first
        self.lock = threading.Lock()

    def authorize(self, api_key):
        return None

    def sweep(self) -> int:
        with self.lock:
            self.sweeps += 1
            if self.fail_first and self.sweeps == 1:
                raise RuntimeError("docker daemon hiccup")
        return 0

    def mark_expired(self) -> int:
        self.marks += 1
        return 0

    def list(self, *, labels, state):
        return []


def test_reaper_survives_a_failing_sweep() -> None:
    provider = _CountingProvider(fail_first=True)
    app = SandboxApplication(provider)  # type: ignore[arg-type]
    try:
        app.start_reaper(0.02)
        assert _wait_for(lambda: provider.sweeps >= 3)
        assert app.reaper_running
    finally:
        app.stop_reaper()


def test_reads_only_mark_when_reaper_runs() -> None:
    provider = _CountingProvider()
    app = SandboxApplication(provider)  # type: ignore[arg-type]
    headers = {"Authorization": "Bearer k"}

    assert app.dispatch("GET", "/v1/sandboxes", headers, b"").status == 200
    assert (provider.sweeps, provider.marks) == (1, 0)  # no reaper: full sweep inline

    app.start_reaper(3600)
    try:
        assert app.dispatch("GET", "/v1/sandboxes", headers, b"").status == 200
        assert (provider.sweeps, provider.marks) == (1, 1)  # reaper: inline read only marks
    finally:
        app.stop_reaper()


def test_reaper_interval_zero_disables() -> None:
    app = SandboxApplication(_CountingProvider())  # type: ignore[arg-type]
    app.start_reaper(0)
    assert not app.reaper_running


@pytest.mark.parametrize(
    ("raw", "want"),
    [(None, REAPER_INTERVAL_DEFAULT_SECONDS), ("5", 5.0), ("0", 0.0), ("junk", REAPER_INTERVAL_DEFAULT_SECONDS), ("-3", 0.0)],
)
def test_reaper_interval_from_env(monkeypatch: pytest.MonkeyPatch, raw, want) -> None:
    if raw is None:
        monkeypatch.delenv("CATHEDRAL_SANDBOX_REAPER_SECONDS", raising=False)
    else:
        monkeypatch.setenv("CATHEDRAL_SANDBOX_REAPER_SECONDS", raw)
    assert reaper_interval_from_env() == want

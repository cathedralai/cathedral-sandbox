"""Broker binding archive helpers (AB#381).

The broker keeps each attested hotel binding under
``GET /v1/broker/bindings/<sha256>`` (operator key). Receipts from an earlier boot
name that sha256; verifiers resolve the binding document for signature checks.
The archive holds the binding JSON only (no SNP report or keys on disk).
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


class RedirectRefused(OSError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def _refuse(self, req, response, headers):
        try:
            location = headers.get("Location") or headers.get("URI")
            target = urllib.parse.urlsplit(urllib.parse.urljoin(req.full_url, location))
            if target.scheme not in ("http", "https") or not target.hostname:
                raise ValueError("unsupported redirect target")
            host, port = target.hostname, target.port
            if not re.fullmatch(r"[A-Za-z0-9.:-]+", host):
                raise ValueError("unsafe redirect host")
            message = f"redirect refused to {host}:{port}" if port is not None else f"redirect refused to {host}"
        except (TypeError, ValueError, UnicodeError):
            message = "redirect refused"
        finally:
            response.close()
        raise RedirectRefused(message)

    def http_error_301(self, req, response, code, message, headers):
        self._refuse(req, response, headers)

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def canonical(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def binding_digest(binding: dict) -> str:
    return hashlib.sha256(canonical(binding)).hexdigest()


def parse_archived_binding(raw: bytes, sha: str) -> dict:
    """The broker's archived bytes: JSON binding whose sha256 is ``sha``."""
    sha = sha.lower()
    if not SHA256_HEX.fullmatch(sha):
        raise ValueError("the binding id is not a 64-character SHA-256 hex digest")
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ValueError("archived bytes do not hash to the requested binding id")
    binding = json.loads(raw)
    if not isinstance(binding, dict):
        raise ValueError("archived binding is not a JSON object")
    if binding_digest(binding) != sha:
        raise ValueError("archived binding does not match its hash")
    return binding


def fetch_archived_binding(broker: str, sha: str, operator_key: str, *, opener=None) -> dict:
    """``GET /v1/broker/bindings/<sha>`` with the operator bearer key."""
    url = broker.rstrip("/") + "/v1/broker/bindings/" + sha.lower()
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + operator_key.strip()})
    open_fn = opener or urllib.request.build_opener(NoRedirect()).open
    try:
        with open_fn(req, timeout=60) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError(f"no archived binding with hash {sha[:16]}...") from exc
        raise ValueError(f"broker binding archive answered {exc.code}") from exc
    except RedirectRefused as exc:
        raise ValueError(str(exc)) from exc
    return parse_archived_binding(raw, sha)


def minimal_attestation(binding: dict, sha: str) -> dict:
    return {"binding": binding, "binding_sha256": sha.lower()}


def resolve_binding(
    sha: str,
    *,
    live_attestation: dict | None,
    archived: dict[str, dict] | None = None,
    broker: str | None = None,
    operator_key: str | None = None,
    opener=None,
) -> dict:
    """Minimal ``{binding, binding_sha256}`` for receipt signature checks."""
    sha = sha.lower()
    archived = archived or {}
    if live_attestation and live_attestation.get("binding_sha256") == sha:
        binding = live_attestation.get("binding")
        if isinstance(binding, dict) and binding_digest(binding) == sha:
            return {"binding": binding, "binding_sha256": sha}
    if sha in archived:
        binding = archived[sha]
        if binding_digest(binding) != sha:
            raise ValueError(f"archived binding {sha[:16]}... does not hash to its name")
        return minimal_attestation(binding, sha)
    if broker and operator_key:
        binding = fetch_archived_binding(broker, sha, operator_key, opener=opener)
        return minimal_attestation(binding, sha)
    raise ValueError(
        f"no binding for {sha[:16]}...: the host may have restarted; use the broker archive "
        "(operator key) or ship archived_bindings in the evidence bundle"
    )

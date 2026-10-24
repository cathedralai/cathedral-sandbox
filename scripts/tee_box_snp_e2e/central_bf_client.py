#!/usr/bin/env python3
"""Drive B.b (and helpers) on measured SNP once Fred-signed materials exist.

Uses the operator central seed + Fred-signed delegation / revocation list.
Does not mint root signatures. Does not overwrite measured central-root-keys.

Env:
  CENTRAL_SEED   path to central seed (base64 32-byte Ed25519)
  MATERIALS      dir with delegation-full.json + revocations-first.json
  WORKER_HOST    default 127.0.0.1
  WORKER_PORT    default 8443
  WORKER_HOTKEY  default smoke hotkey
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import ssl
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cathedral.central_access import (  # noqa: E402
    CENTRAL_REQUEST_HEADER,
    build_central_request_header,
    load_central_root_keys,
    verify_delegation,
)
from cathedral.channel import tls_spki_binding  # noqa: E402

HOTKEY = os.environ.get(
    "WORKER_HOTKEY", "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
)
NETWORK, NETUID = "finney", 94
DEFAULT_MATERIALS = Path(__file__).resolve().parent / "central_access_materials"


def _die(msg: str, code: int = 2) -> int:
    print(f"FAIL: {msg}", file=sys.stderr)
    return code


def _load_seed(path: Path) -> bytes:
    raw = path.read_text().strip()
    seed = base64.b64decode(raw, validate=True)
    if len(seed) != 32:
        raise SystemExit(f"central seed must be 32 bytes, got {len(seed)}")
    return seed


def _materials_dir() -> Path:
    return Path(os.environ.get("MATERIALS", str(DEFAULT_MATERIALS)))


def _load_json(name: str) -> dict:
    path = _materials_dir() / name
    if not path.is_file():
        raise SystemExit(f"missing {path} — drop Fred's signed file here")
    return json.loads(path.read_bytes())


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _peer_binding(host: str, port: int) -> bytes:
    import http.client

    conn = http.client.HTTPSConnection(host, port, context=_tls_context(), timeout=30)
    try:
        conn.connect()
        peer = conn.sock.getpeercert(binary_form=True)
        return tls_spki_binding(peer)
    finally:
        conn.close()


IMAGE_REF = os.environ.get("IMAGE_REF", "docker.io/library/alpine")
IMAGE_DIGEST = os.environ.get(
    "IMAGE_DIGEST",
    "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
)


def call(
    *,
    method: str,
    path: str,
    body: bytes | None,
    delegation: dict,
    seed: bytes,
    host: str,
    port: int,
    sign_method: str | None = None,
    sign_path: str | None = None,
    timeout: float = 120.0,
) -> tuple[int, object]:
    import http.client

    binding = _peer_binding(host, port)
    now = datetime.now(UTC).replace(microsecond=0)
    header = build_central_request_header(
        delegation=delegation,
        central_seed=seed,
        worker_hotkey=HOTKEY,
        network=NETWORK,
        netuid=NETUID,
        method=sign_method or method,
        path=sign_path or path,
        body=body or b"",
        channel_binding=binding,
        nonce=secrets.token_bytes(32),
        issued_at=now,
        expires_at=now + timedelta(seconds=110),
    )
    conn = http.client.HTTPSConnection(host, port, context=_tls_context(), timeout=timeout)
    try:
        conn.connect()
        peer = conn.sock.getpeercert(binary_form=True)
        if tls_spki_binding(peer) != binding:
            raise RuntimeError("TLS SPKI changed between pin and request")
        conn.request(
            method,
            path,
            body=body,
            headers={CENTRAL_REQUEST_HEADER: header},
        )
        resp = conn.getresponse()
        data = resp.read()
        status = resp.status
    finally:
        conn.close()
    try:
        document: object = json.loads(data)
    except ValueError:
        document = data[:500].decode("utf-8", "replace")
    return status, document


def jcall(
    *,
    method: str,
    path: str,
    payload: object | None,
    delegation: dict,
    seed: bytes,
    host: str,
    port: int,
    sign_method: str | None = None,
    sign_path: str | None = None,
    timeout: float = 120.0,
) -> tuple[int, object]:
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    return call(
        method=method,
        path=path,
        body=body,
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
        sign_method=sign_method,
        sign_path=sign_path,
        timeout=timeout,
    )


def _reason(doc: object) -> str | None:
    """Extract a machine reason when present; prefer ``reason`` over free-text error."""

    if isinstance(doc, dict):
        top = doc.get("reason")
        if isinstance(top, str) and top:
            return top
        err = doc.get("error")
        if isinstance(err, dict):
            nested = err.get("reason") or err.get("code")
            if isinstance(nested, str) and nested:
                return nested
        if isinstance(err, str) and err:
            return err
    return None


def _is_relaunch_required(status: int, doc: object) -> bool:
    if status != 409:
        return False
    reason = _reason(doc)
    if reason == "relaunch_required":
        return True
    blob = json.dumps(doc, default=str).lower()
    return "relaunch_required" in blob or "must be relaunched" in blob


def _check(results: list[dict], cid: str, name: str, ok: bool, detail: object) -> None:
    row = {"id": cid, "name": name, "ok": bool(ok), "detail": detail}
    results.append(row)
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {cid}: {name}")
    if not ok:
        print(json.dumps(detail, indent=2, default=str)[:1200])


def cmd_push_revocations(args: argparse.Namespace) -> int:
    seed_path = Path(os.environ.get("CENTRAL_SEED", ""))
    if not seed_path.is_file():
        return _die("set CENTRAL_SEED to the central seed path")
    seed = _load_seed(seed_path)
    delegation = _load_json("delegation-full.json")
    rev_path = _materials_dir() / "revocations-first.json"
    if not rev_path.is_file():
        return _die(f"missing {rev_path}")
    body = rev_path.read_bytes()
    status, doc = call(
        method="POST",
        path="/v1/box/revocations",
        body=body,
        delegation=delegation,
        seed=seed,
        host=args.host,
        port=args.port,
    )
    print(json.dumps({"status": status, "body": doc}, indent=2, default=str))
    return 0 if status in (200, 204) or (
        isinstance(doc, dict) and doc.get("ok") is True
    ) else 1


def cmd_get_box(args: argparse.Namespace) -> int:
    seed_path = Path(os.environ.get("CENTRAL_SEED", ""))
    if not seed_path.is_file():
        return _die("set CENTRAL_SEED to the central seed path")
    seed = _load_seed(seed_path)
    delegation = _load_json("delegation-full.json")
    status, doc = call(
        method="GET",
        path="/v1/box",
        body=None,
        delegation=delegation,
        seed=seed,
        host=args.host,
        port=args.port,
    )
    print(json.dumps({"status": status, "body": doc}, indent=2, default=str))
    return 0 if status == 200 else 1


def cmd_smoke_bb(args: argparse.Namespace) -> int:
    """B.b-shaped smoke: get-box before/after push; expect routes open after."""

    print("== get-box (may be open for GET without list) ==")
    rc1 = cmd_get_box(args)
    print("== push first revocations list ==")
    rc2 = cmd_push_revocations(args)
    print("== get-box after push ==")
    rc3 = cmd_get_box(args)
    if rc2 != 0:
        return _die("revocations push failed — check Fred list + tee-box:revocations scope")
    if rc3 != 0:
        return _die("get-box failed after push")
    print("B.b smoke: push + get-box OK (record full matrix separately)")
    return 0 if rc1 in (0, 1) else rc1


def cmd_matrix_efg(args: argparse.Namespace) -> int:
    """B.e egress + B.f one-customer (single key) + B.g.3 wrong-route 401.

    B.f.2 (second customer key) and B.g box-only / revoke need more Fred-signed
    materials — reported as BLOCKED, not silent pass.
    """

    seed_path = Path(os.environ.get("CENTRAL_SEED", ""))
    if not seed_path.is_file():
        return _die("set CENTRAL_SEED to the central seed path")
    seed = _load_seed(seed_path)
    delegation = _load_json("delegation-full.json")
    host, port = args.host, args.port
    results: list[dict] = []

    # Ensure first rev list is installed (B.b already may have pushed).
    rev_path = _materials_dir() / "revocations-first.json"
    st, doc = call(
        method="POST",
        path="/v1/box/revocations",
        body=rev_path.read_bytes(),
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
    )
    if st not in (200, 204) and not (
        isinstance(doc, dict) and doc.get("sequence") is not None
    ):
        # Re-push of current list can be 200; refusal of older is different.
        if not (isinstance(doc, dict) and "sequence" in str(doc)):
            return _die(f"revocations not ready: {st} {doc}")

    st, box = jcall(
        method="GET", path="/v1/box", payload=None, delegation=delegation, seed=seed, host=host, port=port
    )
    if st != 200 or not isinstance(box, dict):
        return _die(f"GET /v1/box failed: {st}")
    egress = box.get("egress") or {}
    _check(
        results,
        "e.1",
        "internet mode offered, egress enforced",
        "internet" in (box.get("network_modes") or []) and egress.get("enforced") is True,
        {"modes": box.get("network_modes"), "egress": egress.get("enforced")},
    )

    st, lease = jcall(
        method="POST",
        path="/v1/lease",
        payload={"ttl_seconds": 1800},
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
    )
    if st == 409 and _reason(lease) == "relaunch_required":
        return _die(
            "box needs relaunch before B.e/f (boot already released). "
            "Relaunch the SNP guest, restart serve-snp, re-push revocations."
        )
    _check(results, "c.lease", "lease box for e/f", st == 200, (st, lease))
    if st != 200:
        print(json.dumps({"results": results}, indent=2, default=str))
        return 1

    st, imported = jcall(
        method="POST",
        path="/v1/images/import",
        payload={"digest": IMAGE_DIGEST, "reference": IMAGE_REF},
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
        timeout=900,
    )
    _check(
        results,
        "c.import",
        "import alpine by digest",
        st == 200 and isinstance(imported, dict) and imported.get("digest") == IMAGE_DIGEST,
        (st, imported if not isinstance(imported, dict) else {k: imported.get(k) for k in ("digest", "error")}),
    )
    if st != 200:
        print(json.dumps({"results": results}, indent=2, default=str))
        return 1

    st, created = jcall(
        method="POST",
        path="/v1/sandboxes",
        payload={
            "image_id": IMAGE_DIGEST,
            "network": "internet",
            "lifetime_seconds": 900,
            "labels": {"e2e": "snp-e"},
        },
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
    )
    sandbox = created.get("id") if isinstance(created, dict) else None
    _check(results, "e.2", "internet sandbox created", st == 201 and bool(sandbox), (st, created))
    if st != 201 or not sandbox:
        print(json.dumps({"results": results}, indent=2, default=str))
        return 1

    def exec_probe(url: str, header: str | None = None) -> tuple[bool, str]:
        extra = f"--header '{header}' " if header else ""
        script = (
            f"out=$(timeout 10 wget -S -T 8 {extra}-O /dev/null '{url}' 2>&1); "
            f'rc=$?; echo "rc=$rc"; echo "$out" | head -4'
        )
        status, document = jcall(
            method="POST",
            path=f"/v1/sandboxes/{sandbox}/exec",
            payload={"command": ["/bin/sh", "-c", script], "timeout_seconds": 20},
            delegation=delegation,
            seed=seed,
            host=host,
            port=port,
            timeout=45,
        )
        text = str(document.get("stdout", document)) if isinstance(document, dict) else str(document)
        answered = "HTTP/1." in text or "onnection refused" in text
        return answered, f"exec {status}: {text.strip()[:400]}"

    import subprocess

    route = subprocess.run(
        ["ip", "-4", "route", "show", "default"], capture_output=True, text=True
    ).stdout.split()
    gateway = route[route.index("via") + 1] if "via" in route else None
    get = subprocess.run(
        ["ip", "-4", "route", "get", "1.1.1.1"], capture_output=True, text=True
    ).stdout.split()
    box_ip = get[get.index("src") + 1] if "src" in get else None

    probes = [
        ("e.3", "cannot reach metadata 169.254.169.254", "http://169.254.169.254/", "Metadata-Flavor: Google", False),
        ("e.4", f"cannot reach VPC gateway {gateway}", f"http://{gateway}/" if gateway else None, None, False),
        ("e.5", "cannot reach box own address", f"http://{box_ip}/" if box_ip else None, None, False),
        ("e.7", "reaches 1.1.1.1", "http://1.1.1.1/", None, True),
    ]
    for cid, name, url, header, should in probes:
        if url is None:
            results.append({"id": cid, "name": name, "ok": None, "detail": "SKIP address unknown"})
            print(f"[SKIP] {cid}: {name}")
            continue
        answered, detail = exec_probe(url, header)
        _check(results, cid, name, answered == should, detail)

    st, deleted = jcall(
        method="DELETE",
        path=f"/v1/sandboxes/{sandbox}",
        payload=None,
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
    )
    _check(results, "e.10", "internet sandbox deleted", st == 200, (st, deleted))

    # ---- f: one customer per boot (single Fred key) ----------------------------
    st, released = jcall(
        method="DELETE",
        path="/v1/lease",
        payload=None,
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
    )
    st2, box2 = jcall(
        method="GET", path="/v1/box", payload=None, delegation=delegation, seed=seed, host=host, port=port
    )
    boot = box2.get("boot") if isinstance(box2, dict) else {}
    _check(
        results,
        "f.1",
        "release lease → needs_relaunch",
        st == 200
        and isinstance(released, dict)
        and released.get("released") is True
        and (released.get("needs_relaunch") is True or (boot or {}).get("needs_relaunch") is True),
        {"release": released, "boot": boot},
    )
    results.append(
        {
            "id": "f.2",
            "name": "customer B (other key) gets 409 relaunch_required",
            "ok": None,
            "detail": "BLOCKED: needs second Fred-signed central delegation",
        }
    )
    print("[BLOCKED] f.2: needs second Fred-signed central key")

    st, lease_again = jcall(
        method="POST",
        path="/v1/lease",
        payload={"ttl_seconds": 600},
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
    )
    _check(
        results,
        "f.3",
        "same customer A can lease again after release",
        st == 200,
        (st, lease_again),
    )
    st, released2 = jcall(
        method="DELETE",
        path="/v1/lease",
        payload=None,
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
    )
    _check(
        results,
        "f.4",
        "customer A releases again",
        st == 200 and isinstance(released2, dict) and released2.get("released") is True,
        released2,
    )

    # ---- g.3: signed for wrong route ------------------------------------------
    st, wrong = jcall(
        method="GET",
        path="/v1/lease",
        payload=None,
        delegation=delegation,
        seed=seed,
        host=host,
        port=port,
        sign_path="/v1/box",
    )
    _check(results, "g.3", "request signed for GET /v1/box sent to /v1/lease → 401", st == 401, (st, _reason(wrong)))
    results.append(
        {
            "id": "g.1_g.2_g.4",
            "name": "box-only scope + revoked sibling",
            "ok": None,
            "detail": "BLOCKED: need Fred box-only delegation + revoke list with digest",
        }
    )
    print("[BLOCKED] g.1/g.2/g.4: need more Fred-signed materials")

    failed = [r for r in results if r.get("ok") is False]
    print(json.dumps({"summary_failed": len(failed), "results": results}, indent=2, default=str))
    return 1 if failed else 0


def _require_seed_env(name: str) -> bytes:
    path = Path(os.environ.get(name, ""))
    if not path.is_file():
        raise SystemExit(f"set {name} to the central seed path")
    return _load_seed(path)


def cmd_matrix_fg_finish(args: argparse.Namespace) -> int:
    """Finish B.f.2 + B.g with Fred's corrected 2026-10-12 seven-delegation order.

    Expects materials from ``toby-handoff-20261012`` (corrected README) and env:
    CENTRAL_SEED_A, CENTRAL_SEED_B, CENTRAL_SEED_BOX, CENTRAL_SEED_SIBLING.

    Order (never reorder): A2 → B3 → Box4 → A5 → revoked Box6 → Sibling7 → A8.
    """

    host, port = args.host, args.port
    seed_a = _require_seed_env("CENTRAL_SEED_A")
    seed_b = _require_seed_env("CENTRAL_SEED_B")
    seed_box = _require_seed_env("CENTRAL_SEED_BOX")
    seed_sib = _require_seed_env("CENTRAL_SEED_SIBLING")
    del_a2 = _load_json("delegation-a-full-seq2.json")
    del_b = _load_json("delegation-b-full-seq3.json")
    del_box4 = _load_json("delegation-box-scope-seq4.json")
    del_a5 = _load_json("delegation-a-full-seq5.json")
    del_box6 = _load_json("delegation-box-revoke-target-seq6.json")
    del_sib = _load_json("delegation-sibling-box-seq7.json")
    del_a8 = _load_json("delegation-a-cleanup-seq8.json")
    rev2 = _materials_dir() / "revocations-seq2-fresh.json"
    rev3 = _materials_dir() / "revocations-seq3-revoke-box-seq6.json"
    if not rev2.is_file() or not rev3.is_file():
        return _die("missing corrected handoff revocations JSON in MATERIALS")

    receipt_path = _materials_dir() / "SIGNING_RECEIPT.json"
    expected_box_digest = None
    if receipt_path.is_file():
        receipt = json.loads(receipt_path.read_bytes())
        expected_box_digest = receipt.get("BOX_DIGEST")

    results: list[dict] = []

    # Offline verify Box6 before any live use (Fred requirement).
    roots_path = Path(
        os.environ.get(
            "CENTRAL_ROOT_KEYS",
            "/usr/share/cathedral/central-root-keys.json",
        )
    )
    if not roots_path.is_file():
        return _die(f"missing root keys at {roots_path} for offline Box6 verify")
    pinned = os.environ.get(
        "CENTRAL_ROOT_KEYS_DIGEST",
        "sha256:551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e",
    )
    root_keys = load_central_root_keys(str(roots_path), pinned_digest=pinned)
    try:
        verified = verify_delegation(
            del_box6, root_keys, network=NETWORK, netuid=NETUID, now=datetime.now(UTC)
        )
    except Exception as exc:  # noqa: BLE001 — surface authorizer refusal reason
        return _die(f"Box6 offline verify failed: {exc}")
    digest_ok = expected_box_digest is None or verified.digest == expected_box_digest
    scope_ok = verified.routes == frozenset({"tee-box:box"})
    _check(
        results,
        "offline.box6",
        "Box6 signature/subnet/scope/expiry + BOX_DIGEST",
        digest_ok and scope_ok and verified.sequence == 6,
        {
            "digest": verified.digest,
            "expected": expected_box_digest,
            "routes": sorted(verified.routes),
            "sequence": verified.sequence,
            "expires_at": verified.expires_at.isoformat(),
        },
    )
    if not (digest_ok and scope_ok and verified.sequence == 6):
        print(json.dumps({"summary_failed": 1, "results": results}, indent=2, default=str))
        return 1

    # 1) A2 — push rev2, inspect fresh, lease, release
    st, doc = call(
        method="POST",
        path="/v1/box/revocations",
        body=rev2.read_bytes(),
        delegation=del_a2,
        seed=seed_a,
        host=host,
        port=port,
    )
    st_box, view = jcall(
        method="GET",
        path="/v1/box",
        payload=None,
        delegation=del_a2,
        seed=seed_a,
        host=host,
        port=port,
    )
    rev = view.get("revocations") if isinstance(view, dict) else None
    fresh = isinstance(rev, dict) and rev.get("fresh") is True
    rev_seq = rev.get("sequence") if isinstance(rev, dict) else None
    _check(
        results,
        "A2.rev2",
        "push rev seq2; box fresh sequence2",
        st in (200, 204) and st_box == 200 and fresh and rev_seq == 2,
        {"push": (st, doc), "box": view},
    )

    st, leased = jcall(
        method="POST",
        path="/v1/lease",
        payload={"ttl_seconds": 600},
        delegation=del_a2,
        seed=seed_a,
        host=host,
        port=port,
    )
    if st == 409 and _reason(leased) == "relaunch_required":
        return _die(
            "box needs relaunch before A2 lease — STOP per Fred (no guest relaunch "
            "to bypass ordering). Reconcile used-boot state first."
        )
    _check(results, "A2.lease", "A seq2 lease", st == 200, (st, leased))
    st, released = jcall(
        method="DELETE",
        path="/v1/lease",
        payload=None,
        delegation=del_a2,
        seed=seed_a,
        host=host,
        port=port,
    )
    needs = isinstance(released, dict) and released.get("needs_relaunch") is True
    _check(
        results,
        "A2.release",
        "A release → needs_relaunch",
        st == 200 and needs,
        released,
    )

    # 2) B3 — different customer → 409 (auth still raises high-water to 3)
    st, body = jcall(
        method="POST",
        path="/v1/lease",
        payload={"ttl_seconds": 60},
        delegation=del_b,
        seed=seed_b,
        host=host,
        port=port,
    )
    _check(
        results,
        "B3",
        "different-customer lease → 409 relaunch_required",
        _is_relaunch_required(st, body),
        (st, body),
    )

    # 3) Box4 — inspect OK; management + revocations missing-scope 401
    st, box4_view = jcall(
        method="GET",
        path="/v1/box",
        payload=None,
        delegation=del_box4,
        seed=seed_box,
        host=host,
        port=port,
    )
    _check(results, "Box4.get", "box-scope GET /v1/box → 200", st == 200, (st, box4_view))
    st_lease, lease_doc = jcall(
        method="POST",
        path="/v1/lease",
        payload={"ttl_seconds": 60},
        delegation=del_box4,
        seed=seed_box,
        host=host,
        port=port,
    )
    st_list, list_doc = jcall(
        method="GET",
        path="/v1/sandboxes",
        payload=None,
        delegation=del_box4,
        seed=seed_box,
        host=host,
        port=port,
    )
    st_rev, rev_doc = call(
        method="POST",
        path="/v1/box/revocations",
        body=rev2.read_bytes(),
        delegation=del_box4,
        seed=seed_box,
        host=host,
        port=port,
    )
    missing = (
        st_lease == 401
        and st_list == 401
        and st_rev == 401
        and all(
            "scope" in str(_reason(d) or d).lower() or "permission" in str(_reason(d) or d).lower()
            or "route" in str(_reason(d) or d).lower()
            for d in (lease_doc, list_doc, rev_doc)
        )
    )
    # Accept plain 401 on all three even if reason text varies; record bodies.
    _check(
        results,
        "Box4.scope",
        "missing-scope lease/list/revocations → 401",
        st_lease == 401 and st_list == 401 and st_rev == 401,
        {
            "lease": (st_lease, lease_doc),
            "list": (st_list, list_doc),
            "revocations": (st_rev, rev_doc),
            "reason_hint_ok": missing,
        },
    )

    # 4) A5 — same-customer re-lease; push rev3 (revokes Box6 only)
    st, a5_lease = jcall(
        method="POST",
        path="/v1/lease",
        payload={"ttl_seconds": 300},
        delegation=del_a5,
        seed=seed_a,
        host=host,
        port=port,
    )
    _check(results, "A5.lease", "A seq5 same-customer re-lease", st == 200, (st, a5_lease))
    st, rev3_doc = call(
        method="POST",
        path="/v1/box/revocations",
        body=rev3.read_bytes(),
        delegation=del_a5,
        seed=seed_a,
        host=host,
        port=port,
    )
    st_box, view = jcall(
        method="GET",
        path="/v1/box",
        payload=None,
        delegation=del_a5,
        seed=seed_a,
        host=host,
        port=port,
    )
    rev = view.get("revocations") if isinstance(view, dict) else None
    rev_seq = rev.get("sequence") if isinstance(rev, dict) else None
    _check(
        results,
        "A5.rev3",
        "push rev seq3; active list sequence3",
        st in (200, 204) and st_box == 200 and rev_seq == 3,
        {"push": (st, rev3_doc), "box": view},
    )

    # 5) Box6 — first live use after revoke → 401 (worker maps revoke to
    # generic unauthorized; offline verify + sibling 200 prove cause).
    st, box6_doc = jcall(
        method="GET",
        path="/v1/box",
        payload=None,
        delegation=del_box6,
        seed=seed_box,
        host=host,
        port=port,
    )
    _check(
        results,
        "Box6",
        "revoked Box6 GET /v1/box → 401",
        st == 401,
        (st, box6_doc),
    )

    # 6) Sibling7 — unrevoked inspect after revocation
    st, sib_doc = jcall(
        method="GET",
        path="/v1/box",
        payload=None,
        delegation=del_sib,
        seed=seed_sib,
        host=host,
        port=port,
    )
    sib_detail: object = sib_doc
    if isinstance(sib_doc, dict):
        sib_detail = {
            "status": st,
            "revocations": sib_doc.get("revocations"),
            "network_modes": sib_doc.get("network_modes"),
            "egress": (sib_doc.get("egress") or {}).get("enforced")
            if isinstance(sib_doc.get("egress"), dict)
            else sib_doc.get("egress"),
        }
    _check(
        results,
        "Sibling7",
        "sibling GET /v1/box → 200",
        st == 200,
        sib_detail,
    )

    # 7) A8 — cleanup last
    st, a8_view = jcall(
        method="GET",
        path="/v1/box",
        payload=None,
        delegation=del_a8,
        seed=seed_a,
        host=host,
        port=port,
    )
    st_rel, a8_rel = jcall(
        method="DELETE",
        path="/v1/lease",
        payload=None,
        delegation=del_a8,
        seed=seed_a,
        host=host,
        port=port,
    )
    _check(
        results,
        "A8",
        "A cleanup inspect + release",
        st == 200 and st_rel in (200, 404, 409),
        {"box": (st, a8_view), "release": (st_rel, a8_rel)},
    )

    failed = [r for r in results if r.get("ok") is False]
    print(json.dumps({"summary_failed": len(failed), "results": results}, indent=2, default=str))
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=os.environ.get("WORKER_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("WORKER_PORT", "8443")))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("push-revocations").set_defaults(func=cmd_push_revocations)
    sub.add_parser("get-box").set_defaults(func=cmd_get_box)
    sub.add_parser("smoke-bb").set_defaults(func=cmd_smoke_bb)
    sub.add_parser("matrix-efg").set_defaults(func=cmd_matrix_efg)
    sub.add_parser("matrix-fg-finish").set_defaults(func=cmd_matrix_fg_finish)
    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

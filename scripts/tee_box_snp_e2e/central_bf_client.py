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
    if isinstance(doc, dict):
        err = doc.get("error")
        if isinstance(err, dict):
            return err.get("reason") or err.get("code")
        if isinstance(err, str):
            return err
        return doc.get("reason")
    return None


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
    """Finish B.f.2 + B.g after Fred Round-2 signed files land.

    Expects materials from ``fred-signing-batch-bf-fg-20261012.md`` and env:
    CENTRAL_SEED_A, CENTRAL_SEED_B, CENTRAL_SEED_BOX, CENTRAL_SEED_SIBLING.
    """

    host, port = args.host, args.port
    seed_a = _require_seed_env("CENTRAL_SEED_A")
    seed_b = _require_seed_env("CENTRAL_SEED_B")
    seed_box = _require_seed_env("CENTRAL_SEED_BOX")
    seed_sib = _require_seed_env("CENTRAL_SEED_SIBLING")
    del_a2 = _load_json("delegation-a-full-seq2.json")
    del_b = _load_json("delegation-b-full-seq3.json")
    del_box = _load_json("delegation-box-only-seq4.json")
    del_sib = _load_json("delegation-sibling-box-seq5.json")
    del_a6 = _load_json("delegation-a-full-seq6.json")
    rev2 = _materials_dir() / "revocations-seq2-fresh-empty.json"
    rev3 = _materials_dir() / "revocations-seq3-revoke-box-only.json"
    if not rev2.is_file() or not rev3.is_file():
        return _die("missing Round-2 revocations JSON in MATERIALS")

    results: list[dict] = []

    # T0 — fresh empty rev list
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
        method="GET", path="/v1/box", payload=None, delegation=del_a2, seed=seed_a, host=host, port=port
    )
    fresh = isinstance(view, dict) and (view.get("revocations") or {}).get("fresh") is True
    _check(results, "T0", "push rev seq2; box fresh", st in (200, 204) and st_box == 200 and fresh, (st, doc, view))

    # T1/T2 — box-only inspect OK, management 401
    st, _ = jcall(
        method="GET", path="/v1/box", payload=None, delegation=del_box, seed=seed_box, host=host, port=port
    )
    _check(results, "T1", "box-only GET /v1/box → 200", st == 200, st)
    st_lease, _ = jcall(
        method="POST",
        path="/v1/lease",
        payload={"ttl_seconds": 60},
        delegation=del_box,
        seed=seed_box,
        host=host,
        port=port,
    )
    st_list, _ = jcall(
        method="GET", path="/v1/sandboxes", payload=None, delegation=del_box, seed=seed_box, host=host, port=port
    )
    _check(
        results,
        "T2",
        "box-only lease/list → 401",
        st_lease == 401 and st_list == 401,
        {"lease": st_lease, "list": st_list},
    )

    # T3 — A lease then release
    st, _ = jcall(
        method="POST",
        path="/v1/lease",
        payload={"ttl_seconds": 600},
        delegation=del_a2,
        seed=seed_a,
        host=host,
        port=port,
    )
    if st == 409 and _reason(_) == "relaunch_required":
        return _die("box needs relaunch before T3 — reboot guest, restart serve-snp, re-run")
    _check(results, "T3a", "A seq2 lease", st == 200, (st, _))
    st, released = jcall(
        method="DELETE", path="/v1/lease", payload=None, delegation=del_a2, seed=seed_a, host=host, port=port
    )
    needs = isinstance(released, dict) and released.get("needs_relaunch") is True
    _check(results, "T3", "A release → needs_relaunch", st == 200 and needs, released)

    # T4 — B different customer → 409
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
        "T4",
        "B lease → 409 relaunch_required",
        st == 409 and _reason(body) == "relaunch_required",
        (st, body),
    )

    # T5 — A seq6 can lease again
    st, _ = jcall(
        method="POST",
        path="/v1/lease",
        payload={"ttl_seconds": 120},
        delegation=del_a6,
        seed=seed_a,
        host=host,
        port=port,
    )
    _check(results, "T5", "A seq6 lease after B high-water", st == 200, (st, _))
    jcall(method="DELETE", path="/v1/lease", payload=None, delegation=del_a6, seed=seed_a, host=host, port=port)

    # T6 — push revoke list
    st, doc = call(
        method="POST",
        path="/v1/box/revocations",
        body=rev3.read_bytes(),
        delegation=del_a6,
        seed=seed_a,
        host=host,
        port=port,
    )
    _check(results, "T6", "push rev seq3 (revoke box-only)", st in (200, 204), (st, doc))

    # T7/T8 — revoked vs sibling
    st, _ = jcall(
        method="GET", path="/v1/box", payload=None, delegation=del_box, seed=seed_box, host=host, port=port
    )
    _check(results, "T7", "revoked box-only → 401", st == 401, st)
    st, _ = jcall(
        method="GET", path="/v1/box", payload=None, delegation=del_sib, seed=seed_sib, host=host, port=port
    )
    _check(results, "T8", "sibling box-only still → 200", st == 200, st)

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

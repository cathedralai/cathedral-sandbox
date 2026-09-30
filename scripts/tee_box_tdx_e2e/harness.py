#!/usr/bin/env python3
"""End-to-end harness for the cathedral-sandbox TEE box on a real Intel TDX guest.

It runs the real worker (``cathedral worker serve`` with the TEE box flags, via
serve_worker.py) and talks to it as a central-access client: root-signed
delegations minted with the offline root tool
(scripts/cathedral_central_access.py), central requests signed per call and
bound to the worker's TLS key, over HTTPS. The only injected piece on the TD
is the MRCONFIGID binding reader (Polaris launches with MRCONFIGID zero).

Phases (run as root on the TD, after setup.sh):
  pre-luks  docker's data root is still on plain ext4: startup must refuse.
  main      docker's data root is on the LUKS2 integrity mount: checks a-g.

``--local`` runs the same flow on a developer machine with local_fakes.py
(runc for runsc, fake RTMR3/storage/nft/tc, a quote saved earlier on a TD).
It is for developing the harness only and proves nothing about a TD.

Every check prints ``PASS|FAIL|SKIP|INFO <id> <name> -- <detail>`` and the
phase writes a JSON report. Exit status is 1 if any check failed.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import traceback
from datetime import UTC, datetime, timedelta
from pathlib import Path

HERE = Path(__file__).resolve().parent
# The well-known Substrate development address "Bob": no wallet or chain is used.
HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
NETWORK, NETUID = "finney", 94
BOX_ID = "e2e"
ROOT_KEY_ID = "cathedral-e2e-root"
DEFAULT_IMAGE_REF = "docker.io/library/alpine"
DEFAULT_IMAGE_DIGEST = "sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc"
BOX_STATE = "/run/cathedral-tee-box/central.sqlite"
SCRATCH_MOUNT = "/var/lib/cathedral-scratch"
ZERO48 = bytes(48)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


class Report:
    def __init__(self, path: Path, phase: str, local: bool) -> None:
        self.path = path
        self.phase = phase
        self.local = local
        self.rows: list[dict] = []
        self.started = time.time()

    def add(self, cid: str, status: str, name: str, detail: object = "") -> None:
        text = detail if isinstance(detail, str) else json.dumps(detail, sort_keys=True)
        text = text.replace("\n", " | ")
        if len(text) > 1500:
            text = text[:1500] + "..."
        self.rows.append(
            {
                "id": cid,
                "status": status,
                "name": name,
                "detail": text,
                "t": round(time.time() - self.started, 1),
            }
        )
        print(f"{status:<4} {cid:<5} {name}" + (f" -- {text}" if text else ""), flush=True)
        self.save()

    def check(
        self, cid: str, name: str, ok: bool, detail: object = "", *, local_info: bool = False
    ) -> bool:
        status = "PASS" if ok else "FAIL"
        if local_info and self.local:
            status = "INFO"
        self.add(cid, status, name, detail)
        return bool(ok)

    def skip(self, cid: str, name: str, detail: object = "") -> None:
        self.add(cid, "SKIP", name, detail)

    def info(self, cid: str, name: str, detail: object = "") -> None:
        self.add(cid, "INFO", name, detail)

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for row in self.rows:
            out[row["status"]] = out.get(row["status"], 0) + 1
        return out

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(
                {
                    "phase": self.phase,
                    "local": self.local,
                    "counts": self.counts(),
                    "rows": self.rows,
                },
                indent=1,
            )
        )
        os.replace(tmp, self.path)


class Abort(Exception):
    """A check the rest of the phase depends on failed."""


# ---------------------------------------------------------------------------
# offline root tool and principals
# ---------------------------------------------------------------------------


class RootTool:
    """The offline root tool, run as a subprocess, with its keys in ``keys``."""

    def __init__(self, src: Path, keys: Path) -> None:
        self.script = src / "scripts" / "cathedral_central_access.py"
        self.keys = keys
        self.ledger = keys / "delegations.ledger"
        self.root_seed_path = keys / "root.seed"
        self.root_keys_path = keys / "root-keys.json"
        self.out = keys / "documents"
        self.out.mkdir(parents=True, exist_ok=True)
        self._sequence = 0

    def run(self, *args: str) -> str:
        result = subprocess.run(
            [sys.executable, str(self.script), *args], capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            raise RuntimeError(f"root tool {args[0]} failed: {result.stdout} {result.stderr}")
        return result.stdout

    @staticmethod
    def fields(output: str) -> dict[str, str]:
        out = {}
        for line in output.splitlines():
            key, _, value = line.partition(" ")
            out[key] = value.strip()
        return out

    def ensure_root(self) -> None:
        if not self.root_seed_path.exists():
            self.run(
                "keygen",
                "--role",
                "root",
                "--key-id",
                ROOT_KEY_ID,
                "--seed-out",
                str(self.root_seed_path),
                "--keys-out",
                str(self.root_keys_path),
            )
        self.root_keys = self.root_keys_path.read_bytes()
        self.root_digest = "sha256:" + hashlib.sha256(self.root_keys).hexdigest()

    def root_seed(self) -> bytes:
        return base64.b64decode(self.root_seed_path.read_text().strip())

    def ensure_central(self, name: str) -> tuple[bytes, str]:
        seed_path = self.keys / f"{name}.seed"
        if not seed_path.exists():
            self.run("keygen", "--role", "central", "--key-id", name, "--seed-out", str(seed_path))
        seed = base64.b64decode(seed_path.read_text().strip())
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        public = (
            Ed25519PrivateKey.from_private_bytes(seed)
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        return seed, base64.b64encode(public).decode()

    def next_sequence(self) -> int:
        last = 0
        if self.ledger.exists():
            for line in self.ledger.read_text().splitlines():
                if line.strip():
                    last = max(last, int(json.loads(line)["sequence"]))
        # Time-based, so a re-run in the same boot never goes below the high-water.
        self._sequence = max(self._sequence + 1, last + 1, int(time.time() * 1000))
        return self._sequence

    def delegate(self, name: str, public_b64: str, scopes: list[str]) -> tuple[dict, str, int]:
        sequence = self.next_sequence()
        out = self.out / f"delegation-{name}-{sequence}.json"
        args = [
            "delegate",
            "--root-key-file",
            str(self.root_seed_path),
            "--root-key-id",
            ROOT_KEY_ID,
            "--root-keys",
            str(self.root_keys_path),
            "--root-keys-digest",
            self.root_digest,
            "--central-public-key",
            public_b64,
            "--network",
            NETWORK,
            "--netuid",
            str(NETUID),
            "--sequence",
            str(sequence),
            "--valid-hours",
            "3",
            "--ledger",
            str(self.ledger),
            "--out",
            str(out),
        ]
        for scope in scopes:
            args += ["--route", scope]
        fields = self.fields(self.run(*args))
        return json.loads(out.read_bytes()), fields["delegation_digest"], sequence

    def verify_delegation(self, path: Path) -> str:
        result = subprocess.run(
            [
                sys.executable,
                str(self.script),
                "verify",
                "--root-keys",
                str(self.root_keys_path),
                "--root-keys-digest",
                self.root_digest,
                "--delegation",
                str(path),
                "--network",
                NETWORK,
                "--netuid",
                str(NETUID),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return (result.stdout + result.stderr).strip()

    def revocations(self, sequence: int, *, previous: Path | None, revoke: list[str]) -> Path:
        out = self.out / f"revocations-{sequence}.json"
        args = [
            "revoke",
            "--root-key-file",
            str(self.root_seed_path),
            "--root-key-id",
            ROOT_KEY_ID,
            "--root-keys",
            str(self.root_keys_path),
            "--root-keys-digest",
            self.root_digest,
            "--sequence",
            str(sequence),
            "--out",
            str(out),
        ]
        args += ["--previous", str(previous)] if previous else ["--first-list", "--allow-empty"]
        for digest in revoke:
            args += ["--revoke", digest]
        self.run(*args)
        return out


class Principal:
    """One central key and its current root-signed delegation."""

    def __init__(
        self, tool: RootTool, name: str, scopes: list[str], *, auto_refresh: bool = True
    ) -> None:
        self.tool = tool
        self.name = name
        self.scopes = scopes
        self.auto_refresh = auto_refresh
        self.seed, self.public_b64 = tool.ensure_central(name)
        self.caller = "central:" + hashlib.sha256(base64.b64decode(self.public_b64)).hexdigest()
        self.delegation: dict | None = None
        self.digest = ""
        self.sequence = 0
        self.path: Path | None = None
        self.delegations = 0

    def delegate(self) -> None:
        self.delegation, self.digest, self.sequence = self.tool.delegate(
            self.name, self.public_b64, self.scopes
        )
        self.path = self.tool.out / f"delegation-{self.name}-{self.sequence}.json"
        self.delegations += 1


# ---------------------------------------------------------------------------
# HTTPS client with central requests
# ---------------------------------------------------------------------------


class Box:
    def __init__(self, port: int, certificate_der: bytes) -> None:
        from cathedral.channel import tls_spki_binding

        self.port = port
        self.certificate_der = certificate_der
        self.binding = tls_spki_binding(certificate_der)
        self.high_water = 0
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE  # pinned by SPKI below, as the prober does
        self.calls = 0

    def call(
        self,
        principal: Principal,
        method: str,
        target: str,
        body: bytes | None = None,
        *,
        sign_method: str | None = None,
        sign_target: str | None = None,
        timeout: float = 120.0,
    ) -> tuple[int, object]:
        from cathedral.central_access import CENTRAL_REQUEST_HEADER, build_central_request_header
        from cathedral.channel import tls_spki_binding

        if principal.delegation is None or (
            principal.auto_refresh and principal.sequence < self.high_water
        ):
            principal.delegate()
        now = datetime.now(UTC).replace(microsecond=0)
        header = build_central_request_header(
            delegation=principal.delegation,
            central_seed=principal.seed,
            worker_hotkey=HOTKEY,
            network=NETWORK,
            netuid=NETUID,
            method=sign_method or method,
            path=sign_target or target,
            body=body or b"",
            channel_binding=self.binding,
            nonce=secrets.token_bytes(32),
            issued_at=now,
            expires_at=now + timedelta(seconds=110),
        )
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.port, context=self.context, timeout=timeout
        )
        try:
            connection.connect()
            peer = connection.sock.getpeercert(binary_form=True)
            if tls_spki_binding(peer) != self.binding:
                raise RuntimeError("the worker's TLS key is not the pinned one")
            connection.request(method, target, body=body, headers={CENTRAL_REQUEST_HEADER: header})
            response = connection.getresponse()
            data = response.read()
            status = response.status
        finally:
            connection.close()
        self.calls += 1
        if status != 401:
            self.high_water = max(self.high_water, principal.sequence)
        try:
            document: object = json.loads(data)
        except ValueError:
            document = data[:500].decode("utf-8", "replace")
        return status, document

    def j(
        self, principal: Principal, method: str, target: str, document: object = None, **kwargs
    ) -> tuple[int, object]:
        body = None if document is None else json.dumps(document).encode()
        return self.call(principal, method, target, body, **kwargs)


def reason(document: object) -> str | None:
    return document.get("reason") if isinstance(document, dict) else None


# ---------------------------------------------------------------------------
# the worker process
# ---------------------------------------------------------------------------


class Worker:
    def __init__(
        self,
        h: "Harness",
        label: str,
        *,
        binding: str | bytes,
        state: str | None = None,
        extra_env: dict | None = None,
    ) -> None:
        self.h = h
        self.label = label
        self.binding = binding
        self.state = state or h.state
        self.extra_env = extra_env or {}
        self.proc: subprocess.Popen | None = None
        self.stdout: list[str] = []
        self.stderr: list[str] = []
        self.log = h.logs / f"worker-{label}.log"

    def argv(self) -> list[str]:
        h = self.h
        return [
            sys.executable,
            str(HERE / "serve_worker.py"),
            "worker",
            "serve",
            "--hotkey",
            HOTKEY,
            "--host",
            "127.0.0.1",
            "--port",
            str(h.port),
            "--tls-certificate",
            str(h.cert_path),
            "--tls-private-key",
            str(h.key_path),
            "--validator-network",
            NETWORK,
            "--validator-netuid",
            str(NETUID),
            "--tee-box-central-state",
            self.state,
            "--tee-box-executor",
            "runsc",
            "--tee-box-detect-addresses",
            "--tee-box-capacity",
            "3,6144,4096",
            "--tee-box-default-shape",
            "1,1024,512",
            "--tee-box-no-disk-quota",
            "--tee-box-id",
            BOX_ID,
        ]

    def env(self) -> dict:
        env = dict(os.environ)
        env["E2E_SRC"] = str(self.h.src)
        env["CATHEDRAL_WORKER_BEARER_TOKEN"] = secrets.token_hex(24)
        env["PYTHONUNBUFFERED"] = "1"
        if self.binding == "real":
            env["E2E_BINDING"] = "real"
            env.pop("E2E_MRCONFIGID_HEX", None)
        else:
            env.pop("E2E_BINDING", None)
            env["E2E_MRCONFIGID_HEX"] = self.binding.hex()
        if self.h.local:
            env.update(self.h.local_env())
        env.update(self.extra_env)
        return env

    def _pump(self, stream, sink: list[str], tag: str) -> None:  # noqa: ANN001
        with open(self.log, "a") as log:
            for line in stream:
                sink.append(line)
                log.write(f"{tag} {line}")
                log.flush()

    def start(self, timeout: float = 180.0) -> tuple[str, object]:
        with open(self.log, "a") as log:
            log.write(f"=== start {datetime.now(UTC).isoformat()} {' '.join(self.argv())}\n")
        self.proc = subprocess.Popen(
            self.argv(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=self.env(),
            cwd=str(self.h.work),
        )
        threading.Thread(
            target=self._pump, args=(self.proc.stdout, self.stdout, "out"), daemon=True
        ).start()
        threading.Thread(
            target=self._pump, args=(self.proc.stderr, self.stderr, "err"), daemon=True
        ).start()
        deadline = time.time() + timeout
        while time.time() < deadline:
            for line in list(self.stdout):
                try:
                    document = json.loads(line)
                except ValueError:
                    continue
                if (
                    isinstance(document, dict)
                    and document.get("schema") == "cathedral_effective_startup_v1"
                ):
                    return "started", document
            if self.proc.poll() is not None:
                time.sleep(0.3)  # let the pumps drain
                return "refused", "".join(self.stderr).strip() or "".join(self.stdout).strip()
            time.sleep(0.2)
        self.stop()
        return "timeout", "".join(self.stderr)[-2000:]

    def stop(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        self.proc.send_signal(signal.SIGINT)
        try:
            self.proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def sh(argv: list[str], timeout: float = 60, check: bool = False) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode != 0:
        raise RuntimeError(f"{argv} failed: {result.stderr.strip()}")
    return result


def make_tls(directory: Path) -> tuple[Path, Path, bytes]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tee-box-e2e.invalid")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=1))
        .not_valid_after(now + timedelta(days=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("tee-box-e2e.invalid")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "worker-cert.pem", directory / "worker-key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)
    return cert_path, key_path, certificate.public_bytes(serialization.Encoding.DER)


class Listener:
    """A TCP server on the TD host answering HTTP, to prove the box itself is denied."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("0.0.0.0", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.hits: list[str] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                connection, address = self.sock.accept()
            except OSError:
                return
            self.hits.append(address[0])
            try:
                connection.settimeout(2)
                try:
                    connection.recv(4096)
                except OSError:
                    pass
                connection.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n"
                    b"Connection: close\r\n\r\ne2e-listener"
                )
            finally:
                connection.close()

    def close(self) -> None:
        self.sock.close()


def host_http(url: str, headers: dict | None = None, timeout: float = 6) -> str:
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return f"HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return f"no answer ({type(exc).__name__}: {exc})"


# ---------------------------------------------------------------------------
# the harness
# ---------------------------------------------------------------------------


class Harness:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.local = args.local
        self.src = Path(args.src).resolve()
        sys.path.insert(0, str(self.src))
        self.work = Path(args.work).resolve()
        self.work.mkdir(parents=True, exist_ok=True)
        os.chmod(self.work, 0o700)
        self.logs = self.work / "logs"
        self.logs.mkdir(exist_ok=True)
        self.port = args.port
        self.image_ref = args.image_ref
        self.image_digest = args.image_digest
        self.verifier = Path(args.verifier).resolve() if args.verifier else None
        results = (
            Path(args.results) if args.results else self.work / "results" / f"{args.phase}.json"
        )
        self.report = Report(results, args.phase, self.local)
        self.workers: list[Worker] = []
        self.listener: Listener | None = None
        if self.local:
            self.local_dir = self.work / "local"
            self.local_dir.mkdir(exist_ok=True)
            self.tmpfs_dir = self.local_dir / "tmpfs"
            self.state = str(self.tmpfs_dir / "central.sqlite")
            self.rtmr_path = self.local_dir / "rtmr3"
            self.root_keys_target = self.local_dir / "image" / "central-root-keys.json"
        else:
            self.state = BOX_STATE
            from cathedral.tee_box import measured_root

            self.root_keys_target = Path(measured_root.CENTRAL_ROOT_KEYS_PATH)

    # -- environment ---------------------------------------------------------

    def local_env(self) -> dict:
        return {
            "E2E_LOCAL": "1",
            "E2E_ROOT_KEYS_PATH": str(self.root_keys_target),
            "E2E_LOCAL_TMPFS_DIR": str(self.tmpfs_dir),
            "E2E_LOCAL_RTMR3": str(self.rtmr_path),
            "E2E_LOCAL_GUEST_LOG": str(self.logs / "local-guest.log"),
        }

    def setup_common(self) -> None:
        from cathedral.tee_box.measured_root import mrconfigid_for_root_keys

        keys = self.work / "keys"
        keys.mkdir(exist_ok=True)
        os.chmod(keys, 0o700)
        self.tool = RootTool(self.src, keys)
        self.tool.ensure_root()
        # The root key file goes at CENTRAL_ROOT_KEYS_PATH, as the image would hold it.
        self.root_keys_target.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.root_keys_target.with_suffix(".e2e-tmp")
        tmp.write_bytes(self.tool.root_keys)
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.root_keys_target)
        self.mrconfigid = mrconfigid_for_root_keys(self.root_keys_target.read_bytes())
        self.cert_path, self.key_path, self.cert_der = make_tls(self.work / "tls")
        self.box = Box(self.port, self.cert_der)
        if self.local:
            self.tmpfs_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.tmpfs_dir, 0o700)
            if not self.rtmr_path.exists():
                self.rtmr_path.write_bytes(ZERO48)
        self.report.info(
            "env",
            "setup",
            {
                "src": str(self.src),
                "root_digest": self.tool.root_digest,
                "root_keys_path": str(self.root_keys_target),
                "mrconfigid_injected": self.mrconfigid.hex(),
                "state": self.state,
                "image": f"{self.image_ref}@{self.image_digest}",
                "kernel": os.uname().release,
                "local": self.local,
            },
        )

    def start_worker(
        self,
        label: str,
        *,
        binding: str | bytes | None = None,
        state: str | None = None,
        extra_env: dict | None = None,
    ) -> tuple[str, object, Worker]:
        worker = Worker(
            self,
            label,
            binding=self.mrconfigid if binding is None else binding,
            state=state,
            extra_env=extra_env,
        )
        self.workers.append(worker)
        status, detail = worker.start()
        if status != "started":
            worker.stop()
        return status, detail, worker

    def cleanup(self) -> None:
        for worker in self.workers:
            try:
                worker.stop()
            except Exception:  # noqa: BLE001
                pass
        if self.listener is not None:
            self.listener.close()
        # Anything the worker left (it drains on release; this is a backstop).
        listed = sh(
            ["docker", "ps", "-aq", "--filter", f"label=org.cathedral.tee-box.box={BOX_ID}"]
        )
        for container in listed.stdout.split():
            sh(["docker", "rm", "-f", container])
        if self.local:
            sh(["docker", "network", "rm", "cathsbx0"])

    # -- RTMR3 and quotes ------------------------------------------------------

    def rtmr3(self) -> bytes:
        if self.local:
            return self.rtmr_path.read_bytes()
        from cathedral.tee_box.boot import SysfsRtmr3

        return SysfsRtmr3().read()

    def collect(self, nonce: bytes):  # noqa: ANN201
        from cathedral.common import Evidence, EvidenceKind

        if self.local:
            from cathedral.attest import _canonicalize_tdx_configfs_quote

            quote = _canonicalize_tdx_configfs_quote(Path(self.args.local_quote).read_bytes())
            return Evidence(
                kind=EvidenceKind.TDX,
                quote=quote,
                nonce=nonce,
                miner_hotkey=HOTKEY,
                report_data_version=2,
                channel_binding=self.box.binding,
            )
        from cathedral.attest import collect_tdx

        return collect_tdx(nonce, HOTKEY, channel_binding=self.box.binding, report_data_version=2)

    def attest(self, label: str, *, selftest: bool = False) -> dict:
        """A fresh quote bound to (nonce, hotkey, worker TLS key), verified and admitted."""

        from cathedral.capacity import admission
        from cathedral.common import Policy, report_data_v2
        from cathedral.verify import replay_verify_tdx
        from cathedral.verify.tdx_quote import parse_tdx_quote

        nonce = secrets.token_bytes(32)
        evidence = self.collect(nonce)
        quote = evidence.quote
        parsed = parse_tdx_quote(quote)
        expected = report_data_v2(nonce, HOTKEY, self.box.binding)
        out: dict = {
            "label": label,
            "quote_bytes": len(quote),
            "rtmr3": parsed.body.rtmr3,
            "raw_472_520": quote[48 + 472 : 48 + 520],
            "debug": parsed.debug_enabled,
            "measurement": parsed.measurement,
            "report_data_bound": parsed.report_data == expected,
        }
        quotes = self.work / "quotes"
        quotes.mkdir(exist_ok=True)
        quote_path = quotes / f"{label}.bin"
        quote_path.write_bytes(quote)
        if selftest:
            # Local only: the saved quote's REPORT_DATA preimage is unknown, so the
            # binding is taken from the quote to exercise the rest of the path.
            import cathedral.verify as verify_module

            expected = parsed.report_data
            verify_module.evidence_report_data = lambda _evidence, _nonce: parsed.report_data
            admission.report_data_v2 = lambda *_args: parsed.report_data
        out["parser_rtmr3"] = admission._parse_quote(quote, "tdx")[4]
        if self.verifier is None or not self.verifier.exists():
            out["verifier"] = "no verifier binary"
            return out
        run = subprocess.run(
            [str(self.verifier), str(quote_path), expected.hex()], capture_output=True, timeout=90
        )
        if run.returncode != 0:
            out["verifier"] = (
                f"exit {run.returncode}: {run.stderr.decode(errors='replace').strip()[:300]}"
            )
            return out
        claims = json.loads(run.stdout)
        out["claims"] = {
            k: claims.get(k)
            for k in (
                "measurement",
                "tcb_status",
                "advisory_ids",
                "collateral_current",
                "debug_enabled",
            )
        }
        policy = Policy(
            allowed_measurements=frozenset({claims["measurement"]}),
            tdx_strict=True,
            tdx_allowed_tcb_statuses=frozenset({claims["tcb_status"]}),
            tdx_allowed_advisories=frozenset(claims.get("advisory_ids") or ()),
        )
        attested = replay_verify_tdx(evidence, nonce, policy, [str(self.verifier)])
        if attested is None:
            out["verifier"] = "replay_verify_tdx returned None (strict verification refused)"
            return out
        out["verifier"] = "strict VERIFIED"
        measurement_policy = admission.parse_policy(
            json.dumps(
                {
                    "schema": "cathedral_tdx_measurement_policy_v1",
                    "mode": "enforce",
                    "allowed_measurements": [attested.measurement],
                }
            ).encode()
        )
        common = dict(
            verifier_digest="sha256:" + hashlib.sha256(self.verifier.read_bytes()).hexdigest(),
            box_id="tee-box-e2e",
            miner_hotkey=HOTKEY,
            nonce=nonce,
            attested_at=datetime.now(UTC),
            policy=measurement_policy,
            admitted={},
            tls_certificate_der=self.cert_der,
        )
        fresh = admission.admit(attested, quote, require_fresh_boot=True, **common)
        plain = admission.admit(attested, quote, require_fresh_boot=False, **common)
        out["admit_fresh_boot"] = {"admitted": fresh.admitted, "reasons": list(fresh.reasons)}
        out["admit_plain"] = {"admitted": plain.admitted, "reasons": list(plain.reasons)}
        return out

    @staticmethod
    def attest_view(result: dict) -> dict:
        view = dict(result)
        for key in ("rtmr3", "raw_472_520", "parser_rtmr3"):
            if isinstance(view.get(key), bytes):
                view[key] = view[key].hex()
        return view

    # -- box calls -------------------------------------------------------------

    def wait_ready(self, principal: Principal, timeout: float = 90) -> dict:
        deadline = time.time() + timeout
        document: object = None
        while time.time() < deadline:
            status, document = self.box.j(principal, "GET", "/v1/box")
            if status == 200 and isinstance(document, dict) and not document["lease"]["draining"]:
                return document
            time.sleep(1)
        raise Abort(f"the box did not finish its start-up drain: {document}")

    def box_view(self, principal: Principal) -> dict:
        status, document = self.box.j(principal, "GET", "/v1/box")
        if status != 200 or not isinstance(document, dict):
            raise Abort(f"GET /v1/box failed: {status} {document}")
        return document

    def exec_in(
        self, principal: Principal, sandbox: str, command: list[str] | str, timeout: int = 30
    ) -> tuple[int, dict]:
        status, document = self.box.j(
            principal,
            "POST",
            f"/v1/sandboxes/{sandbox}/exec",
            {"command": command, "timeout_seconds": timeout},
            timeout=timeout + 60,
        )
        return status, document if isinstance(document, dict) else {"raw": document}

    def docker_root_on_scratch(self) -> bool:
        root = sh(["docker", "info", "--format", "{{.DockerRootDir}}"]).stdout.strip()
        return root.startswith(SCRATCH_MOUNT + "/")

    # -- phases ----------------------------------------------------------------

    def phase_pre_luks(self) -> None:
        r = self.report
        root = sh(["docker", "info", "--format", "{{.DockerRootDir}}"]).stdout.strip()
        fs = (
            sh(["findmnt", "-no", "SOURCE,FSTYPE", "--target", root]).stdout.strip() if root else ""
        )
        r.info("a.0", "docker data root before the LUKS switch", f"{root} on {fs}")
        if not self.local and self.docker_root_on_scratch():
            r.skip(
                "a.1",
                "startup refuses docker data root on plain ext4",
                "docker is already on the LUKS mount (setup ran before); see the first run's report",
            )
            return
        extra = {"E2E_LOCAL_SCRATCH": "plain"} if self.local else None
        status, detail, _ = self.start_worker("pre-luks", extra_env=extra)
        text = detail if isinstance(detail, str) else json.dumps(detail)
        r.check(
            "a.1",
            "startup refuses docker data root on plain ext4",
            status == "refused" and "TEE box storage" in text and "dm-crypt with integrity" in text,
            f"{status}: {text}",
        )

    def phase_main(self) -> None:
        r = self.report
        box = self.box
        if self.local and not self.args.local_keep_boot:
            # A local "relaunch": fresh state tmpfs and RTMR3 at zero.
            shutil.rmtree(self.tmpfs_dir, ignore_errors=True)
            self.tmpfs_dir.mkdir(parents=True)
            os.chmod(self.tmpfs_dir, 0o700)
            self.rtmr_path.write_bytes(ZERO48)
        from cathedral.central_access import TEE_BOX_CENTRAL_SCOPES, sign_revocations
        from cathedral.policy_registry import canonical_json
        from cathedral.tee_box.boot import RTMR3_CONSUMED
        from cathedral.tee_box.measured_root import mrconfigid_for_root_keys
        from cathedral.tee_box.storage import (
            StorageError,
            default_storage_probe,
            require_protected_scratch,
        )

        all_scopes = sorted(TEE_BOX_CENTRAL_SCOPES)
        if not self.local and not self.docker_root_on_scratch():
            raise Abort("docker's data root is not on the LUKS mount; run setup.sh luks first")

        # ---- a: storage and the measured root at startup --------------------
        status, detail, _ = self.start_worker("real-binding", binding="real")
        text = str(detail)
        if self.local:
            r.info("a.2", "real TDREPORT reader refuses (no TD locally)", f"{status}: {text}")
        else:
            # Polaris launches with MRCONFIGID zero; any other launch value still
            # cannot name this run's freshly minted root.
            r.check(
                "a.2",
                "real TDREPORT reader refuses (Polaris MRCONFIGID is not our root)",
                status == "refused"
                and "TEE box central root" in text
                and ("MRCONFIGID is zero" in text or "does not match MRCONFIGID" in text),
                f"{status}: {text}",
            )
        other = canonical_json(
            {
                "cathedral-e2e-other": base64.b64encode(
                    hashlib.sha256(secrets.token_bytes(32)).digest()
                ).decode()
            }
        )
        status, detail, _ = self.start_worker("wrong-root", binding=mrconfigid_for_root_keys(other))
        r.check(
            "a.3",
            "an MRCONFIGID for another root key file refuses",
            status == "refused" and "does not match MRCONFIGID" in str(detail),
            f"{status}: {detail}",
        )
        disk_state = self.work / "disk-state"
        disk_state.mkdir(exist_ok=True)
        status, detail, _ = self.start_worker(
            "state-on-disk", state=str(disk_state / "central.sqlite")
        )
        r.check(
            "a.4",
            "central state on a disk path refuses (must be tmpfs/ramfs)",
            status == "refused" and "must be on tmpfs or ramfs" in str(detail),
            f"{status}: {detail}",
        )
        try:
            detail = require_protected_scratch("/", default_storage_probe())
            r.check("a.5", "storage probe pointed at / (plain root disk) refuses", False, detail)
        except StorageError as exc:
            r.check("a.5", "storage probe pointed at / (plain root disk) refuses", True, str(exc))

        status, facts, worker = self.start_worker("main")
        if status != "started":
            r.check(
                "a.6",
                "startup with docker on LUKS2 integrity and state on tmpfs",
                False,
                f"{status}: {facts}",
            )
            raise Abort("the worker did not start")
        tee = facts.get("tee_box") or {}
        storage = tee.get("storage") or {}
        scratch = str(storage.get("scratch"))
        r.check(
            "a.6",
            "startup accepts docker data root on dm-crypt with integrity",
            "dm-crypt" in scratch
            and "integrity" in scratch
            and ("aead" in scratch or "hmac" in scratch),
            storage,
        )
        r.check(
            "a.7",
            "central state is on tmpfs",
            storage.get("central_state") == "central state on tmpfs",
            storage.get("central_state"),
        )
        r.check("a.8", "no swap", storage.get("swap") == "no swap", storage.get("swap"))
        r.check(
            "a.9",
            "runsc registered with systrap",
            tee.get("runtime") == "runsc at /usr/local/bin/runsc with systrap",
            tee.get("runtime"),
        )
        r.check(
            "a.10",
            "measured root: digest and key id of the injected binding",
            tee.get("central_root_digest") == self.tool.root_digest
            and tee.get("central_root_key_ids") == [ROOT_KEY_ID]
            and tee.get("central_root_keys") == str(self.root_keys_target),
            {
                k: tee.get(k)
                for k in ("central_root_digest", "central_root_key_ids", "central_root_keys")
            },
        )
        egress = tee.get("egress") or {}
        r.check(
            "a.11",
            "egress table applied and verified at startup",
            egress.get("enforced") is True and "internet" in (tee.get("network_modes") or []),
            {"egress": egress, "network_modes": tee.get("network_modes")},
            local_info=True,
        )
        r.info(
            "a.x",
            "startup facts",
            {k: tee.get(k) for k in ("boot", "box_addresses", "disk_quota", "capacity")},
        )
        if not self.local:
            state_fs = sh(
                ["findmnt", "-no", "FSTYPE,OPTIONS", "--target", str(Path(self.state).parent)]
            ).stdout.strip()
            dev = sh(["findmnt", "-no", "MAJ:MIN", SCRATCH_MOUNT]).stdout.strip()
            uuid = Path(f"/sys/dev/block/{dev}/dm/uuid").read_text().strip() if dev else ""
            name = Path(f"/sys/dev/block/{dev}/dm/name").read_text().strip() if dev else ""
            table = sh(["dmsetup", "table", name]).stdout.split() if name else []
            if len(table) > 4 and table[2] == "crypt":
                table[4] = "<key>"
            status_text = sh(["cryptsetup", "status", name]).stdout if name else ""
            integrity = [
                line.strip()
                for line in status_text.splitlines()
                if line.strip().startswith(("cipher:", "integrity:", "type:"))
            ]
            r.check(
                "a.12",
                "host cross-check: tmpfs state, LUKS2 dm-crypt uuid, hmac(sha256) integrity",
                state_fs.startswith("tmpfs")
                and uuid.startswith("CRYPT-LUKS2-")
                and any("hmac(sha256)" in line for line in integrity)
                and any(item.startswith("integrity:") for item in table),
                {
                    "state_fs": state_fs,
                    "dm_uuid": uuid,
                    "table": " ".join(table),
                    "cryptsetup": integrity,
                },
            )

        # ---- b: auth gating on the revocation list ---------------------------
        cp = Principal(self.tool, "control-plane", ["tee-box:box", "tee-box:revocations"])
        a = Principal(self.tool, "customer-a", all_scopes)
        view = self.wait_ready(cp)
        r.check(
            "b.1",
            "GET /v1/box is served before any revocation list",
            view["revocations"]["pushed"] is False,
            view["revocations"],
        )
        refusals = {}
        for method, target, body in (
            ("GET", "/v1/lease", None),
            ("POST", "/v1/lease", {"ttl_seconds": 600}),
            ("GET", "/v1/sandboxes", None),
        ):
            status, document = box.j(a, method, target, body)
            refusals[f"{method} {target}"] = (status, reason(document))
        r.check(
            "b.2",
            "with no list pushed, routes get 409 revocation_list_required",
            all(v == (409, "revocation_list_required") for v in refusals.values()),
            refusals,
        )
        rev_base = int(time.time() * 1000)
        fresh_path = self.tool.revocations(rev_base, previous=None, revoke=[])
        stale_doc = sign_revocations(
            root_key_id=ROOT_KEY_ID,
            root_seed=self.tool.root_seed(),
            sequence=rev_base + 1,
            issued_at=datetime.now(UTC).replace(microsecond=0) - timedelta(hours=25),
            revoked=[],
        )
        stale = canonical_json(stale_doc)
        status, document = box.call(cp, "POST", "/v1/box/revocations", stale)
        after = box.j(a, "GET", "/v1/lease")
        r.check(
            "b.3",
            "a stale list (issued 25 h ago) is refused 409 revocations_stale; still closed",
            status == 409
            and reason(document) == "revocations_stale"
            and after[0] == 409
            and reason(after[1]) == "revocation_list_required",
            {"push": (status, document), "then GET /v1/lease": (after[0], reason(after[1]))},
        )
        status, document = box.call(cp, "POST", "/v1/box/revocations", fresh_path.read_bytes())
        view = self.box_view(cp)
        r.check(
            "b.4",
            "a fresh signed list is accepted",
            status == 200
            and view["revocations"]["fresh"] is True
            and view["revocations"]["sequence"] == rev_base,
            {"push": (status, document), "revocations": view["revocations"]},
        )
        status, document = box.j(a, "GET", "/v1/lease")
        r.check("b.5", "the fresh list opens the routes", status == 200, (status, document))
        status, document = box.call(cp, "POST", "/v1/box/revocations", stale)
        after = box.j(a, "GET", "/v1/lease")
        view = self.box_view(cp)
        r.check(
            "b.6",
            "a stale list pushed after a fresh one is refused 409; the fresh one stays",
            status == 409
            and reason(document) == "revocations_stale"
            and after[0] == 200
            and view["revocations"]["sequence"] == rev_base,
            {
                "push": (status, document),
                "GET /v1/lease": after[0],
                "sequence": view["revocations"]["sequence"],
            },
        )

        # ---- d (before): RTMR3 at zero and a fresh-boot admission --------------
        rtmr = self.rtmr3()
        boot = self.box_view(a)["boot"]
        consumed_already = rtmr == RTMR3_CONSUMED
        if rtmr == ZERO48:
            r.check(
                "d.1",
                "RTMR3 reads zero before the first lease (sysfs and /v1/box)",
                boot["rtmr3"] == "00" * 48
                and boot["consumed"] is False
                and boot["rtmr3_extended"] is False,
                {"sysfs": rtmr.hex(), "box": boot},
            )
            if self.local:
                r.skip(
                    "d.2",
                    "fresh quote shows RTMR3 zero and admit(require_fresh_boot) admits",
                    "no configfs-tsm locally; the saved quote is a consumed one",
                )
            else:
                result = self.attest("fresh")
                ok = (
                    result["rtmr3"] == ZERO48
                    and result["report_data_bound"]
                    and result.get("admit_fresh_boot", {}).get("admitted") is True
                )
                r.check(
                    "d.2",
                    "fresh quote: RTMR3 zero, bound to nonce/hotkey/TLS key, "
                    "admit(require_fresh_boot=True) admits",
                    ok,
                    self.attest_view(result),
                )
        elif consumed_already:
            r.skip(
                "d.1",
                "RTMR3 reads zero before the first lease",
                "this boot was already consumed by an earlier harness run; relaunch the VM to see zero",
            )
            r.skip("d.2", "fresh quote admitted with require_fresh_boot", "boot already consumed")
        else:
            r.check(
                "d.1",
                "RTMR3 reads zero before the first lease",
                False,
                f"RTMR3 holds an unexpected value {rtmr.hex()}",
            )

        # ---- c: lease, import, create under runsc, exec, delete ----------------
        status, document = box.j(a, "POST", "/v1/lease", {"ttl_seconds": 1800})
        if not r.check(
            "c.1",
            "customer A leases the box",
            status == 200 and document["lease"]["holder"] == a.caller,
            (status, document),
        ):
            raise Abort("customer A could not lease")
        status, document = box.j(
            a,
            "POST",
            "/v1/images/import",
            {"digest": self.image_digest, "reference": self.image_ref},
            timeout=900,
        )
        got = box.j(a, "GET", f"/v1/images/{self.image_digest}")
        r.check(
            "c.2",
            "image imported by digest",
            status == 200 and document.get("digest") == self.image_digest and got[0] == 200,
            {"import": (status, document), "get": got},
        )
        status, document = box.j(
            a,
            "POST",
            "/v1/sandboxes",
            {
                "image_id": self.image_digest,
                "network": "deny_all",
                "lifetime_seconds": 900,
                "labels": {"e2e": "c"},
            },
        )
        if not r.check("c.3", "sandbox created (deny_all)", status == 201, (status, document)):
            raise Abort("sandbox create failed")
        sandbox = document["id"]
        name = f"cathsbx-{sandbox}"
        inspect = sh(
            [
                "docker",
                "inspect",
                "--format",
                "{{.HostConfig.Runtime}} {{.Image}} {{.HostConfig.NetworkMode}}",
                name,
            ]
        )
        runtime, _, rest = inspect.stdout.strip().partition(" ")
        image_id = sh(
            [
                "docker",
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                f"{self.image_ref}@{self.image_digest}",
            ]
        ).stdout.strip()
        expected_runtime = "runc" if self.local else "runsc"
        r.check(
            "c.4",
            f"container runs under {expected_runtime} (docker inspect), from the pinned image id",
            runtime == expected_runtime and rest.split(" ")[0] == image_id,
            {"inspect": inspect.stdout.strip() or inspect.stderr.strip(), "image_id": image_id},
        )
        status, document = self.exec_in(a, sandbox, ["echo", "hello"])
        r.check(
            "c.5",
            "exec echo hello returns hello",
            status == 200
            and document.get("stdout") == "hello\n"
            and document.get("exit_code") == 0,
            (status, document),
        )
        status, document = self.exec_in(a, sandbox, "dmesg 2>&1 | head -3; uname -a")
        stdout = str(document.get("stdout"))
        r.check(
            "c.6",
            "the kernel inside the sandbox is gVisor (dmesg / uname)",
            status == 200 and ("gVisor" in stdout or " 4.4.0 " in stdout),
            (status, document),
            local_info=True,
        )
        status, document = box.j(a, "GET", "/v1/sandboxes?label=e2e=c")
        r.check(
            "c.7",
            "list by label shows the sandbox",
            status == 200 and [row["id"] for row in document["sandboxes"]] == [sandbox],
            (status, document),
        )
        status, document = box.j(a, "DELETE", f"/v1/sandboxes/{sandbox}")
        got = box.j(a, "GET", f"/v1/sandboxes/{sandbox}")
        gone = sh(["docker", "inspect", name])
        r.check(
            "c.8",
            "sandbox deleted (404 after, container gone)",
            status == 200 and got[0] == 404 and gone.returncode != 0,
            {"delete": (status, document), "get": got[0], "docker": gone.stderr.strip()[:120]},
        )

        # ---- d (after): RTMR3 consumed, quote shows it, admission refuses -------
        rtmr = self.rtmr3()
        boot = self.box_view(a)["boot"]
        r.check(
            "d.3",
            "RTMR3 holds RTMR3_CONSUMED after the first lease (sysfs and /v1/box)",
            rtmr == RTMR3_CONSUMED
            and boot["rtmr3"] == RTMR3_CONSUMED.hex()
            and boot["rtmr3_extended"] is True
            and boot["consumed_by_caller"] is True,
            {"sysfs": rtmr.hex(), "expected": RTMR3_CONSUMED.hex(), "box": boot},
        )
        result = self.attest("consumed")
        view = self.attest_view(result)
        r.check(
            "d.4",
            "a fresh quote carries RTMR3_CONSUMED (body 472:520, parser and admission parser)",
            result["rtmr3"] == RTMR3_CONSUMED
            and result["raw_472_520"] == RTMR3_CONSUMED
            and result["parser_rtmr3"] == RTMR3_CONSUMED
            and result["debug"] is False,
            view,
        )
        if "admit_fresh_boot" in result:
            r.check(
                "d.5",
                "strict verifier + admit(require_fresh_boot=True) refuses with boot_consumed only; "
                "without it admits",
                result["admit_fresh_boot"] == {"admitted": False, "reasons": ["boot_consumed"]}
                and result["admit_plain"]["admitted"] is True
                and result["report_data_bound"],
                view,
            )
        elif self.local:
            r.info(
                "d.5",
                "verifier path (local: the saved quote's REPORT_DATA preimage is unknown)",
                result.get("verifier"),
            )
        else:
            r.check(
                "d.5",
                "strict verifier + admit(require_fresh_boot=True) refuses with boot_consumed",
                False,
                f"verifier path unavailable ({result.get('verifier')}); the admission "
                f"parser reads RTMR3 {'consumed' if result['parser_rtmr3'] == RTMR3_CONSUMED else 'NOT consumed'}",
            )
        if self.local and self.args.selftest_verify:
            result = self.attest("selftest", selftest=True)
            r.check(
                "d.6",
                "selftest: full verifier + admission path on the saved quote",
                result.get("admit_fresh_boot") == {"admitted": False, "reasons": ["boot_consumed"]}
                and result.get("admit_plain", {}).get("admitted") is True,
                self.attest_view(result),
            )

        # ---- e: egress from an internet sandbox --------------------------------
        view = self.box_view(a)
        r.check(
            "e.1",
            "internet mode offered, egress enforced",
            "internet" in view["network_modes"] and view["egress"].get("enforced") is True,
            {
                "modes": view["network_modes"],
                "egress": {k: view["egress"].get(k) for k in ("enforced", "enforcement_error")},
            },
            local_info=True,
        )
        status, document = box.j(
            a,
            "POST",
            "/v1/sandboxes",
            {
                "image_id": self.image_digest,
                "network": "internet",
                "lifetime_seconds": 900,
                "labels": {"e2e": "e"},
            },
        )
        if not r.check(
            "e.2",
            "internet sandbox created (tc cap attached and verified)",
            status == 201,
            (status, document),
        ):
            self.egress_diagnostics()
        else:
            self.egress_probes(a, document["id"])

        # ---- g: wrong scope, wrong target, revoked delegation ------------------
        s = Principal(self.tool, "scope-box-only", ["tee-box:box"])
        status, document = box.j(s, "GET", "/v1/box")
        r.check("g.1", "a box-only delegation reaches GET /v1/box (control)", status == 200, status)
        wrong = {
            "POST /v1/lease": box.j(s, "POST", "/v1/lease", {"ttl_seconds": 60})[0],
            "GET /v1/sandboxes": box.j(s, "GET", "/v1/sandboxes")[0],
            "POST /v1/box/revocations": box.call(
                s, "POST", "/v1/box/revocations", fresh_path.read_bytes()
            )[0],
        }
        r.check(
            "g.2",
            "routes outside the delegation's scopes get 401",
            all(v == 401 for v in wrong.values()),
            wrong,
        )
        status, _ = box.j(a, "GET", "/v1/lease", sign_target="/v1/box")
        r.check(
            "g.3",
            "a request signed for another route (GET /v1/box sent to /v1/lease) gets 401",
            status == 401,
            status,
        )
        cp.delegate()  # below both principals minted next, so neither is "older"
        control = Principal(self.tool, "revocation-control", ["tee-box:box"])
        control.delegate()
        revoked = Principal(self.tool, "revoked", ["tee-box:box"], auto_refresh=False)
        revoked.delegate()
        tool_says = self.tool.verify_delegation(revoked.path)
        list_path = self.tool.revocations(
            rev_base + 2, previous=fresh_path, revoke=[revoked.digest]
        )
        push = box.call(cp, "POST", "/v1/box/revocations", list_path.read_bytes())
        ok_control = box.j(control, "GET", "/v1/box")[0]
        refused = box.j(revoked, "GET", "/v1/box")[0]
        r.check(
            "g.4",
            "a revoked delegation gets 401 (a sibling delegation minted before it works)",
            push[0] == 200
            and ok_control == 200
            and refused == 401
            and tool_says.startswith("CENTRAL_DELEGATION_VALID"),
            {
                "push": push,
                "sibling": ok_control,
                "revoked": refused,
                "offline verify of the revoked delegation": tool_says.splitlines()[0],
                "revoked_digest": revoked.digest,
            },
        )

        # ---- f: one customer per boot ------------------------------------------
        status, document = box.j(a, "DELETE", "/v1/lease")
        boot = self.box_view(a)["boot"]
        r.check(
            "f.1",
            "customer A releases; the box reports needs_relaunch",
            status == 200
            and document.get("released") is True
            and document.get("needs_relaunch") is True
            and boot["needs_relaunch"] is True
            and boot["last_released_at"] is not None,
            {"release": document, "boot": boot},
        )
        b = Principal(self.tool, "customer-b", all_scopes)
        lease_b = box.j(b, "POST", "/v1/lease", {"ttl_seconds": 600})
        list_b = box.j(b, "GET", "/v1/sandboxes")
        r.check(
            "f.2",
            "customer B (another delegated key) gets 409 relaunch_required",
            lease_b[0] == 409
            and reason(lease_b[1]) == "relaunch_required"
            and list_b[0] == 409
            and reason(list_b[1]) == "relaunch_required",
            {"POST /v1/lease": lease_b, "GET /v1/sandboxes": (list_b[0], reason(list_b[1]))},
        )
        before = a.delegations
        status, document = box.j(a, "POST", "/v1/lease", {"ttl_seconds": 600})
        rtmr = self.rtmr3()
        r.check(
            "f.3",
            "customer A can lease again (same key, re-delegated); RTMR3 not extended twice",
            status == 200 and document["lease"]["holder"] == a.caller and rtmr == RTMR3_CONSUMED,
            {
                "lease": (status, document),
                "a_redelegated": a.delegations > before,
                "rtmr3": rtmr.hex(),
            },
        )
        status, document = box.j(a, "DELETE", "/v1/lease")
        r.check(
            "f.4",
            "customer A releases again (drain clean)",
            status == 200 and document.get("released") is True,
            document,
        )
        r.info(
            "z",
            "totals",
            {
                "https_calls": box.calls,
                "delegations_minted": {
                    p.name: p.delegations for p in (cp, a, s, control, revoked, b)
                },
            },
        )

    def egress_probes(self, a: Principal, sandbox: str) -> None:
        r = self.report
        route = sh(["ip", "-4", "route", "show", "default"]).stdout.split()
        gateway = route[route.index("via") + 1] if "via" in route else None
        get = sh(["ip", "-4", "route", "get", "1.1.1.1"]).stdout.split()
        box_ip = get[get.index("src") + 1] if "src" in get else None
        net = sh(
            [
                "docker",
                "network",
                "inspect",
                "--format",
                "{{range .IPAM.Config}}{{.Gateway}} {{end}}",
                "cathsbx0",
            ]
        ).stdout.split()
        bridge_gateway = net[0] if net else None
        self.listener = Listener()
        port = self.listener.port
        controls = {
            "metadata": host_http(
                "http://169.254.169.254/computeMetadata/v1/instance/id",
                {"Metadata-Flavor": "Google"},
            )
            if not self.local
            else "skipped locally",
            "gateway": host_http(f"http://{gateway}/") if gateway else "no gateway",
            "gateway_ping": (sh(["ping", "-c", "1", "-W", "2", gateway]).returncode == 0)
            if gateway
            else None,
            "listener_via_box_ip": host_http(f"http://{box_ip}:{port}/") if box_ip else "no box ip",
        }
        r.info(
            "e.0",
            "host-side controls (from the TD itself, outside the sandbox)",
            {
                "gateway": gateway,
                "box_ip": box_ip,
                "bridge_gateway": bridge_gateway,
                "listener_port": port,
                **controls,
            },
        )

        def probe(url: str, header: str | None = None) -> tuple[bool, str]:
            extra = f"--header '{header}' " if header else ""
            script = (
                f"out=$(timeout 10 wget -S -T 8 {extra}-O /dev/null '{url}' 2>&1); "
                f'rc=$?; echo "rc=$rc"; echo "$out" | head -4'
            )
            status, document = self.exec_in(a, sandbox, ["/bin/sh", "-c", script], timeout=25)
            text = str(document.get("stdout", document))
            answered = "HTTP/1." in text or "onnection refused" in text
            return answered, f"exec {status}: {text.strip()}"

        targets = [
            (
                "e.3",
                "sandbox cannot reach GCP metadata 169.254.169.254",
                "http://169.254.169.254/computeMetadata/v1/",
                "Metadata-Flavor: Google",
                False,
            ),
            (
                "e.4",
                f"sandbox cannot reach the VPC gateway {gateway}",
                f"http://{gateway}/" if gateway else None,
                None,
                False,
            ),
            (
                "e.5",
                "sandbox cannot reach the box's own address (host listener)",
                f"http://{box_ip}:{port}/" if box_ip else None,
                None,
                False,
            ),
            (
                "e.6",
                "sandbox cannot reach the bridge gateway (the box, host listener)",
                f"http://{bridge_gateway}:{port}/" if bridge_gateway else None,
                None,
                False,
            ),
            ("e.7", "sandbox reaches 1.1.1.1 (public internet)", "http://1.1.1.1/", None, True),
        ]
        for cid, name, url, header, should_answer in targets:
            if url is None:
                r.skip(cid, name, "address unknown")
                continue
            if self.local and cid in ("e.3", "e.4"):
                r.skip(cid, name, "not probed locally (no enforcement, not a GCP host)")
                continue
            answered, detail = probe(url, header)
            ok = answered == should_answer
            r.check(cid, name, ok, detail, local_info=not should_answer)
        answered, detail = probe("http://one.one.one.one/")
        r.info(
            "e.8",
            "DNS from inside gVisor on the bridge (one.one.one.one by name)",
            f"answered={answered}; {detail}",
        )
        r.info("e.9", "listener connections seen on the host", self.listener.hits)
        status, document = self.box.j(a, "DELETE", f"/v1/sandboxes/{sandbox}")
        r.check("e.10", "internet sandbox deleted", status == 200, (status, document))

    def egress_diagnostics(self) -> None:
        details = {}
        for argv in (
            ["nft", "list", "table", "inet", "cathedral_tee_box_egress"],
            ["docker", "network", "inspect", "cathsbx0"],
            ["ip", "-o", "link", "show", "master", "cathsbx0"],
            ["docker", "ps", "-a", "--filter", f"label=org.cathedral.tee-box.box={BOX_ID}"],
        ):
            result = sh(argv)
            details[" ".join(argv[:3])] = (result.stdout + result.stderr).strip()[:600]
        tail = []
        for worker in self.workers[-1:]:
            tail = worker.stderr[-20:]
        details["worker_stderr_tail"] = "".join(tail)[-1500:]
        self.report.info("e.diag", "egress diagnostics", details)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--phase", choices=("pre-luks", "main"), required=True)
    parser.add_argument("--local", action="store_true", help="developer machine with local fakes")
    parser.add_argument("--src", default=str(HERE / "src" / "sandbox"))
    parser.add_argument("--work", default=None)
    parser.add_argument("--results", default=None)
    parser.add_argument("--port", type=int, default=18443)
    parser.add_argument("--verifier", default=str(HERE / "bin" / "cathedral-tdx-verifier"))
    parser.add_argument("--image-ref", default=DEFAULT_IMAGE_REF)
    parser.add_argument("--image-digest", default=DEFAULT_IMAGE_DIGEST)
    parser.add_argument("--local-quote", default=None, help="local only: a saved configfs quote")
    parser.add_argument(
        "--local-keep-boot",
        action="store_true",
        help="local only: keep the fake RTMR3 and state (a re-run in one boot)",
    )
    parser.add_argument(
        "--selftest-verify",
        action="store_true",
        help="local only: run the verifier+admission path on the saved quote",
    )
    args = parser.parse_args()
    if args.work is None:
        args.work = str(HERE / "local" / "work") if args.local else "/var/lib/cathedral-e2e"
    if not args.local and os.geteuid() != 0:
        raise SystemExit("run as root on the TD (the worker drives docker, nft, tc and RTMR3)")
    if args.local and not args.local_quote:
        raise SystemExit("--local needs --local-quote")
    h = Harness(args)
    code = 0
    try:
        h.setup_common()
        if args.phase == "pre-luks":
            h.phase_pre_luks()
        else:
            h.phase_main()
    except Abort as exc:
        h.report.add("abort", "FAIL", "phase aborted", str(exc))
    except Exception:  # noqa: BLE001
        h.report.add("crash", "FAIL", "harness error", traceback.format_exc())
    finally:
        h.cleanup()
    counts = h.report.counts()
    print(
        f"SUMMARY {args.phase}: "
        + ", ".join(f"{v} {k}" for k, v in sorted(counts.items()))
        + f" -- report {h.report.path}",
        flush=True,
    )
    if counts.get("FAIL"):
        code = 1
    return code


if __name__ == "__main__":
    raise SystemExit(main())

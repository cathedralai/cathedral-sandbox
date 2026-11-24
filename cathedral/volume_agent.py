"""Guest volume agent: workspaces synced as encrypted restic repos (AB#789).

Runs inside the sealed guest, in the receipts front (room_receipts.py, ROOM_VOLUMES=1), and drives
the contract of volume_chain.py against the persistent registry in the API (polariscomputer AB#790,
/v1/cathedral/volumes) and the storage gateway (volume_gateway.py, sub-token per request).

Pieces:

- Pinned restic (RESTIC_VERSION, sha256 of the release .bz2 in room-kit/versions.lock). The agent
  refuses any other version.
- volume-key-install: per boot, the front makes an X25519 key and publishes it signed by the
  attested receipt key (label cathedral.volume-key-install.v1, so it is never a receipt). The owner
  checks that signature against the binding and seals the volume's restic password to it
  (seal_volume_key). Only this boot opens it; the password lives in guest memory only.
- Lease-holder signing route (HolderSigner): the receipt key signs exactly three things for volumes:
  a lease request naming this binding, a sub-token request on this boot's own lease, and a commit
  at head + 1 of a snapshot this agent just stored, on a registry-signed lease that names this
  key. It signs nothing a caller hands it, so the route is not a general signing oracle.
- attach: the new holder checks the chain the registry returned (verify_chain against the pinned
  registry keys) and restores the head snapshot into the workspace. A chain that does not verify
  restores nothing.
- commit: a sub-token for this mount, restic backup of the workspace, sign generation head + 1,
  post. The registry refuses anything but head + 1 from the current holder.
- timer commit (AB#825): CommitTimer commits every attached volume whose workspace changed, every
  ROOM_VOLUME_COMMIT_SECONDS (default 300, 0 = off). The receipt of a commit is the
  registry-signed head it returns (cathedral_volume_head_v1), kept per volume and read with
  GET /room/volume-status. A volume the registry ended (shredded, or its lease handed to another
  boot) is detached, and a shredded one's key is dropped from memory.
- key mode (AB#825): the guest does not care who sealed the key. By default the API holds it and
  seals it to this boot (POST /v1/cathedral/volumes/{id}/key-envelope); with a customer-held key
  the owner seals it with seal_volume_key. Both arrive as the same envelope at /room/volume-key.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote, urlsplit

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cathedral import volume_chain, volume_gateway
from cathedral.volume_chain import VolumeRefused, b64, canonical, make_commit, public_b64, sha, statement_sha256

RESTIC_VERSION = "0.19.1"
RESTIC_URL = "https://github.com/restic/restic/releases/download/v0.19.1/restic_0.19.1_linux_amd64.bz2"
RESTIC_BZ2_SHA256 = "f415415624dcc452f2a02b8c33641791a8c6d6d3b65bbb3543fcf9a25151585c"

HOLDER_REQUEST_SCHEMA = "cathedral_volume_holder_request_v1"
HOLDER_REQUEST_LABEL = b"cathedral.volume-holder-request.v1\n"
KEY_INSTALL_SCHEMA = "cathedral_volume_key_install_v1"
KEY_INSTALL_LABEL = b"cathedral.volume-key-install.v1\n"
KEY_ENVELOPE_SCHEMA = "cathedral_volume_key_envelope_v1"
KEY_HKDF_INFO = b"cathedral.volume-key.v1"
SNAPSHOT_ID_RE = re.compile(r"^[0-9a-f]{64}$")
HTTP_TIMEOUT_SECONDS = 30
RESTIC_TIMEOUT_SECONDS = 3600
COMMIT_SECONDS_DEFAULT = 300
COMMIT_SECONDS_MIN = 30
COMMIT_SECONDS_MAX = 86400
# Registry refusals after which this boot can never commit the volume again: detach it.
DETACH_CODES = frozenset({"volume_shredded", "lease_not_current"})


def _b64d(value) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (TypeError, ValueError, binascii.Error):
        raise VolumeRefused("malformed") from None


def _sign(key: Ed25519PrivateKey, label: bytes, statement: dict) -> dict:
    return {"statement": statement, "signer_ed25519_b64": public_b64(key),
            "signature_b64": b64(key.sign(label + canonical(statement)))}


def _verify(doc, label: bytes, signer_b64: str, code: str) -> dict:
    if not isinstance(doc, dict) or not isinstance(doc.get("statement"), dict):
        raise VolumeRefused("malformed")
    if doc.get("signer_ed25519_b64") != signer_b64:
        raise VolumeRefused(code)
    try:
        volume_chain._public_key(signer_b64).verify(_b64d(doc.get("signature_b64")), label + canonical(doc["statement"]))
    except (InvalidSignature, VolumeRefused):
        raise VolumeRefused(code) from None
    return doc["statement"]


class HolderSigner:
    """What the receipt key signs for volumes. Everything else it is asked for is refused."""

    def __init__(self, receipt_key: Ed25519PrivateKey, binding: dict, registry_keys: list[str],
                 now=time.time):
        self.key = receipt_key
        self.public_b64 = public_b64(receipt_key)
        if binding.get("receipt_key_ed25519_b64") != self.public_b64:
            raise ValueError("the binding does not name this receipt key")
        self.binding = binding
        self.binding_sha256 = sha(canonical(binding))
        self.registry_keys = list(registry_keys)
        self.now = now

    def _request(self, action: str, volume_id: str, **extra) -> dict:
        volume_chain._ident(volume_id, "bad_volume_id")
        return _sign(self.key, HOLDER_REQUEST_LABEL, {"schema": HOLDER_REQUEST_SCHEMA, "action": action,
                                                      "volume_id": volume_id, "issued_at": int(self.now()),
                                                      **extra})

    def lease_request(self, volume_id: str) -> dict:
        return self._request("lease", volume_id, binding_sha256=self.binding_sha256)

    def own_lease(self, lease_doc: dict) -> dict:
        """The statement of a registry-signed lease that names this boot's key and binding."""
        lease = volume_chain._check_signed(lease_doc, volume_chain.LEASE_SCHEMA, self.registry_keys,
                                           "lease_not_signed_by_registry")
        if (lease.get("holder_receipt_key_ed25519_b64") != self.public_b64
                or lease.get("holder_binding_sha256") != self.binding_sha256):
            raise VolumeRefused("lease_not_ours")
        return lease

    def subtoken_request(self, lease_doc: dict) -> dict:
        lease = self.own_lease(lease_doc)
        return self._request("subtoken", lease["volume_id"], lease_id=lease["lease_id"])

    def sign_commit(self, lease_doc: dict, *, generation: int, parent_sha256: str, restic_repo_id: str,
                    restic_snapshot_id: str) -> dict:
        self.own_lease(lease_doc)
        if type(generation) is not int or generation < 1:
            raise VolumeRefused("generation_not_next")
        if not SNAPSHOT_ID_RE.fullmatch(restic_snapshot_id or ""):
            raise VolumeRefused("bad_restic_snapshot_id")
        return make_commit(self.key, lease_doc, generation=generation, parent_sha256=parent_sha256,
                           restic_repo_id=restic_repo_id, restic_snapshot_id=restic_snapshot_id,
                           committed_at=int(self.now()))


def _aad(volume_id: str, key_id: str, binding_sha256: str) -> bytes:
    return canonical({"schema": KEY_ENVELOPE_SCHEMA, "volume_id": volume_id, "key_id": key_id,
                      "binding_sha256": binding_sha256})


def _wrap_key(shared: bytes, ephemeral: bytes, recipient: bytes, aad: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=hashlib.sha256(aad).digest(),
                info=KEY_HKDF_INFO + ephemeral + recipient).derive(shared)


def _raw(key: X25519PublicKey) -> bytes:
    return key.public_bytes(Encoding.Raw, PublicFormat.Raw)


class VolumeKeys:
    """volume-key-install: per-boot X25519 key, restic passwords opened only in guest memory."""

    def __init__(self, signer: HolderSigner):
        self.signer = signer
        self.private = X25519PrivateKey.generate()
        self.public_b64 = b64(_raw(self.private.public_key()))
        self.passwords: dict[str, tuple[str, str]] = {}

    def install_key_document(self) -> dict:
        return _sign(self.signer.key, KEY_INSTALL_LABEL, {
            "schema": KEY_INSTALL_SCHEMA, "x25519_public_b64": self.public_b64,
            "binding_sha256": self.signer.binding_sha256, "issued_at": int(self.signer.now())})

    def install(self, envelope) -> dict:
        if not isinstance(envelope, dict) or envelope.get("schema") != KEY_ENVELOPE_SCHEMA:
            raise VolumeRefused("malformed")
        volume_id = volume_chain._ident(envelope.get("volume_id"), "bad_volume_id")
        key_id = volume_chain._key_id(envelope.get("key_id"))
        if envelope.get("binding_sha256") != self.signer.binding_sha256:
            raise VolumeRefused("envelope_not_for_this_boot")
        ephemeral = _b64d(envelope.get("ephemeral_x25519_b64"))
        try:
            shared = self.private.exchange(X25519PublicKey.from_public_bytes(ephemeral))
        except ValueError:
            raise VolumeRefused("malformed") from None
        aad = _aad(volume_id, key_id, self.signer.binding_sha256)
        wrap = _wrap_key(shared, ephemeral, _raw(self.private.public_key()), aad)
        try:
            password = AESGCM(wrap).decrypt(_b64d(envelope.get("nonce_b64")), _b64d(envelope.get("ciphertext_b64")),
                                            aad)
        except InvalidTag:
            raise VolumeRefused("envelope_does_not_open") from None
        if len(password) < 16:
            raise VolumeRefused("volume_key_too_short")
        self.passwords[volume_id] = (key_id, password.hex())
        return {"volume_id": volume_id, "key_id": key_id, "installed": True}

    def password(self, volume_id: str) -> str:
        if volume_id not in self.passwords:
            raise VolumeRefused("volume_key_not_installed")
        return self.passwords[volume_id][1]


def seal_volume_key(install_doc: dict, binding: dict, *, volume_id: str, key_id: str, secret: bytes) -> dict:
    """Owner side: check the install key is the attested boot's, then seal the volume key to it."""
    statement = _verify(install_doc, KEY_INSTALL_LABEL, binding.get("receipt_key_ed25519_b64"),
                        "install_key_not_signed_by_receipt_key")
    binding_sha256 = sha(canonical(binding))
    if statement.get("schema") != KEY_INSTALL_SCHEMA or statement.get("binding_sha256") != binding_sha256:
        raise VolumeRefused("install_key_wrong_binding")
    recipient = X25519PublicKey.from_public_bytes(_b64d(statement["x25519_public_b64"]))
    ephemeral = X25519PrivateKey.generate()
    eph_raw = _raw(ephemeral.public_key())
    aad = _aad(volume_id, key_id, binding_sha256)
    wrap = _wrap_key(ephemeral.exchange(recipient), eph_raw, _raw(recipient), aad)
    nonce = os.urandom(12)
    return {"schema": KEY_ENVELOPE_SCHEMA, "volume_id": volume_id, "key_id": key_id,
            "binding_sha256": binding_sha256, "ephemeral_x25519_b64": b64(eph_raw), "nonce_b64": b64(nonce),
            "ciphertext_b64": b64(AESGCM(wrap).encrypt(nonce, secret, aad))}


class RegistryError(Exception):
    def __init__(self, status: int, code: str):
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


def _http(method: str, url: str, body: dict | None = None, headers: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as answer:
            return json.loads(answer.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read()).get("detail", {})
            code = detail.get("error", "error") if isinstance(detail, dict) else str(detail)
        except ValueError:
            code = "error"
        raise RegistryError(exc.code, code) from None
    except (urllib.error.URLError, OSError, ValueError):
        # Timeout, refused connection or a non-JSON answer: the request may still have landed.
        raise RegistryError(502, "registry_unreachable") from None


class RegistryClient:
    """The API's lease-holder routes (AB#790). They take no API key: the receipt-key signature is the auth."""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/") + "/v1/cathedral/volumes"

    def subtoken(self, volume_id: str, request_doc: dict) -> dict:
        return _http("POST", f"{self.base}/{quote(volume_id)}/subtoken", {"request": request_doc})["subtoken"]

    def commit(self, volume_id: str, commit_doc: dict) -> dict:
        return _http("POST", f"{self.base}/{quote(volume_id)}/commits", {"commit": commit_doc})["head"]


def restic_version(restic: str) -> str:
    out = subprocess.run([restic, "version"], capture_output=True, text=True, timeout=30)
    match = re.match(r"restic (\S+)", out.stdout)
    return match.group(1) if match else ""


class VolumeAgent:
    def __init__(self, signer: HolderSigner, keys: VolumeKeys, registry: RegistryClient, gateway_url: str,
                 restic: str, cache_dir: str):
        if restic_version(restic) != RESTIC_VERSION:
            raise VolumeRefused("restic_not_pinned")
        self.signer, self.keys, self.registry = signer, keys, registry
        self.gateway = gateway_url.rstrip("/")
        self.restic = restic
        self.cache_dir = cache_dir
        # volume_id -> {"lease": lease_doc, "generation": int, "head_sha256": str, "target": str,
        #               "pending": commit_doc or None}. Set only once the head is restored into target.
        self.mounts: dict[str, dict] = {}
        # The receipts front is a ThreadingHTTPServer, so attach and commit can run at the same time.
        # One lock covers a whole attach (drop, restore, publish) and a whole commit (backup, sign,
        # post): a commit that started on the old mount finishes before a re-attach touches the
        # workspace, and a commit never backs up a restore in progress. One lock rather than one per
        # volume because two volumes may be attached to the same workspace.
        self._lock = threading.Lock()

    def detach(self, volume_id: str, *, forget_key: bool = False) -> None:
        """Stop committing a volume. forget_key also drops its restic password from guest memory."""
        with self._lock:
            self.mounts.pop(volume_id, None)
            if forget_key:
                self.keys.passwords.pop(volume_id, None)

    def _env(self, volume_id: str, token: dict) -> dict:
        parts = urlsplit(self.gateway)
        url = (f"rest:{parts.scheme}://volume:{volume_gateway.encode_token(token)}@{parts.netloc}"
               f"{parts.path}/volumes/{volume_id}/")
        return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": self.cache_dir,
                "RESTIC_REPOSITORY": url, "RESTIC_PASSWORD": self.keys.password(volume_id),
                "RESTIC_CACHE_DIR": self.cache_dir}

    def _restic(self, env: dict, *args: str, cwd: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run([self.restic, *args], env=env, cwd=cwd, capture_output=True, text=True,
                              timeout=RESTIC_TIMEOUT_SECONDS)

    def _token(self, volume_id: str, lease: dict) -> dict:
        return self.registry.subtoken(volume_id, self.signer.subtoken_request(lease))

    def attach(self, grant: dict, target: str) -> dict:
        """Take the lease the registry granted, check the chain, restore the head snapshot into target.

        ``grant`` is the API's lease answer: volume, commits, head and lease. Nothing is restored
        unless the chain verifies against the pinned registry keys and the head is the one it signed.
        """
        with self._lock:
            return self._attach(grant, target)

    def _attach(self, grant: dict, target: str) -> dict:
        lease = self.signer.own_lease(grant.get("lease"))
        volume_id = lease["volume_id"]
        head_commit = volume_chain.verify_chain(grant.get("volume"), grant.get("commits") or [], grant.get("head"),
                                                self.signer.registry_keys)
        head = grant["head"]["statement"]
        if lease.get("base_generation") != head["generation"] or lease.get("base_sha256") != head["head_sha256"]:
            raise VolumeRefused("lease_not_at_head")
        self.keys.password(volume_id)
        # The mount is published only after the restore succeeds: a commit from an empty or half-restored
        # workspace would become the new head. A re-attach drops the old mount for the same reason.
        self.mounts.pop(volume_id, None)
        Path(target).mkdir(parents=True, exist_ok=True)
        restored = None
        if head_commit is not None:
            env = self._env(volume_id, self._token(volume_id, grant["lease"]))
            snapshot = head_commit["restic_snapshot_id"]
            config = self._restic(env, "--no-lock", "cat", "config", "--json")
            if config.returncode != 0 or json.loads(config.stdout).get("id") != head_commit["restic_repo_id"]:
                raise VolumeRefused("restic_repo_not_the_committed_one")
            # commit() backs up "." from the workspace, so the snapshot root is the workspace.
            out = self._restic(env, "--no-lock", "restore", snapshot, "--target", target)
            if out.returncode != 0:
                raise VolumeRefused("restore_failed")
            restored = {"generation": head["generation"], "restic_snapshot_id": snapshot}
        self.mounts[volume_id] = {"lease": grant["lease"], "generation": head["generation"],
                                  "head_sha256": head["head_sha256"], "target": target, "pending": None,
                                  "fingerprint": workspace_fingerprint(target) if head_commit is not None else None}
        return {"volume_id": volume_id, "generation": head["generation"], "restored": restored}

    def commit(self, volume_id: str) -> dict:
        """Back up the mount's workspace and commit it at head + 1. Returns the new signed head."""
        with self._lock:
            return self._commit(volume_id)

    def _commit(self, volume_id: str) -> dict:
        mount = self.mounts.get(volume_id)
        if mount is None:
            raise VolumeRefused("volume_not_attached")
        if mount["pending"] is not None:
            # The last post got no answer. Resend that exact commit: the registry answers an exact resend
            # of its head with the same head, while a fresh backup at the same generation is refused.
            return self._post(volume_id, mount, mount["pending"])
        # Taken before the backup: a file written during it changes the fingerprint, so the next tick commits.
        fingerprint = workspace_fingerprint(mount["target"])
        env = self._env(volume_id, self._token(volume_id, mount["lease"]))
        config = self._restic(env, "--no-lock", "cat", "config", "--json")
        if config.returncode != 0:
            if mount["generation"] != 0:
                raise VolumeRefused("restic_repo_missing")
            init = self._restic(env, "init")
            if init.returncode != 0:
                raise VolumeRefused("restic_init_failed")
            config = self._restic(env, "--no-lock", "cat", "config", "--json")
        repo_id = json.loads(config.stdout)["id"]
        # The lock removal is refused (no delete on a guest token); the snapshot is stored first.
        backup = self._restic(env, "backup", "--json", "--host", "cathedral-volume", ".", cwd=mount["target"])
        # Exit 3 still stores a snapshot, but some files were unreadable: never commit an incomplete one.
        if backup.returncode != 0:
            raise VolumeRefused("backup_failed")
        summary = [json.loads(line) for line in backup.stdout.splitlines() if '"summary"' in line]
        if not summary or not SNAPSHOT_ID_RE.fullmatch(summary[-1].get("snapshot_id", "")):
            raise VolumeRefused("backup_failed")
        commit = self.signer.sign_commit(mount["lease"], generation=mount["generation"] + 1,
                                         parent_sha256=mount["head_sha256"], restic_repo_id=repo_id,
                                         restic_snapshot_id=summary[-1]["snapshot_id"])
        mount["pending_fingerprint"] = fingerprint
        return self._post(volume_id, mount, commit)

    def commit_if_changed(self, volume_id: str) -> dict | None:
        """The timer's commit: None when the workspace is as it was at the last commit or restore."""
        with self._lock:
            mount = self.mounts.get(volume_id)
            if mount is None:
                raise VolumeRefused("volume_not_attached")
            if mount["pending"] is None and workspace_fingerprint(mount["target"]) == mount["fingerprint"]:
                return None
            return self._commit(volume_id)

    def _post(self, volume_id: str, mount: dict, commit: dict) -> dict:
        mount["pending"] = commit
        try:
            head = self.registry.commit(volume_id, commit)
        except RegistryError as exc:
            if exc.status < 500:
                mount["pending"] = None  # a definite refusal: this commit never lands
            raise
        except VolumeRefused:
            mount["pending"] = None
            raise
        mount["pending"] = None
        volume_chain._check_signed(head, volume_chain.HEAD_SCHEMA, self.signer.registry_keys,
                                   "head_not_signed_by_registry")
        if head["statement"]["head_sha256"] != statement_sha256(commit):
            raise VolumeRefused("head_not_our_commit")
        mount["generation"] = head["statement"]["generation"]
        mount["head_sha256"] = head["statement"]["head_sha256"]
        mount["fingerprint"] = mount.pop("pending_fingerprint", None)
        return head


def workspace_fingerprint(target: str) -> str:
    """Digest of every path, type, size and mtime under target: a cheap "did anything change" check."""
    digest = hashlib.sha256()
    root = Path(target)
    if not root.is_dir():
        return ""
    for path in sorted(root.rglob("*")):
        try:
            st = path.lstat()
        except OSError:
            continue
        digest.update(f"{path.relative_to(root)}\0{st.st_mode}\0{st.st_size}\0{st.st_mtime_ns}\n".encode())
    return digest.hexdigest()


def commit_seconds(value) -> int:
    """ROOM_VOLUME_COMMIT_SECONDS: empty is the default, 0 is off, else COMMIT_SECONDS_MIN..MAX."""
    if value in (None, ""):
        return COMMIT_SECONDS_DEFAULT
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        raise RuntimeError("ROOM_VOLUME_COMMIT_SECONDS must be an integer") from None
    if seconds != 0 and not COMMIT_SECONDS_MIN <= seconds <= COMMIT_SECONDS_MAX:
        raise RuntimeError(f"ROOM_VOLUME_COMMIT_SECONDS must be 0 or {COMMIT_SECONDS_MIN}..{COMMIT_SECONDS_MAX}")
    return seconds


class CommitTimer:
    """Commit every attached volume on a timer (AB#825). The signed head each commit returns is its receipt.

    One tick commits the volumes one after another under the agent's lock, so a tick never races an
    attach or a manual commit. A failed tick leaves the volume attached and tries again next tick
    (a lost registry answer is resent as the same commit), except after DETACH_CODES.
    """

    def __init__(self, agent: VolumeAgent, interval_seconds: int, now=time.time):
        self.agent = agent
        self.interval = interval_seconds
        self.now = now
        self.status: dict[str, dict] = {}
        self._status_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def tick(self) -> None:
        for volume_id in list(self.agent.mounts):
            entry = {"checked_at": int(self.now())}
            try:
                head = self.agent.commit_if_changed(volume_id)
            except (VolumeRefused, RegistryError) as refused:
                entry["last_error"] = refused.code
                if refused.code in DETACH_CODES:
                    self.agent.detach(volume_id, forget_key=refused.code == "volume_shredded")
                    entry["detached"] = True
            except Exception as exc:  # noqa: BLE001 one volume's failure never stops the timer
                entry["last_error"] = type(exc).__name__
            else:
                if head is not None:
                    entry.update(receipt=head, generation=head["statement"]["generation"],
                                 committed_at=entry["checked_at"])
            with self._status_lock:
                previous = self.status.get(volume_id, {})
                # Keep the last receipt across ticks that found nothing to commit or failed.
                keep = {k: previous[k] for k in ("receipt", "generation", "committed_at") if k in previous}
                self.status[volume_id] = {**keep, **entry}

    def snapshot(self) -> dict:
        with self._status_lock:
            return json.loads(json.dumps(self.status))

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self.tick()

    def start(self) -> "CommitTimer":
        if self.interval > 0 and self._thread is None:
            self._thread = threading.Thread(target=self._run, name="volume-commit-timer", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)


class FrontRoutes:
    """The receipts front's volume routes (ROOM_VOLUMES=1). room_receipts.py passes path, method, body.

        GET  /room/volume-key-install-key   no bearer: the install key, signed by the receipt key
        POST /room/volume-key               bearer: install a sealed volume key
        POST /room/volume-lease-request     bearer: {"volume_id"} -> the signed lease request
        POST /room/volume-attach            bearer: {"grant", "workspace"} -> verify chain, restore
        POST /room/volume-commit            bearer: {"volume_id"} -> back up, sign head + 1, post
        GET  /room/volume-status            bearer: the timer's last receipt and error per volume
    """

    PATHS = ("/room/volume-key-install-key", "/room/volume-key", "/room/volume-lease-request",
             "/room/volume-attach", "/room/volume-commit", "/room/volume-status")
    WORKSPACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}(/[A-Za-z0-9_.-]{1,128}){0,3}$")

    def __init__(self, agent: VolumeAgent, workspace_root: str, timer: CommitTimer | None = None):
        self.agent = agent
        self.workspace_root = Path(workspace_root)
        self.timer = timer

    def _workspace(self, name) -> str:
        if not isinstance(name, str) or not self.WORKSPACE_RE.fullmatch(name) or ".." in name.split("/"):
            raise VolumeRefused("bad_workspace")
        return str(self.workspace_root / name)

    def handle(self, path: str, method: str, body: bytes | None, authorized: bool) -> tuple[int, dict]:
        try:
            if path == "/room/volume-key-install-key":
                if method != "GET":
                    return 405, {"error": "method_not_allowed"}
                return 200, self.agent.keys.install_key_document()
            if path == "/room/volume-status":
                if not authorized:
                    return 401, {"error": "unauthorized"}
                if method != "GET":
                    return 405, {"error": "method_not_allowed"}
                return 200, {"interval_seconds": self.timer.interval if self.timer else 0,
                             "volumes": self.timer.snapshot() if self.timer else {}}
            if method != "POST":
                return 405, {"error": "method_not_allowed"}
            if not authorized:
                return 401, {"error": "unauthorized"}
            try:
                doc = json.loads(body or b"{}")
            except ValueError:
                return 400, {"error": "malformed"}
            if not isinstance(doc, dict):
                return 400, {"error": "malformed"}
            if path == "/room/volume-key":
                return 200, self.agent.keys.install(doc.get("envelope"))
            if path == "/room/volume-lease-request":
                return 200, {"request": self.agent.signer.lease_request(doc.get("volume_id")),
                             "binding": self.agent.signer.binding}
            if path == "/room/volume-attach":
                return 200, self.agent.attach(doc.get("grant") or {}, self._workspace(doc.get("workspace")))
            if path == "/room/volume-commit":
                return 200, {"head": self.agent.commit(doc.get("volume_id"))}
            return 404, {"error": "not_found"}
        except VolumeRefused as refused:
            return 409, {"error": refused.code}
        except RegistryError as refused:
            return 502 if refused.status >= 500 else 409, {"error": refused.code, "registry_status": refused.status}


def from_env(ledger_key: Ed25519PrivateKey, binding: dict, env) -> FrontRoutes:
    """Build the front's routes from the unit's environment (install.sh, ROOM_VOLUMES=1)."""
    keys = [k for k in env.get("ROOM_VOLUME_REGISTRY_KEYS", "").split(",") if k]
    if not keys:
        raise RuntimeError("ROOM_VOLUMES=1 needs ROOM_VOLUME_REGISTRY_KEYS")
    interval = commit_seconds(env.get("ROOM_VOLUME_COMMIT_SECONDS"))
    signer = HolderSigner(ledger_key, binding, keys)
    cache = env.get("ROOM_VOLUME_CACHE_DIR") or tempfile.mkdtemp(prefix="volume-cache-")
    agent = VolumeAgent(signer, VolumeKeys(signer), RegistryClient(env["ROOM_VOLUME_REGISTRY_URL"]),
                        env["ROOM_VOLUME_GATEWAY_URL"], env.get("ROOM_VOLUME_RESTIC", "/opt/pool-room/bin/restic"),
                        cache)
    return FrontRoutes(agent, env.get("ROOM_VOLUME_WORKSPACES", "/srv/sealed-data/workspaces"),
                       CommitTimer(agent, interval).start())

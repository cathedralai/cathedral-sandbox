#!/usr/bin/env python3
"""Live Intel TDX check: the miner's real evidence against the pinned verifier.

Run inside an Intel TDX guest with configfs-tsm (normally as root). It uses the
same collector the worker uses, ``collect_tdx`` with REPORTDATA v2, and binds a
fresh 32-byte nonce, a miner hotkey and the SHA-256 of a TLS key generated here.
Then it runs ``cathedral-tdx-verifier`` on that quote and checks every verdict
a validator depends on:

1. the correct binding verifies (exit 0) with Intel-verified, quote-bound claims;
2. a different nonce (a replayed quote), a different hotkey (a copied quote),
   a different TLS key (a relayed quote) and a tampered quote all fail (exit 1);
3. with no network, Intel's collateral service is unavailable and the verifier
   reports it as an outage (exit 3), not as an invalid quote.

It prints one line per check and exits 0 only if every check passed. It never
contacts anything but Intel's collateral hosts, through the verifier, and it
writes nothing outside a private temporary directory. A pass proves the
evidence path on this machine; it does not prove registration, chain state or
weights.

    sudo .venv/bin/python scripts/live_tdx_check.py \\
        --verifier /usr/local/bin/cathedral-tdx-verifier
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cathedral.common import ChannelBinding, ChannelBindingType, report_data_v2

EXIT_VALID = 0
EXIT_INVALID = 1
EXIT_COLLATERAL_UNAVAILABLE = 3
VERIFIER_TIMEOUT_SECONDS = 60
# A syntactically valid SS58 hotkey used only as a binding input; the check
# never signs with it and it needs no wallet.
DEFAULT_HOTKEY = "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty"
OTHER_HOTKEY = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
# A quote v4 is a 48-byte header, then the 584-byte TD quote body that the
# quoting enclave signs. Offset 184 is the first byte of MRTD in that body
# (header 48 + TEE_TCB_SVN 16 + MRSEAM 48 + MRSIGNERSEAM 48 + SEAMATTRIBUTES,
# TDATTRIBUTES, XFAM 8 each), so the flip must break the signature, not merely
# an attestation-key field.
TAMPER_OFFSET = 184


@dataclass(frozen=True)
class VerifierRun:
    exit_code: int
    claims: dict[str, object] | None
    stderr: str


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]]


def _default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(command), capture_output=True, timeout=VERIFIER_TIMEOUT_SECONDS, check=False
    )


def run_verifier(
    verifier: Path,
    quote_path: Path,
    report_data: bytes,
    *,
    runner: Runner = _default_runner,
    offline: bool = False,
) -> VerifierRun:
    """Run the pinned verifier once, optionally with no network at all."""

    command = [str(verifier), str(quote_path), report_data.hex()]
    if offline:
        command = ["unshare", "--net", "--map-root-user", *command]
    completed = runner(command)
    claims = None
    if completed.returncode == EXIT_VALID:
        try:
            parsed = json.loads(completed.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        claims = parsed if isinstance(parsed, dict) else None
    return VerifierRun(
        completed.returncode, claims, completed.stderr.decode("utf-8", "replace").strip()
    )


def _binding(digest: bytes) -> ChannelBinding:
    return ChannelBinding(ChannelBindingType.TLS_SPKI_SHA256, digest)


def run_checks(
    quote: bytes,
    *,
    nonce: bytes,
    hotkey: str,
    tls_spki_sha256: bytes,
    verifier: Path,
    workdir: Path,
    runner: Runner = _default_runner,
    check_outage: bool = True,
) -> list[Check]:
    """Every verdict a validator relies on, for one freshly collected quote."""

    quote_path = workdir / "quote.bin"
    quote_path.write_bytes(quote)
    tampered = bytearray(quote)
    tampered[TAMPER_OFFSET] ^= 0x01
    tampered_path = workdir / "quote-tampered.bin"
    tampered_path.write_bytes(bytes(tampered))
    expected = report_data_v2(nonce, hotkey, _binding(tls_spki_sha256))

    def run(path: Path, report_data: bytes, *, offline: bool = False) -> VerifierRun:
        return run_verifier(verifier, path, report_data, runner=runner, offline=offline)

    checks: list[Check] = []
    good = run(quote_path, expected)
    claims = good.claims or {}
    verified = (
        good.exit_code == EXIT_VALID
        and claims.get("intel_verified") is True
        and claims.get("report_data_match") is True
        and claims.get("claims_bound_to_quote") is True
    )
    checks.append(
        Check(
            "real quote with the correct binding verifies",
            verified,
            f"exit {good.exit_code}; tcb_status={claims.get('tcb_status')}; "
            f"measurement={claims.get('measurement')}"
            if verified
            else f"exit {good.exit_code}: {good.stderr}",
        )
    )
    refusals = {
        "a replayed quote (other nonce) is refused": (
            quote_path,
            report_data_v2(secrets.token_bytes(32), hotkey, _binding(tls_spki_sha256)),
        ),
        "a copied quote (other hotkey) is refused": (
            quote_path,
            report_data_v2(nonce, OTHER_HOTKEY, _binding(tls_spki_sha256)),
        ),
        "a relayed quote (other TLS key) is refused": (
            quote_path,
            report_data_v2(nonce, hotkey, _binding(secrets.token_bytes(32))),
        ),
        "a tampered quote is refused": (tampered_path, expected),
    }
    for name, (path, report_data) in refusals.items():
        result = run(path, report_data)
        checks.append(
            Check(
                name,
                result.exit_code == EXIT_INVALID and result.claims is None,
                f"exit {result.exit_code}: {result.stderr}",
            )
        )
    if check_outage:
        outage = run(quote_path, expected, offline=True)
        checks.append(
            Check(
                "with Intel unreachable the verifier reports an outage (exit 3)",
                outage.exit_code == EXIT_COLLATERAL_UNAVAILABLE and outage.claims is None,
                f"exit {outage.exit_code}: {outage.stderr}",
            )
        )
    return checks


def collect_live_quote(nonce: bytes, hotkey: str) -> tuple[bytes, bytes]:
    """Collect real v2 evidence exactly as the worker does; return (quote, SPKI digest)."""

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from cathedral.attest import collect_tdx

    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(spki).digest()
    evidence = collect_tdx(nonce, hotkey, channel_binding=_binding(digest), report_data_version=2)
    return evidence.quote, digest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--verifier", type=Path, required=True, help="cathedral-tdx-verifier")
    parser.add_argument("--hotkey", default=DEFAULT_HOTKEY)
    parser.add_argument(
        "--skip-outage",
        action="store_true",
        help="skip the no-network outage check (needs `unshare --net --map-root-user`)",
    )
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.verifier.is_file() or not os.access(args.verifier, os.X_OK):
        raise SystemExit(f"verifier is not an executable file: {args.verifier}")
    check_outage = not args.skip_outage
    if check_outage and shutil.which("unshare") is None:
        raise SystemExit("`unshare` is required for the outage check; pass --skip-outage")
    nonce = secrets.token_bytes(32)
    quote, spki_digest = collect_live_quote(nonce, args.hotkey)
    with tempfile.TemporaryDirectory(prefix="cathedral-live-tdx-") as workdir:
        os.chmod(workdir, 0o700)
        checks = run_checks(
            quote,
            nonce=nonce,
            hotkey=args.hotkey,
            tls_spki_sha256=spki_digest,
            verifier=args.verifier,
            workdir=Path(workdir),
            check_outage=check_outage,
        )
    passed = all(check.passed for check in checks)
    if args.json:
        print(
            json.dumps(
                {
                    "result": "PASS" if passed else "FAIL",
                    "quote_bytes": len(quote),
                    "checks": [check.__dict__ for check in checks],
                },
                indent=2,
            )
        )
    else:
        for check in checks:
            print(f"{'PASS' if check.passed else 'FAIL'}  {check.name}  ({check.detail})")
        print("LIVE_TDX_CHECK_PASS" if passed else "LIVE_TDX_CHECK_FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""SNP B–F clearout runner for measured tee-box guests (#274).

Runs what we can without the TDX-only quote/RTMR3 path. No E2E_HOST_DATA_HEX.
Records a JSON report for docs/TEE_BOX_SNP_E2E_RESULTS.md.

Usage (as root on measured guest :2225):
  cd /opt/cathedral/sandbox && export PYTHONPATH=$PWD
  unset E2E_HOST_DATA_HEX CATHEDRAL_E2E_HOST_DATA_HEX
  python scripts/tee_box_snp_e2e/run_bf_clear.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = Path(os.environ.get("E2E_SNP_OUT", "/var/lib/cathedral-e2e/snp-bf"))
# setup.sh prepare installs cryptography here; system python3 on measured
# images often has none — phase_a imports cathedral.tee_box → central_access.
HARNESS_VENV_PYTHON = Path(os.environ.get("E2E_VENV_PYTHON", "/opt/cathedral-e2e/venv/bin/python"))


def harness_python() -> str:
    """Prefer the prepare venv so A.launch_bind can import cryptography."""
    if HARNESS_VENV_PYTHON.is_file() and os.access(HARNESS_VENV_PYTHON, os.X_OK):
        return str(HARNESS_VENV_PYTHON)
    return sys.executable


@dataclass
class Check:
    id: str
    verdict: str  # PASS | FAIL | BLOCKED | UNTESTED | SKIP
    detail: str = ""


@dataclass
class Report:
    started_at: str
    host: str
    commit: str
    checks: list[Check] = field(default_factory=list)

    def add(self, id: str, verdict: str, detail: str = "") -> None:
        self.checks.append(Check(id=id, verdict=verdict, detail=detail))
        print(f"[{verdict}] {id}: {detail}", flush=True)


def run(cmd: list[str] | str, **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        shell=isinstance(cmd, str),
        text=True,
        capture_output=True,
        **kwargs,
    )


def git_commit() -> str:
    r = run(["git", "-C", str(ROOT), "rev-parse", "HEAD"])
    return r.stdout.strip() if r.returncode == 0 else "unknown"


def ensure_no_inject(report: Report) -> bool:
    bad = [k for k in ("E2E_HOST_DATA_HEX", "CATHEDRAL_E2E_HOST_DATA_HEX") if os.environ.get(k)]
    if bad:
        report.add("inject", "FAIL", f"inject env set: {bad}")
        return False
    report.add("inject", "PASS", "no HOST_DATA inject env")
    return True


def phase_a(report: Report) -> None:
    py = harness_python()
    # Ensure cryptography is present before blaming launch bind.
    probe = run([py, "-c", "import cryptography; print(cryptography.__version__)"])
    if probe.returncode != 0:
        report.add(
            "A.launch_bind",
            "FAIL",
            f"python={py} missing cryptography; run: "
            f"TEE=snp bash scripts/tee_box_tdx_e2e/setup.sh prepare "
            f"(detail: {(probe.stdout + probe.stderr)[-200:]})",
        )
        return
    r = run(
        [
            py,
            str(ROOT / "scripts/tee_box_snp_e2e/phase_a_launch_bind.py"),
            "--root-keys",
            "/usr/share/cathedral/central-root-keys.json",
        ],
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0 and "phase_a_launch_bind=PASS" in out:
        report.add("A.launch_bind", "PASS", f"HOST_DATA+AMD+#275 via {py}")
    else:
        report.add("A.launch_bind", "FAIL", out[-500:])


def phase_b_prep(report: Report) -> None:
    env = os.environ.copy()
    env["TEE"] = "snp"
    r = run(
        ["bash", str(ROOT / "scripts/tee_box_tdx_e2e/setup.sh"), "prepare"],
        env=env,
    )
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0:
        report.add("B.prepare", "PASS", "setup.sh prepare (SNP)")
    else:
        report.add("B.prepare", "FAIL", out[-800:])
        return
    ver = run(["runsc", "--version"])
    v = ver.stdout + ver.stderr
    if "20261005.0" in v:
        report.add("B.runsc_pin", "PASS", "runsc release-20261005.0")
    else:
        report.add("B.runsc_pin", "FAIL", v[:200])


def phase_b_luks(report: Report) -> None:
    env = os.environ.copy()
    env["TEE"] = "snp"
    env.setdefault("SCRATCH_GIB", "1")
    env.setdefault("SCRATCH_IMG", "/tmp/cathedral-scratch.img")
    r = run(
        ["bash", str(ROOT / "scripts/tee_box_tdx_e2e/setup.sh"), "luks"],
        env=env,
    )
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0:
        report.add("B.a_luks", "PASS", "LUKS2 integrity scratch + docker root")
    else:
        report.add("B.a_luks", "FAIL", out[-800:])


def phase_b_storage_basics(report: Report) -> None:
    swaps = run("grep -vc '^Filename' /proc/swaps || true")
    n = int((swaps.stdout or "0").strip() or "0")
    if n == 0:
        report.add("B.a_no_swap", "PASS", "no swap")
    else:
        report.add("B.a_no_swap", "FAIL", f"swaps={n}")
    state = Path("/run/cathedral-tee-box")
    if state.is_dir():
        fstype = run(["findmnt", "-no", "FSTYPE", str(state)])
        if "tmpfs" in (fstype.stdout or ""):
            report.add("B.a_state_tmpfs", "PASS", str(state))
        else:
            report.add("B.a_state_tmpfs", "FAIL", fstype.stdout.strip())
    else:
        report.add("B.a_state_tmpfs", "FAIL", "missing state dir")


def phase_b_runsc_lifecycle(report: Report) -> None:
    # Minimal create/exec/delete under runsc via docker.
    name = f"cathedral-e2e-{int(time.time())}"
    pull = run(
        [
            "docker",
            "pull",
            "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
        ]
    )
    if pull.returncode != 0:
        report.add("B.c_pull", "FAIL", (pull.stderr or pull.stdout)[-300:])
        return
    report.add("B.c_pull", "PASS", "alpine by digest")
    run_c = run(
        [
            "docker",
            "run",
            "--rm",
            "--runtime=runsc",
            "--name",
            name,
            "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
            "uname",
            "-a",
        ]
    )
    out = (run_c.stdout + run_c.stderr).strip()
    if run_c.returncode == 0 and "gvisor" in out.lower():
        report.add("B.c_runsc_exec", "PASS", out[:200])
    elif run_c.returncode == 0:
        report.add("B.c_runsc_exec", "PASS", f"uname ok: {out[:200]}")
    else:
        report.add("B.c_runsc_exec", "FAIL", out[-400:])


def phase_b_d_blocked(report: Report) -> None:
    report.add(
        "B.d_fresh_boot_hw",
        "BLOCKED",
        "no RTMR3-class register on SNP; SoftwareLeaseRegister is guest-local only "
        "(docs/TEE_BOX_SERVICE.md)",
    )


def phase_rest_untested(report: Report) -> None:
    for cid, why in (
        ("B.b_revocation", "central-access freshness matrix not run in this clearout"),
        ("B.e_egress", "nft/tc egress matrix not run in this clearout"),
        ("B.f_one_customer", "needs full tee-box worker lease path"),
        ("B.g_scope_401", "needs full tee-box worker"),
        ("C.receipts", "Polaris chain / capacity receipt not exercised here"),
        ("D.fork_density", "runsc CoW / checkpoint not run"),
        ("E.customer_formats", "customer verifiers not run"),
        ("F.bundle", "partial — this JSON is the clearout bundle"),
    ):
        report.add(cid, "UNTESTED", why)


def main() -> int:
    if os.geteuid() != 0:
        print("run as root on the measured SNP guest", file=sys.stderr)
        return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report = Report(
        started_at=datetime.now(UTC).isoformat(),
        host=run("hostname").stdout.strip(),
        commit=git_commit(),
    )
    if not ensure_no_inject(report):
        return 1
    phase_a(report)
    phase_b_prep(report)
    if any(c.id == "B.prepare" and c.verdict == "PASS" for c in report.checks):
        phase_b_storage_basics(report)
        phase_b_luks(report)
        phase_b_runsc_lifecycle(report)
    phase_b_d_blocked(report)
    phase_rest_untested(report)

    path = OUT_DIR / f"report-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    path.write_text(json.dumps(asdict(report), indent=2) + "\n")
    summary = {}
    for c in report.checks:
        summary[c.verdict] = summary.get(c.verdict, 0) + 1
    print("SUMMARY", summary, "report", path, flush=True)
    # FAIL only on hard failures in A/B.prepare/runsc; BLOCKED/UNTESTED ok
    hard = [c for c in report.checks if c.verdict == "FAIL"]
    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main())

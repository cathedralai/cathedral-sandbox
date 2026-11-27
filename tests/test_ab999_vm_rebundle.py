"""AB#999 VM6, host side: rebundle (VM runtime spec r3 7.5 step 1) in room-kit/vm/vm_ctl.py.
The fake host of test_ab991_vm_runtime (no KVM, no root), plus a host root for the vm_gates.py
helpers rebundle shares with start (the host file's verified builds, QEMU, the kernel release)."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from test_ab991_vm_runtime import CTL, KIT, host  # noqa: F401  (the fixture)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


measure = _load("vm_measure_rebundle_test", KIT / "vm_measure.py")

# sev-snp-measure stand-in whose answer depends on what it measures: a kernel fix moves it.
MEASURE_TOOL = '''#!/usr/bin/env python3
import hashlib, sys
a = sys.argv[1:]
if a == ["--version"]:
    print("sev-snp-measure 0.0.12")
    sys.exit(0)
h = hashlib.sha384()
for flag in ("--ovmf", "--kernel", "--initrd"):
    with open(a[a.index(flag) + 1], "rb") as f:
        h.update(f.read())
h.update(a[a.index("--append") + 1].encode())
h.update(a[a.index("--vcpus") + 1].encode())
print(h.hexdigest())
'''


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def op(n: int) -> str:
    return "%032x" % (0xA5000000 + n)


QEMU_BYTES = b"qemu-system-x86_64 stand-in"
RELEASE = "6.8.0-cathedral"


class Site:
    """The fake host plus what rebundle needs: B2 with the same base root (a kernel fix), B3 with
    another base root, B4 on disk but not enabled, B5 enabled with no verified build. The host
    file is the one both vm_ctl.py and vm_gates.py read, as on a host (one path)."""

    def __init__(self, fake_host):
        self.h = fake_host
        tool = fake_host.bin / "sev-snp-measure"
        tool.write_text(MEASURE_TOOL)
        tool.chmod(0o755)
        gates = fake_host.root.parent / "gates-root"
        self.config = gates / "etc" / "cathedral" / "snp-vm-host.json"
        self.qemu = gates / "usr" / "bin" / "qemu-system-x86_64"
        for path, data in ((self.config, fake_host.config.read_bytes()), (self.qemu, QEMU_BYTES),
                           (gates / "proc" / "sys" / "kernel" / "osrelease", RELEASE.encode() + b"\n")):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o644)  # vm_gates.read_protected: not group or world writable
        fake_host.environ.update(VM_HOST_CONFIG=str(self.config), VM_GATES_ROOT=str(gates))
        self.b1 = fake_host.bundle
        self.b2 = self.bundle("kernel-fix", kernel_byte=1)
        self.b3 = self.bundle("other-base", verity="cd" * 32)
        self.b4 = self.bundle("not-enabled", kernel_byte=2, enable=False)
        self.b5 = self.bundle("unverified", kernel_byte=3, verify=False)
        self.verify(self.b1)

    def edit_config(self, fn) -> None:
        cfg = json.loads(self.config.read_text())
        fn(cfg)
        self.config.write_text(json.dumps(cfg))

    def verify(self, bundle: str, vcpus: list | None = None) -> None:
        """A verified build of bundle for this host's QEMU and kernel (spec 8.3)."""
        build = {"qemu_sha256": hashlib.sha256(QEMU_BYTES).hexdigest(), "qemu_version": "9.2.0",
                 "kernel_release": RELEASE, "vcpus": vcpus or [1]}
        self.edit_config(lambda cfg: cfg.setdefault("verified", {}).update({bundle: [build]}))

    def bundle(self, label: str, kernel_byte: int = 0, verity: str | None = None, enable: bool = True,
               verify: bool = True, cpu_family: str | None = None) -> str:
        bundles = self.h.root / "bundles"
        staging = self.h.root.parent / f"staging-{label}"
        shutil.copytree(bundles / self.h.bundle, staging)
        manifest = json.loads((staging / "manifest.json").read_bytes())
        manifest["label"] = label
        if kernel_byte:
            kernel = bytearray((staging / "vmlinuz").read_bytes())
            kernel[-1] ^= kernel_byte
            (staging / "vmlinuz").write_bytes(bytes(kernel))
            manifest["sha256"]["vmlinuz"] = hashlib.sha256(kernel).hexdigest()
        if verity:
            manifest["base_root_verity"] = verity
        if cpu_family:
            manifest["cpu_family"] = cpu_family
        raw = measure.canonical(manifest)
        (staging / "manifest.json").write_bytes(raw)
        bundle = hashlib.sha256(raw).hexdigest()
        staging.rename(bundles / bundle)
        if enable:
            self.edit_config(lambda cfg: cfg["bundles"].append(bundle))
        if verify:
            self.verify(bundle)
        return bundle

    @property
    def d(self) -> Path:
        return self.h.root / "vm1"

    def unit(self) -> Path:
        return self.h.units / "cathedral-vm-vm1.service"

    def launch(self) -> dict:
        return json.loads((self.d / "launch.json").read_text())

    def env(self) -> dict:
        return dict(line.split("=", 1) for line in (self.d / "vm.env").read_text().splitlines())

    def files(self) -> dict:
        return {p.name: sha(p) for p in (self.d / "launch.json", self.d / "vm.env", self.unit())}

    def rebundle(self, gen: int, dst: str, expect: int, op_id: str):
        return self.h.ctl(*argv(gen, dst, expect, op_id))

    def binds(self, bundle: str) -> bool:
        return any(line.startswith("BindReadOnlyPaths=") and str(self.h.root / "bundles" / bundle) in line.split()
                   for line in self.unit().read_text().splitlines())

    def ran_once(self) -> None:
        """Generation 1 authorized, started and stopped: closed, the state a rebundle needs."""
        assert self.h.ctl("authorize", "vm1", str(2**33), "1")[0] == 0
        assert self.h.ctl("start", "vm1", "--generation", "1")[0] == 0
        assert self.h.ctl("stop", "vm1", "--generation", "1")[0] == 0


def argv(gen: int, dst: str, expect: int, op_id: str) -> list[str]:
    return ["rebundle", "vm1", "--generation", str(gen), "--expect-revision", str(expect), "--op-id", op_id,
            "--to", dst]


@pytest.fixture
def site(host):
    s = Site(host)
    code, vm = host.create()
    assert code == 0, vm
    return s


# ---- rebundle ------------------------------------------------------------------------

def test_rebundle_commits_once_and_a_restore_is_the_same_verb(site):
    before = site.launch()
    assert before["bundle"] == site.b1 and "bundle_selection_revision" not in before
    assert site.h.ctl("status", "vm1")[1]["bundle_selection_revision"] == 0
    code, res = site.rebundle(0, site.b2, 0, op(1))  # never authorized: generation 0
    assert code == 0, res
    assert res == {"name": "vm1", "op_id": op(1), "bundle": site.b2, "bundle_selection_revision": 1,
                   "expected_measurement": site.launch()["expected_measurement"]}
    assert res["expected_measurement"] != before["expected_measurement"]  # the kernel moved
    after = site.launch()
    # The identity is unchanged, so HOST_DATA and the identity digest are too (spec 7.5 step 1).
    assert (after["identity_sha256"], after["host_data"], after["vm_id"]) == \
        (before["identity_sha256"], before["host_data"], before["vm_id"])
    assert after["selection_ops"] == [{"op_id": op(1), "generation": 0, "expect_revision": 0, "to": site.b2,
                                       "result": {k: res[k] for k in ("bundle", "expected_measurement",
                                                                     "bundle_selection_revision")}}]
    assert site.env()["VM_BUNDLE"] == f"'{site.b2}'" and site.binds(site.b2) and not site.binds(site.b1)
    assert json.loads((site.d / "selection-synced.json").read_text()) == {"revision": 1}
    assert "daemon-reload" in (site.h.root.parent / "systemd.json.log").read_text()
    status = site.h.ctl("status", "vm1")[1]
    assert (status["bundle"], status["bundle_selection_revision"]) == (site.b2, 1)
    # Restore: the same command back to B1; the revision goes up like any selection change.
    code, res = site.rebundle(0, site.b1, 1, op(2))
    assert code == 0 and res["bundle_selection_revision"] == 2
    assert site.launch()["expected_measurement"] == before["expected_measurement"]
    assert site.env()["VM_BUNDLE"] == f"'{site.b1}'" and site.binds(site.b1)
    # --to the current bundle is accepted and still fences every request issued before it.
    code, res = site.rebundle(0, site.b1, 2, op(3))
    assert (code, res["bundle"], res["bundle_selection_revision"]) == (0, site.b1, 3)
    assert site.launch()["expected_measurement"] == before["expected_measurement"]


def test_the_delayed_request_is_refused_by_the_revision_fence(site):
    """Spec r3 7.5, the delayed request of Astra r2 P1 #3: R1 (N=0, B2) is sent and delayed;
    R2 (N=0, B2) and R3 (N=1, B1) are applied; R1 arrives and is refused, exit 19."""
    site.ran_once()
    assert site.rebundle(1, site.b2, 0, op(2))[0] == 0
    assert site.rebundle(1, site.b1, 1, op(3))[0] == 0
    files = site.files()
    code, res = site.rebundle(1, site.b2, 0, op(1))
    assert (code, res["error"], res["reason"]) == (19, "stale_selection", "revision_changed")
    code, res = site.rebundle(1, site.b2, 5, op(4))  # ahead of the host is stale too
    assert (code, res["error"]) == (19, "stale_selection")
    assert site.files() == files and site.launch()["bundle"] == site.b1
    assert site.launch()["bundle_selection_revision"] == 2 and len(site.launch()["selection_ops"]) == 2


def test_a_retried_op_id_returns_its_stored_result_unchanged(site):
    code, first = site.rebundle(0, site.b2, 0, op(1))
    assert code == 0
    assert site.rebundle(0, site.b1, 1, op(2))[0] == 0
    files = site.files()
    # A retry of op 1 whose answer was lost, after op 2 moved the VM back: op 1's stored result
    # (the state right after it), and nothing moves.
    code, again = site.rebundle(0, site.b2, 0, op(1))
    assert (code, again) == (0, first)
    assert site.files() == files and site.launch()["bundle"] == site.b1
    # The same op_id with any other field is not a retry.
    for gen, dst, expect in ((0, site.b1, 0), (0, site.b2, 2), (1, site.b2, 0)):
        code, res = site.rebundle(gen, dst, expect, op(1))
        assert (code, res["error"], res["reason"]) == (19, "stale_selection", "op_id_reused")
    assert site.files() == files
    # Also after a later run: the same answer byte for byte, and nothing written.
    site.ran_once()
    files = site.files()
    p = subprocess.run([str(CTL), *argv(0, site.b2, 0, op(1))], capture_output=True, text=True, timeout=60,
                       env=site.h.environ)
    assert p.returncode == 0 and p.stdout == json.dumps(first, sort_keys=True) + "\n"  # out() writes sorted keys
    assert site.files() == files and site.launch()["bundle"] == site.b1


def test_the_op_log_keeps_the_last_64_and_an_evicted_retry_changes_nothing(site):
    launch = site.launch()
    result = {"bundle": site.b1, "expected_measurement": launch["expected_measurement"]}
    ops = [{"op_id": op(i), "generation": 0, "expect_revision": i, "to": site.b2 if i % 2 == 0 else site.b1,
            "result": {**result, "bundle_selection_revision": i + 1}} for i in range(64)]
    launch.update(bundle_selection_revision=64, selection_ops=ops)
    (site.d / "launch.json").write_text(json.dumps(launch, sort_keys=True) + "\n")
    (site.d / "selection-synced.json").write_text('{"revision": 64}\n')
    assert site.rebundle(0, site.b2, 64, op(64))[0] == 0
    kept = [o["op_id"] for o in site.launch()["selection_ops"]]
    assert len(kept) == 64 and kept[0] == op(1) and kept[-1] == op(64)
    files = site.files()
    # op 0 left the log: its late retry is evaluated as new, and the revision fence refuses it.
    code, res = site.rebundle(0, site.b2, 0, op(0))
    assert (code, res["error"]) == (19, "stale_selection")
    assert site.files() == files and site.launch()["bundle"] == site.b2
    # op 1 is still kept: its stored result.
    assert site.rebundle(0, site.b1, 1, op(1)) == (0, {"name": "vm1", "op_id": op(1), **ops[1]["result"]})


@pytest.mark.parametrize("case", [
    ("stale_generation", "not_current"), ("stale_generation", "generation_open"),
    ("stale_generation", "unit_active"), ("bundle_incompatible", "bundle_not_enabled"),
    ("bundle_incompatible", "no_bundle"), ("bundle_incompatible", "no_bundle/manifest"),
    ("bundle_incompatible", "no_verified_build"),
    ("bundle_incompatible", "no_verified_build/vcpus"), ("bundle_incompatible", "no_verified_build/qemu"),
    ("bundle_incompatible", "base_root_differs"), ("bundle_incompatible", "cpu_family_differs"),
    ("bundle_incompatible", "host_config_invalid"), ("bundle_incompatible", "host_config_invalid/missing")])
def test_fences_refuse_and_write_nothing(site, case):
    error, why = case
    site.ran_once()  # generation 1 closed
    dst, gen = site.b2, 1
    if why == "not_current":
        gen = 0
    elif why == "generation_open":
        # Authorizing the next run raises the generation: a delayed rebundle for 1 is stale,
        # and one for 2 waits until run 2 is cancelled (refused while it is open).
        assert site.h.ctl("authorize", "vm1", str(2**33), "2")[0] == 0
        assert site.rebundle(1, dst, 0, op(9))[1]["reason"] == "not_current"
        gen = 2
    elif why == "unit_active":
        state = site.h.systemd()
        state["cathedral-vm-vm1.service"]["active"] = True
        (site.h.root.parent / "systemd.json").write_text(json.dumps(state))
    elif why == "bundle_not_enabled":
        dst = site.b4
    elif why == "no_bundle":
        shutil.rmtree(site.h.root / "bundles" / site.b2)  # enabled in the host file, directory gone
    elif why == "no_bundle/manifest":
        manifest = site.h.root / "bundles" / site.b2 / "manifest.json"
        manifest.write_bytes(manifest.read_bytes().replace(b"kernel-fix", b"kernel-fyx"))  # sha256 != its id
    elif why == "no_verified_build":
        dst = site.b5
    elif why == "no_verified_build/vcpus":
        site.verify(site.b2, vcpus=[2, 4])  # verified, but not for this VM's 1 vCPU
    elif why == "no_verified_build/qemu":
        site.qemu.write_bytes(b"another QEMU build")  # the host build changed since it was verified
    elif why == "base_root_differs":
        dst = site.b3
    elif why == "cpu_family_differs":
        dst = site.bundle("turin-build", kernel_byte=4, cpu_family="turin")  # this host is genoa
    elif why == "host_config_invalid":
        site.edit_config(lambda cfg: cfg.update(verified="not a map"))  # start's gate refuses it too
    elif why == "host_config_invalid/missing":
        site.config.unlink()
    files = site.files()
    code, res = site.rebundle(gen, dst, 0, op(1))
    want_code = {"stale_generation": 3, "bundle_incompatible": 20}[error]
    assert (code, res["error"], res["reason"]) == (want_code, error, why.split("/")[0]), res
    assert site.files() == files and "selection_ops" not in site.launch()
    if why == "generation_open":
        # Cancelling run 2 closes it as never started: the rebundle for 2 goes through.
        assert site.h.ctl("cancel", "vm1", "2")[0] == 0
        assert site.rebundle(2, dst, 0, op(1))[0] == 0


def test_a_canary_vm_may_select_an_unverified_bundle(site):
    """The one start allowed on an unverified build (vm_gates.host_build_gate) is allowed here too."""
    assert site.rebundle(0, site.b5, 0, op(1))[1]["reason"] == "no_verified_build"
    site.edit_config(lambda cfg: cfg.update(canary_vms=["vm1"]))
    code, res = site.rebundle(0, site.b5, 0, op(1))
    assert (code, res["bundle"]) == (0, site.b5)


@pytest.mark.parametrize("args,error", [
    (["--expect-revision", "0", "--op-id", op(1), "--to", "B2"], "missing_option"),
    (["--generation", "0", "--expect-revision", "0", "--op-id", op(1)], "missing_option"),
    (["--generation", "0", "--expect-revision", "0", "--op-id", op(1), "--to", "B2x"], "invalid_bundle"),
    (["--generation", "0", "--expect-revision", "0", "--op-id", op(1)[:-1], "--to", "B2"], "invalid_op_id"),
    (["--generation", "0", "--expect-revision", "0", "--op-id", op(1).upper(), "--to", "B2"], "invalid_op_id"),
    (["--generation", "0", "--expect-revision", "-1", "--op-id", op(1), "--to", "B2"], "invalid_expect_revision"),
    (["--generation", "x", "--expect-revision", "0", "--op-id", op(1), "--to", "B2"], "invalid_generation"),
    (["--generation", "0", "--expect-revision", "0", "--op-id", op(1), "--to", "B2", "--from", "B1"],
     "invalid_option"),
])
def test_bad_requests_exit_2(site, args, error):
    args = [{"B1": site.b1, "B2": site.b2, "B2x": site.b2[:-1] + "G"}.get(a, a) for a in args]
    files = site.files()
    code, res = site.h.ctl("rebundle", "vm1", *args)
    assert (code, res["error"]) == (2, error)
    assert site.files() == files


def test_rebundle_from_the_broker_reads_no_stdin(site):
    """The broker's forced command passes the four options as tokens (each fits its argument check:
    a bundle id is 64 characters) and sends no stdin for rebundle."""
    command = " ".join(argv(0, site.b2, 0, op(1)))
    p = subprocess.run([str(CTL), "--from-broker"], capture_output=True, text=True, timeout=60,
                       input="not read", env={**site.h.environ, "SSH_ORIGINAL_COMMAND": command})
    assert p.returncode == 0, p.stdout
    assert json.loads(p.stdout)["bundle"] == site.b2
    assert max(len(t) for t in command.split()) == 64


# ---- a rebundle cut at every step after its fences ---------------------------------------

class Cut(BaseException):
    """A crash: nothing catches it, as nothing catches SIGKILL."""


def in_process(site, monkeypatch):
    for k, v in site.h.environ.items():
        monkeypatch.setenv(k, v)
    return _load("vm_ctl_cut_test", KIT / "vm_ctl.py")


@pytest.mark.parametrize("cut", ["measure", "launch.json", "vm.env", "unit", "daemon-reload", "marker"])
def test_a_cut_rebundle_is_finished_by_its_retry_or_the_next_start(site, monkeypatch, capsys, cut):
    site.ran_once()
    mod = in_process(site, monkeypatch)
    real_write, real_systemctl = mod.write_atomic, mod.systemctl

    def write(path, data, mode=0o600):
        if {"launch.json": "launch.json", "vm.env": "vm.env", "unit": "cathedral-vm-vm1.service",
                "marker": "selection-synced.json"}.get(cut) == path.name:
            raise Cut()
        return real_write(path, data, mode)

    def systemctl(*args, check=True):
        if cut == "daemon-reload" and args == ("daemon-reload",):
            raise Cut()
        return real_systemctl(*args, check=check)

    def values(*a):
        raise Cut()

    monkeypatch.setattr(mod, "write_atomic", write)
    monkeypatch.setattr(mod, "systemctl", systemctl)
    if cut == "measure":
        monkeypatch.setattr(mod, "selection_values", values)
    with pytest.raises(Cut):
        mod.main(argv(1, site.b2, 0, op(1)))
    committed = cut not in ("measure", "launch.json")
    assert site.launch()["bundle"] == (site.b2 if committed else site.b1)
    assert site.launch().get("bundle_selection_revision", 0) == (1 if committed else 0)
    if committed:
        # Before the derived files are done, no launch gets through: check-paid refuses (run 2 is
        # authorized and paid, so the selection check is the one that answers).
        assert site.h.ctl("authorize", "vm1", str(2**33), "2")[0] == 0
        code, res = site.h.ctl("check-paid", "vm1")
        assert (code, res["error"]) == (3, "selection_unsynced")
    # The retry (a new process, same op_id) applies it exactly once or returns the stored result,
    # and leaves every derived file and systemd done.
    log = site.h.root.parent / "systemd.json.log"
    log.write_text("")
    code, res = site.h.ctl(*argv(1, site.b2, 0, op(1)))
    assert code == 0 and res["bundle"] == site.b2 and res["bundle_selection_revision"] == 1
    assert [o["op_id"] for o in site.launch()["selection_ops"]] == [op(1)]
    assert site.env()["VM_BUNDLE"] == f"'{site.b2}'" and site.binds(site.b2)
    assert "daemon-reload" in log.read_text()  # also when the cut fell after the unit write
    assert json.loads((site.d / "selection-synced.json").read_text()) == {"revision": 1}


@pytest.mark.parametrize("cut", ["vm.env", "daemon-reload"])
def test_start_finishes_a_cut_rebundle_before_it_launches(site, monkeypatch, cut):
    site.ran_once()
    mod = in_process(site, monkeypatch)
    real_write, real_systemctl = mod.write_atomic, mod.systemctl
    monkeypatch.setattr(mod, "write_atomic",
                        lambda p, data, mode=0o600: (_ for _ in ()).throw(Cut()) if p.name == cut
                        else real_write(p, data, mode))
    monkeypatch.setattr(mod, "systemctl",
                        lambda *a, check=True: (_ for _ in ()).throw(Cut()) if a == (cut,)
                        else real_systemctl(*a, check=check))
    with pytest.raises(Cut):
        mod.main(argv(1, site.b2, 0, op(1)))
    assert site.h.ctl("authorize", "vm1", str(2**33), "2")[0] == 0
    log = site.h.root.parent / "systemd.json.log"
    log.write_text("")
    code, vm = site.h.ctl("start", "vm1", "--generation", "2")
    assert code == 0 and vm["bundle"] == site.b2 and vm["state"] == "running"
    lines = log.read_text().splitlines()
    assert lines.index("daemon-reload") < next(i for i, line in enumerate(lines) if line.startswith("start "))
    assert site.env()["VM_BUNDLE"] == f"'{site.b2}'" and site.binds(site.b2)
    assert site.h.ctl("check-paid", "vm1")[0] == 0


def test_a_sigkill_during_daemon_reload_is_finished_by_the_retry(site):
    """A real crash: systemctl daemon-reload kills vm-ctl (its parent) with SIGKILL."""
    site.ran_once()
    killer = site.h.root.parent / "killbin"
    killer.mkdir()
    (killer / "systemctl").write_text(textwrap.dedent(f"""\
        #!/bin/sh
        if [ "$1" = daemon-reload ]; then kill -9 $PPID; exit 1; fi
        exec {site.h.bin / 'systemctl'} "$@"
        """))
    (killer / "systemctl").chmod(0o755)
    p = subprocess.run([str(CTL), *argv(1, site.b2, 0, op(1))], capture_output=True, text=True, timeout=60,
                       env={**site.h.environ, "PATH": f"{killer}:{site.h.environ['PATH']}"})
    assert p.returncode == -9 and p.stdout == ""
    assert site.launch()["bundle"] == site.b2 and site.binds(site.b2)  # the file is right ...
    assert not (site.d / "selection-synced.json").exists()  # ... systemd is not
    code, res = site.rebundle(1, site.b2, 0, op(1))
    assert code == 0 and res["bundle_selection_revision"] == 1
    assert json.loads((site.d / "selection-synced.json").read_text()) == {"revision": 1}


def test_rebundle_is_documented():
    readme = (KIT / "README.md").read_text()
    for word in ("rebundle", "stale_selection", "bundle_incompatible", "op_id_reused", "no_verified_build",
                 "bundle_selection_revision", "selection-synced.json", "selection_committed_sync_failed",
                 "host_config_invalid", "cpu_family_differs"):
        assert word in readme, word


def test_a_sync_failure_after_the_commit_exits_21_and_the_same_op_id_finishes_it(site):
    """daemon-reload fails after launch.json is committed: not "rebundle failed" (exit 1) but exit 21,
    selection_committed_sync_failed. No launch gets through until the same op_id (or start) syncs."""
    site.ran_once()
    failing = site.h.root.parent / "failbin"
    failing.mkdir()
    (failing / "systemctl").write_text(textwrap.dedent(f"""\
        #!/bin/sh
        if [ "$1" = daemon-reload ]; then echo "Failed to reload daemon" >&2; exit 1; fi
        exec {site.h.bin / 'systemctl'} "$@"
        """))
    (failing / "systemctl").chmod(0o755)
    p = subprocess.run([str(CTL), *argv(1, site.b2, 0, op(1))], capture_output=True, text=True, timeout=60,
                       env={**site.h.environ, "PATH": f"{failing}:{site.h.environ['PATH']}"})
    res = json.loads(p.stdout)
    assert (p.returncode, res["error"]) == (21, "selection_committed_sync_failed"), res
    assert "same op_id" in res["detail"]
    assert site.launch()["bundle"] == site.b2 and site.launch()["bundle_selection_revision"] == 1
    assert site.h.ctl("authorize", "vm1", str(2**33), "2")[0] == 0
    assert site.h.ctl("check-paid", "vm1")[1]["error"] == "selection_unsynced"
    code, res = site.rebundle(1, site.b2, 0, op(1))
    assert (code, res["bundle"], res["bundle_selection_revision"]) == (0, site.b2, 1)
    assert json.loads((site.d / "selection-synced.json").read_text()) == {"revision": 1}
    # The selection check passes now; run 2 has no start line yet, so that check answers instead.
    assert site.h.ctl("check-paid", "vm1")[1]["error"] == "start_not_recorded"
    assert site.h.ctl("start", "vm1", "--generation", "2")[0] == 0

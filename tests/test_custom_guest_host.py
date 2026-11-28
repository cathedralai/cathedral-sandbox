"""Custom guest host phases (spec-r9 5.1, 5.3, 5.8, 5.12; test plan 14.1).

Single-hotel eligibility, the shared-host rehearsal mode, the unit's confinement,
the start token, and the one host lock. Fake systemctl and /proc; real files and
real flock(2)."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

import pytest

from custom_guest_support import CG, HOST, HOTEL, LAUNCH, Host, load_host_module


@pytest.fixture
def host(tmp_path):
    return Host(tmp_path)


# ---------------------------------------------------------------- 5.1 single hotel

def test_single_hotel_host_passes(host):
    rc, r = host.phase("inbox")
    assert rc == 0 and r["ok"], r
    assert (host.root / f"srv/custom-guest/{HOTEL}/inbox/{LAUNCH}").is_dir()


def test_phase_refuses_a_hotel_the_allow_file_does_not_list(host):
    host.allow(hotel="chi-ur")
    rc, r = host.phase("inbox")
    assert rc == 1 and r["error_code"] == "custom_guest_hold_unsupported"


def test_two_hotel_folders_refused(host):
    (host.root / "srv/sealed-hotel-chi-other").mkdir(parents=True)
    rc, r = host.phase("inbox")
    assert r["error_code"] == "custom_guest_host_not_single_hotel"


def test_two_kit_units_refused(host):
    (host.root / "etc/systemd/system/room-sealed-chi-other.service").write_text("[Service]\n")
    rc, r = host.phase("inbox")
    assert r["error_code"] == "custom_guest_host_not_single_hotel"


def test_offer_refresh_unit_is_a_miner_host(host):
    (host.root / "etc/systemd/system/hotel-offer-refresh.timer").write_text("[Timer]\n")
    rc, r = host.phase("inbox")
    assert r["error_code"] == "custom_guest_miner_hotel"


@pytest.mark.parametrize("leftover", ["marker", "folder"])
def test_another_launch_on_the_host_refused(host, leftover):
    if leftover == "marker":
        (host.sealed / "custom-guest.hold").write_text(json.dumps({"launch_id": "cg-aaaaaaaaaaaa", "state": "kit_start"}))
    else:
        (host.root / f"srv/custom-guest/{HOTEL}/cg-aaaaaaaaaaaa").mkdir(parents=True)
    rc, r = host.phase("inbox")
    assert r["error_code"] == "custom_guest_previous_launch_on_host"


def test_vm_unit_and_stray_qemu_refused(host):
    (host.root / "etc/systemd/system/cathedral-vm-a.service").write_text("[Service]\n")
    assert host.phase("inbox")[1]["error_code"] == "custom_guest_host_not_exclusive"
    os.remove(host.root / "etc/systemd/system/cathedral-vm-a.service")
    host.add_qemu(4242, "something-else.service")
    assert host.phase("inbox")[1]["error_code"] == "custom_guest_host_not_exclusive"


# ---------------------------------------------------------------- 5.12 shared-host rehearsal

@pytest.fixture
def shared(tmp_path):
    h = Host(tmp_path, shared=True)
    for name in ("chi-sealed", "chi-escape"):
        h.add_hotel(name)
    return h


def test_shared_mode_passes_with_the_recorded_kit_units(shared):
    rc, r = shared.phase("inbox")
    assert rc == 0, r
    inv = [e for e in shared.journal() if e["event"] == "shared_inventory"][0]
    assert inv["units"] == ["room-sealed-chi-escape.service", "room-sealed-chi-sealed.service"]
    assert len(inv["qemu"]) == 2
    assert shared.phase("inbox")[0] == 0


def test_shared_mode_fails_with_a_third_qemu_or_a_new_vm_unit(shared):
    assert shared.phase("inbox")[0] == 0
    shared.add_qemu(4243, "room-sealed-chi-new.service")
    assert shared.phase("inbox")[1]["error_code"] == "custom_guest_host_not_exclusive"
    for d in (shared.proc / "4243").iterdir():
        d.unlink()
    (shared.proc / "4243").rmdir()
    (shared.root / "etc/systemd/system/cathedral-vm-a.service").write_text("[Service]\n")
    assert shared.phase("inbox")[1]["error_code"] == "custom_guest_host_not_exclusive"


def test_shared_mode_fails_when_a_kit_unit_appears(shared):
    assert shared.phase("inbox")[0] == 0
    shared.add_hotel("chi-third", running=False)
    assert shared.phase("inbox")[1]["error_code"] == "custom_guest_host_not_single_hotel"


def request(kernel="11", initrd="22", root="33"):
    return {"schema": "cathedral.custom_guest.request/v1",
            "kernel": {"url": "https://x/k", "sha256": kernel * 32, "bytes": 10},
            "initrd": {"reference": "1", "sha256": initrd * 32},
            "root_disk": {"url": "https://x/r", "sha256": root * 32, "bytes": 8192},
            "cmdline": "x", "data_disk_gib": 0, "vcpus": 4, "mem_gib": 24, "cpu_model": "EPYC-Genoa-v1",
            "owner_ed25519_b64": "", "ssh_public_key": "ssh-ed25519 AAAA", "launch_nonce_hex": "00" * 32,
            "ports": [{"public": 20022, "guest": 22}]}


TEST_IMAGE = {"kernel_sha256": "11" * 32, "initrd_sha256": "22" * 32, "root_sha256": "33" * 32}


@pytest.mark.parametrize("toby_go", [None, "core-msg-1"])
def test_shared_mode_refuses_any_image_but_the_test_image(shared, toby_go):
    rc, r = shared.phase("intake", {"request": request(kernel="44"), "test_image": TEST_IMAGE, "toby_go": toby_go})
    assert rc == 1 and r["error_code"] == "custom_guest_shared_host_needs_test_image"


def test_shared_mode_caps_the_guest_at_the_kit_size(shared):
    req = request()
    req["vcpus"] = 57
    rc, r = shared.phase("intake", {"request": req, "test_image": TEST_IMAGE})
    assert r["error_code"] == "custom_guest_resources_exceeded"


def test_customer_image_needs_toby_go_on_a_single_hotel_host(host):
    rc, r = host.phase("intake", {"request": request(kernel="44"), "test_image": TEST_IMAGE, "toby_go": None})
    assert r["error_code"] == "custom_guest_toby_go_required"


# ---------------------------------------------------------------- 5.8 unit

def test_unit_confinement(host):
    mod = load_host_module(host.env)
    ctx = mod.Ctx("boot", HOTEL, LAUNCH, {}, {})
    text = mod.unit_text(ctx, 24)
    lines = set(text.splitlines())
    for want in ("User=cg-chi-ur-2", "Group=cg-chi-ur-2", "SupplementaryGroups=kvm cg-sev", "Restart=no",
                 "DevicePolicy=closed", "DeviceAllow=/dev/kvm rw", "DeviceAllow=/dev/sev rw",
                 "DeviceAllow=/dev/vhost-net rw", "DeviceAllow=/dev/net/tun rw", "ProtectSystem=strict",
                 "ProtectHome=yes", "PrivateTmp=yes", "TemporaryFileSystem=/srv:ro", "MemoryMax=40G",
                 "MemorySwapMax=0", "TasksMax=512", "LimitNOFILE=4096", "LimitCORE=0", "LimitMEMLOCK=infinity",
                 "NoNewPrivileges=yes", "CapabilityBoundingSet=", "ProtectKernelTunables=yes",
                 "ProtectKernelModules=yes", "ProtectKernelLogs=yes", "ProtectControlGroups=yes",
                 "RestrictNamespaces=yes", "RestrictSUIDSGID=yes", "LockPersonality=yes",
                 "RestrictAddressFamilies=AF_UNIX", f"BindReadOnlyPaths={ctx.d}/images",
                 f"BindPaths={ctx.d}/disks {ctx.d}/run"):
        assert want in lines, want
    assert "[Install]" not in text, "the unit is never enabled"
    pre = [ln for ln in text.splitlines() if ln.startswith("ExecStartPre=")]
    # The modprobe line keeps its `-` (a failed modprobe must not stop the start): `+-`, not `+`.
    assert [ln for ln in pre if "modprobe" in ln] == [f"ExecStartPre=+-{mod.HOST_NS} /sbin/modprobe -q kvm_amd"]
    assert pre[0] == f"ExecStartPre=+{mod.HOST_NS} {mod.LIBDIR}/custom-guest-host.sh check-start --hotel {HOTEL} --launch-id {LAUNCH}"
    assert all(ln.startswith("ExecStartPre=+") for ln in pre), "root steps are + prefixed only"
    assert [ln for ln in text.splitlines() if ln.startswith("ExecStart=")] == [
        f"ExecStart=/usr/bin/python3 -I {mod.LIBDIR}/launch-custom-guest.py {ctx.d}"]
    assert f"ExecStopPost=+{mod.HOST_NS} {mod.LIBDIR}/custom-guest-host.sh exited --hotel {HOTEL} --launch-id {LAUNCH}" in lines
    # Every + hook enters the host mount namespace: the unit's own (TemporaryFileSystem=/srv:ro, ProtectSystem=strict)
    # hides the host journal from a + hook as well, on systemd 255 and 259 alike.
    assert mod.HOST_NS == "/usr/bin/nsenter --mount=/proc/1/ns/mnt --"
    privileged = [ln for ln in text.splitlines() if ln.startswith(("ExecStartPre=+", "ExecStopPost=+"))]
    assert len(privileged) == 6
    assert all(f"+{mod.HOST_NS} " in ln or f"+-{mod.HOST_NS} " in ln for ln in privileged), privileged
    # The guest process is not wrapped: it keeps the unit's namespace, the one that hides /srv.
    assert not [ln for ln in text.splitlines() if ln.startswith("ExecStart=") and "nsenter" in ln]


def test_a_host_without_nsenter_is_refused_before_anything_is_written(host, tmp_path, monkeypatch):
    mod = load_host_module(host.env)
    assert mod.HOST_NS.startswith(mod.NSENTER + " ")
    monkeypatch.setattr(mod, "ROOT", "")
    monkeypatch.setattr(mod, "LIBDIR", str(tmp_path / "lib"))
    monkeypatch.setattr(mod, "NSENTER", str(tmp_path / "no-nsenter"))
    with pytest.raises(mod.Halt) as refused:
        mod.install_tools()
    assert "nsenter" in refused.value.detail
    assert not (tmp_path / "lib").exists(), "nothing was installed"


# ---------------------------------------------------------------- 5.11 isolation: the fds QEMU holds

GMEM = "/[kvm-gmem] (deleted)"
HOST_MNT, KERNEL_MNT = "48", "234"  # as surveyed on the kit's SNP QEMU: the host's ext4 is listed, gmem's mount is not


def isolation_rig(host, tmp_path, monkeypatch, fds, mountinfo=None, fdinfo=None):
    """verify_isolation over a fake /proc. fds maps a name to (readlink target, regular file, mnt_id or None).
    A gmem-named fd gets KERNEL_MNT and a real path HOST_MNT unless given; mnt_id None writes no fdinfo."""
    import types
    mod = load_host_module(host.env)
    ctx = mod.Ctx("boot", HOTEL, LAUNCH, {}, {})
    pid = tmp_path / "proc" / "4242"
    (pid / "fd").mkdir(parents=True)
    (pid / "fdinfo").mkdir()
    lines = mountinfo if mountinfo is not None else [f"{HOST_MNT} 1 8:1 / / rw - ext4 /dev/sda1 rw", "50 48 0:5 / /dev rw - devtmpfs devtmpfs rw"]
    if lines is not False:
        (pid / "mountinfo").write_text("\n".join(lines) + "\n")
    stats = {}
    for name, (target, regular, mnt) in fds.items():
        target = target.replace("{D}", ctx.d)
        (pid / "fd" / name).symlink_to(target)  # may dangle: the stat is faked below, as /proc would answer it
        stats[target] = types.SimpleNamespace(st_mode=(0o100600 if regular else 0o020644), st_nlink=1)
        if mnt is not None:
            (pid / "fdinfo" / name).write_text(f"pos:\t0\nflags:\t02\nmnt_id:\t{mnt}\nino:\t5\n")
    monkeypatch.setattr(mod, "PROC", str(tmp_path / "proc"))
    monkeypatch.setattr(mod, "FD_STAT", lambda fd: stats[os.readlink(fd)])
    monkeypatch.setattr(mod, "custom_qemu", lambda c: [{"pid": 4242}])
    monkeypatch.setattr(mod, "qmp", lambda c, req: [{"return": [{"device": "root", "inserted": {"file": ctx.d + "/images/root.raw", "ro": True}}]}])
    monkeypatch.setattr(mod, "load_doc", lambda path: ({"data_disk_gib": 0}, b"{}"))
    return mod, ctx


def refused(mod, ctx):
    with pytest.raises(mod.Halt) as r:
        mod.verify_isolation(ctx)
    assert r.value.code == "custom_guest_isolation_failed"
    return r.value.detail


def test_a_kvm_guest_memfd_with_an_unlisted_mount_is_not_a_host_file(host, tmp_path, monkeypatch):
    mod, ctx = isolation_rig(host, tmp_path, monkeypatch, {
        "3": (GMEM, True, KERNEL_MNT), "4": ("/dev/kvm", False, None), "5": ("/memfd:qemu-ram (deleted)", True, "9"),
        "6": ("{D}/disks/root.raw", True, HOST_MNT), "7": ("anon_inode:kvm-vm", False, None)})
    assert mod.KVM_GMEM_TARGET == GMEM
    mod.verify_isolation(ctx)  # three gmem-like fds of different sizes in the real survey: the rule is the same


def test_the_gmem_name_with_a_listed_mount_still_fails(host, tmp_path, monkeypatch):
    mod, ctx = isolation_rig(host, tmp_path, monkeypatch, {"3": (GMEM, True, HOST_MNT)})
    assert GMEM in refused(mod, ctx)


def test_a_regular_host_file_outside_the_launch_folder_still_fails(host, tmp_path, monkeypatch):
    mod, ctx = isolation_rig(host, tmp_path, monkeypatch, {"3": (GMEM, True, KERNEL_MNT), "4": ("/etc/shadow", True, HOST_MNT)})
    detail = refused(mod, ctx)
    assert "/etc/shadow" in detail and "kvm-gmem" not in detail
    # An unlisted mount id does not excuse another name.
    mod, ctx = isolation_rig(host, tmp_path / "b", monkeypatch, {"3": ("/etc/shadow", True, KERNEL_MNT)})
    assert "/etc/shadow" in refused(mod, ctx)


def test_an_unreadable_fdinfo_or_mountinfo_fails_closed(host, tmp_path, monkeypatch):
    mod, ctx = isolation_rig(host, tmp_path, monkeypatch, {"3": (GMEM, True, None)})  # no fdinfo file
    assert GMEM in refused(mod, ctx)
    mod, ctx = isolation_rig(host, tmp_path / "m", monkeypatch, {"3": (GMEM, True, KERNEL_MNT)}, mountinfo=False)  # no mountinfo
    assert GMEM in refused(mod, ctx)
    mod, ctx = isolation_rig(host, tmp_path / "e", monkeypatch, {"3": (GMEM, True, KERNEL_MNT)}, mountinfo=[])  # empty mountinfo
    assert GMEM in refused(mod, ctx)
    mod, ctx = isolation_rig(host, tmp_path / "j", monkeypatch, {"3": (GMEM, True, KERNEL_MNT)}, mountinfo=["not-a-number rest"])
    assert GMEM in refused(mod, ctx)
    # A fdinfo with no mnt_id line.
    mod, ctx = isolation_rig(host, tmp_path / "n", monkeypatch, {"3": (GMEM, True, KERNEL_MNT)})
    (tmp_path / "n" / "proc" / "4242" / "fdinfo" / "3").write_text("pos:\t0\nflags:\t02\n")
    assert GMEM in refused(mod, ctx)


def test_a_file_inside_the_launch_folder_and_non_regular_fds_pass(host, tmp_path, monkeypatch):
    mod, ctx = isolation_rig(host, tmp_path, monkeypatch, {"3": ("{D}/disks/root.raw", True, HOST_MNT), "4": ("/some/socket", False, None)})
    mod.verify_isolation(ctx)


def test_every_offender_is_listed_once_in_one_bounded_line(host, tmp_path, monkeypatch):
    fds = {"3": ("/etc/shadow", True, HOST_MNT), "4": ("/var/lib/other\nline", True, HOST_MNT), "5": ("/etc/shadow", True, HOST_MNT),
           "6": (GMEM, True, HOST_MNT)}  # the gmem name on a listed mount is not guest memory
    for i in range(7, 30):
        fds[str(i)] = (f"/root/very-long-name-{i}-" + "x" * 40, True, HOST_MNT)
    mod, ctx = isolation_rig(host, tmp_path, monkeypatch, fds)
    detail = refused(mod, ctx)
    assert detail.count("/etc/shadow") == 1, "one entry per target"
    assert "/var/lib/other line" in detail and "\n" not in detail
    assert len(detail) <= 300 and all(" " <= c <= "~" for c in detail)
    assert detail.startswith("QEMU holds open, outside the launch folder: /etc/shadow, /var/lib/other line, /[kvm-gmem] (deleted)")
    mod2, ctx2 = isolation_rig(host, tmp_path / "two", monkeypatch, {"3": ("/etc/shadow", True, HOST_MNT), "4": ("/etc/gshadow", True, HOST_MNT)})
    two = refused(mod2, ctx2)
    assert "/etc/shadow" in two and "/etc/gshadow" in two


def test_only_the_exact_gmem_name_is_skipped(host, tmp_path, monkeypatch):
    for i, target in enumerate(("/[kvm-gmem]", "/[kvm-gmem] (deleted) ", "/x/[kvm-gmem] (deleted)", "/[KVM-GMEM] (deleted)")):
        mod, ctx = isolation_rig(host, tmp_path / f"c{i}", monkeypatch, {"3": (target, True, KERNEL_MNT)})
        refused(mod, ctx)


def test_validator_line_is_the_spec_line(host):
    mod = load_host_module(host.env)
    ctx = mod.Ctx("intake", HOTEL, LAUNCH, {}, {})
    argv = mod.stage_argv(ctx, "/srv/custom-guest/H/inbox/L", "/srv/custom-guest/H/staging/L")
    assert argv == ["systemd-run", "--wait", "--pipe", "--uid=cg-stage", "--gid=cg-stage",
                    "-p", "PrivateNetwork=yes", "-p", "ProtectSystem=strict", "-p", "ProtectHome=yes",
                    "-p", "PrivateTmp=yes", "-p", "NoNewPrivileges=yes", "-p", "CapabilityBoundingSet=",
                    "-p", "MemoryMax=4G", "-p", "TasksMax=16", "-p", "LimitCORE=0", "-p", "RuntimeMaxSec=3600",
                    "-p", "ReadOnlyPaths=/srv/custom-guest/H/inbox/L", "-p", "ReadWritePaths=/srv/custom-guest/H/staging/L",
                    "python3", "-I", f"{mod.LIBDIR}/custom_guest_stage.py",
                    "--inbox", "/srv/custom-guest/H/inbox/L", "--staging", "/srv/custom-guest/H/staging/L"]


# ---------------------------------------------------------------- check-start token

def held(host):
    (host.sealed / "custom-guest.hold").write_text(json.dumps({"launch_id": LAUNCH, "state": "held"}))
    host.systemctl("disable", "--now", f"room-sealed-{HOTEL}.service")


def test_check_start_needs_a_fresh_boot_intent_as_latest_entry(host):
    held(host)
    mod = load_host_module(host.env)
    ctx = mod.Ctx("boot", HOTEL, LAUNCH, {}, {})
    assert host.phase("check-start")[1]["error_code"] == "custom_guest_boot_failed"
    ctx.log("boot", state="intent", generation=1, token="t1")
    assert host.phase("check-start")[0] == 0
    # The token is spent: a manual start afterwards is refused.
    assert host.phase("check-start")[1]["error_code"] == "custom_guest_boot_failed"


def test_check_start_refuses_while_the_kit_runs_or_guests_exist(host):
    held(host)
    mod = load_host_module(host.env)
    ctx = mod.Ctx("boot", HOTEL, LAUNCH, {}, {})
    from custom_guest_support import sev_doc
    host.set_sev(sev_doc(guests=1))
    ctx.log("boot", state="intent", generation=1, token="t2")
    assert host.phase("check-start")[1]["error_code"] == "custom_guest_host_not_exclusive"


# ---------------------------------------------------------------- 5.3 lock

def hold_lock(host, seconds: float) -> subprocess.Popen:
    """A top-level entry that holds the host lock (as roll.sh host_install will, PR 2)."""
    code = ("import fcntl,json,os,sys,time\n"
            "fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o644)\nfcntl.flock(fd,fcntl.LOCK_EX)\n"
            "open(sys.argv[2],'w').write(json.dumps({'owner':'roll:host_install','pid':os.getpid()}))\n"
            "print('locked',flush=True)\ntime.sleep(float(sys.argv[3]))\n")
    p = subprocess.Popen([sys.executable, "-c", code, str(host.root / "run/lock/cathedral-snp-host.lock"),
                          str(host.root / "run/lock/cathedral-snp-host.owner"), str(seconds)],
                         stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "locked"
    return p


def test_second_entry_waits_then_refuses_with_the_owner_record(host):
    p = hold_lock(host, 30)
    try:
        t = time.time()
        rc, r = host.phase("inbox")
        assert rc == 1 and r["error_code"] == "custom_guest_lifecycle_busy"
        assert "roll:host_install" in r["detail"] and time.time() - t >= 2
    finally:
        p.kill()
        p.wait()


def test_killed_holder_frees_the_lock(host):
    p = hold_lock(host, 30)
    p.send_signal(signal.SIGKILL)
    p.wait()
    rc, r = host.phase("inbox")
    assert rc == 0, r


def test_timer_tick_skips_while_a_phase_holds_the_lock(host):
    p = hold_lock(host, 30)
    try:
        rc, r = host.phase("tick")
        assert rc == 0 and r.get("skipped")
    finally:
        p.kill()
        p.wait()


def test_hooks_never_take_the_lock(host):
    held(host)
    mod = load_host_module(host.env)
    mod.Ctx("boot", HOTEL, LAUNCH, {}, {}).log("boot", state="intent", generation=1, token="t3")
    p = hold_lock(host, 30)
    try:
        t = time.time()
        assert host.phase("check-start")[0] == 0
        assert host.phase("exited")[0] in (0, 1)
        assert time.time() - t < 2, "a hook waited on the lock"
    finally:
        p.kill()
        p.wait()


def test_phase_exports_the_lock_to_its_helper_and_refuses_to_nest(host):
    rc, r = host.phase("inbox", extra={"CATHEDRAL_SNP_LOCK_FD": "9"})
    assert rc == 1 and r["error_code"] == "custom_guest_lifecycle_busy"
    rc, r = host.phase("inbox")
    assert rc == 0 and not (host.root / "run/lock/cathedral-snp-host.owner").exists(), "owner record removed at release"


def test_phase_runs_under_its_deadline(host):
    log = host.bin / "timeout"
    log.write_text('#!/bin/sh\necho "$@" >> "$FAKE_STATE.timeout"\nwhile [ "${1#-}" != "$1" ]; do shift; done\nshift\nexec "$@"\n')
    assert host.phase("inbox")[0] == 0
    line = open(str(host.state) + ".timeout").read().split()
    assert line[:2] == ["--kill-after=30s", "300s"]


# ---------------------------------------------------------------- Astra review of #780 (findings 1, 4, 9)

def test_serial_tail_never_follows_a_link_qemu_planted(host, monkeypatch):
    """Finding 1: D/run is QEMU-writable; root writes the serial tail only into the root-only D/log."""
    import stat
    mod = load_host_module(host.env)
    ctx = mod.Ctx("stop", HOTEL, LAUNCH, {}, {})
    run_dir = os.path.join(ctx.d, "run")
    os.makedirs(run_dir)
    victim = host.sealed / "data.raw"
    before = victim.read_bytes()
    os.symlink(victim, os.path.join(run_dir, "serial-tail.txt"))
    monkeypatch.setattr(mod, "qmp", lambda c, *a, **k: [{"return": "guest console tail"}])
    path = mod.save_ring(ctx)
    assert victim.read_bytes() == before, "the kit disk was written through the link"
    assert path == os.path.join(ctx.d, "log", "serial-tail.txt")
    assert open(path).read() == "guest console tail"
    assert stat.S_IMODE(os.stat(os.path.join(ctx.d, "log")).st_mode) == 0o700


def test_serial_tail_refuses_a_linked_log_folder(host, monkeypatch):
    mod = load_host_module(host.env)
    ctx = mod.Ctx("stop", HOTEL, LAUNCH, {}, {})
    os.makedirs(ctx.d)
    os.symlink(host.sealed, os.path.join(ctx.d, "log"))
    monkeypatch.setattr(mod, "qmp", lambda c, *a, **k: [{"return": "x"}])
    assert mod.save_ring(ctx) is None
    assert not (host.sealed / "serial-tail.txt").exists()


def test_qmp_runs_as_the_guest_user(host, monkeypatch):
    """Finding 1: a root connect to D/run/qmp.sock could follow a planted link to another socket."""
    mod = load_host_module(host.env)
    ctx = mod.Ctx("stop", HOTEL, LAUNCH, {}, {})
    seen = []

    def fake_run(argv, timeout=120, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout='[{"return": {}}]', stderr="")

    monkeypatch.setattr(mod, "run", fake_run)
    assert mod.qmp(ctx, {"execute": "query-block"}) == [{"return": {}}]
    assert seen[0][:4] == ["runuser", "-u", f"cg-{HOTEL}", "--"]
    assert seen[0][-3] == f"{ctx.d}/run/qmp.sock"


def test_qmp_client_speaks_qmp(host):
    import socket
    import tempfile
    import threading
    mod = load_host_module(host.env)
    d = tempfile.mkdtemp(dir="/tmp")
    sock_path = os.path.join(d, "q.sock")
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(sock_path)
    srv.listen(1)
    got = []

    def serve():
        c, _ = srv.accept()
        f = c.makefile("rwb")
        f.write(b'{"QMP": {"version": {}}}\n')
        f.flush()
        for _ in range(2):
            got.append(json.loads(f.readline()))
            f.write(b'{"event": "X"}\n{"return": {"ok": 1}}\n')
            f.flush()
        c.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    p = subprocess.run([sys.executable, "-I", "-c", mod.QMP_CLIENT, sock_path, "5",
                        json.dumps([{"execute": "query-block"}])], capture_output=True, text=True, timeout=20)
    t.join(5)
    srv.close()
    os.remove(sock_path)
    os.rmdir(d)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout) == [{"return": {"ok": 1}}]
    assert got == [{"execute": "qmp_capabilities"}, {"execute": "query-block"}]


def test_boot_retry_after_a_crash_between_start_and_booted_finishes_the_checks(host):
    """Finding 4: the unit runs for this generation but "booted" never landed: the checks run, not skipped."""
    held(host)
    mod = load_host_module(host.env)
    ctx = mod.Ctx("boot", HOTEL, LAUNCH, {}, {})
    ctx.log("baselined", fingerprint_sha256="f" * 64)
    ctx.log("boot", state="intent", generation=1, token="t1")
    ctx.log("token_used", token="t1", generation=1)
    os.makedirs(ctx.images)
    with open(os.path.join(ctx.images, "bootstrap.json"), "w") as f:
        f.write(json.dumps({"network": {"guest_ip": "10.217.0.2"}}, sort_keys=True, separators=(",", ":")))
    unit = f"custom-guest-{LAUNCH}.service"
    st = host.systemd()
    st[unit] = {"active": True, "enabled": False, "invocation": "i1", "enter": 1}
    host.state.write_text(json.dumps(st))
    rc, r = host.phase("boot", {"generation": 1}, extra={"CG_PROBE_TIMEOUT": "1", "CG_PROBE_ADDR": "127.0.0.1:9"})
    assert rc == 1 and r["error_code"] == "custom_guest_boot_failed", r
    assert not host.systemd()[unit]["active"], "a failed check stops the unit"
    assert not [e for e in host.journal() if e["event"] == "booted"]


def test_facts_show_inbox_and_staging_and_discard_clears_them(host):
    """Finding 9: cancel must see the inbox and staging folders, and discard removes them."""
    assert host.phase("inbox")[0] == 0
    (host.root / f"srv/custom-guest/{HOTEL}/staging/{LAUNCH}").mkdir(parents=True)
    f = host.phase("facts")[1]
    assert f["inbox_dir"] and f["staging_dir"] and not f["launch_dir"]
    assert host.phase("discard")[0] == 0
    f = host.phase("facts")[1]
    assert not (f["inbox_dir"] or f["staging_dir"] or f["launch_dir"])


# ---------------------------------------------------------------- Q5: the owner's folder is wiped after the return

def _launch_folder(host, guest_uid=None):
    """The folder as intake leaves it: root's (here the test user's) 0755, the guest's disks/ and run/ in it."""
    d = host.root / f"srv/custom-guest/{HOTEL}/{LAUNCH}"
    (d / "images").mkdir(parents=True, exist_ok=True)
    (d / "images/root.raw").write_bytes(b"x" * 4096)
    for name in ("disks", "run"):
        (d / name).mkdir(mode=0o700, exist_ok=True)
    (d / "disks/data.raw").write_bytes(b"d" * 8192)
    d.chmod(0o755)
    uid = os.getuid() if guest_uid is None else guest_uid
    (host.bin / "getent").write_text(
        f'#!/bin/sh\n[ "$1 $2" = "passwd cg-{HOTEL}" ] && echo "cg-{HOTEL}:x:{uid}:{uid}::/nonexistent:/bin/false"\n'
        'exit 0\n')
    return d


def _hold_marker(host):
    (host.sealed / "custom-guest.hold").write_text(json.dumps({"launch_id": LAUNCH, "state": "kit_start"}))


def test_return_finish_keeps_the_owners_folder_for_the_wipe(host):
    d = _launch_folder(host)
    _hold_marker(host)
    rc, r = host.phase("return-finish", {"record_state": "returned"})
    assert rc == 0 and r["ok"], r
    assert not (host.sealed / "custom-guest.hold").exists() and d.is_dir()


def test_the_wipe_runs_only_after_the_return_and_r15_and_is_idempotent(host):
    d = _launch_folder(host)
    rc, r = host.phase("wipe", {"record_state": "returning"})
    assert rc != 0 and r["error_code"] == "custom_guest_journal_behind" and d.is_dir(), r
    _hold_marker(host)
    rc, r = host.phase("wipe", {"record_state": "returned"})
    assert rc != 0 and "R15" in r["detail"] and d.is_dir(), r
    (host.sealed / "custom-guest.hold").unlink()
    rc, r = host.phase("wipe", {"record_state": "returned"})
    assert rc == 0 and r["ok"] and not d.exists(), r
    rc, r = host.phase("wipe", {"record_state": "returned"})  # again, as after a lost answer or a reboot
    assert rc == 0 and r["ok"], r
    wiped = [e for e in host.journal() if e.get("sub") == "launch_wiped" and e.get("state") == "done"]
    assert len(wiped) == 2  # observed done both times; the folder was removed once


def _victim(host):
    v = host.tmp / "victim"
    v.mkdir()
    (v / "keep").write_text("not the launch's\n")
    return v


def test_the_wipe_never_follows_a_link_planted_in_the_folder(host):
    d = _launch_folder(host)
    victim = _victim(host)
    (d / "disks/escape").symlink_to(victim)
    (d / "run/file-link").symlink_to(victim / "keep")
    rc, r = host.phase("wipe", {"record_state": "returned"})
    assert rc == 0 and r["ok"], r
    assert not d.exists() and (victim / "keep").read_text() == "not the launch's\n"


@pytest.mark.parametrize("where", ["launch", "hotel"])
def test_the_wipe_refuses_a_folder_that_is_a_link(host, where):
    victim = _victim(host)
    (victim / LAUNCH).mkdir()
    base = host.root / f"srv/custom-guest/{HOTEL}"
    base.mkdir(parents=True, exist_ok=True)
    if where == "launch":
        (base / LAUNCH).symlink_to(victim)
    else:  # the hotel folder itself is swapped for a link to elsewhere
        os.rename(base, host.tmp / "hotel-was")
        base.symlink_to(victim)
    rc, r = host.phase("wipe", {"record_state": "returned"})
    assert rc != 0 and r["error_code"] == "custom_guest_wipe_unsafe", r
    assert (victim / "keep").exists() and (victim / LAUNCH).is_dir()


def test_the_wipe_refuses_guest_folders_another_user_owns(host):
    d = _launch_folder(host, guest_uid=os.getuid() + 1)
    rc, r = host.phase("wipe", {"record_state": "returned"})
    assert rc != 0 and r["error_code"] == "custom_guest_wipe_unsafe" and "cg-" in r["detail"], r
    assert d.is_dir()


def test_the_wipe_refuses_a_group_writable_folder(host):
    d = _launch_folder(host)
    d.chmod(0o775)
    rc, r = host.phase("wipe", {"record_state": "returned"})
    assert rc != 0 and r["error_code"] == "custom_guest_wipe_unsafe", r
    assert d.is_dir()


def test_facts_report_the_folders_bytes_while_it_waits(host):
    _launch_folder(host)
    rc, r = host.phase("facts")
    assert rc == 0 and r["launch_dir"] is True and r["launch_dir_bytes"] >= 4096 + 8192, r


def test_folders_lists_every_launch_folder_without_a_launch_id(host):
    """Q5 check: the operator compares these with the API's list; a link named like a launch is listed, not followed."""
    _launch_folder(host)
    base = host.root / f"srv/custom-guest/{HOTEL}"
    (base / "cg-bbbbbbbbbbbb").mkdir()
    (base / "inbox").mkdir(exist_ok=True)  # not a launch folder
    os.symlink("/etc", base / "cg-cccccccccccc")
    argv = ["bash", str(HOST), "folders", "--hotel", HOTEL]
    p = subprocess.run(argv, capture_output=True, text=True, env=host.env, timeout=60)
    r = json.loads([ln for ln in p.stdout.splitlines() if ln.startswith("RESULT ")][-1][7:])
    assert p.returncode == 0 and r["ok"], (r, p.stderr)
    got = {f["launch_id"]: f for f in r["folders"]}
    assert set(got) == {LAUNCH, "cg-bbbbbbbbbbbb", "cg-cccccccccccc"}
    assert got[LAUNCH]["plain_dir"] is True and got[LAUNCH]["bytes"] >= 4096 + 8192
    assert got["cg-cccccccccccc"]["plain_dir"] is False


def test_only_folders_runs_without_a_launch_id(host):
    p = subprocess.run(["bash", str(HOST), "facts", "--hotel", HOTEL], capture_output=True, text=True, env=host.env,
                       timeout=60)
    r = json.loads([ln for ln in p.stdout.splitlines() if ln.startswith("RESULT ")][-1][7:])
    assert p.returncode == 1 and r["error_code"] == "custom_guest_request_invalid", r

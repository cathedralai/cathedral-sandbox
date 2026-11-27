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

from custom_guest_support import CG, HOTEL, LAUNCH, Host, load_host_module


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
    assert pre[0] == f"ExecStartPre=+{mod.LIBDIR}/custom-guest-host.sh check-start --hotel {HOTEL} --launch-id {LAUNCH}"
    assert all(ln.startswith("ExecStartPre=+") for ln in pre), "root steps are + prefixed only"
    assert [ln for ln in text.splitlines() if ln.startswith("ExecStart=")] == [
        f"ExecStart=/usr/bin/python3 -I {mod.LIBDIR}/launch-custom-guest.py {ctx.d}"]
    assert f"ExecStopPost=+{mod.LIBDIR}/custom-guest-host.sh exited --hotel {HOTEL} --launch-id {LAUNCH}" in lines


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

#!/usr/bin/env python3
"""Build a deterministic verity root from an explicitly pinned Debian base tar.

No guest code is executed or mounted. This builds the root component only, not
an approved kernel/initrd, a boot proof or an intake-ready guest image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'room-kit'))
from custom_guest_initrd import static_elf  # noqa: E402

VERSIONS = {'mksquashfs': 'mksquashfs version 4.7.5', 'veritysetup': 'veritysetup 2.8.4'}
SSH_CONFIG = '''Port 22
HostKey /run/cathedral/ssh_host_ed25519_key
AuthorizedKeysFile /run/cathedral/authorized_keys
PermitRootLogin prohibit-password
AllowUsers root
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM no
StrictModes yes
UseDNS no
PrintMotd no
PidFile /run/cathedral/sshd.pid
Subsystem sftp internal-sftp
'''
SSH_UNIT = '''[Unit]
Description=Owner-key SSH for the verified custom guest
Requires=cathedral-network.service
After=cathedral-network.service
ConditionPathExists=/run/cathedral/ssh_host_ed25519_key
ConditionPathExists=/run/cathedral/authorized_keys

[Service]
Type=simple
RuntimeDirectory=sshd
ExecStartPre=/usr/sbin/sshd -t -f /etc/ssh/cathedral_sshd_config
ExecStart=/usr/sbin/sshd -D -e -f /etc/ssh/cathedral_sshd_config
Restart=on-failure
RestartSec=2
UMask=0077

[Install]
WantedBy=multi-user.target
'''

NETWORK_UNIT = '''[Unit]
Description=Apply the init-validated custom guest network
Before=cathedral-sshd.service

[Service]
Type=oneshot
EnvironmentFile=/run/cathedral/network.env
ExecStart=/usr/bin/ip link set dev ${CATHEDRAL_INTERFACE} up
ExecStart=/usr/bin/ip address add ${CATHEDRAL_GUEST_CIDR} dev ${CATHEDRAL_INTERFACE}
ExecStart=/usr/bin/ip route add default via ${CATHEDRAL_GATEWAY} dev ${CATHEDRAL_INTERFACE}
RemainAfterExit=yes
'''


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked(path, expected):
    if len(expected) != 64 or any(c not in '0123456789abcdef' for c in expected):
        raise ValueError('expected SHA256 must be lowercase hex')
    if path.is_symlink() or not path.is_file() or digest(path) != expected:
        raise ValueError('input digest mismatch or non-regular input')


def extract(base, root):
    # This is a trusted distribution root, not customer intake. Still refuse
    # traversal and never materialize device nodes from the package archive.
    with tarfile.open(base, 'r:*') as archive:
        seen = set()
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or str(name) in seen:
                raise ValueError('unsafe or duplicate base archive name')
            seen.add(str(name))
            if not name.parts or name.parts[0] in ('dev', 'proc', 'sys', 'run'):
                continue
            if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
                raise ValueError('unsupported base archive entry')
            if member.issym() and member.linkname.startswith('/'):
                # Root-internal absolute links (e.g. var/run -> /run) become
                # relative so tarfile's data filter can enforce containment.
                member.linkname = os.path.relpath(root / member.linkname.lstrip('/'), root / str(name.parent))
            archive.extract(member, path=root, filter='data')
    for name in ('dev', 'proc', 'sys', 'run'):
        (root / name).mkdir(exist_ok=True)


def write(root, name, data, mode=0o644):
    target = root / name
    if target.is_symlink():
        raise ValueError('refuse configuration symlink: ' + name)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.resolve().is_relative_to(root.resolve()):
        raise ValueError('configuration escapes root')
    target.write_bytes(data if isinstance(data, bytes) else data.encode())
    target.chmod(mode)


def link(root, name, target):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        path.unlink()
    path.symlink_to(target)


def configure(root, helper, helper_hash, data_helper=None, cryptsetup=None):
    """data_helper (cathedral-data) and cryptsetup travel together: the unlock tool pins
    the digest of this static cryptsetup, never the root's own."""
    if (data_helper is None) != (cryptsetup is None):
        raise ValueError('cathedral-data and its pinned cryptsetup must be installed together')
    for name in ('sbin/init', 'usr/sbin/sshd', 'usr/bin/ip'):
        path = root / name
        if not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
            raise ValueError('base is missing required binary: ' + name)
        # Read the complete required binaries now; the boot init independently
        # reads them again through dm-verity before entering this root.
        if path.read_bytes()[:4] != b'\x7fELF':
            raise ValueError('required root binary is not ELF')
    for path in (root / 'etc/ssh').glob('ssh_host_*'):
        if path.is_dir():
            raise ValueError('unexpected SSH key directory')
        path.unlink()
    owner_ssh = root / 'root/.ssh'
    if owner_ssh.is_symlink() or (owner_ssh.exists() and
            (not owner_ssh.is_dir() or any(owner_ssh.iterdir()))):
        raise ValueError('base must not contain root SSH credentials')
    if (root / 'etc/ssh/authorized_keys').exists():
        raise ValueError('base must not contain authorized keys')
    write(root, 'etc/machine-id', '')
    for name in ('var/lib/dbus/machine-id', 'var/lib/systemd/random-seed'):
        path = root / name
        if path.exists() or path.is_symlink():
            path.unlink()
    # A non-locking, invalid hash allows OpenSSH public-key account checks
    # without an empty or usable password. Password auth and console login
    # services are also disabled.
    shadow = root / 'etc/shadow'
    rows = shadow.read_text().splitlines()
    if sum(row.startswith('root:') for row in rows) != 1:
        raise ValueError('base root account missing or duplicated')
    rows = [(':'.join([parts[0], 'x', *parts[2:]]) if parts[0] == 'root' else row)
            for row in rows for parts in [row.split(':')]]
    write(root, 'etc/shadow', '\n'.join(rows) + '\n', 0o600)
    write(root, 'etc/cloud/cloud-init.disabled', '')
    write(root, 'etc/ssh/cathedral_sshd_config', SSH_CONFIG)
    write(root, 'etc/systemd/system/cathedral-sshd.service', SSH_UNIT)
    write(root, 'etc/systemd/system/cathedral-network.service', NETWORK_UNIT)
    write(root, 'usr/bin/cathedral-attest', helper, 0o755)
    write(root, 'usr/share/cathedral/report-helper.sha256', helper_hash + '\n')
    if data_helper is not None:
        # mke2fs runs from this verity-protected root; cryptsetup does not.
        mke2fs = root / 'usr/sbin/mke2fs'
        if not mke2fs.resolve().is_relative_to(root.resolve()) or not mke2fs.is_file() \
                or mke2fs.read_bytes()[:4] != b'\x7fELF':
            raise ValueError('base is missing mke2fs (e2fsprogs)')
        if not (root / 'mnt').is_dir() or (root / 'mnt').is_symlink():
            raise ValueError('base is missing a plain /mnt directory')
        # The root is read-only squashfs at boot, so cathedral-data cannot create its
        # mount target then; it must already be in the image, owner-only and empty.
        target = root / 'mnt/cathedral-data'
        if target.is_symlink() or (target.exists() and (not target.is_dir() or any(target.iterdir()))):
            raise ValueError('base /mnt/cathedral-data must be absent or an empty directory')
        target.mkdir(exist_ok=True)
        target.chmod(0o700)
        write(root, 'usr/bin/cathedral-data', data_helper, 0o755)
        write(root, 'usr/lib/cathedral/cryptsetup', cryptsetup, 0o755)
    write(root, 'etc/hostname', 'cathedral-guest\n')
    write(root, 'etc/hosts', '127.0.0.1 localhost\n::1 localhost\n')
    write(root, 'etc/resolv.conf', '')
    write(root, 'etc/fstab', 'tmpfs /tmp tmpfs nodev,nosuid,mode=1777 0 0\n')
    link(root, 'etc/systemd/system/multi-user.target.wants/cathedral-sshd.service', '../cathedral-sshd.service')
    for unit in ('ssh.service', 'sshd.service', 'ssh.socket', 'getty@.service',
                 'serial-getty@.service', 'console-getty.service', 'container-getty@.service',
                 'console-shell.service', 'rescue.service', 'emergency.service',
                 'getty.target', 'debug-shell.service', 'systemd-firstboot.service',
                 'systemd-networkd.service', 'systemd-networkd.socket', 'networking.service',
                 'apt-daily.timer', 'apt-daily-upgrade.timer', 'systemd-networkd-wait-online.service'):
        link(root, 'etc/systemd/system/' + unit, '/dev/null')
    write(root, 'etc/systemd/journald.conf', '[Journal]\nStorage=volatile\nRuntimeMaxUse=16M\n')


def run(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True,
                          env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}, timeout=300)


def pinned_binary(path, sha):
    checked(path, sha)
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != sha:
        raise ValueError('input changed during read')
    static_elf(data)
    return data


def build(base, base_sha, helper_path, helper_sha, epoch, output, data=None, cryptsetup=None):
    """data and cryptsetup are optional (path, sha256) pairs, given together for a data-disk image."""
    checked(base, base_sha)
    helper = pinned_binary(helper_path, helper_sha)
    if (data is None) != (cryptsetup is None):
        raise ValueError('cathedral-data and cryptsetup must be given together')
    data_bytes = pinned_binary(*data) if data else None
    cryptsetup_bytes = pinned_binary(*cryptsetup) if cryptsetup else None
    if output.exists() or not 0 <= epoch <= 2**32 - 1:
        raise ValueError('output must be new; epoch must fit squashfs')
    versions = {}
    for tool, prefix in VERSIONS.items():
        text = run([tool, '-version' if tool == 'mksquashfs' else '--version']).stdout.splitlines()[0]
        if not text.startswith(prefix + ' ') and text != prefix:
            raise ValueError('wrong build tool version: ' + text)
        versions[tool] = text
    with tempfile.TemporaryDirectory(prefix='custom-guest-root-') as temp:
        scratch = Path(temp)
        root = scratch / 'root'
        root.mkdir()
        pinned_base = scratch / 'base.tar'
        shutil.copyfile(base, pinned_base)
        checked(pinned_base, base_sha)
        extract(pinned_base, root)
        configure(root, helper, helper_sha, data_bytes, cryptsetup_bytes)
        image = scratch / 'root.raw'
        run(['mksquashfs', str(root), str(image), '-noappend', '-all-root', '-no-xattrs',
             '-comp', 'zstd', '-processors', '1', '-mkfs-time', str(epoch), '-all-time', str(epoch), '-no-progress'])
        size = image.stat().st_size
        if size % 4096:
            raise ValueError('squashfs is not block-aligned')
        salt = digest(image)
        metadata = run(['veritysetup', 'format', str(image), str(image), '--data-block-size=4096',
                        '--hash-block-size=4096', '--data-blocks=' + str(size // 4096),
                        '--hash-offset=' + str(size), '--salt=' + salt,
                        '--uuid=' + str(uuid.UUID(salt[:32]))]).stdout
        roots = [line.split(':', 1)[1].strip() for line in metadata.splitlines() if line.startswith('Root hash:')]
        if len(roots) != 1 or len(roots[0]) != 64:
            raise ValueError('missing verity root hash')
        root_hash = roots[0]
        run(['veritysetup', 'verify', str(image), str(image), root_hash, '--hash-offset=' + str(size)])
        result = {'schema': 'cathedral.custom_guest.root-build/v1', 'base_sha256': base_sha,
                  'helper_sha256': helper_sha, 'data_helper_sha256': data[1] if data else None,
                  'cryptsetup_sha256': cryptsetup[1] if cryptsetup else None, 'source_date_epoch': epoch, 'tools': versions,
                  'root_verity': root_hash, 'root_data_bytes': size, 'bytes': image.stat().st_size,
                  'sha256': digest(image), 'verity_verified': True, 'boot_verified': False,
                  'packages_sha256': digest(root / 'var/lib/dpkg/status')}
        with output.open('xb') as destination, image.open('rb') as source:
            shutil.copyfileobj(source, destination)
            os.fchmod(destination.fileno(), 0o444)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--base-sha256', required=True)
    parser.add_argument('--helper', type=Path, required=True)
    parser.add_argument('--helper-sha256', required=True)
    parser.add_argument('--data-helper', type=Path, help='static cathedral-data (needs --cryptsetup)')
    parser.add_argument('--data-helper-sha256')
    parser.add_argument('--cryptsetup', type=Path, help='static pinned cryptsetup for cathedral-data')
    parser.add_argument('--cryptsetup-sha256')
    parser.add_argument('--epoch', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = cryptsetup = None
    if args.data_helper or args.cryptsetup:
        if not (args.data_helper and args.data_helper_sha256 and args.cryptsetup and args.cryptsetup_sha256):
            parser.error('--data-helper, --cryptsetup and their digests are given together')
        data = (args.data_helper, args.data_helper_sha256)
        cryptsetup = (args.cryptsetup, args.cryptsetup_sha256)
    print(json.dumps(build(args.base, args.base_sha256, args.helper, args.helper_sha256,
                           args.epoch, args.output, data, cryptsetup), sort_keys=True))


if __name__ == '__main__':
    main()

"""Offline root recipe guards; no mounts, guest boot, or customer files."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile

import pytest

spec = importlib.util.spec_from_file_location('custom_root', Path(__file__).parents[1] / 'scripts/build_custom_guest_root.py')
root_builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(root_builder)


def base_tree(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    for name in ('sbin/init', 'usr/sbin/sshd', 'usr/bin/ip'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'\x7fELFsynthetic-test-binary')
    (root / 'etc/ssh').mkdir(parents=True)
    (root / 'etc/shadow').write_text('root:!:20000:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\n')
    (root / 'root/.ssh').mkdir(parents=True)
    return root


def test_reference_root_discards_build_credentials_and_configures_ram_only_ssh(tmp_path):
    root = base_tree(tmp_path)
    (root / 'etc/ssh/ssh_host_ed25519_key').write_text('synthetic package-generated fixture')
    (root / 'var/lib/systemd').mkdir(parents=True)
    (root / 'var/lib/systemd/random-seed').write_bytes(b'synthetic seed')
    root_builder.configure(root, b'helper', hashlib.sha256(b'helper').hexdigest())
    assert not list((root / 'etc/ssh').glob('ssh_host_*'))
    assert not (root / 'var/lib/systemd/random-seed').exists()
    assert (root / 'etc/machine-id').read_bytes() == b''
    assert (root / 'etc/resolv.conf').read_bytes() == b''
    assert (root / 'etc/shadow').read_text().startswith('root:x:')
    assert (root / 'etc/shadow').stat().st_mode & 0o777 == 0o600
    assert (root / 'etc/cloud/cloud-init.disabled').exists()
    conf = (root / 'etc/ssh/cathedral_sshd_config').read_text()
    for text in ('HostKey /run/cathedral/ssh_host_ed25519_key',
                 'AuthorizedKeysFile /run/cathedral/authorized_keys',
                 'PasswordAuthentication no', 'KbdInteractiveAuthentication no',
                 'PermitEmptyPasswords no', 'UsePAM no'):
        assert text in conf
    for unit in ('ssh.service', 'ssh.socket', 'rescue.service', 'emergency.service',
                 'console-getty.service', 'serial-getty@.service', 'getty.target'):
        assert (root / 'etc/systemd/system' / unit).readlink() == Path('/dev/null')
    network = (root / 'etc/systemd/system/cathedral-network.service').read_text()
    assert 'EnvironmentFile=/run/cathedral/network.env' in network
    assert 'Requires=cathedral-network.service' in (root / 'etc/systemd/system/cathedral-sshd.service').read_text()
    assert '/bin/sh' not in network
    assert (root / 'usr/bin/cathedral-attest').read_bytes() == b'helper'


@pytest.mark.parametrize('bad', ['root_key', 'ssh_link', 'missing_init', 'bad_shadow', 'config_link'])
def test_refuses_credentialed_or_incomplete_root(tmp_path, bad):
    root = base_tree(tmp_path)
    if bad == 'root_key':
        (root / 'root/.ssh/authorized_keys').write_text('synthetic-key')
    elif bad == 'ssh_link':
        (root / 'root/.ssh').rmdir()
        (root / 'root/.ssh').symlink_to('../../etc')
    elif bad == 'missing_init':
        (root / 'sbin/init').unlink()
    elif bad == 'bad_shadow':
        (root / 'etc/shadow').write_text('nobody:*:1::::::\n')
    else:
        (root / 'etc/machine-id').symlink_to('../outside')
    with pytest.raises(ValueError):
        root_builder.configure(root, b'helper', '00' * 32)


def archive(tmp_path, entries):
    path = tmp_path / 'base.tar'
    with tarfile.open(path, 'w') as stream:
        for name, kind, target in entries:
            entry = tarfile.TarInfo(name)
            if kind == 'file':
                entry.size = 1
                stream.addfile(entry, io.BytesIO(b'x'))
            elif kind == 'symlink':
                entry.type, entry.linkname = tarfile.SYMTYPE, target
                stream.addfile(entry)
            elif kind == 'device':
                entry.type = tarfile.CHRTYPE
                stream.addfile(entry)
    root = tmp_path / 'extract'
    root.mkdir()
    return path, root


@pytest.mark.parametrize('entries', [
    [('../escape', 'file', '')], [('/absolute', 'file', '')],
    [('same', 'file', ''), ('./same', 'file', '')],
    [('elsewhere/device', 'device', '')],
    [('link', 'symlink', '../outside'), ('link/file', 'file', '')],
])
def test_base_tar_cannot_escape_or_create_devices(tmp_path, entries):
    base, root = archive(tmp_path, entries)
    with pytest.raises((ValueError, tarfile.FilterError)):
        root_builder.extract(base, root)
    assert not (tmp_path / 'escape').exists()
    assert not (tmp_path / 'outside/file').exists()


def test_base_tar_converts_absolute_internal_links_and_omits_devices(tmp_path):
    base, root = archive(tmp_path, [('var/run', 'symlink', '/run'), ('dev/null', 'device', '')])
    root_builder.extract(base, root)
    assert (root / 'var/run').resolve() == root / 'run'
    assert not (root / 'dev/null').exists()


def test_source_pin_rejects_wrong_bytes_and_symlinks(tmp_path):
    source = tmp_path / 'base'
    source.write_bytes(b'base')
    wanted = hashlib.sha256(b'base').hexdigest()
    root_builder.checked(source, wanted)
    with pytest.raises(ValueError):
        root_builder.checked(source, '0' * 64)
    link = tmp_path / 'link'
    link.symlink_to(source)
    with pytest.raises(ValueError):
        root_builder.checked(link, wanted)

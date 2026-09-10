"""Exercise real TLS issuance and atomic grant installation in private temp paths."""
import json
from pathlib import Path
import stat
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2] / 'deploy/reliquary-workers'


def run(name, *args, okay=True):
    result = subprocess.run([sys.executable, str(ROOT / name), *map(str, args)],
                            text=True, capture_output=True, timeout=60)
    if okay:
        assert result.returncode == 0, result.stderr
    else:
        assert result.returncode != 0
    return result


@pytest.fixture(scope='module')
def package(tmp_path_factory):
    root = tmp_path_factory.mktemp('operator-package')
    pki = root / 'pki'
    run('issue-pki.py', '--endpoint', 'https://executor.example:8443', '--output', pki, '--days', '1')
    manifest = root / 'manifest.json'
    manifest.write_text(json.dumps({'schema': 'cathedral_reliquary_build_v1',
        'source_revision': '0be0cda0c9a73dc3f08e3af2a07dda9407635aa7', 'platform': 'linux/amd64',
        'image_id': 'sha256:' + 'a' * 64, 'runtime_id': 'grader-sha256:' + 'b' * 64}))
    output = root / 'deployment'
    run('prepare.py', '--manifest', manifest, '--pki', pki, '--output', output,
        '--allocation-id', 'test-trial', '--owner-id', '00000000-0000-4000-8000-000000000001',
        '--endpoint', 'https://executor.example:8443', '--bind-address', '192.0.2.10',
        '--host-name', 'synthetic-test-machine', '--cpus', '4', '--memory-gib', '32',
        '--platform', 'kvm', '--expires-at', '2099-01-01T00:00:00Z')
    return root, pki, output


def test_tls_roles_hostname_and_private_key_custody(package):
    _, pki, output = package
    for role, name, purpose in (('executor', 'server', 'sslserver'), ('api', 'client', 'sslclient')):
        command = ['openssl', 'verify', '-CAfile', str(pki / role / 'ca.crt'), '-purpose', purpose]
        if role == 'executor':
            command.extend(['-verify_hostname', 'executor.example'])
        assert subprocess.run([*command, str(pki / role / f'{name}.crt')], capture_output=True).returncode == 0
        assert not (pki / role / 'ca.key').exists()
        assert stat.S_IMODE((pki / role / f'{name}.key').stat().st_mode) == 0o600
    wrong = subprocess.run(['openssl', 'verify', '-CAfile', str(pki / 'executor/ca.crt'),
        '-verify_hostname', 'other.example', str(pki / 'executor/server.crt')], capture_output=True)
    assert wrong.returncode != 0
    assert not list((output / 'host').rglob('client.key'))
    assert not list((output / 'api').rglob('server.key'))
    assert not list(output.rglob('ca.key'))


def test_install_disable_and_duplicate_refusal_preserve_store(package, tmp_path):
    _, _, output = package
    store = tmp_path / 'grants.json'
    run('admission.py', 'install', '--store', store, '--package', output / 'api/grants.json')
    installed = json.loads(store.read_text())
    assert installed['allocations'][0]['enabled'] is False
    assert stat.S_IMODE(store.stat().st_mode) == 0o600
    run('admission.py', 'enable', '--store', store, '--allocation-id', 'test-trial')
    enabled = store.read_bytes()
    assert json.loads(enabled)['allocations'][0]['enabled'] is True
    run('admission.py', 'install', '--store', store, '--package', output / 'api/grants.json', okay=False)
    assert store.read_bytes() == enabled
    run('admission.py', 'disable', '--store', store, '--allocation-id', 'test-trial')
    assert json.loads(store.read_text())['allocations'][0]['enabled'] is False
    assert any(path.read_bytes() == enabled for path in tmp_path.glob('*.bak'))


def test_disabled_same_owner_install_cannot_break_current_assignment(package, tmp_path):
    _, _, output = package
    store = tmp_path / 'grants.json'
    run('admission.py', 'install', '--store', store, '--package', output / 'api/grants.json')
    run('admission.py', 'enable', '--store', store, '--allocation-id', 'test-trial')
    second = json.loads((output / 'api/grants.json').read_text())
    second['allocations'][0]['allocation_id'] = 'second-trial'
    second['grants'][0].update(allocation_id='second-trial', grant_id='second-grant')
    source = tmp_path / 'second.json'
    source.write_text(json.dumps(second))
    before = store.read_bytes()
    run('admission.py', 'install', '--store', store, '--package', source, okay=False)
    assert store.read_bytes() == before


def test_second_owner_cannot_enable_the_same_executor(package, tmp_path):
    _, _, output = package
    store = tmp_path / 'grants.json'
    run('admission.py', 'install', '--store', store, '--package', output / 'api/grants.json')
    run('admission.py', 'enable', '--store', store, '--allocation-id', 'test-trial')
    second = json.loads((output / 'api/grants.json').read_text())
    owner = '00000000-0000-4000-8000-000000000002'
    second['allocations'][0].update(allocation_id='second-trial', owner_id=owner)
    second['grants'][0].update(allocation_id='second-trial', grant_id='second-grant', owner_id=owner)
    source = tmp_path / 'second.json'
    source.write_text(json.dumps(second))
    run('admission.py', 'install', '--store', store, '--package', source)
    before = store.read_bytes()
    run('admission.py', 'enable', '--store', store, '--allocation-id', 'second-trial', okay=False)
    assert store.read_bytes() == before


@pytest.mark.parametrize('section,field,value', [
    ('allocations', 'runtime_id', None), ('allocations', 'endpoint', 'http://executor.example'),
    ('allocations', 'endpoint', 'https://executor.example:bad'), ('allocations', 'client_key', 'relative.key'),
    ('allocations', 'ca_cert', ''), ('allocations', 'owner_id', 'invalid owner'),
    ('grants', 'expires_at', '2099-01-01T00:00:00'), ('grants', 'source', 'invalid source'),
])
def test_invalid_disabled_package_never_poison_shared_store(package, tmp_path, section, field, value):
    _, _, output = package
    store = tmp_path / 'grants.json'
    run('admission.py', 'install', '--store', store, '--package', output / 'api/grants.json')
    run('admission.py', 'enable', '--store', store, '--allocation-id', 'test-trial')
    before = store.read_bytes()
    second = json.loads((output / 'api/grants.json').read_text())
    owner = '00000000-0000-4000-8000-000000000002'
    second['allocations'][0].update(allocation_id='second-trial', owner_id=owner)
    second['grants'][0].update(allocation_id='second-trial', grant_id='second-grant', owner_id=owner)
    second[section][0][field] = value
    path = tmp_path / 'invalid.json'
    path.write_text(json.dumps(second))
    run('admission.py', 'install', '--store', store, '--package', path, okay=False)
    assert store.read_bytes() == before

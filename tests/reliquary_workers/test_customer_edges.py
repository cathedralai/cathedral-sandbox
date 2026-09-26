"""Deterministic shutdown and trusted-launcher regressions. No remote host."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2] / 'deploy/reliquary-workers'


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_drain_does_not_finish_during_twelve_second_post_upload():
    drain = load('drain')
    clock, physical_reads = [0.0], []
    replicas = [{'origin': 'https://api1.invalid', 'replica_id': 'one', 'boot_id': 'boot1'},
                {'origin': 'https://api2.invalid', 'replica_id': 'two', 'boot_id': 'boot2'}]
    def request(origin, path, **kw):
        if path == '/v1/health':
            physical_reads.append(clock[0])
            return {'runtime_id': 'runtime', 'executor_id': 'allocation', 'api': {'inflight': 0}}
        replica = next(r for r in replicas if r['origin'] == origin)
        return {**replica, 'allocation_id': 'allocation', 'runtime_id': 'runtime',
                'configuration_enabled': False, 'admission_closed': True,
                'dispatches_pending': int(replica['replica_id'] == 'one' and clock[0] < 12), 'dispatches_unknown': 0}
    args = SimpleNamespace(allocation_id='allocation', runtime_id='runtime', endpoint='https://executor.invalid', timeout=20)
    result = drain.wait_for_drain(args, replicas, 'synthetic', None, request=request,
                                 monotonic=lambda: clock[0], sleep=lambda n: clock.__setitem__(0, clock[0] + n))
    assert result['status'] == 'drained' and clock[0] >= 12
    assert physical_reads and min(physical_reads) >= 12  # Zero physical occupancy alone never passes.


@pytest.mark.parametrize('change', [{'boot_id': 'restarted'}, {'dispatches_unknown': 1},
                                    {'configuration_enabled': True}, {'admission_closed': False},
                                    {'replica_id': 'wrong'}, {'dispatches_pending': True}])
def test_fence_rejects_stale_or_ambiguous_evidence(change):
    drain = load('drain')
    expected = {'replica_id': 'one', 'boot_id': 'boot'}
    state = {**expected, 'allocation_id': 'allocation', 'runtime_id': 'runtime',
             'configuration_enabled': False, 'admission_closed': True, 'dispatches_pending': 0,
             'dispatches_unknown': 0, **change}
    with pytest.raises(ValueError):
        drain.validate_replica(state, expected, 'allocation', 'runtime')


def test_launcher_uses_fifty_shadow_workers_and_retains_local_authority(monkeypatch):
    launcher = load('shadow-grader')
    monkeypatch.setenv('RELIQUARY_GRADER_EXECUTOR_MODE', 'shadow')
    monkeypatch.setenv('RELIQUARY_SHADOW_WORKERS', '50')
    args = launcher.configuration(['--socket', '/tmp/grader.sock', '--bundle', '/local/bundle', '--health-path', '/tmp/health.json', '--pool-size', '64'])
    captured = {}
    remote = SimpleNamespace(runtime_id='runtime')
    def server(**kw):
        captured.update(kw)
        return object()
    module = SimpleNamespace(remote_executor_from_env=lambda: remote, runsc_worker_argv=lambda bundle: ['runsc', bundle], GraderServer=server)
    launcher.make_server(args, module)
    assert captured['shadow_workers'] == 50 and captured['pool_size'] == 64
    assert captured['sandbox_executor'] is None and captured['shadow_executor'] is remote
    assert captured['worker_argv'] == ['runsc', '/local/bundle']


def test_launcher_refuses_remote_authority(monkeypatch):
    launcher = load('shadow-grader')
    monkeypatch.setenv('RELIQUARY_GRADER_EXECUTOR_MODE', 'remote')
    with pytest.raises(SystemExit):
        launcher.configuration(['--socket', '/tmp/grader.sock', '--bundle', '/bundle', '--health-path', '/tmp/health.json', '--pool-size', '64'])

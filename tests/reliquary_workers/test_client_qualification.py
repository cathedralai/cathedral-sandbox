"""A successful subprocess alone must never qualify the wrong pool or workload."""
import copy
import importlib.util
from pathlib import Path

import pytest

PATH = Path(__file__).resolve().parents[2] / 'deploy/reliquary-workers/qualify-client.py'
SPEC = importlib.util.spec_from_file_location('qualify_client', PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def health():
    return {'status': 'ok', 'protocol_version': 2, 'executor_id': 'trial', 'runtime_id': 'runtime',
            'sandbox_backend': 'runsc', 'sandbox_platform': 'kvm',
            'api': {'max_inflight': 50}, 'pool': {'pool_size': 50, 'workers_alive': 50,
            'retire_worker_after_batch': True, 'worker_reap_failures_total': 0,
            'container_delete_failures_total': 0}}


@pytest.mark.parametrize('section,key,value', [
    (None, 'executor_id', 'someone-else'), (None, 'runtime_id', 'other-runtime'),
    (None, 'sandbox_backend', 'subprocess'), ('pool', 'retire_worker_after_batch', False),
    ('pool', 'pool_size', 64), ('pool', 'workers_alive', 49), ('api', 'max_inflight', 64),
    ('pool', 'worker_reap_failures_total', 1), ('pool', 'container_delete_failures_total', None),
])
def test_healthy_wrong_or_unclean_pool_never_qualifies(section, key, value):
    data = health()
    (data[section] if section else data)[key] = value
    with pytest.raises(ValueError):
        MODULE.validate_health(data, 'trial', 'runtime')


def test_load_reports_require_complete_accounting_and_finite_latency():
    data = {'requests': 3000, 'successful': 3000, 'parallel': 50, 'failures': [],
            'runtime_id': 'runtime', 'latency_ms': {'p50': 400, 'p95': 600, 'p99': 800, 'max': 1200}}
    MODULE.validate_load(data, 3000, 50, 'runtime', 1000)
    for change in ({'successful': 2999}, {'parallel': 32}, {'runtime_id': 'other'}, {'failures': ['wrong_result']}):
        bad = {**data, **change}
        with pytest.raises(ValueError):
            MODULE.validate_load(bad, 3000, 50, 'runtime', 1000)
    for value in (float('nan'), float('inf'), -1, 1001, True):
        bad = copy.deepcopy(data)
        bad['latency_ms']['p95'] = value
        with pytest.raises(ValueError):
            MODULE.validate_load(bad, 3000, 50, 'runtime', 1000)

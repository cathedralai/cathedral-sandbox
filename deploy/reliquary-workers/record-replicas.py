#!/usr/bin/env python3
"""Record all direct API process identities while admission remains disabled.

Operator inventory must match the actual serving topology. Do not use a load
balanced address for a process. One process per replica origin is required.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origins', type=Path, required=True, help='JSON array of direct HTTPS origins for EVERY serving process')
    parser.add_argument('--allocation-id', required=True)
    parser.add_argument('--runtime-id', required=True)
    parser.add_argument('--operator-token-file', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    import re
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}', args.allocation_id):
        parser.error('invalid allocation')
    spec = importlib.util.spec_from_file_location('workers_drain', Path(__file__).with_name('drain.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    origins = json.loads(args.origins.read_text())
    if type(origins) is not list or not 1 <= len(origins) <= 64 or len(set(origins)) != len(origins):
        raise ValueError('invalid inventory')
    token = args.operator_token_file.read_text().strip()
    if not 32 <= len(token) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise ValueError('invalid token')
    replicas = []
    for origin in origins:
        state = module.request_json(origin, f'/v1/workers/operator/fence/{args.allocation_id}', token=token)
        if (state.get('allocation_id') != args.allocation_id or state.get('runtime_id') != args.runtime_id
                or state.get('configuration_enabled') is not False or state.get('admission_closed') is not False
                or state.get('dispatches_pending') != 0 or state.get('dispatches_unknown') != 0
                or not state.get('replica_id') or not state.get('boot_id')):
            raise ValueError('process is not a fresh disabled allocation')
        replicas.append({'origin': origin, 'replica_id': state['replica_id'], 'boot_id': state['boot_id']})
    if len({r['replica_id'] for r in replicas}) != len(replicas) or len({r['boot_id'] for r in replicas}) != len(replicas):
        raise ValueError('duplicate process')
    # Exclusive creation preserves the previous trial inventory.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump({'allocation_id': args.allocation_id, 'runtime_id': args.runtime_id, 'replicas': replicas}, output, indent=2)
        output.write('\n')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, TypeError):
        raise SystemExit('Replica inventory NOT recorded. Keep admission disabled. Check direct process origins and identity. No credentials were printed.')

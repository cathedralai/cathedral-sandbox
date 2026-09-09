#!/usr/bin/env python3
"""Trusted trial launcher for the unchanged Reliquary GraderServer class.

Run in the customer's pinned Reliquary environment. Local runsc owns grades.
This launcher exposes the existing shadow_workers constructor parameter.
"""
from __future__ import annotations

import argparse
import os
import signal
import threading


def configuration(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--bundle", required=True, help="Local trusted runsc bundle")
    parser.add_argument("--pool-size", type=int, required=True, help="Preserve the existing local grader pool size")
    parser.add_argument("--shadow-workers", type=int, default=int(os.environ.get("RELIQUARY_SHADOW_WORKERS", "50")))
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--metrics-port", type=int, default=9876)
    parser.add_argument("--health-path", required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.pool_size <= 128 or not 1 <= args.shadow_workers <= 50 or not 0 < args.timeout <= 30:
        parser.error("pool size 1-128, shadow workers 1-50 and timeout (0, 30] required")
    if os.environ.get("RELIQUARY_GRADER_EXECUTOR_MODE", "shadow") != "shadow":
        parser.error("this launcher requires shadow mode with local grading authority")
    return args


def make_server(args, module):
    remote = module.remote_executor_from_env()
    if remote is None:
        raise ValueError("source the running relay environment before starting the grader")
    return module.GraderServer(
        socket_path=args.socket, pool_size=args.pool_size,
        worker_argv=module.runsc_worker_argv(args.bundle), eval_timeout_s=args.timeout,
        metrics_port=args.metrics_port, health_path=args.health_path,
        sandbox_executor=None, shadow_executor=remote, shadow_workers=args.shadow_workers,
        runtime_id=remote.runtime_id,
    )


def main():
    args = configuration()
    from reliquary.environment.grader import server as module
    server = make_server(args, module)
    stopped = threading.Event()
    previous = {sig: signal.signal(sig, lambda *_: stopped.set()) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        server.start()
        while not stopped.wait(1):
            pass
    finally:
        server.stop()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    main()

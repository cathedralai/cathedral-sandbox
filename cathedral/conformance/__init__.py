"""Sandbox API conformance suite.

Runs the measurable requirements a large evaluation customer (Affine, SN120)
set for a sandbox provider against any API that speaks the Cathedral
``/v1/sandboxes`` contract, and writes one JSON report. The same report is the
merge gate for sandbox work and the admission test for a compute source.
"""

from cathedral.conformance.checks import CHECKS, Check, Result

__all__ = ["CHECKS", "Check", "Result"]

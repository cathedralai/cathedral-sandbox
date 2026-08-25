# AGENTS.md — cathedral-sandbox

SN39 sandbox, customer receipts, and launch evidence. The validator-facing
Python package lives here. Do not advertise a capability the live catalog or
a signed receipt does not yet carry.

## Work-pass Codex QA

After implementation and tests, before declaring work done or marking a PR
ready, follow `.cursor/skills/codex-qa/SKILL.md`. Do not wait to be asked.
Missing Codex CLI login is not a skip: Codex CLI is `gpt-5.5` at
`model_reasoning_effort=xhigh`; fall back to a Cursor Task with model
`gpt-5.6-sol-xhigh`.

Write the report to `/opt/cursor/artifacts/codex-qa-<topic>.md`. Fix
fail-closed and honesty findings in the same pass.

## Hard rules for this repo

- Customer receipts use `cathedral_customer_receipt_v1` and Ed25519.
- New signed receipt fields must be optional. Legacy receipts without them
  must still load.
- Do not invent `approved_workload_sha256` or a solver digest.
- Keep `cathedral-sandbox#142` open until PolarIS mint is merged and the live
  catalog advertises the new trust fields.
- Do not enable `agent_enclave` rewards on `tls_pinning` alone.

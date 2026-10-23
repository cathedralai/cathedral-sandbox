# Agent IDE sealed smoke — 2026-10-23 **GREEN**

Staging tip `6c1e2771` · `deployed_sha=95b8061f…` · `migration_head=cath_decision_ver_64_20261021` · health **healthy**.

## What blocked create (and how Eng cleared it)

| Blocker | Fix |
| --- | --- |
| Cherry guest journal / dead TLS after prior wipe | Restarted `cathedral-customer-guest-cherry46` → boot `259d0861-aa02-49aa-b6e9-545ef6d88681`, `:8444` HTTP 404 |
| Stuck sealed offer `792e47fc…` (boot `b69ee3b3…`) | Ended + deleted |
| Ready join slot `f8aea039…` (`join-26cbd094…`) | Marked `deleted` |
| Stale roster / supply | Re-posted Eng UID5 roster; bumped `cathedral_snp_supply.listed_at` |
| Waiting offer | Discovery wrote `f2933548…` for boot `259d0861…` |

## Join seal (precondition)

| Step | Result |
| --- | --- |
| `POST /v1/sandboxes` `required_hardware=amd_sev_snp` | **202** → `1a18bb6b-3f2a-4ee8-859d-9297f4931506` |
| Poll | **running** / `amd_sev_snp` |
| Offer | `f2933548…` **sealed** on Cherry `.46` |
| Delete | **202** `deleting` |

## Agent IDE create → exec → delete

| Step | Result |
| --- | --- |
| Create labels `customer=agent_ide` `smoke=post-reseal` | **202** → `b90ef359-3f8e-4449-b82f-8dfac337550c` → **running** / `amd_sev_snp` |
| Exec `command=["/bin/sh","-c","echo AGENT_IDE_OK && uname"]` | **200** `exit_code=0` stdout `AGENT_IDE_OK\nLinux\n` |
| Native receipt | `sha256:ae24d8f5242c11b9efc33f6cd7fddd208214d4c3c8b91b2c20324d12e8950a94` |
| Delete | **202** `deleting` |

Auth: `CATHEDRAL_STAGING_TEST_API_KEY`. Eng self-serve; no Fred for this smoke.

## Hold (unchanged)

job_reward **pay** off · Finney / mainnet cutover is Fred’s call after this note · live thin-broker CONST deploy skipped this pass (code on `fix/const-feedback-2026-10-23`).

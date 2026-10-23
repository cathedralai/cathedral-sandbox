# Agent IDE sealed smoke rerun — 2026-10-23 (G5 ammo)

Fresh create → exec → delete on the **current** staging tip after overnight reset (not last night’s `6c1e2771`).

## Tip

| Field | Value |
| --- | --- |
| UTC | 2026-10-23T12:06:36Z create |
| `deployment_id` | `bd8272aa-c39e-40c4-a49c-a69992fa805c` |
| `deployed_sha` | `95b8061f58923ab4c1cdb89046fb347faa264606` |
| `migration_head` | `cath_decision_ver_64_20261021` |
| Health | `status=healthy` |
| Auth | `CATHEDRAL_STAGING_TEST_API_KEY` |

Same bake SHA as prior tip; **new** Railway deployment id after reset.

## Result

| Step | Result |
| --- | --- |
| Create labels `customer=agent_ide` `smoke=g5-rerun-2026-10-23` | **202** → `5c7b5df2-3f38-43ed-94c4-9983bc95fad6` → **running** / `amd_sev_snp` |
| Exec `command=["/bin/sh","-c","echo AGENT_IDE_OK && uname"]` | **200** `exit_code=0` stdout `AGENT_IDE_OK\nLinux\n` |
| Native receipt | `sha256:c09a23977635aa4a1493e3ffb090e647fb3e36316bc8fa76d2534dc05cbc56f9` |
| Delete | **202** `deleting` |

## Verdict

**GREEN** for G5 IDE-agents path on current tip `bd8272aa`.

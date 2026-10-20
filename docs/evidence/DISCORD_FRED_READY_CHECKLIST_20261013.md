# Discord → Fred (headline checklist — what I can do now)

@wallscaler On your “what you can do now” list:

**Confirm observer path + signer alignment**
- Inbox (absolute, no `~/`, no symlink): `/Users/user/.cathedral-snp-staging-qualification/independent_probe_inbox`
- Mode `0700`, owned by API/staging UID `501`
- `signing_key_id` `snp-staging-observer-1` + pubkey `33w8TDt31qA9sNI75SPQYiBKi27sJa1v7CWleal92y8=` match retained local signer
- Private key stays with me

**Boot preparation pinned to #1449 verified inputs**
- raw `8296f243…` · `images-verity` · APPEND `roothash=5607dede… console=ttyS0 systemd.volatile=overlay rw panic=-1`
- HOST_DATA unchanged; historical `e1a3ce4f` / `a7ad573b` / `ef0ab84e` blocked
- Dry-run still refuses (reviewed launcher + policy accept unset)

**#1451 ready for whole-guest absence → cleanup closeout**
- Producer present; wire helper present; **34/34** tests still green
- Will publish to the absolute inbox above after verified DELETE + owner teardown + host observation

**Still held (execution blockers on your side)**
- Released launcher (incl. explicit 4 vCPU / 8 GiB + 2 GiB host overhead approval)
- Image/policy acceptance + checkpoint
- Then 900s central grant once HTTPS + policy ready (clock not running — acknowledged)

Target unchanged: create → exec → native evidence → usage → delete → independently confirmed cleanup.

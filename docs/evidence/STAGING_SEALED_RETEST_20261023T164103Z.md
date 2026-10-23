# Staging sealed retest — 20261023T164103Z

## Health
```json
{"status":"healthy","service":"Polaris Computer","version":"2.1.0","release_sha":"95b8061f58923ab4c1cdb89046fb347faa264606","source_sha":"unknown","deployed_sha":"95b8061f58923ab4c1cdb89046fb347faa264606","release_identity":"release_only","deployment_id":"a8f77a30-bf49-427b-91a7-691a87ca9946","migration_head":"cath_decision_ver_64_20261021","database":"connected","compute":"disabled","uptime_seconds":2061}
```

| tip | `a8f77a30-bf49-427b-91a7-691a87ca9946` |
| sha | `95b8061f58923ab4c1cdb89046fb347faa264606` |

## 1. Roster refresh
{"accepted": true, "roster_id": "sha256:8aebc7953881bed33a41a5121272a85c40ebc040de9ad1326d536b16d04bf055", "rows": 1, "sequence": 1792773668, "status": "POSTED"}
roster: OK

## 2. Supply bump + wait for waiting offer
supply_bumped waiting_now=1
poll: 42a2f44f-f7fc-47a7-82e0-96cefc5ddbb0|9d3f91f2-736e-4f38-933e-eadb98b5ef8b

waiting offer `42a2f44f-f7fc-47a7-82e0-96cefc5ddbb0` boot `9d3f91f2-736e-4f38-933e-eadb98b5ef8b`

## 3. Smokes
### join
create HTTP=202
```json
{"id":"50c46468-1327-4889-95f4-f41f6a174dca","state":"creating","box":null,"waiting_for":null,"retry_after_s":null,"error_code":null,"template":"cathedral-snp-pilot","hardware":"unknown","resources":{"cpu":1,"memory_gib":1,"disk_gib":5},"network":"deny_all","labels":{},"image":"sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764","image_id":null,"snapshot_id":null,"workspace":null,"lifetime_deadline_at":"2026-10-23T16:44:35+00:00","cleanup_state":"none","failed_by":null,"billed":null,"operation":{"id":"302e8cc8-ba56-4cf9-98cb-4449b2873338","state":"reserved","kind":"create"},"error":null,"created_at":"2026-10-23T16:41:35.329493+00:00","receipts":null}
```
poll 1: state=running hardware=amd_sev_snp
exec HTTP=200
```json
{"exit_code":0,"stdout":"join_OK\nLinux\n","stderr":"","duration_ms":963,"stdout_truncated":null,"stderr_truncated":null,"timed_out":null,"stdout_b64":"am9pbl9PSwpMaW51eAo=","stderr_b64":"","duration_scope":"api_round_trip","native_operation_id":"6b662ec2-2780-4c1f-867f-d445862385cc","native_receipt_sha256":"cc3d02857aa14f7653df9dd9f914331e199d988ee1b4fa7efb50b352ec1236b3","env":null}
```
**GREEN** join sid=`50c46468-1327-4889-95f4-f41f6a174dca` exit_code=0

### agent_ide
create HTTP=202
```json
{"id":"b81083af-9192-485f-9529-93d4b778fe99","state":"creating","box":null,"waiting_for":null,"retry_after_s":null,"error_code":null,"template":"cathedral-snp-pilot","hardware":"unknown","resources":{"cpu":1,"memory_gib":1,"disk_gib":5},"network":"deny_all","labels":{"smoke":"post-policy-20261023T164103Z","customer":"agent_ide"},"image":"sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764","image_id":null,"snapshot_id":null,"workspace":null,"lifetime_deadline_at":"2026-10-23T16:44:45+00:00","cleanup_state":"none","failed_by":null,"billed":null,"operation":{"id":"36c25a1f-0d16-471a-be1c-e6451495c36a","state":"reserved","kind":"create"},"error":null,"created_at":"2026-10-23T16:41:45.453859+00:00","receipts":null}
```
poll 1: state=running hardware=amd_sev_snp
exec HTTP=200
```json
{"exit_code":0,"stdout":"agent_ide_OK\nLinux\n","stderr":"","duration_ms":909,"stdout_truncated":null,"stderr_truncated":null,"timed_out":null,"stdout_b64":"YWdlbnRfaWRlX09LCkxpbnV4Cg==","stderr_b64":"","duration_scope":"api_round_trip","native_operation_id":"34ff9c3a-8a9b-47bd-a659-da1c50494f07","native_receipt_sha256":"a81d11ed49cbb860e797b52ee991f1c73ec06743e3d3e497900d8209dd661aed","env":null}
```
**GREEN** agent_ide sid=`b81083af-9192-485f-9529-93d4b778fe99` exit_code=0

### ditto
create HTTP=202
```json
{"id":"0bc659d2-acc4-4605-b4fa-0f7f89086ebf","state":"creating","box":null,"waiting_for":null,"retry_after_s":null,"error_code":null,"template":"cathedral-snp-pilot","hardware":"unknown","resources":{"cpu":1,"memory_gib":1,"disk_gib":5},"network":"deny_all","labels":{"smoke":"post-policy-20261023T164103Z","customer":"ditto"},"image":"sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764","image_id":null,"snapshot_id":null,"workspace":null,"lifetime_deadline_at":"2026-10-23T16:44:57+00:00","cleanup_state":"none","failed_by":null,"billed":null,"operation":{"id":"e2f9f0fb-b042-4d65-82e4-37e09aec75b8","state":"reserved","kind":"create"},"error":null,"created_at":"2026-10-23T16:41:57.122182+00:00","receipts":null}
```
poll 1: state=running hardware=amd_sev_snp
exec HTTP=200
```json
{"exit_code":0,"stdout":"ditto_OK\nLinux\n","stderr":"","duration_ms":1003,"stdout_truncated":null,"stderr_truncated":null,"timed_out":null,"stdout_b64":"ZGl0dG9fT0sKTGludXgK","stderr_b64":"","duration_scope":"api_round_trip","native_operation_id":"0a3e4757-3c84-4e64-bc21-dfdca127c763","native_receipt_sha256":"eb569dcbda508a87b60a848eb95bc91f4e43b916d0a433a1bd1a20b9cf3c0b76","env":null}
```
**GREEN** ditto sid=`0bc659d2-acc4-4605-b4fa-0f7f89086ebf` exit_code=0

### reliquary
create HTTP=202
```json
{"id":"dd86f82b-3057-461f-8277-47d6292ad88d","state":"creating","box":null,"waiting_for":null,"retry_after_s":null,"error_code":null,"template":"cathedral-snp-pilot","hardware":"unknown","resources":{"cpu":1,"memory_gib":1,"disk_gib":5},"network":"deny_all","labels":{"smoke":"post-policy-20261023T164103Z","customer":"reliquary"},"image":"sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764","image_id":null,"snapshot_id":null,"workspace":null,"lifetime_deadline_at":"2026-10-23T16:45:09+00:00","cleanup_state":"none","failed_by":null,"billed":null,"operation":{"id":"cfef05e5-d306-42d6-8691-694dbb89407e","state":"reserved","kind":"create"},"error":null,"created_at":"2026-10-23T16:42:09.076884+00:00","receipts":null}
```
poll 1: state=running hardware=amd_sev_snp
exec HTTP=200
```json
{"exit_code":0,"stdout":"reliquary_OK\nLinux\n","stderr":"","duration_ms":1057,"stdout_truncated":null,"stderr_truncated":null,"timed_out":null,"stdout_b64":"cmVsaXF1YXJ5X09LCkxpbnV4Cg==","stderr_b64":"","duration_scope":"api_round_trip","native_operation_id":"ff971e59-b407-4074-90d5-32c7f4d23ff2","native_receipt_sha256":"e0ab4675c2f2c46743b41a45b8f417caad0083e9c65b1c81f190546a1583f1bf","env":null}
```
**GREEN** reliquary sid=`dd86f82b-3057-461f-8277-47d6292ad88d` exit_code=0

## Verdict
**GREEN** — Join + IDE + ditto + reliquary create→exec→delete on tip `a8f77a30-bf49-427b-91a7-691a87ca9946`.

# Toby staging check — absence observer + UID5 — 20261023T184820Z

## Health
```json
{"status":"healthy","service":"Polaris Computer","version":"2.1.0","release_sha":"95b8061f58923ab4c1cdb89046fb347faa264606","source_sha":"unknown","deployed_sha":"95b8061f58923ab4c1cdb89046fb347faa264606","release_identity":"release_only","deployment_id":"b38802ac-d8b8-4d71-bc6f-bd7bd42d0f86","migration_head":"cath_decision_ver_64_20261021","database":"connected","compute":"disabled","uptime_seconds":805}
```

## UID5 endpoint (.46 miner :8081 / customer :8444)
- :8081 TCP OPEN
- :8081 HTTPS http=000curlfail
- :8444 TCP OPEN
- :8444 HTTPS http=404

## Roster refresh (UID5)
```
{"accepted": true, "roster_id": "sha256:764f7f3272e8c0dc3fa21a1fa43c80339e0d64eb08974aae2b5f92f424245b3a", "rows": 1, "sequence": 1792781308, "status": "POSTED"}
```
roster: OK

## Absence observer (staging flags + script import)
- staging test key present
```json
{
  "env_hits": {},
  "settings_flag": false,
  "settings_raw": false,
  "db_error": "UndefinedColumnError:column \"created_at\" does not exist\nHINT:  Perhaps you meant to reference the column \"cathedral_snp_guest_offers.sealed_at\" or the column \"cathedral_snp_guest_offers.updated_at\"."
}
```

## Local absence observer module
local_default_flag False
module_ok True

## DB after roster + supply bump
```
TABLE cathedral_snp_guest_offers ['id', 'machine_id', 'hardware_id', 'chip_id', 'hotkey', 'endpoint', 'boot_id', 'tls_spki_sha256', 'certificate_pem', 'identity', 'measurement', 'approved_image_id', 'policy_digest', 'state', 'provider_row_id', 'slot_row_id', 'slot_generation', 'customer_scope', 'admission_body', 'binding', 'binding_sha256', 'imported_image_digest', 'lease_expires_at', 'seal_attempts', 'error', 'relaunch_needed', 'first_seen_at', 'last_seen_at', 'sealed_at', 'ended_at', 'updated_at']
TABLE cathedral_snp_supply ['machine_id', 'validator_hotkey', 'uid', 'hotkey', 'endpoint', 'roster_row_id', 'listed_at']
{
  "waiting_count": 0,
  "recent_offers": [
    {
      "id": "42a2f44f-f7fc-47a7-82e0-96cefc5ddbb0",
      "machine_id": "1d7ba6c7db10f27c4b7a656b15821e0255edb416894fe23dffab3bcae7569165",
      "hardware_id": "26cbd094c451ed1f146e07bf798c3ada85bb9cf721def068960b6381b0418fdd",
      "chip_id": "275173b6acc4f735621cf49e28e545109e6061ed7f4b5ac235d852728e5edb1eebaea3f0bddd65e565c2e2b67e9474b287a4f6c85415af75bf51087476e17c82",
      "hotkey": "5CftP3XTpK9FF79xdpAZLCMbBLUwBtm7CVU8h3MZyGU5snzX",
      "endpoint": "https://84.32.220.46:8444",
      "boot_id": "9d3f91f2-736e-4f38-933e-eadb98b5ef8b",
      "tls_spki_sha256": "b412bc8e84f10a98033289d245f80bffe40af2942e79645974a8c83f6b9b70b9",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIBZTCCAQugAwIBAgIUOtc7nPPxBKQSyWIBlOIEF+To6K8wCgYIKoZIzj0EAwIw\nITEfMB0GA1UEAwwWY2F0aGVkcmFsLWN1c3RvbWVyLXNucDAeFw0yNjEwMjMxNjIy\nMTBaFw0yNjEwMzExNjI3MTBaMCExHzAdBgNVBAMMFmNhdGhlZHJhbC1jdXN0b21l\nci1zbnAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR/ti/kI2FTIR0oXyveiMKo\nOxvMvUhw729M55a+vi3P7t7+RQvrR4ff/rOCpdK6XPFmQaA0cNjB2xqyOGN8Z9g7\noyEwHzAMBgNVHRMBAf8EAjAAMA8GA1UdEQQIMAaHBFQg3C4wCgYIKoZIzj0EAwID\nSAAwRQIhANGz+655Reirk5XkM1ym8QRj71eGmM9PgxyVsmNPH8zwAiBnGsEp9g3V\n502fUau7L5ApQ5y2VRzlWtEhd50pcIYunQ==\n-----END CERTIFICATE-----\n",
      "identity": "{\"hotkey\": \"5CftP3XTpK9FF79xdpAZLCMbBLUwBtm7CVU8h3MZyGU5snzX\", \"schema\": \"cathedral_customer_boot_identity_v1\", \"boot_id\": \"9d3f91f2-736e-4f38-933e-eadb98b5ef8b\", \"endpoint\": \"https://84.32.220.46:8444\", \"nonce_hex\": \"1929c09ece60dbe8dc4d5ed747bd83b7849fa93f5b18313e4935c443dd4befe6\", \"quote_b64\": \"BQAAAAAAAAAAAAMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAMAAAAAAAcWCUAAAAAAAAAAAAAAAAAAAA3PS1YeSSumXB+ZV3fPwbGsbqqmA0tQE4jIdDh7h51CR8nKO+vAFe/qZYnoVP9+7fSBVcO1cNK6QR2OD2S7XN+qZTXwrulGV8g1UhyHHjkk7QtrlDw52HOTKrPHK9ojWvyWkUD1zyFgOEn/dv43YYAVR35Ls6k4fpnvRDD0rCX13XEvq+LaOxOAF/2bXHJiF4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACYF7y+22m3z9n9rHZxAaf0dLarmEDa99kLzBIjvXE6x///////////////////////////////////////////DAAAAAAAHFgZEQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAnUXO2rMT3NWIc9J4o5UUQnmBh7X9LWsI12FJyjl7bHuuuo/C93WXlZcLitn6UdLKHpPbIVBWvdb9RCHR24XyCDAAAAAAAHFgCOgEAAjoBAAwAAAAAABxYDwAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/bgy2yFt47sfEQnMQr32THu3sVh6tNLN2T9CFKPmN9cO9axXtXHioaTnmxu6WRQfAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFDZgh4QxcQT+Lk33q2bdlWqBNe+TiQhai7dyhXsvc20IpErx0aXR0SaBLaPJGKbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\", \"measurement\": \"a994d7c2bba5195f20d548721c78e493b42dae50f0e761ce4caacf1caf688d6bf25a4503d73c8580e127fddbf8dd8600\", \"certificate_b64\": \"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJaVENDQVF1Z0F3SUJBZ0lVT3RjN25QUHhCS1FTeVdJQmxPSUVGK1RvNks4d0NnWUlLb1pJemowRUF3SXcKSVRFZk1CMEdBMVVFQXd3V1kyRjBhR1ZrY21Gc0xXTjFjM1J2YldWeUxYTnVjREFlRncweU5qRXdNak14TmpJeQpNVEJhRncweU5qRXdNekV4TmpJM01UQmFNQ0V4SHpBZEJnTlZCQU1NRm1OaGRHaGxaSEpoYkMxamRYTjBiMjFsCmNpMXpibkF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVIvdGkva0kyRlRJUjBvWHl2ZWlNS28KT3h2TXZVaHc3MjlNNTVhK3ZpM1A3dDcrUlF2clI0ZmYvck9DcGRLNlhQRm1RYUEwY05qQjJ4cXlPR044WjlnNwpveUV3SHpBTUJnTlZIUk1CQWY4RUFqQUFNQThHQTFVZEVRUUlNQWFIQkZRZzNDNHdDZ1lJS29aSXpqMEVBd0lEClNBQXdSUUloQU5Heis2NTVSZWlyazVYa00xeW04UVJqNzFlR21NOVBneHlWc21OUEg4endBaUJuR3NFcDlnM1YKNTAyZlVhdTdMNUFwUTV5MlZSemxXdEVoZDUwcGNJWXVuUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K\", \"tls_spki_sha256\": \"b412bc8e84f10a98033289d245f80bffe40af2942e79645974a8c83f6b9b70b9\", \"max_lease_seconds\": 604800, \"native_vendor_verification\": \"consumer required\"}",
      "measurement": "a994d7c2bba5195f20d548721c78e493b42dae50f0e761ce4caacf1caf688d6bf25a4503d73c8580e127fddbf8dd8600",
      "approved_image_id": "cathedral-customer-snp-20261016-b7144296",
      "policy_digest": "sha256:a6ab44032bc358ebba76807296c9923fd4fed35d5fea52a1733e0687ec1ffecf",
      "state": "sealed",
      "provider_row_id": "cc167ef9-a631-459e-80df-cb1f9462f8cb",
      "slot_row_id": "f408efce-9de7-4198-95e2-d6245bfae68c",
      "slot_generation": "snp-9d3f91f2-736e-4f38-933e-eadb98b5ef8b",
      "customer_scope": "user:1ac47e6e-8c06-53af-9983-8eb0b479898d",
      "admission_body": "{\"schema\": \"cathedral_customer_admission_v2\", \"boot_id\": \"9d3f91f2-736e-4f38-933e-eadb98b5ef8b\", \"allocation\": {\"binding_metadata\": {\"slot_id\": \"join-26cbd094c451ed1f146e07bf\", \"endpoint\": \"https://84.32.220.46:8444\", \"lease_id\": \"6d1c53cb-006d-45c1-b204-6eb4c2a2f060\", \"worker_id\": \"join-42a2f44ff7fc47a782e096cefc5ddbb0\", \"incarnation\": \"9d3f91f2-736e-4f38-933e-eadb98b5ef8b\", \"measurement\": \"a994d7c2bba5195f20d548721c78e493b42dae50f0e761ce4caacf1caf688d6bf25a4503d73c8580e127fddbf8dd8600\", \"policy_sha256\": \"a6ab44032bc358ebba76807296c9923fd4fed35d5fea52a1733e0687ec1ffecf\", \"customer_scope\": \"user:1ac47e6e-8c06-53af-9983-8eb0b479898d\", \"software_sha256\": \"f6ef892f5137e77259480d71f97a7410340cc1de1224a5691c84f90c8026f6f4\", \"lease_expires_at\": 1793376028, \"approved_image_id\": \"cathedral-customer-snp-20261016-b7144296\", \"physical_machine_id\": \"275173b6acc4f735621cf49e28e545109e6061ed7f4b5ac235d852728e5edb1eebaea3f0bddd65e565c2e2b67e9474b287a4f6c85415af75bf51087476e17c82\"}, \"authorized_caller\": \"central:0304b1e702e7162147b17eb5d758bdf4ac71939d2dfe090aef951ec1b79b149d\", \"central_revocations\": {\"schema\": \"cathedral_central_revocations_v1\", \"revoked\": [\"sha256:01487b00ad03dbf31087a3a048ef661d6800b1c64c77b285f16d8269d7395c74\", \"sha256:5119a549dcc5933783f503eebc1100a6c8ea41f406e4f9f5e2a79c201c10cdf6\"], \"sequence\": 28, \"issued_at\": \"2026-10-23T09:28:38Z\", \"signature\": {\"algorithm\": \"ed25519\", \"value_base64\": \"m+mj9rp69Vi8SXiTUgl+Pky81q3CCos2SVkJ/LnbJkKaFHh4WxZKpfxkZUsscAgL4ztJNH3LvNJAAZgl2AeCAQ==\"}, \"root_key_id\": \"cathedral-root-1\"}}, \"challenge_hex\": \"1929c09ece60dbe8dc4d5ed747bd83b7849fa93f5b18313e4935c443dd4befe6\", \"tls_spki_sha256\": \"b412bc8e84f10a98033289d245f80bffe40af2942e79645974a8c83f6b9b70b9\"}",
      "binding": "{\"boot_id\": \"9d3f91f2-736e-4f38-933e-eadb98b5ef8b\", \"slot_id\": \"join-26cbd094c451ed1f146e07bf\", \"endpoint\": \"https://84.32.220.46:8444\", \"lease_id\": \"6d1c53cb-006d-45c1-b204-6eb4c2a2f060\", \"worker_id\": \"join-42a2f44ff7fc47a782e096cefc5ddbb0\", \"incarnation\": \"9d3f91f2-736e-4f38-933e-eadb98b5ef8b\", \"measurement\": \"a994d7c2bba5195f20d548721c78e493b42dae50f0e761ce4caacf1caf688d6bf25a4503d73c8580e127fddbf8dd8600\", \"root_sha256\": \"551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e\", \"policy_sha256\": \"a6ab44032bc358ebba76807296c9923fd4fed35d5fea52a1733e0687ec1ffecf\", \"worker_hotkey\": \"5CftP3XTpK9FF79xdpAZLCMbBLUwBtm7CVU8h3MZyGU5snzX\", \"customer_scope\": \"user:1ac47e6e-8c06-53af-9983-8eb0b479898d\", \"receipt_key_b64\": \"6tWs8zfP66jFP5EHf+dAeFWuVlRYNP7/mAH/LeXPByI=\", \"software_sha256\": \"f6ef892f5137e77259480d71f97a7410340cc1de1224a5691c84f90c8026f6f4\", \"tls_spki_sha256\": \"b412bc8e84f10a98033289d245f80bffe40af2942e79645974a8c83f6b9b70b9\", \"lease_expires_at\": 1793376028, \"approved_image_id\": \"cathedral-customer-snp-20261016-b7144296\", \"physical_machine_id\": \"275173b6acc4f735621cf49e28e545109e6061ed7f4b5ac235d852728e5edb1eebaea3f0bddd65e565c2e2b67e9474b287a4f6c85415af75bf51087476e17c82\"}",
      "binding_sha256": "4f3d61ffe1b616c9cb03024f0f20e186dd97fb2e3c7c634bab7f87af71d1fb39",
      "imported_image_digest": "sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764",
      "lease_expires_at": "2026-10-30 16:00:28+00:00",
      "seal_attempts": 0,
      "error": null,
      "relaunch_needed": false,
      "first_seen_at": "2026-10-23 16:33:58+00:00",
      "last_seen_at": "2026-10-23 16:41:01+00:00",
      "sealed_at": "2026-10-23 16:41:34+00:00",
      "ended_at": null,
      "updated_at": "2026-10-23 16:41:34+00:00"
    }
  ],
  "supply": [
    {
      "machine_id": "1d7ba6c7db10f27c4b7a656b15821e0255edb416894fe23dffab3bcae7569165",
      "validator_hotkey": "5HNKFeHjvppKyKHTA1SK4rN7L2SZWpJeoNjeLo4DDg2FcRKh",
      "uid": 5,
      "hotkey": "5CftP3XTpK9FF79xdpAZLCMbBLUwBtm7CVU8h3MZyGU5snzX",
      "endpoint": "https://84.32.220.46:8081",
      "roster_row_id": "20bed3ee-244e-4635-8e36-ae2e1e1ee97f",
      "listed_at": "2026-10-23 18:49:50.263232+00:00"
    }
  ],
  "absence_tables": [
    "container_images"
  ]
}
```

## Cherry host guest units
```
cathedral-team-lab-1
Fri Oct 23 18:49:55 UTC 2026
  UNIT                                      LOAD   ACTIVE   SUB     DESCRIPTION
  cathedral-customer-guest-cherry46.service loaded active   running Cathedral sealed SEV-SNP customer standing guest (image b7144296, 40 vCPU / 96 GiB) on Cherry 84.32.220.46 (not bound to any customer)
  cathedral-sn94-miner-guest.service        loaded active   running Cathedral SN94 testnet 584 SEV-SNP miner guest (4 vCPU / 8 GiB, same launch as Contabo UID 3)
  cathedral-sn94-vac-refresh.service        loaded inactive dead    Refresh Cathedral SN94 testnet 584 validator-access snapshot and push to miner guest
  cathedral-staging-join-roster.service     loaded inactive dead    Post Eng-signed UID5 SNP join roster to api-staging

Legend: LOAD   → Reflects whether the unit definition was properly loaded.
        ACTIVE → The high-level unit activation state, i.e. generalization of SUB.
        SUB    → The low-level unit activation state, values depend on unit type.

4 loaded units listed.
To show all installed unit files use 'systemctl list-unit-files'.
====
LISTEN 0      1       84.32.220.46:8081       0.0.0.0:*    users:(("qemu-system-x86",pid=176659,fd=18))             
LISTEN 0      1       84.32.220.46:8444       0.0.0.0:*    users:(("qemu-system-x86",pid=1473167,fd=16))            
====
-- cathedral-customer-guest-cherry46.service
active
ActiveState=active
SubState=running
MainPID=1473167
-- cathedral-sn94-miner-guest.service
active
ActiveState=active
SubState=running
MainPID=176659
-- cathedral-sn94-miner.service
inactive
ActiveState=inactive
SubState=dead
MainPID=0
```

## Ditto + Reliquary sealed smokes (Toby proof)
prior ditto create f12b0c34-94cd-4519-bf70-96577281f1d6 state=running
prior ditto exec exit=None
### ditto
create HTTP=202 sid=41fd1b09-1206-438a-bf59-a9d44eec917d
poll 1: state=running hardware=amd_sev_snp
exec exit_code=0 stdout=
delete 422
**GREEN** ditto sid=41fd1b09-1206-438a-bf59-a9d44eec917d
### reliquary
create HTTP=429 sid=
**FAIL** no id

## Cleanup leftover sandboxes then Reliquary retry
delete f12b0c34-94cd-4519-bf70-96577281f1d6 -> 202 {"id":"f12b0c34-94cd-4519-bf70-96577281f1d6","state":"deleting","box":null,"waiting_for":null,"retry_after_s":null,"erro
delete 41fd1b09-1206-438a-bf59-a9d44eec917d -> 202 {"id":"41fd1b09-1206-438a-bf59-a9d44eec917d","state":"deleting","box":null,"waiting_for":null,"retry_after_s":null,"erro
delete-list 41fd1b09-1206-438a-bf59-a9d44eec917d (running ditto) -> 202
delete-list f12b0c34-94cd-4519-bf70-96577281f1d6 (running ditto) -> 202
catalog after cleanup:
{'available': True, 'concurrency': 48}
reliquary create HTTP=202 sid=bb488a96-abbd-47e2-a8b4-fdde6e184649 body={"id":"bb488a96-abbd-47e2-a8b4-fdde6e184649","state":"creating","box":null,"waiting_for":null,"retry_after_s":null,"error_code":null,"template":"cathedral-snp-pilot","hardware":"unknown","resources":{"cpu":1,"memory_gib":1,"disk_gib":5},"network":"deny_all","labels":{"smoke":"toby-check","customer":
reli poll 1: running amd_sev_snp
reli exec: None
STDOUT None
reli delete 202
**FAIL** reliquary

## Final Ditto then Reliquary (serial)
active-ish count=8
active-ish count=8
active-ish count=8
active-ish count=8
active-ish count=8
active-ish count=8
ditto create HTTP=202 sid=8ffa5f1d-213e-4743-a146-19a9d695c6ad
ditto poll 1 running amd_sev_snp
ditto exec HTTP=200
ditto exec body={"exit_code":0,"stdout":"ditto_OK\nLinux\n","stderr":"","duration_ms":1316,"stdout_truncated":null,"stderr_truncated":null,"timed_out":null,"stdout_b64":"ZGl0dG9fT0sKTGludXgK","stderr_b64":"","duration_scope":"api_round_trip","native_operation_id":"64d6f368-9348-4b95-839d-7847d6c94d34","native_receipt_sha256":"a5525e046098f51fed923a840ec3bdc2a9a255905c3c0c8b1400d184e54a57c2","env":null}
ditto exec parsed: 0
ditto_OK
Linux
ditto delete 202
reliquary create HTTP=202 sid=b80e460e-3404-4c0c-a904-710aa53c3329
reliquary poll 1 running amd_sev_snp
reliquary exec HTTP=200
reliquary exec body={"exit_code":0,"stdout":"reliquary_OK\nLinux\n","stderr":"","duration_ms":1301,"stdout_truncated":null,"stderr_truncated":null,"timed_out":null,"stdout_b64":"cmVsaXF1YXJ5X09LCkxpbnV4Cg==","stderr_b64":"","duration_scope":"api_round_trip","native_operation_id":"5dc54681-fe96-4af9-ab4a-0ec4334b1b6d","native_receipt_sha256":"58332dbe66638e9ecdfa11fc94d0ed55cf8c0aa50f4906dde03a89e44728e06f","env":null}
reliquary exec parsed: 0
reliquary_OK
Linux
reliquary delete 202
**GREEN** ditto + reliquary serial smokes passed

## Ditto + Reliquary serial proof (final)

| Client | Result | Sandbox | Notes |
| --- | --- | --- | --- |
| ditto | **GREEN** | `8ffa5f1d-213e-4743-a146-19a9d695c6ad` | create 202 → running `amd_sev_snp` → exec exit 0 `ditto_OK` → delete 202 |
| reliquary | **GREEN** | `b80e460e-3404-4c0c-a904-710aa53c3329` | create 202 → running `amd_sev_snp` → exec exit 0 `reliquary_OK` → delete 202 |

ALL_GREEN serial proof at ~2026-10-23T18:53Z on tip `b38802ac` / sha `95b8061f…`.

## Absence observer

- Staging `cathedral_container_absence_observer_enabled` = **false** (default off).
- Module importable; producer never stops guests; sealed create path does not require the flag.
- No absence-specific DB tables beyond `container_images`.

## UID5

- Roster POSTED `sha256:764f7f3272e8c0dc3fa21a1fa43c80339e0d64eb08974aae2b5f92f424245b3a` seq `1792781308` (UID5 / `.46:8081`).
- Supply `listed_at` bumped.
- Host units: `cathedral-sn94-miner-guest` active (TCP :8081), `cathedral-customer-guest-cherry46` active (HTTPS :8444 → 404 OK).
- Eng curl to `:8081` TLS alert 40 without client cert — expected for mTLS miner; join customer path uses `:8444`.

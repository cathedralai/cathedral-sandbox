# TEE box attestation over caller data (`attest.report`)

`POST /v1/box/attest` returns a fresh AMD SEV-SNP attestation report from the guest VM
the TEE box runs in, with REPORT_DATA set to 64 bytes the caller chose. It is the guest
side alternative to the sealed hotel's `POST /room/attest` (room kit, #327): same kernel
path (configfs-tsm at `/sys/kernel/config/tsm/report`), same request, nearly the same
answer.

Scope `tee-box:attest`. No lease needed; the box must have a fresh revocation list like
every route but `GET /v1/box`.

## Request

```json
{"report_data_hex": "<128 hex characters>"}
```

The 64 bytes go to `inblob` verbatim. The box does not hash them. So the caller puts a
digest of what it binds there (for example sha512 of its statement, or sha256 of it plus
32 zero bytes) and checks REPORT_DATA against the same digest. Upper and lower case hex
are the same bytes. Any other field, length or character is `400`, and a `400` does not
use a rate-limit slot.

## Answer 200

```json
{"report_b64": "...", "cert_chain_b64": {"vcek": "...", "ask": "...", "ark": "..."},
 "measurement": "<96 hex>", "chip_id": "<128 hex>", "reported_tcb": "<16 hex>",
 "generated_at": 1761400000}
```

- `report_b64`: the configfs-tsm `outblob`, the 1184-byte SNP report.
- `cert_chain_b64`: from the host certificate table (`auxblob`), or `null` unless VCEK,
  ASK and ARK are all there; then fetch them from AMD KDS.
- `measurement`, `chip_id`, `reported_tcb`: read from the report, for convenience. The
  caller verifies the report signature (VCEK) and these fields itself.
- Before answering, the box checks the provider is `sev_guest`, the report parses, its
  signature field is not empty, and its REPORT_DATA is exactly the 64 bytes asked for.
  It does not verify the signature.

Compared with the hotel's answer there is no `binding_sha256`: the TEE box has no room
kit receipt binding. The guest's identity is the measurement and the TLS key the caller
pinned before sending its signed request.

## Errors

- `429` `attest_rate_limit` with `retry_after_seconds`: more than
  `--tee-box-attest-per-minute` reports (default 30, 1 to 600) in 60 s. One report is
  asked for at a time.
- `503` `attest_unavailable`: no configfs-tsm, a provider other than `sev_guest` (a TDX
  box answers this), or a report that fails the checks above.

## Where it can run today

`build_tee_box_api` still refuses any TEE but TDX (`configure.py`, no RTMR3 on SNP for the
one-customer-per-boot extend). So this route answers 200 only on an SEV-SNP guest that
runs this service once SNP boot identity is built, or on a guest that ports the route.

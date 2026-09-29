# Live Intel TDX check

`scripts/live_tdx_check.py` checks, on a real Intel TDX guest, the verdicts
a validator depends on:
- a miner's evidence is accepted when it is genuine;
- it is refused when it is replayed, copied, relayed or tampered with;
- an Intel collateral outage is reported as an outage, not as a bad quote.

It uses the worker's own collector, `collect_tdx` with REPORTDATA v2, and the
pinned `cathedral-tdx-verifier`. It needs no wallet, chain, validator or API key.

## Run it

You need an Intel TDX guest with configfs-tsm (`/sys/kernel/config/tsm/report`)
and root. Any TDX provider works, including a rented TDX sandbox such as a
Polaris "Sealed CPU" machine. Then:
1. Install the reviewed source as in [Development tests](TESTING.md).
2. Install the verifier from its release, as in
   [Intel TDX verifier release](TDX_VERIFIER_RELEASE.md).
3. Run the check:

```bash
sudo .venv/bin/python scripts/live_tdx_check.py \
  --verifier /usr/local/bin/cathedral-tdx-verifier
```

Success ends with `LIVE_TDX_CHECK_PASS` and exit status 0. `--json` prints the
same result as JSON.

The outage check runs the verifier with no network at all, through
`unshare --net --map-root-user`. Pass `--skip-outage` where `unshare` is not
available.

## What each check means

| Check | Expected verifier result | What it shows |
|---|---|---|
| Real quote with the correct binding | exit 0, `intel_verified`, `report_data_match`, `claims_bound_to_quote` | The genuine evidence verifies against live Intel collateral. The output also shows the TCB status and the measurement. |
| Other nonce | exit 1 | A replayed quote is refused. |
| Other hotkey | exit 1 | A quote copied to another miner is refused. |
| Other TLS key | exit 1 | A quote relayed from a different machine is refused. |
| One bit flipped | exit 1 | A tampered quote is refused. |
| No network | exit 3 | An Intel outage is infrastructure, not an invalid quote. |

A pass proves the evidence path on that machine only. It does not prove
registration, chain state, validator admission or weights.

## Recorded runs

On 2026-09-29, two separate Intel TDX guests (Google Cloud TDX, Ubuntu 24.04,
kernel 6.17) were rented as Polaris "Sealed CPU Small" sandboxes. Both used the
verifier built from this branch.
- **Script run:** the first guest was used to check the steps by hand; the
  second ran this script. All six checks passed, with TCB status `UpToDate`
  and no advisories.
- **Validator side:** the first guest's quote also went through
  cathedral-validator's `SubprocessQuoteVerifier` with the validator's own
  REPORTDATA v2 computation. It gave PASS for the genuine binding; FAIL for
  another nonce, hotkey, TLS key or a tampered quote; and INFRA with no network.
- **Full suite:** the full test suite also passed on the first guest.
- **Measurements differed:** the two guests reported different
  `tdx-measurement-sha256` values although they were the same product size.
  The measurement covers the RTMRs, which record what each boot loaded. A
  measurement allowlist for rented TDX guests has to be built from the exact
  image, not from one sample boot.

The two older hardware tests, `tests/test_attest_tdx_hw.py` and
`tests/test_tdx_sat_e2e_hw.py`, drive the retained `CATHEDRAL_TDX_VERIFY_CMD`
adapter (`scripts/tdx_verify_json.py`). That adapter expects a different
verifier's output, so it cannot run with `cathedral-tdx-verifier`. This check is
the current live path.

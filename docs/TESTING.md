# Test Cathedral sandbox

The default suite runs without confidential-compute hardware. It tests the
real software interfaces with local fixtures and test doubles. A green run does
not prove live hardware, deployment, miner eligibility, chain state, weights,
or emissions.

## Install and run

Requires Python 3.11 or newer.

```bash
cd /path/to/cathedral-sandbox
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pytest -q
```

The full suite must pass before publication. Do not publish a fixed passing
count. Hardware-gated tests skip on machines without the required TEE.

## SAT smoke test

```bash
.venv/bin/python scripts/demo_sat.py
```

Success ends with:

```text
PASS
```

This proves local SAT dispatch, solving, and certificate verification. It does
not prove a remote miner or validator scoring cycle.

## Intel TDX hardware tests

Run inside an Intel TDX guest:

```bash
CATHEDRAL_RUN_TDX_HW=1 \
  .venv/bin/python -m pytest -q \
  tests/test_attest_tdx_hw.py tests/test_tdx_sat_e2e_hw.py
```

Run the negative control on a non-TDX Linux host:

```bash
CATHEDRAL_RUN_TDX_NEGATIVE=1 \
  .venv/bin/python -m pytest -q tests/test_attest_tdx_negative.py
```

The remote worker contract also requires native TLS and verified SPKI binding.
Follow [TDX_LAUNCH.md](TDX_LAUNCH.md). Plain HTTP is loopback-only test
compatibility and is not a production validator path.

## AMD SEV-SNP friend test

Run only on a friend-owned SEV-SNP guest:

```bash
CATHEDRAL_RUN_SNP_HW=1 \
  .venv/bin/python -m pytest -q tests/test_attest_snp_hw.py
```

Follow [AMD_SEV_SNP_FRIEND_TEST.md](AMD_SEV_SNP_FRIEND_TEST.md) for the bounded
probe and evidence capture. Passing this test does not enable production
scoring or prove the end-to-end validator path.

## Installed commands

- `cathedral` runs the operator and worker CLI.
- `cathedral-census` reports confidential-compute capability.
- `cathedral-prober` is the retained central-registry probe. Current mining
  does not use it.
- `cathedral-snp-friend-probe` runs the bounded AMD SEV-SNP friend probe.

Use `cathedral worker serve` for the production signed-access worker. The
published c730 image still uses a temporary `public-legacy-audit` migration
bridge. See [WORK_REQUEST_V2.md](WORK_REQUEST_V2.md) for the exact boundary.

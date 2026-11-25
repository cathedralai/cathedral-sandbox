# testdata

All files are public. They are published on the Cathedral site.

- `attestation-proof.json` (named so because the repository ignores files called `attestation.json`), `amd/ark.der`, `amd/ask.der`, `amd/vcek.der`: from `public/proof/4000-agents/sealed/` (and its `amd/` folder) in the cathedral-site repo.
- `receipts-first5.json`: receipts with sequence 1 to 5 from `public/proof/4000-agents/sealed/receipts.json` (3369 receipts, about 4 MB). Each receipt object is copied byte for byte; the wrapper holds only `receipts` (no `head`, no `count`).
- `attestation-library.json`: `public/library/runs/20261022-sealed/attestation.json`.
- `openenv-echo.receipts.json`: `public/library/runs/20261022-sealed/openenv-echo.receipts.json`.
- `amd-turin/attestation-report.bin`: a real Turin (CPUID family 0x1A, model 0x02) version 5 report, byte for byte `tests/fixtures/snp/attestation-report.bin`. `amd-turin/vcek.der` is its VCEK from AMD KDS `vcek/v1/Turin/d010789547cc0e11?fmcSPL=1&blSPL=3&teeSPL=2&snpSPL=5&ucodeSPL=97`; `amd-turin/ask.der` and `amd-turin/ark.der` are `vcek/v1/Turin/cert_chain` (ARK sha256 1f084161..., the Turin pin in `broker/amd_chain.go`).
- `amd-turin/attestation-chi-ur-2.json`: the attestation the sealed UR hotel chi-ur-2 served on 2026-11-25 (`/room/attestation` on its public origin) from host engaging-loon (EPYC 9355P, family 0x1A model 0x02, reported TCB 0103030800000076). `amd-turin/vcek-chi-ur-2.der` is its VCEK from AMD KDS `vcek/v1/Turin/8da577edcb99abd7?fmcSPL=1&blSPL=3&teeSPL=3&snpSPL=8&ucodeSPL=118`; same ASK and ARK.

# Fred PR #1449 handoff — 2026-10-13

Source: https://github.com/bigailabs/polariscomputer/pull/1449  
Branch: `fix/toby-snp-staging-20261013` @ `30769ea2`  
Stacked on #1447 / `fix/staging-migration-version-width-20261012` @ `3d5727d0`

## Commits
1. `66deb72e` — public SNP join / broker / journal / adapter (already matched our 66deb72e bundle)
2. `70ef3381` — pre-dispatch recovery + public usage
3. `ec243899` — protected `cathedral_snp_startup.py` + lifespan wrap
4. `30769ea2` — expired-lease evidence-only cleanup

## Integrated locally (compare, then take tip)
- Checked out tip versions of startup/sandboxes/adapters/journal/tests/docs + `app_server` wrap + `cathedral_snp_startup_file`
- Kept operator helpers: `scripts/snp_staging/*`, `cathedral_snp_staging_install.py`
- Lifecycle `maybe_install` now **skips** when `CATHEDRAL_SNP_STARTUP_FILE` is set (no double hook)

## Corrected image (UNQUALIFIED_CORRECTED_IMAGE_CANDIDATE)
| Artifact | SHA256 |
|---|---|
| `.raw` | `ef0ab84e57dd6e4c38fec60ee0c06e297cb963afbb47206277eacd6742a95689` |
| `.efi` | `65e4412d519ebbc78098ae3c956e711584b6da03c8d9ffa686e149614b63dd96` |
| `.initrd` | `18275f1c43df461c0c1436fbf3d78dcd31f888ec2ad6675e2af121af550c0298` |
| `.vmlinuz` | `9f55ef7253055a9cf68f8a04323c93dead2fca617386d842fbde9ca7b178b27e` |
| bootstrap | `992f4010f6771b49f8370c8dbbd6f4ecaaa6cf99edbb867a445153ac34acfc99` |

Host stem: `/root/snp-launch/cathedral-staging-20261013/images-rootfix/cathedral-staging-snp-rootfix-20261013`  
Blocked old raw: `a7ad573b…`  
HOST_DATA_B64 (cathedral-root-1, 32 digest bytes): `VR35Ls6k4fpnvRDD0rCX13XEvq+LaOxOAF/2bXHJiF4=`  
Root file SHA256: `551df92ecea4e1fa67bd10c3d2b097d775c4beaf8b68ec4e005ff66d71c9885e`

## Still not provided by PR (owner inputs)
- Exact kernel **APPEND** / verity **roothash**
- Policy accept + signed measurement list / verifier pins
- Root-signed 900s grant (8 scopes) naming Toby’s caller
- Independent observer absence materials
- No boot / merge / deploy performed from this handoff

## Public caller reply (Fred request #1)
Isolated API signer (newly minted for this staging path; seed only in `/tmp`, not git):

- pubkey hex: `3c44952eb0f9f083976691809073357e1d9cd1a18326cbaacfefd08a7f07ecc7`
- pubkey b64: `PESVLrD58IOXZpGAkHM1fh2c0aGDJsuqz+/Qin8H7Mc=`
- pubkey sha256: `89e9d66128db2e39e25a562e2ab8e37ecff4965f26b3a650c982222434f979e7`
- caller_id: `central:3c44952eb0f9f083976691809073357e1d9cd1a18326cbaacfefd08a7f07ecc7`
- API origin: live `/tmp/cathedral-snp-staging-url.txt` (bore; ephemeral)
- scope/network/netuid: staging pilot / `finney` / `94`
- customer: deny-all, lifetime 180s, max_spend $1

## Launch source reply (Fred request #2)
- Backend: this repo, integrating PR #1449 tip; operator scripts under `scripts/snp_staging/`
- Boot draft: `scripts/snp_staging/boot_new_guest.sh` (ports `:2226`/`:8444`, refuses without policy accept + APPEND)
- HOST_DATA / expected raw SHA now defaulted from this PR; APPEND still required before `--execute`

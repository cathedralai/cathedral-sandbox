# Resume — f90e1a00 perms fix on #1452 + identity proven (2026-10-14)

## Status now
- **#1457 MERGED** into #1452 @ `a402b410` (includes `f90e1a00` finalize chmod)
- **Cherry image:** `images-customer-f90e1a00/` (built from `f90e1a00`; tree matches merge tip for ExtraTrees fix)
- **Pins:** measurement `c32db58d…b9c47c` · roothash `c834dcd6…e3cdd72` · raw `46061be1…c3b75`
- Guest unit **cleared**; `:8444` clear; fences intact; `boot10` staged
- **Standing by** for Fred **release 4 / grant 12** → one fresh identity boot → admission-first

## Root cause → fix verified
umask 077 → `80-dhcp.network` **0600** → networkd Permission denied. Fixed image: network/units **0644**, `/opt/cathedral` **0755**; `wait-online` **Finished**.

## Leave alone
`:2222` / `:2224` / `:2225`; preserve images + `netbisect-skyrocket/`

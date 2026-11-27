#!/bin/bash
# Host phases of a custom SNP guest launch (spec-r9 5.3, 5.4, 11). The operator's
# custom-guest.sh runs one phase per SSH call:
#   custom-guest-host.sh <phase> --hotel H --launch-id L [options] < input.json
# Lock phases (inbox, intake, measure, discard, hold-stop, unhold, hold-baseline,
# boot, verify-disks, stop, return-kit, return-finish) run under their deadline
# and hold /run/lock/cathedral-snp-host.lock for the whole phase. tick tries the
# lock and skips while a phase holds it. The unit hooks (check-start, exited),
# boot-record and facts never take it. See custom_guest_host.py.
set -euo pipefail
exec python3 -I "$(dirname "$(readlink -f "$0")")/custom_guest_host.py" "$@"

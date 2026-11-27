#!/bin/bash
# Operator lifecycle of one custom SNP guest on a dedicated host (spec-r9 5.4, 11).
# Runs on the operator machine only; see custom_guest.py for the steps and config.
#   custom-guest.sh <step> --hotel H --launch-id L [options]
set -euo pipefail
exec python3 "$(dirname "$(readlink -f "$0")")/custom_guest.py" "$@"

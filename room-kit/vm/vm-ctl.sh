#!/bin/bash
# Host runtime for customer VMs (AB#991). All logic is in vm_ctl.py next to this
# file; see README.md. Every command prints one JSON line on stdout.
# -I: ignore PYTHON* env and the current directory, so a forced SSH command
# (vm-ctl.sh --from-broker) runs only the kit's code.
export PATH=${PATH:-/usr/bin:/bin}:/usr/sbin:/sbin
exec python3 -I "$(dirname "$(readlink -f "$0")")/vm_ctl.py" "$@"

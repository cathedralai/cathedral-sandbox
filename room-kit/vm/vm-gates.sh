#!/bin/bash
# Pre-launch gates and the host change gate for sealed customer VMs (AB#999). Run as root:
#   vm-gates.sh check <name> | enforce | baseline [--replace] | host-build
# All logic and the exit codes are in vm_gates.py next to this file. -I: ignore PYTHON* env and
# the current directory, so a unit's ExecStartPre runs only the kit's code.
export PATH=${PATH:-/usr/bin:/bin}:/usr/sbin:/sbin
exec python3 -I "$(dirname "$(readlink -f "$0")")/vm_gates.py" "$@"

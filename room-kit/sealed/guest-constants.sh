# Fixed link constants of the sealed guest image (sourced by build-guest.sh,
# launch-guest.sh, host-net.sh and install-sealed.sh AFTER sealed.env).
# They are inside the measured initrd, so they must be the same on every host:
# one guest per host on its own tap, so no host needs its own address. They
# override any value left in an older sealed.env. The hotel name is NOT here;
# it reaches the guest through fw_cfg (opt/cathedral/hotel-name), unmeasured.
SEALED_HOST_IP=10.215.0.1
SEALED_GUEST_IP=10.215.0.2
SEALED_GUEST_MAC=52:54:00:5e:a1:ed
SEALED_DNS="1.1.1.1 8.8.8.8"

# CPU model: QEMU -cpu, sev-snp-measure --vcpu-type and the manifest all read this one
# variable, so the measured vCPU type cannot drift from the one the guest runs. Unlike
# the constants above, a value in sealed.env wins: set SEALED_CPU_MODEL=EPYC-v4 there
# for a baseline hotel. EPYC-Genoa-v1 shows AVX-512 to the guest (EPYC-v4 hides it) and
# needs a Zen 4 host. The CPUID signature is measured, so changing it changes the measurement.
SEALED_CPU_MODEL=${SEALED_CPU_MODEL:-EPYC-Genoa-v1}

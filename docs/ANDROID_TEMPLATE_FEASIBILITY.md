# AB#757: Android sandbox template feasibility

Status: evaluation only. No Android template is approved for the customer catalog.

## Current runtime boundary

The room installer configures the room Docker daemon with `runsc` as its default
runtime (`room-kit/install.sh`), and the `/v1` profile sends sandbox commands to
that daemon (`room-kit/profiles/v1.sh`). The TEE box configuration explicitly
requires `runsc` (`cathedral/tee_box/configure.py`). The existing host assessment
records whether `/dev/kvm` exists, but that check does not expose KVM to a
customer sandbox (`room-kit/assess.py`).

Android's accelerated emulator on Linux requires usable KVM and a compatible
host CPU and system image. Its software emulation path is much slower and is not
a qualified production fallback. The current `runsc` sandbox path therefore
**has no demonstrated accelerated Android runtime**. This is an inference from
the code and Android's requirements, not a failed test on a production host.
Do not label a direct-host emulator as an AMD SEV-SNP sealed sandbox.

Sources:

- [Android emulator acceleration requirements](https://developer.android.com/studio/run/emulator-acceleration)
- [Android emulator command-line options and acceleration check](https://developer.android.com/studio/run/emulator-commandline)
- [gVisor platform architecture](https://gvisor.dev/docs/architecture_guide/platforms/)

## Read-only host qualification

Run these on an approved, nonproduction candidate host before selecting a
runtime. Record the host model, CPU architecture, kernel, and command output.
The `emulator` command requires the Android SDK emulator package to be present.

```sh
uname -m
uname -r
test -c /dev/kvm && echo kvm-device-present || echo kvm-device-absent
test -r /dev/kvm && test -w /dev/kvm && echo kvm-accessible || echo kvm-inaccessible
command -v emulator
emulator -accel-check
```

Presence and access do not prove that an emulator boots. A candidate must also
boot a pinned Android system image with acceleration enabled, with no software
emulation fallback, and provide timing and resource measurements.

## Route to a customer template

1. Choose an isolation route: a separately isolated direct-host KVM lane, or a
   managed physical-device pool. Name its trust label and tenant boundary. Do
   not silently add privileged KVM access to the current sealed `runsc` lane.
2. Approve host capacity, the Android SDK/system-image license review, and the
   expected cost and billing unit before provisioning a pilot.
3. Pin the emulator, SDK tools, and system image by immutable version and hash;
   record them in the create receipt or equivalent customer evidence.
4. Prove the full lifecycle on the chosen host: create, accelerated boot, ADB
   connect, install and launch an APK, capture screen and input, stop, delete,
   cleanup, and repeat. Record boot time, memory, CPU, disk, and concurrency.
5. Test tenant separation, network policy, image integrity, reset between
   customers, failure recovery, and the absence of leftover ADB access.
6. Only after a peer review and live pilot proof, decide whether to publish the
   template and what its trust and pricing copy says.

**Next decision:** approve a nonproduction host and choose the direct-host KVM
or physical-device route. Until then AB#757 remains open; there is no
production Android sandbox claim.

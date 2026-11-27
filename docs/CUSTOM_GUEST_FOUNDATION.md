# Custom guest foundation (AB#1004, AB#1008)

This is a draft component of the custom SNP guest build. It does not enable custom guests or change an existing hotel. The platform API key authenticates the Cathedral account; the Ed25519 owner key below signs launch documents and is a separate credential.

## Implemented component

`room-kit/custom_guest_protocol.py` implements the versioned manifest/bootstrap readers and the domains from spec-r9 sections 8 and 10. Inputs must be canonical JSON bytes, with integer versions, printable ASCII strings and no unknown fields. The owner key is supplied independently. The bootstrap signature, the measured cmdline owner, and the manifest hash must agree before deriving HOST_DATA.

Shared interoperability inputs and expected outputs are in `tests/fixtures/custom_guest_v1.json`. These are synthetic test values, never production credentials. The optional omitted `data_disk_gib` means zero; its original canonical bytes are retained for hashing. Producers should always write that field.

`owner_sign.py --custom-guest-bootstrap --key OWNER_KEY --body bootstrap.json` prints a base64 signature over the custom-guest domain and the digest of the exact bootstrap bytes. It refuses a bootstrap naming another owner. The existing room-create signing path is unchanged. The owner must inspect the launch documents before signing.

`cathedral_attest.py`, to be installed as `/usr/bin/cathedral-attest` in the verified root, requires root. It combines the verifier's 32-byte challenge with the wire-format Ed25519 host key from `/run/cathedral/ssh_host_ed25519_key.pub`, then uses the native `/dev/sev-guest` collector. It has no proxy or emulated fallback. The init must generate the matching private/public host key pair in RAM and configure sshd to use that private key.

`verify_custom_guest.py` makes one fresh OpenSSH connection, runs the report command there and reads the host key OpenSSH accepted after key exchange. It verifies the report against that key, the fresh challenge and the owner's launch expectations. An existing SSH config, agent, proxy or multiplexed connection cannot silently replace this connection. Response size and elapsed time are bounded.

A trust file is created only after every check succeeds, with mode 0600 and exclusive creation. Existing trust files are never overwritten. `PASS` applies to this SSH-bound report. It does not prove a future connection, application behavior, disk freshness, or that arbitrary guest code consumed the bootstrap. Re-attest after a relaunch or changed report identity; do not automatically release secrets.

## Owner-side invocation

Supply the independently computed measurement, approved chip/CPU/complete firmware floor and AMD root fingerprint. The launch files must be the owner's retained copies, not values taken from the report or substituted by an API response. `owner.pub` is exactly 32 raw bytes and `bootstrap.sig` is exactly 64 raw bytes (decode the signing tool's base64 output).

```sh
python3 room-kit/verify_custom_guest.py \
  --host HOST_FROM_SIGNED_BOOTSTRAP --port SSH_PUBLIC_PORT \
  --identity OWNER_SSH_PRIVATE_KEY \
  --manifest manifest.json --bootstrap bootstrap.json \
  --bootstrap-signature bootstrap.sig --owner-public-key owner.pub \
  --expected-measurement EXPECTED_MEASUREMENT \
  --expected-chip-id EXPECTED_CHIP_ID --expected-cpuid FAMILY:MODEL:STEPPING \
  --min-tcb turin:fmc=FMC,bl=BL,tee=TEE,snp=SNP,ucode=UCODE \
  --ark-sha256 TRUSTED_AMD_ROOT_SHA256 \
  --known-hosts-out newly_verified_known_hosts
```

The endpoint must match the owner-signed public host and first port mapping. The wrapper currently supports the strict Turin verifier; Genoa rehearsal evidence is a separate, partial qualification and must not be presented as Turin acceptance.

## Static native helper and bootstrap library

`room-kit/custom-guest` contains a dependency-free Go implementation for Linux
amd64. Its `cathedral-attest CHALLENGE_HEX` command has the same response envelope
as the Python reference command. It requires root, a root-only native SNP device
and a root-owned SSH public key. There is no device override, network, proxy or
emulated-report option. The ioctl buffers are explicitly pinned during the call.

For the reference init, `cathedral-attest --boot-host-data EXPECTED_HEX` generates
a fresh 32-byte nonce and uses the separate boot-check domain. It checks the
returned nonce, HOST_DATA, exact launch policy, VMPL and unmasked VCEK selection.
The expected hash must come from validated signed launch documents. This mode
checks a local native response; it does not validate AMD certificates or publish
an owner-side PASS. The SSH-bound verifier still performs those independent checks.

The Go bootstrap library validates canonical launch bytes, every document field,
the owner signature and HOST_DATA. Its key anchor is the exact measured
`/proc/cmdline`, including the firmware's `initrd=initrd ` prefix. It shares the
Python interoperability vector. A caller must still compare the validated values
with guest-observed CPU, memory, disk, MAC and policy before using them. This
library alone does not satisfy that boot gate.

With the pinned Go 1.26.11 compiler installed:

```sh
python3 scripts/build_custom_guest_helper.py \
  --go /PATH/TO/go1.26.11/bin/go --output cathedral-attest
```

The builder disables cgo and network dependency resolution, rebuilds in two
separate directories, requires identical bytes and validates the static ELF.
Its JSON result records the candidate digest and source digests. CI tests the Go
code with the race detector and runs the double build. This is a candidate helper,
not the published reference initrd or a boot-tested guest image.

ABI references: [Linux SNP guest UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/sev-guest.h),
[Go runtime pinning](https://pkg.go.dev/runtime#Pinner).

## Reference initrd packaging

`custom_guest_initrd.py` builds and validates the archive from a separately reviewed
JSON mapping of executable path to SHA-256. `init` is mandatory; helpers belong
under `usr/lib/cathedral/`. The staging tree contains only those files and their
parent directories. No closure digest is learned from an untrusted archive.

```sh
python3 -m pip install -e '.[custom-guest-build]'
python3 room-kit/custom_guest_initrd.py build \
  --root STAGING_TREE --closure REVIEWED_CLOSURE.json --archive initrd.zst
python3 room-kit/custom_guest_initrd.py check \
  --closure REVIEWED_CLOSURE.json --archive initrd.zst
```

The build uses python-zstandard 0.25.0 / libzstd 1.5.7, level 19, one thread,
content size and checksum. It normalizes timestamps, ownership, modes, ordering
and inode numbers. Keep the input tree quiescent during the build. The output is
created exclusively, so a previous artifact cannot be silently replaced.

The checker accepts one bounded zstd frame containing one `newc` archive with a
trailer, no trailing bytes, no repeated names or hard links, no symlinks or special
files, and no files outside the pinned executable closure. Every executable must
be an x86_64 ELF with no interpreter or shared-library dependency. The archive
policy is deliberately stricter than the [kernel's general initramfs format](https://www.kernel.org/doc/html/v6.10/driver-api/early-userspace/buffer-format.html).
Decompression checks the frame size before allocation and refuses extra frames,
using the [zstandard decompression API](https://python-zstandard.readthedocs.io/en/latest/decompressor.html).

`archive_verified` only verifies the bytes/layout against the supplied closure.
It does not establish that `/init` enforces the bootstrap or is safe to boot.
There is no published production closure or reference-image digest yet. The
reference init and pinned helper build recipes must land before those can exist.

## Evidence and remaining work

Tests exercise real OpenSSH key exchange and a forced report command on a loopback sshd, with explicitly synthetic SNP reports/certificates. The command is refused for tampered reports, and no key is saved on failure. Signed reports for another challenge or host key also fail. This is transport/cryptographic integration evidence, not a chip or customer-host test.

Before this foundation can be marked ready:

- Qualify the static reference `/init` (`cmd/cathedral-init`), its pinned helper closure and the deterministic initrd by booting them (image acceptance harness; not part of the recipe PR).
- Enforce the bootstrap against guest-observed state before networking/root use; enforce root-only SNP and configfs report access.
- Build the reference kernel and verified-root test image, configure SSH, verify the helper digest and disable cloud-init/imported credentials.
- Reproducible reference-image evidence and a boot of `cathedral-data unlock` in a guest; the helper and its loop-device tests exist.
- Cross-review the complete result, then run the approved hardware rehearsals through Spock's launcher/operator path.

The launcher, broker hold and API are separate Spock-owned PRs. No host operation, customer interruption, new compute or production switch is part of this component.

### Reference root component

`scripts/build_custom_guest_root.py` builds a read-only SquashFS root and appends
its dm-verity hash tree. It takes an explicitly SHA256-pinned Debian base tar and
the pinned static report helper. It never executes or mounts the base. Build
versions are pinned to mksquashfs 4.7.5 and veritysetup 2.8.4. A fixed epoch, salt
and UUID make repeated builds from these same inputs identical. The initial
package-resolution step is not itself a reproducible source build; preserve and
publish the exact base tar, its package inventory and its digest with the recipe.

A fresh base can be prepared in an isolated unshare namespace:

```sh
mmdebstrap --mode=unshare --variant=minbase \
  --customize-hook='rm -f "$1"/etc/ssh/ssh_host_* "$1"/var/lib/systemd/random-seed' \
  --include=systemd-sysv,openssh-server,iproute2,e2fsprogs,ca-certificates \
  bookworm base.tar https://deb.debian.org/debian
sha256sum base.tar cathedral-attest
python3 scripts/build_custom_guest_root.py \
  --base base.tar --base-sha256 EXPECTED_BASE_SHA256 \
  --helper cathedral-attest --helper-sha256 EXPECTED_HELPER_SHA256 \
  --epoch 1795770000 --output root.raw
# For an image that supports a data disk, add the unlock tool and its own static
# cryptsetup (never the root's): --data-helper cathedral-data --data-helper-sha256 SHA \
#   --cryptsetup cryptsetup --cryptsetup-sha256 SHA
```

The JSON output records `root_verity`, `root_data_bytes`, the full root digest,
base/helper/package-inventory digests, and tool versions. It always records
`boot_verified: false`. `veritysetup verify root.raw root.raw ROOT_HASH
--hash-offset=ROOT_DATA_BYTES` checks the resulting component without a device
mapper or VM. The output path must be new. Tar traversal, escaping links, device
entries outside `/dev`, unpinned inputs and pre-existing owner SSH credentials
are refused. Device/pseudo-filesystem contents from the base are omitted.

The image has no baked-in SSH host key. Package-generated keys, machine ID and
random seed are removed. SSH reads its host key and authorized keys exclusively
from `/run/cathedral`, disables password/PAM authentication, and permits only the
owner's root login. Cloud-init is disabled; other SSH and console login services
are masked. The root account has a non-locking invalid password hash, not an
empty password. DNS is left unconfigured rather than copying the build host's
resolver settings. The system journal and `/tmp` are volatile.

The measured init (`cathedral-init`, below) validates all signed launch fields and observed
hardware, verify HOST_DATA, mount this root through dm-verity with
`--panic-on-corruption`, and populate a root-only tmpfs `/run/cathedral` before
entering `/sbin/init`. That tmpfs holds the fresh private/public SSH host keys,
`authorized_keys`, and `network.env` with exactly these validated values:

```text
CATHEDRAL_INTERFACE=eth0
CATHEDRAL_GUEST_CIDR=10.217.0.2/30
CATHEDRAL_GATEWAY=10.217.0.1
```

These are examples, not defaults. Init must select the observed interface by the
signed MAC and emit the signed address/prefix/gateway. The system manager reads
the private file and invokes `ip` directly with one argument per value, without a
shell. SSH requires successful network setup. No DHCP or alternate network
manager is enabled. A root image alone is not the reference init, kernel,
optional owner data-disk unlock helper, or a complete bootable test image.

### Static verity helper

`scripts/build_custom_guest_verity.py` builds cryptsetup 2.8.4's static
`veritysetup` with a static device-mapper library. The adjacent
`custom_guest_verity_inputs.json` pins the source archives and Debian-format
development packages by SHA-256. Acquire those files separately into a directory
containing exactly the lock's files. The builder does not download or install
packages. Source archives are from the upstream
[cryptsetup releases](https://www.kernel.org/pub/linux/utils/cryptsetup/v2.8/)
and [LVM2 releases](https://sourceware.org/pub/lvm2/); development packages come
from Ubuntu's signed package metadata. GCC 15.2.0 and Make 4.4.1 are required.

```sh
python3 scripts/build_custom_guest_verity.py --inputs PINNED_INPUT_DIRECTORY \
  --output veritysetup --cryptsetup-output cryptsetup --log verity-build.log
```

`--cryptsetup-output` also writes the static `cryptsetup` from the same source,
flags and double build. `cathedral-data` runs only that binary (pinned by digest),
never a `cryptsetup` that the root image happens to contain.

The builder snapshots and rechecks inputs, uses the pinned headers and static
libraries, builds in two separate directories, requires identical output and
checks the ELF for an interpreter or shared-library dependency. Output and log
paths must be new. This is a toolchain-specific reproducibility check, not a
claim of a hermetic compiler bootstrap.

The helper was checked unprivileged in an otherwise empty chroot containing
only the executable, root image and `/dev/random` and `/dev/urandom`. It accepted
the correct verity root and refused a wrong one. Cryptsetup requires both entropy
devices even for verification; init must mount devtmpfs before invoking it.
This userspace check does not prove a device-mapper mount or guest boot.

### Reference kernel candidate

`scripts/build_custom_guest_kernel.sh SOURCE_DEB EMPTY_WORK_DIRECTORY NEW_OUTPUT`
builds from the pinned Ubuntu `linux-source-7.0.0_7.0.0-44.44_all.deb` input with
GCC 15.2.0 and Make 4.4.1. Use a scratch filesystem with at least 6 GiB free.
No kernel is installed, and no VM is launched. The source digest is checked
before extraction. SNP, TSM, virtio, dm-verity, dm-crypt, dm-integrity, SquashFS
and config extraction are built in. Modules, built-in command lines, embedded
boot configuration, embedded initramfs and unused hardware drivers are disabled.
`CONFIG_IPV6_SIT` is disabled too: `x86_64_defconfig` turns it on, the kernel
then creates a device-less `sit0` at boot, and `bootstate` refuses every
interface except the one virtio NIC. The build fails if any of these come back.

The recipe contains one explicit source adjustment: x86 `COMMAND_LINE_SIZE`
is increased from 2048 to 4096. Linux advertises one less in the boot header;
the unmodified kernel advertises 2047 and fails spec-r9's minimum of 2048.
This does not widen the signed command-line allowlist or exact boot comparison.
Output includes the kernel, config and input/output hashes. Embedded config must
match the build config; EFI/PE, Linux boot protocol, 64-bit and command-line
capacity checks must pass. These checks do not establish a hardware boot.

### Volatile SSH key material

The Go `internal/bootkeys` package generates a fresh Ed25519 host key in OpenSSH
format, copies the validated owner's public key, and prepares the three validated
network settings. Entropy failure returns no material. The tests use OpenSSH's
own private-key parser and check that each invocation generates a different key.
No key is baked into the root or initrd. A reference PID1 must call it only after
bootstrap, observed-hardware, HOST_DATA and verified-root checks, then write the
files mode 0600 into the root-owned 0700 tmpfs directory. This package alone does
not implement PID1 or start SSH.

### Guest-observed device checks

`internal/bootstate.CheckDevices` is a read-only component for the reference
init, called with a validated signed launch after mounting a fresh kernel sysfs
and before any device mapping or networking. It compares the online CPU count,
finds exactly one read-only `custom-root` virtio disk with the signed root size,
and enforces the optional `custom-data` disk's presence and exact size. It
selects by serial, never by assuming `vda` is the root. One virtio NIC must match
the signed MAC. Missing or unreadable attributes, duplicate disks, unexpected
devices and arithmetic overflow refuse without returning a partial selection.
Zero-sized unused loop/ram devices are ignored.

This function neither opens a disk nor authorizes boot. The memory rule from
spec 8.7 is `bootstate.CheckMemory` (below); usable Linux memory is not nominal QEMU
memory, so it is not part of this function. Native policy
and HOST_DATA, dm-verity, root contract and PID1 integration remain required.
The caller must use the returned disk only through verity and account for device
changes before later access; a sysfs read is not a pinned device handle.

The device tests use synthetic sysfs trees with swapped disk enumeration and
negative controls, not a booted SNP guest. The sysfs interfaces are defined by
[Linux CPU topology](https://www.kernel.org/doc/html/latest/admin-guide/cputopology.html)
and the [virtio block driver](https://github.com/torvalds/linux/blob/master/drivers/block/virtio_blk.c).

### Verified-root contract check

`internal/bootstate.CheckRoot` implements the reference init's root inspection
step. The caller must already have mounted the dm-verity root read-only, without
submounts. It compares `/usr/bin/cathedral-attest` with a digest pinned in the
measured init build, refuses installed cloud-init without the disable marker,
and reads `/sbin/init` and `/usr/sbin/sshd` in full before returning their hashes.
It refuses non-regular, non-executable, writable or oversized program files.
No inspected program is executed. The cloud-init check covers the supported
root recipes' standard installation paths; it is not an audit of arbitrary
owner software.

Absolute symlinks such as `/sbin/init -> /lib/systemd/systemd` resolve inside the
guest root, never against the build or host filesystem. Traversal above that
root, symlink loops and special files fail. Go's `os.Root` confines file access;
the module now requires Go 1.26, matching the existing pinned 1.26.11 build and
CI compiler. Tests include a real extracted reference root, but do not exercise
a kernel dm-verity mapping or replace the pending PID1/hardware qualification.

### Firmware input and native HOST_DATA binding

`internal/bootstrap.ReadBoundLaunch` joins the signed-document validator to the
native report collector. It reads only the three fixed Cathedral firmware
attributes and `/proc/cmdline`, after measured init mounts fresh proc/sysfs and
restricts the SNP device to root. Reads are bounded, including the binary
signature; missing, extra or malformed inputs refuse before any report request.
Kernel-created directory symlinks in the
[Linux fw_cfg ABI](https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-firmware-qemu_fw_cfg)
are supported, but the final raw attribute cannot be a symlink, FIFO or device.

After the owner signature and measured command line agree, a new random boot
challenge is sent through the native ioctl collector. The returned report must
match the challenge, expected policy, VMPL, VCEK selection and computed
HOST_DATA. Failure returns no launch fields. No report or nonce is published by
this function, and no test backend or input path is selectable by a caller.

This is local input binding, not owner-side certificate verification or complete
boot approval. It starts no network, opens no data disk and executes no owner
program. Observed-resource checks (including the unresolved memory rule), verity
mounting, root checks and PID1 handoff remain mandatory. Tests use the shared
signed protocol vector, synthetic firmware attributes and synthetic report
responses; they are not hardware acceptance evidence.

### Held root device

`internal/bootstate.OpenRootDevice` repeats device selection, then opens only
the selected root with read-only, no-follow and close-on-exec flags. It compares
the descriptor's block-device number with kernel sysfs, and uses BLKROGET and
BLKGETSIZE64 on that descriptor to require a read-only device of the signed size.
It repeats inventory checks after opening and closes the descriptor on failure.
It never opens the optional data disk. The caller owns the successful handle
and must pass that handle to the verity helper instead of reopening its pathname.

Tests show that replacing the pathname after opening does not replace the held
file, that symlinks and regular files are refused, and that failures close the
descriptor. The positive handle tests use synthetic files and an injected
inspection seam; real block-device ioctls and dm-verity mounting still require
guest integration testing. This component neither mounts nor executes a root.

### Verity mount integration

`internal/bootstate.MountVerifiedRoot` joins the held root handle to the pinned
static verity helper and a read-only squashfs mount at `/newroot`. It refuses
outside root PID1, requires a fresh mapper/mount target, and offers no raw-root
or writable fallback. Its caller must first complete all launch, report and
resource checks, establish fresh proc/sysfs/devtmpfs and private mounts, and
power off on any error. Root inspection and key generation still follow it.

The disk header is checked for reference format 1, SHA256, 4096-byte blocks,
the signed data length and enough hash-tree space. The helper receives explicit
geometry and the measured root hash with `--no-superblock`, so rereading a
changed header cannot override the validated geometry. The salt is copied from
the header; the expected root hash binds it. Hash data starts one block after
the superblock. `--panic-on-corruption` is mandatory. Cryptsetup 2.8.4 creates
verity mappings read-only; the mount also requests read-only, nodev and nosuid.

The helper is read and checked against its build pin before execution through
the same open handle. Both helper and root are inherited file descriptors; no
shell or environment settings choose an alternative program or root. Execution
is bounded to 30 seconds. This does not execute any owner-root program.

The actual reference root passes userspace verification using these explicit
parameters, the pinned static helper and inherited descriptors; a wrong root
hash fails. Unit tests reject changed geometry, truncated headers/trees and
invalid helper pins. Kernel mapper creation, mounting and a complete PID1 boot
remain unqualified until guest rehearsal. No complete initrd is published yet.

### RAM runtime and root handoff

`PrepareVerifiedRuntime` now orders device checks, verity mounting, root checks
and fresh SSH material in a restricted tmpfs. The runtime directory must be
root-owned and not writable by others; its new `cathedral` child is 0700 and
all four files are 0600. Existing children, aliases, invalid network/owner inputs
and entropy failures refuse. Keys are generated only after the preceding checks.
The optional data disk remains unopened.

Only successful preparation returns a `ReadyRoot`. Its handoff consumes the
ready state, moves dev/sys/proc (proc last), switches root and executes only
`/sbin/init` with fixed arguments and environment. Root descriptors are closed
before owner code. Any error requires PID1 to power off, without retry or shell.
The old initramfs is hidden but its memory is not reclaimed by this component.

Tests exercise actual restricted tmpfs storage in a private mount namespace.
`scripts/test_custom_guest_handoff.sh` additionally runs a synthetic root PID1
and proves the root/mount/descriptor/environment handoff. It deliberately
bypasses preparation; it does not prove signed inputs, verity or SNP boot.
The complete PID1 caller, memory rule, data unlock and hardware proof remain
pending. Do not treat these component tests as a complete boot image.

### Memory observation (spec 8.7 errata)

`bootstate.CheckMemory` sums `end - start + 1` over the `/sys/firmware/memmap`
entries whose type is exactly `System RAM` and accepts only
`mem_gib * 2^30 - 128 MiB <= S <= mem_gib * 2^30`. `MemTotal` is not used: it
subtracts SWIOTLB and kernel reservations. A missing, empty or unparseable
inventory (any entry, RAM or not), an inverted range and overlapping or touching
RAM entries refuse. The kernel needs `CONFIG_FIRMWARE_MEMMAP=y`. The measured
deficit on an 8 GiB guest was 5.6 MiB (one guest); the 128 MiB window is the
errata's, not a fitted value.

### Reference PID1

`cmd/cathedral-init` runs, in order: `PrepareKernelViews`, `ReadBoundLaunch`,
`CheckMemory`, `PrepareVerifiedRuntime` (devices, verity, root contract, RAM keys)
and `Exec`. Any error, any panic and any return from `Exec` powers the guest off
(sync, then `reboot(POWER_OFF)`; PID1 exit is a kernel panic, which ends a
`-no-reboot` guest). There is no retry, shell or fallback root.

The veritysetup digest and the `cathedral-attest` digest are linked into the init
at build time (`-X main.pinVeritySHA256`, `-X main.pinReportSHA256`) by
`build_custom_guest_helper.py --init-output`, and the attest digest is that of the
binary built in the same run. An unlinked, short, uppercase or all-zero pin
powers off before any mount. The pins are therefore part of the measured initrd.

### Owner data unlock

`cathedral-data unlock` runs in the verified root over the owner-bound SSH
session. The passphrase is read from stdin only (at most 4096 bytes, a 30 second
bound, a terminal is refused) and is never an argument or environment value:

```sh
printf '%s' "$PASSPHRASE" | ssh -p PORT root@HOST cathedral-data unlock
```

It re-reads the bound launch (`ReadBoundLaunch`) to get the signed
`data_disk_gib`, holds only the `custom-data` disk (`datavolume.OpenData`), and
runs `datavolume.Unlock`. First use on a disk that is all zero: LUKS2,
`aes-xts-plain64`, 4096-byte sectors, `hmac-sha256` integrity (argon2id), then
ext4, mounted at `/mnt/cathedral-data` with `nosuid,nodev,noexec`. The root is
read-only at boot, so the root build creates that directory (empty, `0700`). A
disk with a
nonzero byte and no LUKS magic is refused untouched. A disk with LUKS and no ext4
(a cut between format and mkfs) is refused and never formatted again; it needs
deliberate recovery. The header is copied off the disk once
(`luksHeaderBackup` into a private directory under `/run`); the policy check
dumps that copy and `open --header` unlocks with it, so a host that rewrites the
on-disk header after the check cannot substitute its own keyslots. A header that
fails `CheckHeaderPolicy` (for example a null cipher) is refused before open.
After open the live stack is read back from sysfs (crypt over dm-integrity over
exactly the held disk) and `cryptsetup status`, in cryptsetup 2.8.4's output
format. `mke2fs -F` runs only on a volume formatted in the same run whose
plaintext still reads as all zero.

First-use formatting wipes the integrity area, which takes time proportional to
the disk. The unlock deadline is 6 hours. The adapter runs the pinned static
`/usr/lib/cathedral/cryptsetup` through the digest-checked descriptor with an
empty environment; `mke2fs` comes from the verity root. Tests that need root run
in CI against loop devices (`custom-guest-data-root`).

### Initrd recipe

`scripts/custom_guest_initrd_closure.json` is the reviewed recipe: the initrd holds
`init` and `usr/lib/cathedral/veritysetup`, nothing else. `scripts/make_custom_guest_initrd.py`
takes `--cathedral-init` and `--veritysetup`, refuses extra or missing inputs,
symlinks and non-static ELF files, derives the `{path: sha256}` closure, builds
twice, requires identical bytes and verifies the archive with
`custom_guest_initrd.py`. Build order: verity helper, then
`build_custom_guest_helper.py --init-output ... --verity-sha256 <that digest>`, then
this tool. The root carries the same `cathedral-attest` the init pinned.

### Reference build in CI

`.github/workflows/reference-build.yml` runs the kernel recipe and that initrd build
order with real pins on GitHub-hosted `ubuntu-latest` (Ubuntu 26.04: GCC 15.2.0,
Make 4.4.1), never on a hotel host. It runs on `workflow_dispatch` and on pull
requests that touch the recipes, their locks or the custom guest source.

- Every download is checked against a sha256 before use:
  `scripts/fetch_reference_build_inputs.py` takes the verity inputs from
  `custom_guest_verity_inputs.json` (URLs from `vm_initrd_tools_inputs.json`, matched
  by sha256) and the rest from `scripts/reference_build_inputs.json`: the kernel
  source, Go 1.26.11, python-zstandard 0.25.0 and the two kernel host tools the
  image lacks (`bc`, `libelf-dev`, with its dependencies).
- The kernel and the initrd are each built on two fresh runners (the kernel in work
  directories of different lengths). Each builder also builds twice on its own runner.
- The summary job requires byte-identical outputs across the two runners, checks the
  closure against the files built beside it, checks the archive with
  `custom_guest_initrd.py check`, and uploads the `reference-build` artifact:
  `vmlinuz`, `kernel.config`, `cathedral-custom-initrd-<version>.cpio.zst`,
  `closure-list.txt` (`<sha256>  <path>` per line), `closure.json`, the five static
  binaries, `SHA256SUMS`, the toolchain record of each runner and `summary.json`.
- It builds only. OVMF, the measurement and a boot come from the host rehearsal.

### Early kernel views and report permissions

`PrepareKernelViews` is a root-PID1-only component intended to run before any
launch input is read. It makes mount propagation private, mounts fresh proc,
sysfs and devtmpfs views, and restricts the kernel-identified SNP character
device to root:root 0600. It mounts configfs and restricts its root to 0700
before owner code can access the TSM report interface. Invalid targets or any
failed mount/permission check stop preparation; the caller must power off.

Tests cover ordering, failure at every stage, alias refusal and permission
readback. The positive character-device test uses a newly created null-driver
inode in a private scratch filesystem. Tests never mount production devtmpfs
or configfs and never change the host SNP device. A mount namespace alone is
not isolation for these kernel-global objects: do not run this setup component
in a host/container rehearsal.

`cmd/cathedral-init` now calls it first. None of this establishes a bootable image
or hardware acceptance.

### Runtime capacity and exact document fields

The inherited `/run` now uses systemd 252's bounded capacity: 20% of guest RAM
and 800k inodes, retaining `nosuid,nodev,noexec`. Systemd leaves an existing
`/run` mount in place, so sizing it only for the four Cathedral files was too
small. The source contracts are
[the mount table](https://github.com/systemd/systemd/blob/v252/src/shared/mount-setup.c)
and [the runtime limits](https://github.com/systemd/systemd/blob/v252/src/shared/mount-util.h).

`scripts/test_custom_guest_runtime.sh` mounts only scratch tmpfs in a private
mount namespace. It writes the runtime files, 512 zero-byte unit-state files
and 17 MiB of simulated re-execution state. Restoring either old limit causes
ENOSPC; the new limits pass. This validates capacity, not a complete systemd
or SNP boot. That acceptance test remains required.

Signed JSON field names must now match their declared spelling exactly,
including nested network and port objects. Case aliases and simultaneous
case variants are refused before decoding into Go structs. The optional
`data_disk_gib` field remains optional; fixture signatures and HOST_DATA are
unchanged. Eight signed regression cases failed before the fix.

### Data-volume preservation checks (not yet wired)

`internal/datavolume` adds two read-only guards for the planned owner unlock
command. `CheckBlank` reads every byte of the bounded candidate and refuses
nonzero data, incomplete reads or cancellation. A blank header is insufficient:
data behind a lost header can remain recoverable with its backup.

`CheckHeaderPolicy` checks the encryption fields of cryptsetup JSON metadata:
one AES-XTS segment, 4096-byte sectors, HMAC-SHA256 integrity, encrypted keyslots,
and no persistent bypass or reencryption flags. It rejects duplicate JSON keys,
excessive nesting and oversized metadata. The policy uses the cryptsetup 2.8.4
layout: 64-byte XTS plus 32-byte HMAC volume keys and 64-byte keyslot wrapping.
Tests use synthetic metadata, not a complete checksummed LUKS header.

Neither result authorizes a write. The command still needs held device identity,
exclusive use, bounded passphrase intake, cryptsetup validation, active mapping
verification and restricted filesystem handling. Existing filesystems must never
be reformatted; first-use formatting must follow the full blank check under the
same device hold. Nothing opens the data disk at boot. The owner unlock command,
complete PID1/initrd integration and hardware acceptance remain unfinished.

The unlock coordinator now enforces operation ordering against an explicit
adapter contract. Existing headers must pass policy checks before any open;
only an explicit non-LUKS probe followed by a full zero scan permits first-use
formatting. Filesystem creation is permitted only in that same invocation.
Interrupted initialization is preserved for recovery on a later retry, never
silently reformatted. The coordinator checks the active mapping before filesystem
work and again before mounting, and accepts only ext4 from the filesystem probe.

Failed opens that allocated a mapping, failed checks and cancelled operations
close only that invocation's mapping using a fresh bounded cleanup context.
Cleanup failures remain visible. Passphrases are bounded to 4096 raw bytes,
never normalized or placed in error text, and the consumed buffer is cleared.
The future CLI must supply a bounded non-TTY input stream; it must never echo a
passphrase or pass it through arguments, environment variables or disk files.

These are tests with an injected disk/mapping adapter, including partial failures
and relaunch retries. No Linux adapter, unlock CLI, real LUKS format/mount or
hardware proof is supplied by this component. Adapter identity, serialization,
cryptsetup behavior and mount restrictions still require independent validation.


The first Linux adapter component now holds the data device by descriptor.
`OpenData` is an owner-command operation, never a boot operation. It selects
`custom-data` by serial, checks the signed size and writable virtio identity,
refuses partitions, existing holders and mounts, and repeats inventory checks
after opening. Kernel device type, major/minor, size and read-only state are
checked on the held descriptor. Later cryptsetup calls must inherit that
same descriptor; they must not reopen a user-supplied pathname.

A root-owned private runtime lock serializes this helper. Failed opens release
both descriptors; closing the holder never closes a device-mapper mapping.
This cooperative lock does not prevent the owner from deliberately accessing
the disk through another root program. The complete adapter must recheck
identity/use before writes and verify its own active mapping before filesystem
work. It must retain ownership records for cleanup of partial opens.

The new tests use private sysfs/dev/mount fixtures, with descriptor ioctl checks
substituted by a test callback. The real inspector is tested to reject ordinary
files. Root-owned lock tests require uid 0 and skip otherwise. No real block
device, LUKS formatting, mounting, runtime CLI or hardware acceptance is claimed.

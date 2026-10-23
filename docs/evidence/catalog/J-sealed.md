# Catalog J: sealed kit (room-kit/sealed) at 22e7824

Artifact: cathedral-sandbox 22e7824 (PR #311 head), frozen at /private/tmp/claude-501/r6.
Files: room-kit/sealed/{build-guest.sh, launch-guest.sh, host-net.sh, guest-boot.sh,
install-sealed.sh, sealed.env.example, README.md}. Context read: room-kit/install.sh,
room-kit/room_receipts.py, room-kit/verify_receipts.py, room-kit/lib/{receipts_mode.sh,
room_nets_mode.sh, room-data.sh, room-net.sh}, room-kit/profiles/v1.sh,
room-kit/versions.lock, room-kit/make-dist.sh, broker/{config.example.json, probe.go,
hotels.go}, tests/test_room_kit_sealed_kit.py. docs/DEDICATED_SEALED.md does not exist.

Entry point: `install.sh --sealed sealed.env` (install.sh:12) execs
`sealed/install-sealed.sh sealed.env`. Everything runs as root on the host. The guest
later runs the same install.sh with the room.env that the build wrote into the image.

Outside sources checked (not the repo): QEMU target/i386/sev.c (default policy 0x30000,
kernel hash table, reset), Linux arch/x86/kvm/svm/sev.c (policy mask), sev-snp-measure
v0.0.12 (vcpu_types.py, cli.py, sev_hashes.py), GNU cpio manual (--reproducible),
mmdebstrap (cleanup/reproducible, SOURCE_DATE_EPOCH), ufw-init-functions
(flush_builtins), util-linux sulogin.8, systemd sulogin-shell.c, Linux
drivers/firmware/qemu_fw_cfg.c, shadow passwd.c, Ubuntu edk2 packaging for noble,
questing and resolute, Debian trixie ovmf file list.

---------------------------------------------------------------------------------------

## 1. install-sealed.sh (host, 100 lines)

### top level, L1 to L20
- Purpose: source sealed.env (readlink -f, L14 to L16), require root, name the unit
  `room-sealed-$SEALED_NAME.service`, pin `SNP_MEASURE_VERSION=0.0.12`.
- Trusts: every SEALED_* value as shell text (sourced, unquoted later in heredocs).
- Side effects: none yet. Locks: none. Callers: install.sh:12.
- Invariant: sealed.env is the operator's file; no validation of names, IPs, MAC.

### log(), L17
- Prints `[sealed] ...` to stdout. No secrets pass through it.

### step 1 assess, L22 to L33
- Checks kvm_amd sev_snp=Y, /dev/sev, `-r $SEALED_API_KEY_FILE`, free disk after a
  full scratch, MemAvailable > SEALED_MEM_GIB + 32 (skipped when the unit is active).
- Trusts: `df`/`du`/`/proc/meminfo` arithmetic; the key file only for readability
  (not mode, owner, or content).
- Side effects: `mkdir -p $SEALED_DIR/images $SEALED_DIR/run` with umask 022 (0755).
- Invariant: the header (L3) promises a free ASID check; the code has none.

### step 2 host packages, L35 to L47
- Installs qemu-system-x86, ovmf, mmdebstrap, zstd, cpio, python3-venv when the
  command or `$SEALED_OVMF` file is missing; `apt-get install` with no prior
  `apt-get update`. Then checks `qemu-system-x86_64 -object help` lists
  `  sev-snp-guest` (exact two-space indent).
- Trusts: that the `ovmf` package provides `$SEALED_OVMF`. It does not recheck the
  file after apt. Ubuntu 24.04 `ovmf` ships no AmdSev build; Ubuntu 25.10 `ovmf`
  ships /usr/share/ovmf/OVMF.amdsev.fd; Ubuntu 26.04 moves it to `ovmf-amdsev` at the
  same path (the `ovmf` metapackage depends on it); Debian trixie ships none.
- Side effects: apt on the host. Invariant: the host distro has an AmdSev OVMF.

### step 3 build and expected measurement, L49 to L61
- Runs build-guest.sh unless `SEALED_SKIP_BUILD=1` and `images/current` exists.
- Makes `$SEALED_DIR/venv` once: `pip install sev-snp-measure==0.0.12` (PyPI, version
  pinned, no hash; pulls `cryptography>=39.0.1` unpinned; venv reused forever).
- Computes EXPECTED: `sev-snp-measure --mode snp --vcpus $SEALED_VCPUS
  --vcpu-type $SEALED_CPU_MODEL --ovmf $IMG/OVMF.amdsev.fd --kernel $IMG/vmlinuz
  --initrd $IMG/initrd.cpio.zst --append "$(cat $IMG/cmdline)"`. Defaults left in
  place: `--vmm-type QEMU`, `--guest-features 0x1` (SNP_ACTIVE only), hex output.
  Writes `$IMG/expected-measurement`.
- Trusts: the venv content; `$SEALED_CPU_MODEL` is a name sev-snp-measure knows
  (`host` is refused, the install stops here, fail closed).
- Invariant: launch-guest.sh is given the same values at the time of launch. Both
  read sealed.env at run time, so a later edit of SEALED_VCPUS or SEALED_CPU_MODEL
  changes both without a rebuild while manifest.json keeps the old values.

### step 4 unit, L63 to L84
- Installs host-net.sh and launch-guest.sh into `$SEALED_DIR` (0755); copies
  sealed.env to `$SEALED_DIR/sealed.env` (0600) unless the given file is that copy.
- Writes `/etc/systemd/system/room-sealed-<name>.service`:
  `After/Wants=network-online.target`, `Type=simple`,
  `ExecStartPre=host-net.sh up`, `ExecStart=launch-guest.sh`,
  `ExecStopPost=host-net.sh down`, `KillSignal=SIGTERM`, `TimeoutStopSec=60`,
  `Restart=no`, `LimitMEMLOCK=infinity`, `WantedBy=multi-user.target`.
- Invariant: the unit is the only thing that applies the host link rules; nothing
  re-applies them while the guest runs. Restart=no: a QEMU exit ends the hotel until
  an operator acts.

### step 5 start and check, L86 to L100
- `systemctl restart $UNIT` unconditionally (L87): kills a running guest and every
  room in it; no live-room check (install.sh has one for shared hotels, L34 to L49).
- Poll loop L91 to L95: up to 180 times, `curl -fsS -m 5` GET
  `http://$SEALED_GUEST_IP:18090/room/attestation` (unauthenticated route of the
  receipts front); on success `mv .part attestation.json` and break; else exit 1 if
  the unit is not active, else sleep 5. Worst case about 30 min; the message says 15.
- L97: reads `binding.measurement` with python; a level 1 binding (no SNP) has no
  such key, so the script dies with a KeyError traceback (fail closed, ugly).
- L98: copies the attestation to `$IMG/attestation-<utc stamp>.json`.
- L99: string compare GOT vs EXPECTED; mismatch logs and `exit 1` (B37) but leaves
  the unit active and enabled.
- Files kept: `$SEALED_DIR/run/attestation.json`, `$IMG/attestation-*.json`,
  `$IMG/expected-measurement`, `$SEALED_DIR/run/serial.log`,
  `$SEALED_DIR/run/booted-image` (symlink). All under a 0755 directory.
- Trusts: the guest's own report of its measurement (no signature check here; the
  broker's probeSealed does not check it either; only verify_receipts.py does).

---------------------------------------------------------------------------------------

## 2. build-guest.sh (host, 227 lines)

### top level, L12 to L22
- `set -euo pipefail`, umask 022, KIT = room-kit dir, source sealed.env, STAMP = UTC
  time, OUT = `$SEALED_DIR/images/<stamp>`, B = `$SEALED_DIR/build`.
- Callers: install-sealed.sh:51, or an operator by hand.

### log(), L17
- `[sealed-build] ...` to stdout.

### step 1 base root file system, L24 to L36
- PKGS (L25): systemd, systemd-sysv, udev, kmod, iproute2, nftables, iptables,
  conntrack, docker.io, containerd, xfsprogs, cryptsetup-bin, curl, ca-certificates,
  bzip2, python3, procps, util-linux, iputils-ping, linux-image-virtual,
  openssh-server, less, tar, gzip, zstd, passwd, dmsetup. No version pins.
- BASE_ID (L26) = first 12 hex of sha256("$SUITE $MIRROR $PKGS"): the cache key has
  no package versions, so a base built once is reused on that host forever, and two
  hosts get different bases.
- mmdebstrap (L30 to L31): `--variant=minbase`, Install-Recommends false,
  components main,universe, suite `$SEALED_SUITE` (example: resolute, release pocket
  only, no -updates or -security), mirror `$SEALED_MIRROR` (plain http; apt verifies
  with the host's keyring), no keyring option, no SOURCE_DATE_EPOCH.
- Then `cp -a base rootfs` (L34 to L36).
- Side effects: network to the mirror; `$SEALED_DIR/build/*` (0755 tree, contains the
  guest's /etc/shadow with a locked root and no hashes).

### step 2 kernel out, L38 to L41
- KVER = highest `ls /lib/modules` (the mirror's current linux-image-virtual).
- Copies `/boot/vmlinuz-$KVER` to `$OUT/vmlinuz` (0644); removes /boot, apt .deb
  archives and apt lists from the root.

### step 3 guest configuration, L43 to L200
- L44: `/init -> usr/lib/systemd/systemd`. L45: hostname `room-$SEALED_NAME`.
  L46: empty /etc/machine-id (transient id at boot). L47: empty fstab.
  L48 to L49: static resolv.conf from SEALED_DNS (no systemd-resolved).
- L51 to L65: systemd-networkd files: `.link` renames the NIC with
  `MACAddress=$SEALED_GUEST_MAC` to `uplink`; `.network` sets
  `$SEALED_GUEST_IP/30`, gateway `$SEALED_HOST_IP`, `LinkLocalAddressing=no`,
  `IPv6AcceptRA=no`. The MAC is therefore inside the measured image.
- L66 to L74: modules-load: sev-guest, tsm_report, qemu_fw_cfg, dm-crypt, xfs,
  overlay, br_netfilter (failures are logged, not fatal).
- L76: `DEBUG=1` iff `SEALED_DEBUG_SSH_PUBKEY` is non-empty. The only switch.
- L77 to L94: `/etc/sealed-guard.nft`, table inet sealed_guard: input (priority -10,
  policy accept): uplink established/related accept; uplink from `$SEALED_HOST_IP`
  tcp dport 18090 accept; debug only: tcp dport 22 from the host IP; everything else
  from uplink drop. forward: uplink established/related accept, else uplink drop.
  Nothing filters traffic that does not arrive on uplink.
- L95 to L108: `sealed-guard.service`: oneshot, RemainAfterExit,
  `DefaultDependencies=no`, `Before=network-pre.target`,
  `After=systemd-modules-load.service`, `ExecStart=nft -f /etc/sealed-guard.nft`,
  `WantedBy=sysinit.target`.
- L110: guest-boot.sh installed as `/usr/local/sbin/sealed-hotel-boot.sh` (0755).
- L111 to L125: `sealed-hotel.service`: oneshot, RemainAfterExit,
  `Wants=network-online.target sealed-guard.service` (Wants, not Requires),
  `After=network-online.target sealed-guard.service systemd-modules-load.service
  containerd.service`, `ExecStart=/usr/local/sbin/sealed-hotel-boot.sh`,
  stdout/stderr `journal+console` (so the host serial log gets the install output),
  `TimeoutStartSec=1800`, `WantedBy=multi-user.target`. No Restart.
- L127 to L130: the kit copy. `tar -C $KIT --exclude=./sealed/work -cf - . | tar -C
  $R/opt/room-kit -xf -`: every file under room-kit as it sits on the host, with its
  host mtime, uid, gid and mode. Tracked files that land: README.md, assess.py,
  install.sh, lib/{net_capacity.py, net_plan.py, receipts_mode.sh, room-data.sh,
  room-net.sh, room_nets_mode.sh}, make-dist.sh, profiles/v1.sh, room.env.example,
  room_api.py, room_egress.py, room_health.py, room_receipts.py, sealed/{README.md,
  build-guest.sh, guest-boot.sh, host-net.sh, install-sealed.sh, launch-guest.sh,
  sealed.env.example}, size.py, uninstall.sh, verify_receipts.py, versions.lock,
  files/requirements.lock, .gitignore. Untracked files that land too:
  dist/cathedral-6701dda.tar.gz (required by install.sh:164, git-ignored, made by
  make-dist.sh), and anything else present (an operator's sealed/sealed.env, editor
  swap files, __pycache__). Probe test_probe_kit_copy_takes_only_tracked_kit_files
  shows sealed/sealed.env and room.env.swp packed and sealed/work excluded.
  L130: `/opt/room-kit/KIT_COMMIT` from a KIT_COMMIT file, else `git rev-parse HEAD`
  (as root in a checkout owned by another user this fails on safe.directory), else
  `unknown`. It does not reflect uncommitted edits.
- L131 to L175: `/opt/room-kit/room.env` (the guest's room.env, measured):
  ROOM_ID=room-sealed, ROOM_CUSTOMER=broker, API_PROFILE=v1,
  ROOM_API_KEY_FILE=/run/room-api-key, API 18090, health 18091, ROOM_TLS=off (no
  Caddy), registry mirror mirror.gcr.io, ROOM_DATA_DIR=/srv/room-sealed,
  ROOM_DATA_DEVICE=/dev/mapper/sealed-scratch, ROOM_DATA_DEVICE_WIPE=yes (mkfs every
  boot), bridge rmbr0 10.213.0.1/21, ROOM_DNS=$SEALED_DNS, runsc systrap,
  ROOM_ALLOW_DIND=1, shape 1 vCPU/4 GiB/10 GiB, MEM_OVERCOMMIT=20, CPU_OVERCOMMIT=16,
  ROOM_MAX_SLOTS=$SEALED_ROOM_MAX_SLOTS, ROOM_CREATES_PER_MINUTE=6000,
  ROOM_NETS=$SEALED_ROOM_NETS, ROOM_RECEIPTS=1,
  ROOM_RECEIPTS_LISTEN=$SEALED_GUEST_IP:18090, ROOM_HOTEL_NAME=$SEALED_NAME.
  ROOM_EGRESS unset (defaults to 1 in install.sh).
- in_root(), L178: `chroot $R "$@"`.
- L179 to L180: mask docker.service, docker.socket, serial-getty@ttyS0,
  getty@tty1, console-getty, getty.target, apt-daily.timer, apt-daily-upgrade.timer;
  errors hidden by `2>/dev/null || true`. Not masked: rescue.service,
  emergency.service, rescue.target, emergency.target, debug-shell.service (B61).
- L181: enable systemd-networkd (its Also= pulls networkd.socket and
  networkd-wait-online), sealed-guard, sealed-hotel, containerd.
- L182: `passwd -l root` (prefixes "!" to the already starred hash; no age update;
  rewrites /etc/shadow and leaves /etc/shadow-).
- L183 to L194 (debug): /root/.ssh 0700, authorized_keys 0600 with the operator's
  key; sshd_config.d/10-sealed-debug.conf: `ListenAddress $SEALED_GUEST_IP`,
  `PasswordAuthentication no`, `PermitRootLogin prohibit-password`;
  ssh.service.d/10-hostkeys.conf resets ExecStartPre to `ssh-keygen -A` then
  `sshd -t` (B31 fix, tested by test_room_kit_sealed_kit.py); enable ssh.service;
  mask ssh.socket.
- L195 to L198 (production): mask ssh.service and ssh.socket; remove host keys.
- L200: remove host keys in both branches (debug makes new ones at every boot).
- Users: only what the packages create (root locked, no human user; docker group
  from docker.io). install.sh adds `poolroom` inside the guest at boot.

### step 4 initrd, cmdline, OVMF, manifest, L202 to L227
- L204 to L205: `find . -mindepth 1` pruning the contents of ./proc, ./sys, ./dev
  (the empty directories stay), `LC_ALL=C sort -z`, `cpio --null -o -H newc
  --reproducible --quiet`, `zstd -q -T0 -10`. GNU cpio `--reproducible` means
  `--ignore-devno --ignore-dirnlink --renumber-inodes`: inode numbers and device
  numbers are normalised; mtime, uid, gid, mode and size are kept as on disk.
  zstd output depends on the zstd version and level, not on the thread count.
- L206 to L207: cmdline `console=ttyS0 loglevel=7 systemd.show_status=error
  panic=-1 rdinit=/init cathedral.hotel=$SEALED_NAME cathedral.debug=$DEBUG`,
  written with no trailing newline. No `root=`: the kernel keeps the unpacked
  initramfs as the root (tmpfs). `panic=-1`: reboot at once on a panic; QEMU treats a
  reset of a protected guest as a terminate (older) or a rebuild with a new launch
  (newer): either way every room ends.
- L208: copies `$SEALED_OVMF` to `$OUT/OVMF.amdsev.fd` (0644): whatever file sits at
  that host path; no package or version recorded.
- L210 to L225: manifest.json (sorted keys, indent 1):
  schema `cathedral_sealed_hotel_guest_v1`, hotel, vcpus (int), cpu_model,
  kernel_release, debug (bool), base_rootfs (the 12-hex BASE_ID, an input hash, not a
  content hash), cmdline (string), sha256 of OVMF.amdsev.fd, vmlinuz, initrd.cpio.zst
  and cmdline, bytes of the first three. Not in it: the expected measurement, package
  versions, tool versions, KIT_COMMIT, the cathedral commit, the SEALED_* values other
  than name, vcpus, cpu model.
- L226: `images/current -> <stamp>` flipped before any measurement check; the next
  unit start boots it.
- Invariant assumed: everything the guest will ever run is inside the initrd or
  pinned by hash in versions.lock and requirements.lock inside it.

---------------------------------------------------------------------------------------

## 3. launch-guest.sh (host, 26 lines)

- L6 to L9: source sealed.env, IMG = readlink of images/current, RUN dir.
- L12: HOST_DATA = base64(sha256(manifest.json)); the host's label for the build.
- L13: creates the sparse scratch file (`truncate -s ${SEALED_SCRATCH_GIB}G`, mode
  0644 under umask 022) if absent; never recreated or wiped by the host.
- L14: `run/booted-image -> $IMG`.
- L15 to L26: `exec qemu-system-x86_64`. Callers: the unit's ExecStart.
  Trusts: the image directory content; the key file path; sealed.env values.

### The QEMU command line: measured or not

| Argument | In the launch measurement | Why |
|---|---|---|
| `-no-user-config -nodefaults` | No | Device set, not launch data. Removes the default NIC, VGA, floppy, CD. |
| `-name sealed-<name>` | No | Process label. |
| `-enable-kvm` | No | Accelerator. |
| `-cpu $SEALED_CPU_MODEL` (EPYC-v4) | Partly | Every VMSA is measured and its EDX reset value is the CPUID signature of the model. EPYC-v4 = family 0x17 model 1 stepping 2 (0x800F12), the same for EPYC, EPYC-v1, v2, v3, IBPB (sev-snp-measure vcpu_types.py L29 to L34). Feature flags are not measured. The guest sees a Naples feature set (no AVX-512 and the like). |
| `-smp $SEALED_VCPUS` | Yes | One VMSA page per vCPU is measured; `--vcpus` must match. Default topology is N sockets of one core. |
| `-m ${SEALED_MEM_GIB}G` | No | Memory size is not launch data; discovered by firmware and kernel. |
| `-machine q35,confidential-guest-support=sev0,memory-backend=ram1` | No | Machine type is hardware layout; the VMSA reset state is architectural. |
| `-object memory-backend-memfd,id=ram1,size=...,share=true,prealloc=false` | No | Backing store for shared pages; private pages use guest_memfd. Lazy allocation. |
| `-object sev-snp-guest,... policy=0x30000` | No (report field) | POLICY is in the signed report, not in the digest. 0x30000 = bit 16 SMT allowed, bit 17 reserved must be one. DEBUG (bit 19) 0, MIGRATE_MA (18) 0, SINGLE_SOCKET (20) 0, ABI major/minor 0 (any firmware), bits 24 to 28 (CXL, AES-256-XTS, RAPL_DIS, CIPHERTEXT_HIDING, PAGE_SWAP_DISABLE) 0. Same as QEMU's default. KVM accepts only bits in KVM_SNP_POLICY_MASK_VALID and requires bit 17; MIGRATE_MA is outside the mask, so a Linux host cannot launch with it. The host can flip SMT, DEBUG, SINGLE_SOCKET and ABI bits without changing the measurement; verify_receipts.py refuses only DEBUG (L201). |
| `cbitpos=51,reduced-phys-bits=1` | No | Hardware constants (Milan, Genoa); wrong values fail to boot. |
| `kernel-hashes=on` | Enables measurement of kernel, initrd, cmdline | QEMU writes sha256(kernel file), sha256(initrd file), sha256(cmdline + NUL) into the OVMF area marked SEV_HASH_TABLE_RV_GUID; that page is launch data, so the three are measured indirectly. The AmdSev OVMF refuses a blob whose hash differs. Without it they would be unmeasured. |
| `host-data=$HOST_DATA` | No (report field) | 32 bytes the host chooses, copied into HOST_DATA of every report. Here sha256(manifest.json). A label, not evidence; the guest copies it into the binding. |
| `-bios $IMG/OVMF.amdsev.fd` | Yes | The firmware image and its metadata-described pages (secrets, CPUID, zero pages) form the launch digest. Copied from the host's `$SEALED_OVMF` by the build; only its sha256 and size are recorded. |
| `-kernel $IMG/vmlinuz` | Yes, via the hash table | Bytes of the file. |
| `-initrd $IMG/initrd.cpio.zst` | Yes, via the hash table | Bytes of the compressed file, so compression determinism matters. |
| `-append "$(cat $IMG/cmdline)"` | Yes, via the hash table | Bytes plus a NUL; `$(cat)` strips trailing newlines and the file has none. sev-snp-measure appends the NUL (sev_hashes.py L72). |
| `-drive if=none,id=scratch,format=raw,file=scratch.raw,cache=none,aio=io_uring` | No | Host file; the guest encrypts it. cache=none bypasses the host page cache. io_uring must be allowed on the host (kernel.io_uring_disabled). |
| `-device virtio-blk-pci,drive=scratch,serial=sealed-scratch,disable-legacy=on,iommu_platform=true` | No | `serial` gives /dev/disk/by-id/virtio-sealed-scratch in the guest. iommu_platform makes the guest bounce DMA through shared pages (needed under SEV). Modern virtio only. |
| `-netdev tap,id=net0,ifname=$SEALED_TAP,script=no,downscript=no,vhost=on` | No | The tap that host-net.sh made. vhost-net in the host kernel. |
| `-device virtio-net-pci,netdev=net0,mac=$SEALED_GUEST_MAC,disable-legacy=on,iommu_platform=true,romfile=` | No, but the MAC is pinned by the measured .link file | `romfile=` loads no option ROM (an unmeasured blob avoided). A different MAC would leave the NIC unnamed and the guest without network. |
| `-fw_cfg name=opt/cathedral/room-api-key,file=$SEALED_API_KEY_FILE` | No | Read by the guest at boot (sysfs `raw`, mode 0400 root). fw_cfg also carries the kernel, initrd and cmdline blobs (hash-checked by OVMF) and QEMU's ACPI, SMBIOS and e820 tables (not checked). |
| `-display none -vga none` | No | No graphics. |
| `-monitor none` | No | No monitor, no QMP. The only control path is the process (SIGTERM). |
| `-serial file:$RUN/serial.log` | No | Guest console to a host file, output only (no input into the guest). Truncated at every QEMU start (char-file.c: O_TRUNC unless append=on). |
| Absent: vsock, virtio-rng, `-S`, `-no-reboot`, `-smbios`, `-chardev socket` | | No vsock channel. No host RNG: guest entropy comes from RDRAND/RDSEED of the CPU model plus kernel jitter. |

Not measured and host-generated, trusted by the guest kernel as any SNP guest does:
ACPI tables, SMBIOS, e820, the virtio devices' behaviour, the clock (kvm-clock).

---------------------------------------------------------------------------------------

## 4. host-net.sh (host, 45 lines)

- L10 to L15: source sealed.env; chains `SEALED-<TAP upper>-FWD` and `-IN`; comment
  tag `sealed-hotel:$SEALED_NAME`; PRIVATE = 10/8, 172.16/12, 192.168/16, 100.64/10,
  169.254/16. Needs bash 4 (`${TAP^^}`).

### up, L18 to L36 (ExecStartPre)
- Creates the tap if absent, `ip addr replace $SEALED_HOST_IP/30`, link up,
  `sysctl net.ipv4.ip_forward=1` (global, no FORWARD policy set).
- FWD chain (flushed and rebuilt): `-i tap -d PRIVATE DROP`; `-i tap -s GUEST_IP
  ACCEPT`; `-i tap DROP`; `-o tap ESTABLISHED,RELATED ACCEPT`; `-o tap DROP`.
  Jump inserted at FORWARD position 1 if the tagged jump is absent.
- IN chain: `-i tap ESTABLISHED,RELATED ACCEPT`; `-i tap DROP`. Jump at INPUT 1.
- nat: `POSTROUTING -s GUEST_IP/32 ! -o tap MASQUERADE` appended if absent.
- Effects: the guest reaches the internet with the host's address and nothing
  private, cannot open a connection to any host address; only processes in the host
  network namespace (the broker) can open connections into the guest; containers and
  other machines are dropped in FORWARD. IPv4 only: no ip6tables rule and IPv6 is not
  disabled on the host side of the tap (it gets an fe80:: address).
- Trusts: that nothing else on the host flushes or reorders these rules. ufw's
  flush_builtins (`iptables -F`, `-X`, policies ACCEPT, `nat -F POSTROUTING`) runs on
  `ufw reload`, `ufw disable` and `systemctl restart ufw`.
- Idempotent: safe to run by hand (undocumented).

### down, L37 to L44 (ExecStopPost)
- Deletes the two jumps and the MASQUERADE rule, flushes and deletes the chains,
  deletes the tap. All errors ignored.

---------------------------------------------------------------------------------------

## 5. guest-boot.sh (inside the guest, 28 lines, sealed-hotel.service)

- log(), L8: `[sealed-hotel] ...` to journal and console (the host serial log).
- L10 to L12: wait up to 60 s for /dev/disk/by-id/virtio-sealed-scratch; exit 1
  if absent (fail closed).
- L13 to L17: if /dev/mapper/sealed-scratch is absent: `DM_DISABLE_UDEV=1 cryptsetup
  open --type plain --cipher aes-xts-plain64 --key-size 512 --hash plain --key-file
  /dev/urandom --keyfile-size 64 --sector-size 4096 $DEV sealed-scratch`.
  Cipher: AES-XTS with two 256-bit keys. Key source: 64 bytes from the guest's
  /dev/urandom used as-is. Where the key lives: only in the kernel's dm-crypt
  target, in SNP-encrypted guest memory; no header, no file, no passphrase; a new
  key at every boot, so the old scratch content is unreadable afterwards. Plain mode
  has no integrity or anti-replay: the host can corrupt (16-byte granularity) or
  replay (4 KiB sector) ciphertext without detection.
- L18: logs the size (blockdev).
- L20 to L23: wait up to 30 s for
  /sys/firmware/qemu_fw_cfg/by_name/opt/cathedral/room-api-key/raw (0400 root);
  `install -m 0600 /dev/null /run/room-api-key`; `cat $KEY > /run/room-api-key`.
  If the entry never appears, `cat` fails and the unit fails (fail closed). The fw_cfg
  entry itself stays readable by guest root for the life of the guest.
- L25 to L26: `/opt/room-kit/install.sh /opt/room-kit/room.env`. Inside the guest
  this: finds no room socket (guard returns), skips apt (all commands present),
  writes /etc/pool-room/room.env, formats /dev/mapper/sealed-scratch as xfs (blkid
  sees garbage, WIPE=yes), mounts it with prjquota, fetches gVisor, uv, Python,
  the wheel set and Caddy by pinned hash over the host NAT, creates `poolroom`,
  writes daemon.json (runsc default, iptables=false, data-root on the scratch),
  starts room-sealed-docker.service (room-net.sh up: rmbr0 and the ROOM_NETS
  bridges, private ranges dropped for rooms), sizes slots, pulls alpine:3.20,
  copies the key to /etc/pool-room/api.key (0640 root:poolroom), secret.env (0600),
  reaper.headers (0600), writes and starts room-sealed.service (API,
  127.0.0.1:18090, user poolroom), -health (127.0.0.1:18091), -reaper.timer,
  -egress (root; DNS and proxy bound on bridge gateway addresses only), -receipts
  (root; binds $SEALED_GUEST_IP:18090; TSM provider sev_guest gives the sealed
  binding and two SNP reports). No Caddy (ROOM_TLS=off). Everything under /opt and
  /etc is in the tmpfs root, in guest memory.
- L27: removes /run/room-api-key (skipped if install.sh failed, set -e).
- What fails open: nothing in this script. At unit level: sealed-guard is only
  Wanted, so a failed `nft -f` still lets the hotel install and serve; an install.sh
  failure after step 13 began leaves API units running while the unit shows failed.

### Order of operations at every boot (nothing persists between boots)
1. OVMF (measured) loads kernel, initrd and cmdline from fw_cfg and checks them
   against the measured hash table.
2. Kernel unpacks the initrd into a tmpfs root (no `root=`), execs /init (systemd);
   hostname room-<name>; a new transient machine-id.
3. sysinit: modules-load (sev-guest, tsm_report, qemu_fw_cfg, dm-crypt, xfs, overlay,
   br_netfilter), udev, sealed-guard.service (nft rules on uplink).
4. systemd-networkd: NIC with SEALED_GUEST_MAC renamed uplink, static /30, no IPv6;
   networkd-wait-online gates network-online.target.
5. containerd.service.
6. sealed-hotel.service runs guest-boot.sh (above); the receipts front comes up last
   and answers GET /room/attestation; the host's install loop sees it.
7. Every later boot repeats this: new dm-crypt key, new xfs, new downloads (pinned),
   new receipts key and chain (B22).

---------------------------------------------------------------------------------------

## 6. sealed.env.example (42 lines)

| Variable | Used by | Enters the measured image |
|---|---|---|
| SEALED_NAME | hostname (build L45), cmdline (L206), room.env (L132, L174), unit name, tag | Yes |
| SEALED_DIR | all host scripts | No |
| SEALED_VCPUS | QEMU -smp, sev-snp-measure --vcpus, manifest | Yes (VMSA count) |
| SEALED_MEM_GIB | QEMU -m, memfd, assess | No |
| SEALED_CPU_MODEL | QEMU -cpu, --vcpu-type, manifest | Yes (CPUID signature only) |
| SEALED_SCRATCH_GIB | truncate, assess | No |
| SEALED_MIN_HOST_FREE_GIB | assess | No |
| SEALED_TAP | host-net.sh, QEMU netdev | No |
| SEALED_HOST_IP | host-net.sh, .network gateway (L62), nft guard (L78, L84) | Yes |
| SEALED_GUEST_IP | host-net.sh, .network (L61), room.env listen (L173), debug sshd (L187), poll URL | Yes |
| SEALED_GUEST_MAC | .link (L53), QEMU mac | Yes |
| SEALED_DNS | resolv.conf (L49), room.env (L152) | Yes |
| SEALED_SUITE, SEALED_MIRROR | mmdebstrap, BASE_ID | Yes (package set) |
| SEALED_OVMF | build L208, install L38 | Yes (the firmware bytes) |
| SEALED_ROOM_MAX_SLOTS, SEALED_ROOM_NETS | room.env (L164, L169) | Yes |
| SEALED_API_KEY_FILE | install L25, QEMU fw_cfg | No (never measured) |
| SEALED_DEBUG_SSH_PUBKEY | build L76, L185 | Yes (authorized_keys and the debug flag) |
| SEALED_SKIP_BUILD (undocumented) | install L50 | No |

Two hotels with different names or addresses never share a measurement. A customer's
expected measurement must be computed from the same sealed.env and the same build
inputs.

---------------------------------------------------------------------------------------

## 7. Host-side secrets and fw_cfg

- `$SEALED_API_KEY_FILE` (example /etc/thin-broker/hotel-sealed-1.key): the broker's
  hotel key for this hotel (broker config `key_file`, broker/config.example.json;
  format `[A-Za-z0-9_-]{32,}` checked by the broker, hotels.go:123, and by the
  guest's install.sh:289). The kit does not make it (install-sealed.sh:25 says so)
  and checks only that root can read it; mode and owner are not checked. Read once by
  QEMU at start; a rotation needs a guest restart (all rooms end). Not printed by any
  kit script; `ps` shows the path and HOST_DATA, not the key. install.sh step 9 turns
  xtrace off around the key. In the guest the key is in /etc/pool-room/api.key
  (0640 root:poolroom), secret.env (0600), reaper.headers (0600), the API unit's
  environment, and the fw_cfg sysfs entry (0400 root), all in encrypted memory.
- `$SEALED_DIR/sealed.env` copy, 0600; holds paths and a public key, no secret.
- Through fw_cfg from the kit: only `opt/cathedral/room-api-key`. QEMU's own items
  ride the same channel: kernel, initrd, cmdline (verified by OVMF against the
  measured hash table), ACPI, SMBIOS, e820 and the boot order (not verified).
- Not secret but exposed on the host at 0644/0755: `run/serial.log` (guest console
  with the install log), `run/attestation.json`, `images/*`, `scratch.raw`
  (ciphertext), `build/rootfs` (the guest root, root locked, no hashes).

---------------------------------------------------------------------------------------

## 8. Production build vs debug build

Every difference comes from `SEALED_DEBUG_SSH_PUBKEY` being non-empty (build L76):
1. cmdline `cathedral.debug=1` instead of `=0` (L206). Measured.
2. `/etc/sealed-guard.nft` gains `tcp dport 22 accept` from the host IP (L78, L85).
   Measured.
3. `/root/.ssh/authorized_keys` with the operator's key (L184 to L186). Measured.
4. `/etc/ssh/sshd_config.d/10-sealed-debug.conf` (L187 to L188). Measured.
5. `/etc/systemd/system/ssh.service.d/10-hostkeys.conf` (L189 to L192). Measured.
6. ssh.service enabled and ssh.socket masked, instead of both masked (L193 to L196).
   Measured.
7. manifest.json `debug: true` (L220), so HOST_DATA differs. Report field only.
8. At run time sshd listens on `$SEALED_GUEST_IP:22` with host keys made at each
   boot; the host can log in as root with the key over the tap.
Identical in both: SNP policy 0x30000, OVMF, kernel, packages, locked root, no getty,
API key path, receipts behaviour.

How a customer tells from the attestation alone:
- `binding.kernel_cmdline` holds `cathedral.debug=1`; verify_receipts.py L204 to
  L205 fails on it (B36). This value is self-reported by the measured software.
- The measurement differs from the published production value (cmdline and initrd
  differ); `--expected-measurement` catches it. This is the only check that does not
  trust the image's own words.
- `host_data` differs (manifest debug field), only useful with the manifest in hand.
- The report's POLICY field does not tell them apart: both builds use 0x30000 with
  DEBUG off. install-sealed.sh and the broker's probeSealed do not refuse a debug
  build; only the customer's verifier does.

---------------------------------------------------------------------------------------

## 9. Reproducibility: sources of difference between two builds (B61)

build-guest.sh
- L25 to L26: package versions unpinned; BASE_ID has no versions, so a host reuses a
  stale base forever and two hosts build different bases. Release pocket only: no
  -updates or -security, so the guest's kernel, docker, containerd, runc and openssh
  stay at release versions.
- L30 to L31: mmdebstrap without SOURCE_DATE_EPOCH. It removes dpkg.log, apt logs,
  alternatives.log, ldconfig aux-cache and empties machine-id
  (cleanup/reproducible), but files that maintainer scripts write keep the build
  time: /etc/shadow and /etc/gshadow, /etc/ld.so.cache, /var/lib/dpkg/*,
  /lib/modules/<kver>/modules.*, the systemd catalog, python __pycache__.
- L39 to L40: KVER is whatever the mirror served.
- L44 to L49, L51 to L74, L79 to L94, L95 to L108, L110, L111 to L125, L128 to
  L130, L131 to L175, L179 to L200: files written at build time carry the current
  mtime; cpio keeps mtimes (`--reproducible` does not clamp them).
- L129: the whole kit directory with host mtimes (checkout time), uid and gid of the
  checkout owner, modes from the checkout umask, and every untracked file (dist/,
  sealed/sealed.env, swap files, __pycache__). Only ./sealed/work is excluded.
- L130: KIT_COMMIT varies with git state and with who owns the checkout.
- L182: /etc/shadow rewritten, /etc/shadow- created (deterministic content, new
  mtime).
- L204 to L205: cpio version (GNU, `--reproducible` needs 2.13 or later) and zstd
  version change the bytes; neither is recorded. Thread count does not.
- L208: OVMF bytes from the host's package or a hand-copied file; package name and
  version unrecorded (Ubuntu 24.04: no AmdSev build in any package; 25.10: `ovmf`;
  26.04: `ovmf-amdsev`; Debian trixie: none).
- Config dependence (not nondeterminism): every SEALED_* value marked Yes in section
  6 changes the image.

install-sealed.sh
- L54 to L57: sev-snp-measure 0.0.12 from PyPI without hashes, `cryptography`
  unpinned. Affects only the operator's expected value, not the guest.
- L58: vcpus and cpu model read at run time; a sealed.env edit changes the launch
  and the expected value without a rebuild, while manifest.json keeps the old values.

Deterministic parts: find order (sorted), cpio format, the manifest, the cmdline,
HOST_DATA for a given manifest, the sev-snp-measure computation for given inputs.

---------------------------------------------------------------------------------------

## 10. Hazards (code that trusts something it did not check)

1. install-sealed.sh:87 restarts the guest on every run with no live-room check;
   install.sh:34 to 49 has one for shared hotels. Every room of the dedicated
   customer ends; a rebuild also changes the measurement.
2. install-sealed.sh:74 to 76 and host-net.sh: rules applied once at ExecStartPre,
   never re-asserted; `ufw reload` and friends flush them (no NAT: rooms lose
   internet while health stays green; no tap isolation). The only kit path back is a
   unit restart, which ends every room; `host-net.sh up` by hand works but is
   undocumented.
3. install-sealed.sh:38 trusts the `ovmf` package to provide `$SEALED_OVMF` and
   never rechecks; on Ubuntu 24.04 or Debian the build runs mmdebstrap for many
   minutes and dies at build-guest.sh:208. build-guest.sh:208 accepts any file at
   that path and records only its sha256.
4. build-guest.sh:129 packs untracked and operator files into the measured initrd
   (probe: sealed/sealed.env, room.env.swp, __pycache__).
5. build-guest.sh never checks that `$KIT/dist/cathedral-<commit>.tar.gz` exists
   with the pinned sha256 (git-ignored, made by make-dist.sh); the guest's install.sh
   fails on it at boot (install.sh:164) after the downloads, and the host waits up to
   30 min for an attestation.
6. install-sealed.sh:99 exits on a measurement mismatch but leaves the unit running
   and enabled; the broker keeps placing rooms there; it returns at every host boot.
7. build-guest.sh:226 flips images/current before any check; launch-guest.sh:7 boots
   it at the next start. A failed install between L51 and L87, or a manual build,
   changes the next boot's measurement silently.
8. guest-boot.sh:15 to 16: dm-crypt plain, no dm-integrity: the host can corrupt or
   replay scratch sectors (room /work files, image layers in the docker data-root);
   with the hotel key it can first write known plaintext through a room (receipted)
   and later replay those ciphertext sectors into another room's files (not
   receipted). B47 names the key; this is the disk side.
9. build-guest.sh:114 to 115: sealed-hotel Wants, not Requires, sealed-guard; an nft
   failure leaves the uplink unfiltered. Exposure today is small: only the receipts
   front (and debug sshd) listen on the uplink address.
10. host-net.sh:22 turns on global IPv4 forwarding and sets no FORWARD policy; on a
    host without Docker (policy ACCEPT) the host forwards between all its interfaces.
11. host-net.sh is IPv4 only; the host side of the tap has an fe80:: address and no
    ip6tables rule; a guest root (after a gVisor escape) reaches host services bound
    on `::` by link local. The measured guest itself does not speak IPv6 on uplink.
12. build-guest.sh:179 to 180 hides a failed mask (`|| true`); rescue.service,
    emergency.service and debug-shell.service are not masked (B61). With root locked
    and no SYSTEMD_SULOGIN_FORCE (env or cmdline, both outside the host's reach since
    the cmdline is measured), sulogin gives no shell; the units are a dead end today,
    not an entry.
13. install-sealed.sh:3 claims an ASID check that L22 to L33 do not perform.
14. install-sealed.sh:47 depends on the exact indentation of `-object help`.
15. install-sealed.sh:45 installs packages without `apt-get update`.
16. install-sealed.sh:91 to 96 can run 30 min while saying 15; the serial log is the
    only diagnostic and QEMU truncates it at every start.
17. launch-guest.sh:21 `aio=io_uring` fails on hosts with io_uring disabled; the
    unit fails at start with no hint in the kit.
18. launch-guest.sh:19: SMT, SINGLE_SOCKET and ABI policy bits are host-chosen and
    checked by nobody in the kit; the README table (L54) files policy under "in the
    measurement" although it is a report field; HOST_DATA likewise.
19. launch-guest.sh:13 and install-sealed.sh:26: umask 022 makes `$SEALED_DIR`,
    serial.log, attestation files and scratch.raw readable by every local user.
20. The guest has no NTP; kvm-clock is host-driven; receipt `issued_at` and TLS
    validity checks inside the guest follow the host's clock.
21. install-sealed.sh:97 and broker probeSealed trust the guest's own binding
    (no AMD chain check on the host); verify_receipts.py is the only signature check.
    A level 1 fallback (TSM missing) fails the install with a KeyError and is flagged
    by probeSealed ("gives no SEV-SNP attestation"); the verifier's level 1 path
    ignoring --expected-measurement is covered by
    tests/probe_receipts_front_r6.py (another reader).
22. sealed.env.example documents neither SEALED_SKIP_BUILD nor the manual
    `host-net.sh up` re-apply.

# SNP staging guest — boot draft (NOT launched)

Frozen after read-only host check 2026-10-13. **Do not run until image-policy accept.**  
Preserve existing guests: `snp-guest` (:2222), `tee-box-dev` (:2224), `tee-box-official` (:2225).

## Verified on host `84.32.220.48` (`cathedral-snp-274`)

| Artifact | SHA-256 |
|---|---|
| `…0029cec5-20261013.raw` | `a7ad573bc5801d404525823ef670f632860fe2d41174c58a0df0c2ceac7abae5` |
| `…efi` | `eff4006e35dc85c9c27e00bc84de17c5b9a9f9aebc3430f4db0d87a41f02cf32` |
| `…initrd` | `18275f1c43df461c0c1436fbf3d78dcd31f888ec2ad6675e2af121af550c0298` |
| `…vmlinuz` | `9f55ef7253055a9cf68f8a04323c93dead2fca617386d842fbde9ca7b178b27e` |

Matches Fred addendum. File SHA ≠ SNP launch measurement.

## Planned new guest (draft only)

| Field | Value |
|---|---|
| Name | `cathedral-staging-snp-0029cec5` |
| SSH forward | host `:2226` → guest `:22` (**free**) |
| HTTPS forward | host `:8444` → guest `:8443` (**free**) |
| Firmware | `/usr/share/ovmf/OVMF.amdsev.fd` |
| CPU/RAM | 4 vCPU / 8 GiB (same class as existing SNP guests) |
| Disk | readonly raw image above |
| Kernel/initrd | matching vmlinuz/initrd from same image dir |
| Run dir | `/root/snp-launch/cathedral-staging-20261013/run-staging/` (create at launch) |

## Draft qemu shape (review before use — NOT executed)

```bash
# POLICY ACCEPT REQUIRED. Creates NEW guest only. Does not stop 2222/2224/2225.
IMG=/root/snp-launch/cathedral-staging-20261013/images
RUN=/root/snp-launch/cathedral-staging-20261013/run-staging
mkdir -p "$RUN"
# host-data must match measured Cathedral root — confirm with launch owner before boot
qemu-system-x86_64 -name cathedral-staging-snp-0029cec5 -enable-kvm \
  -cpu EPYC-v4 -smp 4 -m 8G \
  -machine q35,confidential-guest-support=sev0,memory-backend=ram1 \
  -object memory-backend-memfd,id=ram1,size=8G,share=true,prealloc=false \
  -object sev-snp-guest,id=sev0,policy=0x30000,cbitpos=51,reduced-phys-bits=1,kernel-hashes=on,host-data=REPLACE_WITH_ROOT_DIGEST_B64 \
  -bios /usr/share/ovmf/OVMF.amdsev.fd \
  -kernel "$IMG/cathedral-staging-snp-0029cec5-20261013.vmlinuz" \
  -initrd "$IMG/cathedral-staging-snp-0029cec5-20261013.initrd" \
  -append 'REPLACE_roothash_and_console_args' \
  -drive if=none,id=disk0,format=raw,readonly=on,file="$IMG/cathedral-staging-snp-0029cec5-20261013.raw" \
  -device virtio-blk-pci,drive=disk0,disable-legacy=on,iommu_platform=true \
  -netdev user,id=net0,hostfwd=tcp::2226-:22,hostfwd=tcp::8444-:8443 \
  -device virtio-net-pci,netdev=net0,disable-legacy=on,iommu_platform=true,romfile= \
  -display none -vga none \
  -monitor unix:"$RUN/monitor",server,nowait \
  -pidfile "$RUN/guest.pid" \
  -serial file:"$RUN/serial.log" \
  -daemonize
```

## Still required before this becomes a real boot

1. Image/policy accept of disk + CPython 3.13.9 / sr25519 pins  
2. Exact `roothash=` / append line from measured image (do not guess)  
3. Correct `host-data` (Cathedral root digest) from launch owner  
4. After boot: native AMD quote verify + TLS pin + Fred 15-min grant  

## Staging API key

Key ID `b30b7437-7d2d-53fc-b7b4-97f4f47f9081` — expiry extended to 2026-10-15T05:40:31Z.  
**Secret not present** in local `.secrets` (only central-access seeds). Obtain via secure channel.

#!/bin/bash
# Off-host checks of the REHEARSAL-ONLY test image, with THROWAWAY keys only (no owner key is read):
#  0. intake: this checkout's ops/custom-guest/custom_guest_stage.py (the operator's intake validator,
#     spec-r9 5.5) accepts the kernel, the initrd as a listed reference initrd and the verity root;
#  1. launch documents: make_launch_docs.py, room-kit/owner_sign.py, custom_guest_protocol.validate_launch,
#     and ops/custom-guest/launch-custom-guest.py --print on a staged launch directory;
#  2. boot the reference kernel + this initrd under QEMU TCG (no SNP) with the three fw_cfg
#     documents: the init must accept the documents, then power off at "no /dev/sev-guest"
#     (the HOST_DATA check needs a real SNP guest);
#  3. the same boot with a bootstrap changed after signing: the init must refuse it;
#  4. sshd from the initrd in a linux/amd64 container: key login as root, no password login, and
#     /usr/bin/cathedral-attest reachable over SSH (it fails closed with no SNP device).
# Usage: test-offline.sh BUILD_OUT OVMF_AMDSEV OVMF_PLAIN TEST_DIR
#   BUILD_OUT    output of build.sh (vmlinuz, initrd.cpio.zst, root.raw, cmdline)
#   OVMF_AMDSEV  the OVMF.amdsev.fd the launch uses (staged for the launcher check)
#   OVMF_PLAIN   a plain OVMF.fd of the same edk2 build: TCG has no SNP, and the AmdSev build boots
#                no kernel without SNP kernel hashes. It puts "initrd=initrd " in front of the
#                cmdline as the AmdSev build does.
#   TEST_DIR     scratch directory visible to Docker
set -euo pipefail
BUILD=$(cd "${1:?BUILD_OUT}" && pwd)
OVMF_SEV=${2:?OVMF_AMDSEV}
OVMF_PLAIN=${3:?OVMF_PLAIN}
mkdir -p "${4:?TEST_DIR}"
T=$(cd "$4" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(git -C "$HERE" rev-parse --show-toplevel)
log() { echo "[rehearsal-test] $*"; }
rm -rf "${T:?}"/* && mkdir -p "$T/repo" "$T/D/images" "$T/D/disks" "$T/D/run" "$T/bad" "$T/inbox" "$T/staging"
git -C "$REPO" archive HEAD room-kit ops/custom-guest | tar -x -C "$T/repo"

# Throwaway owner and SSH keys, made here and deleted at the end.
openssl genpkey -algorithm ed25519 -out "$T/throwaway-owner.pem" 2>/dev/null
openssl pkey -in "$T/throwaway-owner.pem" -pubout -outform DER | tail -c 32 > "$T/owner.pub"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$T/client_key"
OWNER_B64URL=$(python3 -c 'import base64,sys;print(base64.urlsafe_b64encode(open(sys.argv[1],"rb").read()).rstrip(b"=").decode())' "$T/owner.pub")
I=$T/D/images
cp "$OVMF_SEV" "$I/OVMF.amdsev.fd"
cp "$OVMF_PLAIN" "$T/OVMF.fd"
cp "$BUILD/vmlinuz" "$BUILD/root.raw" "$I/"
cp "$BUILD/initrd.cpio.zst" "$I/initrd"
# The built cmdline with the throwaway owner in place of the build's owner key.
sed -E "s/cathedral\.owner=[A-Za-z0-9_-]+/cathedral.owner=$OWNER_B64URL/" "$BUILD/cmdline" | tr -d '\n' > "$I/cmdline"

log "0. intake validator (custom_guest_stage.py) on the kernel, initrd and root"
cp "$I/vmlinuz" "$I/initrd" "$I/root.raw" "$T/inbox/"
python3 - "$T" <<'EOF'
import base64, hashlib, json, os, sys
t = sys.argv[1]
f = lambda n: open(os.path.join(t, "D/images", n), "rb").read()
sha = lambda b: hashlib.sha256(b).hexdigest()
req = {"schema": "cathedral.custom_guest.request/v1",
       "kernel": {"url": "https://example.invalid/vmlinuz", "sha256": sha(f("vmlinuz")), "bytes": len(f("vmlinuz"))},
       "initrd": {"reference": "rehearsal-test-v1", "sha256": sha(f("initrd"))},
       "root_disk": {"url": "https://example.invalid/root.raw", "sha256": sha(f("root.raw")), "bytes": len(f("root.raw"))},
       "cmdline": f("cmdline").decode(), "data_disk_gib": 0, "vcpus": 4, "mem_gib": 8, "cpu_model": "EPYC-v4",
       "owner_ed25519_b64": base64.b64encode(open(os.path.join(t, "owner.pub"), "rb").read()).decode(),
       "ssh_public_key": " ".join(open(os.path.join(t, "client_key.pub")).read().split()[:2]),
       "launch_nonce_hex": "00" * 32, "ports": [{"public": 20022, "guest": 22}]}
json.dump(req, open(os.path.join(t, "inbox/request.json"), "w"), sort_keys=True)
json.dump({"reference_initrds": {"rehearsal-test-v1": sha(f("initrd"))}}, open(os.path.join(t, "inbox/inputs.json"), "w"))
EOF
docker run --rm --platform linux/amd64 -v "$T:/t" debian:trixie-slim bash -euo pipefail -c '
  apt-get -qq update >/dev/null && apt-get -qq install -y --no-install-recommends python3 cryptsetup-bin >/dev/null
  python3 -I /t/repo/ops/custom-guest/custom_guest_stage.py --inbox /t/inbox --staging /t/staging' | tee "$T/intake.txt"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert r.get("ok") is True, r; print("intake validator ok:", json.dumps(r["kernel"]))' "$T/staging/report.json"
cmp "$T/staging/cmdline" "$I/cmdline"

python3 "$HERE/make_launch_docs.py" --images "$I" --out "$I" --owner-pub "$T/owner.pub" \
  --owner-scope user:00000000-0000-4000-8000-000000000000 --ssh-public-key "$(cat "$T/client_key.pub")" \
  --launch-id cg-0123456789ab --public-host 192.0.2.10 --mem-gib 4 --reference-initrd rehearsal-test-v1 > "$T/docs.json"
log "documents: $(tr -d '\n ' < "$T/docs.json")"

log "1. sign with owner_sign.py, validate with custom_guest_protocol, print argv with the launcher"
docker run --rm -v "$T:/t" python:3.12-slim bash -euo pipefail -c '
  pip install -q --disable-pip-version-check cryptography==46.0.3 2>/dev/null || pip install -q --disable-pip-version-check cryptography
  cd /t/repo/room-kit
  python3 owner_sign.py --custom-guest-bootstrap --key /t/throwaway-owner.pem --body /t/D/images/bootstrap.json \
    | base64 -d > /t/D/images/bootstrap.sig
  python3 -c "
import json, custom_guest_protocol as p
r = lambda n: open(\"/t/D/images/\" + n, \"rb\").read()
_, b, hd = p.validate_launch(r(\"manifest.json\"), r(\"bootstrap.json\"), r(\"bootstrap.sig\"), open(\"/t/owner.pub\", \"rb\").read())
want = json.load(open(\"/t/docs.json\"))[\"host_data_hex\"]
hd = hd if isinstance(hd, str) else hd.hex(); assert hd == want, (hd, want)
print(\"validate_launch ok, HOST_DATA\", hd)"
  python3 -I /t/repo/ops/custom-guest/launch-custom-guest.py /t/D --print > /t/argv.json
  echo "launcher accepted the launch directory"'
python3 -c 'import json,sys;a=json.load(open(sys.argv[1]));print(" ".join(a))' "$T/argv.json" > "$T/argv.txt"

# A tampered bootstrap: public port changed after the signature was made.
cp "$I"/* "$T/bad/"
python3 - "$T/bad/bootstrap.json" <<'EOF'
import json, sys
p = sys.argv[1]
doc = json.load(open(p))
doc["ports"][0]["public"] = 20023
open(p, "wb").write(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode())
EOF

boot() {  # $1: directory with the documents, $2: log file
  docker run --rm -v "$T:/t" -v "$1:/docs" debian:bookworm-slim bash -euo pipefail -c '
    apt-get -qq update >/dev/null && apt-get -qq install -y --no-install-recommends qemu-system-x86 >/dev/null
    timeout 600 qemu-system-x86_64 -machine q35,memory-backend=ram1 -object memory-backend-memfd,id=ram1,size=4G,share=on -accel tcg,thread=multi -cpu max -smp 4 -m 4G -no-reboot -nodefaults \
      -bios /t/OVMF.fd -kernel /t/D/images/vmlinuz -initrd /t/D/images/initrd \
      -append "$(cat /t/D/images/cmdline)" \
      -drive if=none,id=root,format=raw,readonly=on,file=/t/D/images/root.raw \
      -device virtio-blk-pci,drive=root,serial=custom-root,disable-legacy=on,iommu_platform=true \
      -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:c7:01:23,disable-legacy=on,iommu_platform=true,romfile= \
      -fw_cfg name=opt/cathedral/manifest.json,file=/docs/manifest.json \
      -fw_cfg name=opt/cathedral/bootstrap.json,file=/docs/bootstrap.json \
      -fw_cfg name=opt/cathedral/bootstrap.sig,file=/docs/bootstrap.sig \
      -display none -serial stdio' > "$2" 2>&1 || true
}
log "2. TCG boot, signed documents (no SNP: expect documents ok, then power off at /dev/sev-guest)"
boot "$I" "$T/boot-good.log"
grep -a "rehearsal-init" "$T/boot-good.log" | tee "$T/boot-good.init.txt"
grep -aq "documents ok: launch cg-0123456789ab" "$T/boot-good.log"
grep -aq "FAIL: no /dev/sev-guest: not an SEV-SNP guest" "$T/boot-good.log"
grep -aq "powering off" "$T/boot-good.log"
grep -a "Command line:" "$T/boot-good.log" | head -1 > "$T/tcg-kernel-cmdline.txt"
grep -aq "Command line: initrd=initrd $(cat "$I/cmdline")" "$T/boot-good.log"
log "3. TCG boot, bootstrap changed after signing (expect refused, power off)"
boot "$T/bad" "$T/boot-bad.log"
grep -a "rehearsal-init\|rehearsal-bootcheck" "$T/boot-bad.log" | tee "$T/boot-bad.init.txt"
grep -aq "FAIL: launch documents refused" "$T/boot-bad.log"
! grep -aq "documents ok" "$T/boot-bad.log"

log "4. sshd from the initrd (linux/amd64 container): root key login, cathedral-attest over SSH"
mkdir -p "$T/ssh"
cp "$T/client_key" "$T/ssh/"
docker run --rm --platform linux/amd64 -v "$T:/t" alpine:3.22 sh -euc '
  apk add -q --no-cache zstd cpio openssh-client >/dev/null
  mkdir /r && cd /r && zstd -dc /t/D/images/initrd | cpio -id --quiet
  mknod -m 0666 /r/dev/null c 1 3; mknod -m 0666 /r/dev/zero c 1 5; mknod -m 0444 /r/dev/urandom c 1 9
  mkdir -p /r/run/cathedral && chmod 0700 /r/run/cathedral
  cut -d" " -f1,2 /t/client_key.pub > /r/run/cathedral/authorized_keys
  chmod 0600 /r/run/cathedral/authorized_keys
  chroot /r /usr/bin/ssh-keygen -q -t ed25519 -N "" -C rehearsal -f /run/cathedral/ssh_host_ed25519_key
  chroot /r /usr/sbin/sshd -f /etc/ssh/sshd_config -E /run/sshd.log
  sleep 1
  o="-F /dev/null -o UserKnownHostsFile=/tmp/kh -o StrictHostKeyChecking=accept-new -o HostKeyAlgorithms=ssh-ed25519 -o BatchMode=yes -o IdentitiesOnly=yes -i /t/ssh/client_key"
  chmod 0600 /t/ssh/client_key
  ssh $o -T root@127.0.0.1 "id; cat /etc/rehearsal-image"
  set +e
  ssh $o -T root@127.0.0.1 "/usr/bin/cathedral-attest $(head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n")"; echo "attest exit $?"
  ssh -F /dev/null -o UserKnownHostsFile=/tmp/kh2 -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o PubkeyAuthentication=no -o PasswordAuthentication=yes -T root@127.0.0.1 true; echo "password login exit $? (want 255)"' 2>&1 | tee "$T/ssh.log"
grep -q "uid=0(root)" "$T/ssh.log"
grep -q "custom_guest_report_failed" "$T/ssh.log"
grep -q "password login exit 255" "$T/ssh.log"
rm -f "$T/throwaway-owner.pem" "$T/client_key" "$T/ssh/client_key"
log "all offline checks passed (throwaway private keys removed)"

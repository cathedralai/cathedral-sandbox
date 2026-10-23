# Sealed hotel (room kit, sealed mode)

A sealed hotel is one AMD SEV-SNP guest on a host. The rooms run under gVisor
(runsc, systrap platform) inside that guest. The guest runs the same room kit
and the same hotel API as an unsealed hotel. It also signs a receipt for each
create, exec, process start, network change and delete that comes through the
API, with a key that an SNP attestation report binds to the guest. Rooms that
expire get no receipt (see "Not covered yet").

One command on the host:

```
sudo ./install.sh --sealed sealed.env
```

## What the command does

1. **Assess.** It checks that SEV-SNP is on (`kvm_amd sev_snp=Y`, `/dev/sev`),
   that the hotel key file exists, and that the host keeps
   `SEALED_MIN_HOST_FREE_GIB` free after the scratch disk is full.
2. **Host packages.** QEMU with `sev-snp-guest`, OVMF (AmdSev build),
   mmdebstrap, zstd, cpio, python3-venv.
3. **Build** (`build-guest.sh`). It makes three files:
   - `vmlinuz`: the Ubuntu kernel.
   - `initrd.cpio.zst`: the WHOLE root file system (Ubuntu minbase, Docker,
     containerd, the room kit, the guest `room.env`). There is no root disk.
   - `cmdline`: the kernel command line.
   It writes `manifest.json` with the sha256 of each file and of OVMF. It
   computes the expected launch measurement with `sev-snp-measure` (pinned).
4. **Unit** `room-sealed-<name>.service`:
   - `host-net.sh up`: a tap device with a /30, NAT to the internet, own
     iptables chains only.
   - `launch-guest.sh`: QEMU with `kernel-hashes=on`, the scratch disk, the
     tap link and the hotel key in fw_cfg.
5. **Check.** It waits for `GET /room/attestation` from the guest. It compares
   the measurement in the report with the build.

Inside the guest, `sealed-hotel.service` runs at every boot:

1. It encrypts the scratch disk with dm-crypt (plain, AES-XTS-512) and a random
   key from the guest's `/dev/urandom`. The key exists only in guest memory.
2. It reads the hotel key from fw_cfg.
3. It runs `install.sh` with the guest `room.env` (`ROOM_RECEIPTS=1`). This
   is the same installer as on an unsealed hotel.

## What the measurement covers

| Item | In the measurement | How |
|---|---|---|
| OVMF firmware | Yes | SNP launch digest |
| Kernel, initrd, command line | Yes | OVMF kernel hashes (`kernel-hashes=on`) |
| Root file system: Ubuntu packages, Docker, the room kit, `room.env` | Yes | It is inside the initrd |
| vCPU count and CPU model | Yes | One VMSA per vCPU |
| Guest policy (no debug, `0x30000`) | Yes | In the report |
| Debug access | Yes | `cathedral.debug=0/1` in the command line |
| Files the kit downloads at boot (gVisor, uv, Python, Caddy, the pinned API wheel set) | No, but pinned | The installer refuses a file whose sha256 or sha512 differs from `versions.lock` and `requirements.lock`, which are in the measured initrd |
| Room images (for example `alpine:3.20`) | No | Pulled at create. The receipt records the image reference and the image id |
| Hotel API key | No | fw_cfg. It authenticates the broker. The host gives it, so the host can call the API too; each call gets a receipt |
| HOST_DATA | No (host chooses it) | It carries the sha256 of `manifest.json`, so a report names the build it claims |

## What the host cannot do

- It cannot read room memory or the receipt key. SEV-SNP encrypts guest memory.
- It cannot read room data on disk. The scratch disk is encrypted with a key
  from inside the guest.
- It cannot log in. A production build has no SSH, no console login and no
  getty. `cathedral.debug=1` (a debug build) adds root SSH from the host on
  the tap link, and the measurement shows it.
- It cannot change the guest software without changing the measurement.

What the host can do besides availability:

- It holds the hotel API key, so it can create rooms, run commands and read
  files through the API. Every such call passes the signing front and gets a
  receipt, so it is on the chain.
- The broker reaches the API over plain HTTP on the tap link. The host can
  read that traffic (commands, outputs, files) without leaving a receipt.

The host still controls availability: it can stop the guest, drop the
network, or refuse the scratch disk.

## Receipts

`room_receipts.py` runs inside the guest. It fronts the API and health on
`ROOM_RECEIPTS_LISTEN`:

- At start it makes an Ed25519 key in memory. It writes a binding document:
  hotel, boot id, receipt public key, measurement, chip id, TCB, policy,
  HOST_DATA, kernel command line, kit and API commits.
- It asks the AMD secure processor for a report with
  `REPORT_DATA = sha256(canonical(binding)) || 32 zero bytes`.
- For each create, exec, background process start, delete and network
  policy switch, it signs a statement. The statement has the same core fields as the staging lane:
  `operation_id`, `action`, `target`, `customer_request_sha256`,
  `command_sha256`, `result_sha256`, `sequence`, `previous_receipt_sha256`,
  `issued_at`. It adds `hotel`, `sandbox_id`, `image`, `image_digest`,
  `status` and `binding_sha256`. Receipt 1 links to the binding. Each next
  receipt links to the receipt before it.
- Create and network switch receipts also carry `network_policy` (the
  canonical policy the hotel applied: mode and sorted allowlist) and
  `network_policy_sha256`. The egress rules run inside the guest, so the host
  cannot change them.

Routes (through the broker):

| Route | Gives |
|---|---|
| `X-Room-Receipt` header on create, exec and delete | The signed receipt, base64url of canonical JSON |
| `GET /v1/sandboxes/<id>/receipts` | The receipts of one room |
| `GET /v1/hotels/<id>/attestation` | Binding, binding sha256, SNP report |
| `GET /v1/hotels/<id>/receipts?after=&limit=` | The chain of this boot |

`result_sha256` is the sha256 of the hotel's own response body. The broker
changes room ids in response bodies (`<hotel>.<id>`), so a guest can check
`result_sha256` only against the body the hotel sent, not against the body
the broker sends.

### Verify

```
python3 verify_receipts.py --attestation attestation.json --receipts chain.json \
  --expected-measurement <from manifest build>
```

It checks the binding digest, REPORT_DATA, that the guest is not a debug
build (`cathedral.debug=1` on the measured command line fails), the AMD chain
(ARK, ASK and VCEK from AMD KDS, RSA-PSS SHA-384; pin the ARK with
`--ark-sha256`, or the KDS answer and the local cache are trusted), the VCEK chip id and TCB extensions, the
report signature (ECDSA P-384), each receipt signature (Ed25519) and the
chain links. It prints the policy timeline of each room
(`policy_timeline`) and checks each policy sha256.

### Not covered yet

- **Image approval.** The verifier proves which measurement signed the
  receipts. It does not prove that this measurement is an approved image.
  A signed policy release that lists approved measurements is a later step.
- A new boot makes a new key and a new chain. A restart of
  `room-sealed-receipts.service` inside the guest also makes a new key and a
  new binding.
- Rooms that the TTL reaper removes get no delete receipt. Neither do rooms
  that a bulk delete or an API restart removes one by one.
- After a restart of the receipts service, the broker serves the new
  binding only. Receipts signed under the old one verify only against an
  attestation saved at the time (`verify_receipts.py --save`).
- Broker to guest traffic is plain HTTP on the tap (see above).
- The verifier has no minimum TCB and does not pin the AMD ARK by default.
- The broker's own records (placement, queue) are not signed.

## Remove

```
sudo systemctl disable --now room-sealed-<name>.service   # stops the guest, removes the host link rules
sudo rm -f /etc/systemd/system/room-sealed-<name>.service && sudo systemctl daemon-reload
sudo rm -rf $SEALED_DIR                                    # images, scratch disk, venv
```

Remove the hotel from the broker config. The apt packages stay.

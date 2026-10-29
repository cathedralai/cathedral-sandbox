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
5. **Check.** Before the restart it refuses to go on while the running guest
   has rooms (`SEALED_RESTART_WITH_ROOMS=1` overrides). It waits for
   `GET /room/attestation` from the guest and compares the measurement in
   the report with the build. On a mismatch it stops and disables the unit,
   points `images/current` back at the previous image and exits 1. A timer
   checks the host link rules every minute and restores them after a
   firewall reload.

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
| Hotel API key | No | Config hotel: fw_cfg. It authenticates the broker. The host gives it, so the host can call the API too; each create, exec, process start, network change and delete gets a receipt. Miner hotel: never from the host (see "Miner hotel") |
| Miner hotel settings (`ROOM_MINER`, TLS port, install signers) | Yes | In the guest `room.env`, and the HTTPS port rule in the guest firewall; only when `SEALED_MINER=1` |
| HOST_DATA | No (host chooses it at launch; the chip signs it and nobody can change it after) | Shared machine: the sha256 of `manifest.json`, so a report names the build it claims. Dedicated machine: also the owner key (see "Dedicated machine") |
| Owner key and manifest digest (dedicated only) | No | fw_cfg. The guest checks them against HOST_DATA and stops if they differ |

## What the host cannot do

- It cannot read room memory or the receipt key. SEV-SNP encrypts guest memory.
- It cannot read room data on disk. The scratch disk is encrypted with a key
  from inside the guest.
- It cannot log in. A production build has no SSH, no console login and no
  getty. `cathedral.debug=1` (a debug build) adds root SSH from the host on
  the tap link, and the measurement shows it.
- It cannot change the guest software without changing the measurement.

What the host of a config hotel can do besides availability (a miner hotel
keeps the key and the traffic from the host; see "Miner hotel"):

- It holds the hotel API key, so it can create rooms, run commands and read
  files through the API. Create, exec, process start, network change, delete
  and bulk delete pass the signing front and get a receipt. File read and
  write, tar, stat, snapshot, fork, wait, process logs and process stop do
  not: the host can read or plant a file in a room with no receipt.
- The broker reaches the API over plain HTTP on the tap link. The host can
  read that traffic (commands, outputs, files) without leaving a receipt.
- On a dedicated machine the host still holds the hotel key, but it cannot
  start a room or an image build that the owner did not sign (see below).

The host still controls availability: it can stop the guest, drop the
network, or refuse the scratch disk.

## Dedicated machine (one owner)

A shared sealed machine keeps the host and Cathedral out; gVisor separates
the customers inside it. A dedicated machine also proves to its one customer
that no other customer's rooms run in it, without trusting Cathedral, the
broker or the host.

Set `SEALED_OWNER_PUBKEY_FILE` in `sealed.env` to a file with the 32 raw bytes
of the owner's Ed25519 public key. The owner keeps the private key.

```
openssl genpkey -algorithm ed25519 -out owner.pem          # the owner, on their side
python3 owner_sign.py --key owner.pem --public --raw-out owner.pub
```

### The trust chain

1. **AMD signs the report.** The verifier checks ARK, ASK, VCEK and the report
   signature, as for any sealed hotel.
2. **MEASUREMENT covers the gate.** `room_receipts.py` is in the measured
   initrd. It is the only listener the host can reach in the guest
   (`sealed-guard.nft` lets in port 18090 on the uplink, and the room API
   listens on 127.0.0.1). Check the measurement with `--expected-measurement`
   against the published build.
3. **HOST_DATA names the owner.** `launch-guest.sh` sets
   `HOST_DATA = sha256("cathedral-dedicated-v1\0" || sha256(manifest.json) || owner key)`
   and puts the key and the manifest digest in fw_cfg
   (`opt/cathedral/owner-pubkey`, `opt/cathedral/manifest-sha256`). At start the
   front recomputes HOST_DATA from those two files and compares it with its
   own report. A mismatch, a key that is not 32 bytes, or a key with no
   manifest digest: the front does not start (`REFUSING TO SERVE` on the guest
   console, the serial log on the host), so the hotel stays down. No key in
   fw_cfg: a shared machine.
4. **Every create is owner-signed.** On a dedicated machine the front refuses
   `POST /v1/sandboxes` and `POST /v1/images/build` (a build runs Dockerfile
   steps in the guest) with 403 `owner_signature_required` or
   `owner_signature_invalid` unless they carry `X-Cathedral-Owner-Timestamp`
   (unix seconds, within 300 s of the guest clock) and
   `X-Cathedral-Owner-Signature` (base64 Ed25519 by the owner key) over
   `"cathedral-owner-<create|build>-v1\n" || timestamp || "\n" || owner_request_sha256`.
   The refused request never reaches the room API. A refused create still
   gets a receipt (status 403).
5. **The binding says so.** It carries `"tenancy": "dedicated"`,
   `owner_ed25519_b64` and `manifest_sha256` (shared machines: `"tenancy": "shared"`),
   so anyone can recompute HOST_DATA from published fields. REPORT_DATA
   commits to the binding as before.
6. **Each create receipt shows the signature.** A create receipt carries
   `owner_request_sha256`, `owner_timestamp` and `owner_signature_b64`.

### What the owner signs

`owner_request_sha256` is the sha256 of the canonical JSON (sorted keys, no
spaces, whole numbers without `.0`) of the create as the hotel receives it,
minus the `broker_batch` label. The broker changes a create on the way:

| Broker change | In the signed document |
|---|---|
| Removes `hotels`, `hotel_labels`, `exclude_hotel_labels`, `sealed`, `placement`, `count` | No (removed first) |
| Sets `network` to `deny_all` when it is missing | Yes, as `deny_all` |
| Adds label `broker_guest: <guest id>` | Yes: the room cannot be moved to another guest's workspaces or secrets |
| Adds label `broker_batch: <random id>` | No (the hotel leaves it out) |
| Rewrites a `<hotel>.<name>` workspace to `<name>` | Yes, as `<name>` |
| Rewrites `template` and `snapshot_id` | Not signable yet: name the image; no snapshot forks |

`owner_sign.py` makes these changes and prints the two headers:

```
python3 owner_sign.py --key owner.pem --guest <broker guest id> --body create.json
curl -H @<(python3 owner_sign.py --key owner.pem --guest acme --body create.json) \
  -H "Authorization: Bearer $KEY" --data @create.json https://<broker>/v1/sandboxes
```

One signature covers every room of a `count` batch (each room gets the same
body) and any repeat of the same create within 300 s.

### The customer's check

```
python3 verify_receipts.py --broker https://<broker> --key-file KEY --hotel <id> \
  --owner-pubkey <base64 key> --expected-measurement <published build> --ark-sha256 <pin>
```

It fails unless the binding says dedicated and names this key, the report's
HOST_DATA equals the recomputed value, and every successful create receipt
carries an owner signature that verifies.

### What the broker or host can and cannot do on a dedicated machine

Cannot:
- Start a room or an image build the owner did not sign. A signature covers
  the image, command, env, resources, network, workspace, labels and count.
- Name another owner without a relaunch. HOST_DATA is fixed at launch; a
  relaunch is a new guest (new memory, new receipt key, new REPORT_ID) whose
  binding names the other key, so the owner's check fails.
- Hide the owner check: a key in fw_cfg that HOST_DATA does not name stops
  the front; no key while HOST_DATA names the owner gives a binding that says
  shared; a changed front changes MEASUREMENT.

Can:
- Replay a signed create within 300 s (the tap link is plain HTTP). The guest
  clock comes from the host, so a host that moves it can replay later too.
  Either way it only starts more copies of a room the owner asked for.
- Run the other room operations with the hotel key: exec, process start,
  files, tar, terminals, network change, snapshot, delete, workspaces and
  secrets are not gated.
- Stop the guest or refuse to route creates (availability).

The broker passes the two headers through on `POST /v1/sandboxes` only.
Image builds through the broker are not signed, so a dedicated machine
refuses them; build elsewhere and push to a registry. The broker's capability
probe (`POST /v1/broker/probe`) is also refused there.

The broker admits the machine only if its HOST_DATA is in `sealed_host_data`
(when that list is set). `install.sh --sealed` prints the value
(`tenancy dedicated host_data <hex>`); add it to the broker config.

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
| `X-Room-Receipt` header on create, exec, process start, network change and delete | The signed receipt, base64url of canonical JSON |
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

Through the broker: `--broker https://<broker> --key-file KEY --hotel <id>`
(`--hotel` has no default). Add `--require-sealed` so a level 1 (unsealed)
binding fails even without `--expected-measurement`. `--sandbox <id>` lists
one room's receipts while the room exists.

It checks the binding digest, REPORT_DATA, that the guest is not a debug
build (`cathedral.debug=1` on the measured command line fails), the AMD chain
(ARK, ASK and VCEK from AMD KDS, RSA-PSS SHA-384; pin the ARK with
`--ark-sha256`, repeated to accept any of several roots, or the KDS answer and the local cache are trusted), the VCEK chip id and TCB extensions, the
report signature (ECDSA P-384), each receipt signature (Ed25519) and the
chain links. It prints the policy timeline of each room
(`policy_timeline`) and checks each policy sha256.

A dedicated machine's create receipts also carry `owner_request_sha256`,
`owner_timestamp` and `owner_signature_b64`; `--owner-pubkey` checks them.

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
- Broker to guest traffic is plain HTTP on the tap on a config hotel (see
  above). A miner hotel serves HTTPS from the guest; the broker pin is still open.
- The verifier has no minimum TCB and does not pin the AMD ARK by default.
- The broker's own records (placement, queue) are not signed.

## Miner hotel

A founding-miner hotel (AB#57) runs on a host the miner controls. The host is
not trusted with the hotel key or with room traffic. `SEALED_MINER=1` in
`sealed.env` builds a guest that keeps both inside:

```
SEALED_MINER=1
SEALED_HOTEL_KEY_INSTALL_SIGNERS="<base64 Ed25519 public key of the control plane install key>"
SEALED_MINER_TLS_PORT=18443      # guest HTTPS port (measured)
SEALED_MINER_PUBLIC_PORT=9443    # host port forwarded to it (not measured)
```

### At boot, inside the guest

1. `guest-boot.sh` does not read a hotel key from fw_cfg. If the host puts
   one there, the guest logs it and ignores it, and `launch-guest.sh` passes
   none. The guest makes a guest-internal API key from its own
   `/dev/urandom`. Only the API, the health service and the reaper inside
   the guest use it. It never leaves the guest.
2. The receipts front makes three things in memory: the receipt key (as
   before), a P-256 TLS key with a self-issued certificate, and an X25519
   install key. The binding names all three, plus the pinned signers:

   | Binding field | Value |
   |---|---|
   | `tls_spki_sha256` | sha256 of the TLS key's DER SubjectPublicKeyInfo |
   | `hotel_key_install_x25519_b64` | the install key |
   | `hotel_key_install_signers_ed25519_b64` | the control plane keys from the measured `room.env` |
   | `hotel_key_source` | `"install"` |

   `REPORT_DATA = sha256(canonical(binding)) || 32 zero bytes`, as before,
   so the AMD-signed report commits to the TLS key and the install key.
3. The front serves every route over HTTPS on `SEALED_MINER_TLS_PORT` with
   that key. Plain HTTP on the tap (`:18090`) serves `GET /room/attestation`
   only. Anything else gets 403 `https_required`, and its body is not read.
   No bearer and no room traffic crosses the tap in the clear.
4. Until a key is installed, every call is 401 and nothing reaches the API.
   After that the front accepts only the installed key. It puts the
   guest-internal key on each call it passes to the API. The internal key is
   not a hotel key on the front.

A new boot, or a restart of the receipts service, makes new keys and a new
binding. The installed key is in memory only, so it is gone too. The control
plane treats that as a new boot: drain, then a fresh join with a new key.

### Join (control plane: polariscomputer #1588)

1. The miner signs an offer with `https://<public ip>:<SEALED_MINER_PUBLIC_PORT>`
   and the `binding_sha256` of this boot.
2. The control plane fetches `GET /room/attestation` over TLS. The peer SPKI
   must equal `binding.tls_spki_sha256`. The report must commit to the
   binding, the AMD chain must verify, and the measurement must be on the
   published list.
3. `GET /room/hotel-key-install-key`, over the same pinned TLS. The guest
   answers `{algorithm, binding_sha256, purpose: "hotel-key-install",
   x25519_public_b64, signature_b64}`, signed by the binding's receipt key
   over the canonical four fields.
4. `POST /room/hotel-key` with:

   ```json
   {"schema": "cathedral_hotel_key_install_v1", "binding_sha256": "<this boot>",
    "hotel_id": "miner-<id>", "key_sha256": "<sha256 of the key>", "issued_at": <unix seconds>,
    "envelope": {"algorithm": "x25519-hkdf-sha256-aes256gcm-v1", "ephemeral_public_b64": "...",
                 "nonce_b64": "...", "ciphertext_b64": "..."},
    "signature_b64": "<Ed25519, a pinned signer, over canonical(request without signature_b64)>"}
   ```

   The envelope uses the Escape plant construction: X25519, then HKDF-SHA256
   with salt = AAD and info = `cathedral.hotel-key-install.v1` || ephemeral
   || recipient, then AES-256-GCM. AAD = `hotel-key-install:<binding_sha256>`.

   The guest refuses the request in these cases:

   | Code | Status | Cause |
   |---|---|---|
   | `install_fields_invalid` | 400 | The field set is not exact |
   | `install_signature_invalid` | 403 | No pinned signer verifies the signature |
   | `install_wrong_binding` | 409 | The request names another boot |
   | `install_not_fresh` | 409 | `issued_at` is more than 900 s old or more than 300 s ahead |
   | `install_replayed` | 409 | `issued_at` is not newer than the last install |
   | `install_envelope_does_not_open` | 400 | Sealed to another key or under another AAD |
   | `install_key_invalid` | 400 | The key is not 32 to 256 of `[A-Za-z0-9_-]` |
   | `install_key_digest_mismatch` | 400 | The key's sha256 is not `key_sha256` |

   The exact request that installed the current key answers 200
   `"unchanged"`, so a retry after a lost answer is safe. A newer install
   replaces the key at once. The answer is `{key_sha256, hotel_id,
   issued_at, status}`. A receipt (`hotel_key_install`) records `key_sha256`
   and the signer, never the key.
5. The control plane joins the broker with the scoped miner enrollment key
   (#365) and the per-hotel key. The broker uses that key as the bearer to
   the guest.

### On the host

`host-net.sh` (run by the unit) adds, in miner mode only:

- a DNAT of `SEALED_MINER_PUBLIC_PORT` on this host's own addresses to the
  guest's HTTPS port;
- a FORWARD accept for new connections to that port;
- the answers on those connections.

Nothing else comes in. The minute timer puts the rules back. The miner must
also do the following:

- Open the public port in any firewall outside this path: a cloud security
  group, a router port-forward, or an nftables forward chain with a drop
  policy.
- Have a public IPv4 address.
- Check from the host itself with `https://<guest ip>:<SEALED_MINER_TLS_PORT>`.
  The host's own connections to its public address are not forwarded.

`install-sealed.sh` cannot count rooms in a running miner guest, because the
host has no key. A restart needs `SEALED_RESTART_WITH_ROOMS=1`, after the
control plane drains the hotel.

A debug build (`SEALED_DEBUG_SSH_PUBKEY`) gives the host root in the guest,
and so the hotel key. The measured command line shows `cathedral.debug=1`,
and #1588 and `verify_receipts.py` refuse it.

### Verify

```
python3 verify_receipts.py --origin https://<public ip>:<port> --require-sealed \
  --expected-measurement <from the build> --ark-sha256 <pin>
```

This makes one TLS connection to the guest, with no reconnect. It fetches the
attestation and the install key, and checks:

- that the TLS peer is the key the binding names;
- that the install key is signed by the binding's receipt key and is the one
  the binding names;
- everything a sealed attestation is checked for.

With a saved attestation, use `--tls-spki-sha256 <peer SPKI sha256>`, or
`--require-tls` to fail a binding that names no TLS key.

### Still open (broker)

- **TLS pin.** The broker must reach miner hotels over HTTPS pinned to the
  attested `tls_spki_sha256`, check it on every connection, refuse `http://`
  miner APIs, and re-admit the hotel when the binding changes. Until then,
  #365 refuses scoped miner joins with `guest_tls_required` before it sends
  the key.
- **Admission checks.** For miner hotels, the broker's admission must require
  `tls_spki_sha256` and `hotel_key_source: "install"`, and pass
  `--tls-spki-sha256 <peer>` to the `amd_verifier` command.
- **`admission_policy`.** The broker must report it in operator capacity
  (#1588 checklist).

## Remove

```
sudo systemctl disable --now room-sealed-<name>-net.timer # or it puts the host link back every minute
sudo systemctl disable --now room-sealed-<name>.service   # stops the guest, removes the host link rules
sudo rm -f /etc/systemd/system/room-sealed-<name>.service /etc/systemd/system/room-sealed-<name>-net.{service,timer}
sudo systemctl daemon-reload
sudo rm -rf $SEALED_DIR                                    # images, scratch disk, venv
```

Remove the hotel from the broker config. The apt packages stay.

# Supply a Cathedral runtime box

From "I have a server" to a box that validators pay for. The design is in
[`CAPACITY.md`](CAPACITY.md) (from #217): the SN94 owner's prober creates sandboxes on your
box each round, checks its CPU and memory with a challenge, and signs receipts that validators
pay by market value. You never talk to validators directly.

## 1. The server

- Linux with KVM (`/dev/kvm`), Ubuntu with kernel 6.8 or later, and a public IPv4 address.
- Bare metal, or a TEE host (Intel TDX or AMD SEV-SNP) for the higher TEE rate.
- At least the smallest consumer shape the current price table lists (for example SN120's);
  a smaller box earns nothing.
- More than 10 GiB of memory per vCPU is proven, and paid, only up to 10 GiB per vCPU.

## 2. Install the runtime

From a machine that can SSH to the server, with a checkout of `cathedralai/runtime`:

```bash
deploy/cathedral/install-runtime-host.sh \
  --bundle "$BUNDLE_URL" --sha256 "$BUNDLE_SHA256" \
  --direct-ip "$PUBLIC_IP" --ssh-from "$YOUR_CIDR" \
  SSH_TARGET
```

The installer checks the host, installs the runtime and its front door (a pinned TLS
certificate on 443 and 8443), builds the templates, and runs the preflight. It leaves two
files in `CATHEDRAL_CREDENTIALS_DIR`:

- `cathedral-runtime-LABEL.values`: the box's host values (front door, certificate pin,
  measured capacity, templates);
- `cathedral-runtime-LABEL.key` (mode 600): the box's runtime API key.

`LABEL` is `CATHEDRAL_HOST_LABEL`, which defaults to the SSH target. Registration needs the
direct front door (`--direct-ip`): a tunnel install has no certificate pin and is refused.

See the runtime's `deploy/cathedral/README.md` for every option.

## 3. Register the box

On a machine holding your miner hotkey (the hotkey stays in your wallet and is never passed
on the command line):

```bash
python -m cathedral.box_registration \
  --host-values cathedral-runtime-LABEL.values \
  --runtime-key-file cathedral-runtime-LABEL.key \
  --prober-key "$SN94_PROBER_X25519_PUBLIC_KEY_HEX" \
  --netuid "$NETUID" --kind bare_metal \
  --wallet-name YOUR_WALLET --hotkey-name YOUR_HOTKEY \
  > registration.json
```

`NETUID` is the subnet the SN94 owner publishes with the prober key.

The registration names your hotkey, the box's front door and certificate pin, its capacity and
templates, and carries the runtime API key **sealed to the prober**: only the prober can open
it, and only for this registration. Your hotkey signs all of it. It is valid for 24 hours by
default (`--valid-hours`, at most 168); register again before it expires, and after the
front door's certificate is renewed (the installer renews it when less than 48 hours of its
7 days remain), since the registration pins the certificate.

**What you hand over.** The key is the runtime's team key for this box; the runtime has no
narrower key yet. Through the front door it reaches only the routes the ingress allowlists
(create, look up, time out and delete sandboxes, snapshots, template builds), but it controls
every sandbox on the box. Run nothing else on a registered box.

**Check the prober key.** Take `--prober-key` only from the SN94 owner's published prober
attestation, whose quote binds that key; a key from anywhere else could hand your box to
someone else.

Use `--kind tee` on a TDX or SEV-SNP host; the prober verifies that claim separately.

## 4. Submit it

Send `registration.json` to the SN94 owner's registration endpoint (published with the prober
key). The prober verifies the signature, opens the key, probes the box through its front door,
and admits it once a probe passes. From then on each round's receipt carries your box's
verified capacity, and validators pay your hotkey its market value.

**One box, one hotkey.** The prober admits each box under one hotkey, keyed on its control
IP. (`box_key` comes from the certificate pin alone, so it names the current certificate and
changes when the certificate is renewed; the IP does not.) The first registration for an IP
whose key opens and passes a probe wins; a later one for the same IP under another hotkey is
refused, and the first hotkey keeps earning. Registering again under the same hotkey, including
after a certificate renewal, keeps the claim; it lapses when its registration expires unrenewed
or its key stops passing the probe. To move a box to another hotkey, let the old registration
expire, then register under the new hotkey.

A second IP doesn't make a second box. The prober also compares the keys it opens and refuses a
registration for another IP whose key it already holds, under any hotkey, yours included, so a
proxy on a second IP forwarding to the same box is refused. It also challenges every admitted
box at the same time, so two registrations served by one box share its CPU and memory and
can't both pass.

The certificate pin and IP are public, so what shows the box is yours is holding its key:
anyone who has it and registers first holds the box. Keep the key file at mode 600 (the command
warns when the group or others can read it). A box-side binding is planned in the runtime: the
installer records your hotkey and the front door serves it over the pinned TLS, so the prober
also checks box to hotkey.

**Replays.** A registration has no nonce, so anyone who saw one could resubmit it while it is
valid, and anyone can sign one naming your box's public IP and certificate pin under their own
hotkey. The endpoint orders registrations by `issued_at` per control IP and hotkey, and counts
one only after its key opens and it passes a probe. It then refuses an older registration from
that hotkey for that IP, or a different one with the same `issued_at`, so an old registration
can't replace your current one. The order is the signed `issued_at`, so a replayed copy ranks
where the original did; keep your clock synchronised, because a registration you date ahead
outranks your own later renewals until real time passes it. A registration under
another hotkey never refuses your renewal, whatever its date: conflicts between hotkeys follow
"One box, one hotkey" above. Each network's prober has its own key, so a registration replayed
to another network's prober doesn't open there.

## Keep it paid

- Keep the box reachable on 443 and 8443 from the prober, and the runtime healthy.
- The prober's sandboxes are ordinary customer-shaped sandboxes: a box that treats them
  differently from customer traffic fails the same checks customers would.
- A failed challenge or a missed deadline earns nothing for that round.
- A registration for a box or IP that another hotkey holds is refused (see "One box, one
  hotkey" above).

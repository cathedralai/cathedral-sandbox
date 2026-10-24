# Mining Cathedral

This is the only miner guide for Bittensor subnet 94 (SN94). Cathedral runs on
SN94; SN39 is legacy. The testnet mirror is netuid 584.

Run an AMD SEV-SNP machine. The Intel TDX path is legacy; it is at the end of
this page. Start at the [repository overview](../README.md). Do the steps in
order.

## How mining works

The Cathedral validator reads serving SN94 miners without validator permits. It
does not download weights from Cathedral and it does not use a weight relay.
SN94 has commit-reveal on, so a weight row appears on chain only after the
reveal delay.

For each UID, the validator:

1. reads the miner's on-chain HTTPS endpoint;
2. verifies fresh evidence and the live TLS key;
3. reads the miner's fleet list through the verified channel;
4. verifies fresh evidence and the live TLS key for each added machine;
5. zeroes every claimant involved in a duplicate endpoint, hardware identity,
   or TLS key;
6. sends one bounded SAT task to each remaining machine; and
7. assigns weight from the verified work those machines returned.

The validator uses zero burn. Registration, uptime, a quote, or a
self-reported machine count earns nothing by itself.

This repository serves SNP evidence and SAT work. The separate
[Cathedral validator](https://github.com/cathedralai/cathedral-validator)
verifies and scores. The retained legacy runtime in this repository is not the
SN94 weight-writing path.

## Pay

You earn SN94 emission (alpha) through validator weights. Weight does not
guarantee emission: the subnet needs positive emission.

## Founding miners

Cathedral admits a small group of operators first. Apply with the
[Founding Miner Application](https://docs.google.com/forms/d/e/1FAIpQLScxnX15Hb70AnkeZcHBI53cv_yN7aen4_h95njQvMzBxBiMpQ/viewform).
Cathedral answers every application within 48 hours.

The application asks for:

- your company, a contact name and role, and a Telegram or Discord handle;
- your machines: how many, where they are, whether you own, colocate or rent
  them, their specs, and whether they are AMD SEV-SNP or Intel TDX capable.
  Attested hardware is required to earn emission;
- your SOC 2 status;
- the capacity you can commit, and your agreement never to access, copy or
  interfere with customer workloads or data.

After Cathedral accepts you, set up each machine with the steps below.

## Current support

| Path | Status | Weight |
|---|---|---|
| AMD SEV-SNP on Linux (EPYC Milan, Genoa, Turin) | SN94 miner path | Eligible after the validator's policy admits the measurement and TCB, then fresh evidence and SAT pass |
| More AMD SEV-SNP machines on one UID | SN94 miner path | Each distinct verified machine adds to that UID's score |
| Intel TDX on Linux | Legacy | Eligible after fresh TDX and SAT verification |

The validator owns its SNP measurement and TCB allowlist. An AMD machine earns
zero until the policy admits its live measurement and TCB. The validator
proves an admitted guest measurement, distinct hardware, the live HTTPS key,
and returned SAT work. It does not remotely attest the OCI image digest or
continuous runtime integrity after boot.

The image page records one testnet 584 admission of an AMD guest, on
2026-10-16. This repository records no SN94 mainnet admission. See
[SN94 AMD SEV-SNP miner image](SN94_SNP_MINER_IMAGE.md).

## What you need

- An AMD EPYC server: Milan, Genoa or Turin, one socket. SEV-SNP is on in the
  BIOS and the kernel. On the host, `/sys/module/kvm_amd/parameters/sev_snp`
  reads `Y` and `/dev/sev` exists.
- An SNP guest on that host with native `/dev/sev-guest`. Ordinary SEV and a
  vTPM are not SNP. Run one SNP guest per physical host.
- In the guest: Git, Python 3.12 with `venv`, Docker, `nft`, and `curl`.
- A public IPv4 address with TCP `8081` open.
- A wallet machine with Bittensor CLI (`btcli`) 11.x, a coldkey with TAO for
  the registration burn, and one public hotkey.
- A control host that you own, with Git and Python 3.12 with `venv`. It signs
  the validator-access snapshot.

Keep the coldkey and wallet off every worker. The worker needs only its public
hotkey. Each machine creates its own TLS private key inside its guest.

The validator requires the `SINGLE_SOCKET` guest policy bit unless its
operator turns the check off. A multi-socket Linux KVM host cannot set it. See
the [socket policy and hardware identity](AMD_SEV_SNP_FRIEND_TEST.md#socket-policy-and-hardware-identity)
notes. They also explain why two guests on one host score zero.

## Rehearse before renting or registering

Run the local rehearsal on any machine with Python 3.11 or newer. It uses a
fresh temporary directory and an OS-assigned loopback port on every run. It
does not open a wallet, query a chain, contact the example fleet IPs, use
Docker, or read a TEE device.

```bash
git clone https://github.com/cathedralai/cathedral-sandbox.git cathedral-rehearsal
cd cathedral-rehearsal
python3 -m venv .venv-rehearsal
.venv-rehearsal/bin/python -m pip install -e .

for run in 1 2 3; do
  .venv-rehearsal/bin/python scripts/rehearse_sn94_miner.py
done
```

Each run must end with `"status": "PASS"`. The script starts the real worker
protocol on loopback with clearly synthetic TDX and SEV-SNP evidence. It checks
the exact invalid-evidence health response, evidence identity and nonce
binding, capabilities, canonical SAT, a primary-plus-secondary fleet, and
duplicate fleet rejection. A pass proves local package and protocol wiring
only. It does not prove hardware, vendor evidence, measurement, TCB, guest
policy, native TLS, signed validator access, public reachability, registration,
weight, or emission.

## Run one AMD SEV-SNP machine

Each step ends with what must be true before the next step. Stop at the first
step that does not hold. See [Stop and get help](#stop-and-get-help).

### 1. Check the hardware

Follow [Check the hardware](SNP_OWN_SERVER_ONBOARDING.md#1-check-the-hardware).

Before step 2: the guest boots with `/dev/sev-guest` readable and writable by
root.

### 2. Prove the hardware

Follow [Prove the hardware](SNP_OWN_SERVER_ONBOARDING.md#2-prove-the-hardware).
The validator operator who will review it supplies the challenge and
watches the run.

Before step 3: the transcript says `LOCAL_PASS`.

### 3. Get admitted

Follow [Get admitted](SNP_OWN_SERVER_ONBOARDING.md#3-get-admitted).

Before step 4: the validator operator confirms that the policy admits your
measurement and TCB. Do not register before this.

### 4. Refresh validator access from a control host

The worker admits any hotkey with a current SN94 validator permit. You create
and keep the small Ed25519 key used to sign that chain snapshot. Cathedral
does not issue a credential and no Cathedral API is involved.

On a separate miner-controlled machine, check out the source revision of your
image. For SNP, take the revision from
[SN94 AMD SEV-SNP miner image](SN94_SNP_MINER_IMAGE.md). This checkout
supplies code only. Ignore its local README and MINING files and keep
following this guide.

```bash
SOURCE_COMMIT='REVISION_FROM_SN94_SNP_MINER_IMAGE_MD'
git clone https://github.com/cathedralai/cathedral-sandbox.git cathedral-access
git -C cathedral-access checkout --detach "$SOURCE_COMMIT"
test "$(git -C cathedral-access rev-parse HEAD)" = "$SOURCE_COMMIT"
test -z "$(git -C cathedral-access status --porcelain)"

python3.12 -m venv cathedral-access/.venv
cathedral-access/.venv/bin/pip install -e \
  'cathedral-access[enrollment-operator]'
install -d -m 0700 cathedral-validator-access-state

cathedral-access/.venv/bin/python \
  cathedral-access/scripts/cathedral_validator_access.py init-key \
  --signing-key-id cathedral-validator-access-1 \
  --signing-key-out cathedral-validator-access-state/snapshot.seed \
  --keys-out cathedral-validator-access-state/snapshot-keys.json

cathedral-access/.venv/bin/python \
  cathedral-access/scripts/cathedral_validator_access.py capture \
  --network finney \
  --netuid 94 \
  --minimum-stake-rao 0 \
  --signing-key-id cathedral-validator-access-1 \
  --signing-key-file cathedral-validator-access-state/snapshot.seed \
  --out cathedral-validator-access-state/validator-access.json \
  --valid-seconds 900
```

The `init-key` command prints `keys_digest sha256:...`. Keep the full value
after `keys_digest`, with `sha256:`, for step 5.

`cathedral-validator-access-state` is beside the Git clone, not inside it.
Keep `snapshot.seed` on this control host. Transfer only
`snapshot-keys.json` and `validator-access.json` to a private staging directory
on each worker. Then install them on that worker:

```bash
sudo install -d -o root -g root -m 0700 \
  /etc/cathedral/validator-access \
  /var/lib/cathedral/validator-access
sudo install -o root -g root -m 0644 \
  /path/to/staging/snapshot-keys.json \
  /etc/cathedral/validator-access/snapshot-keys.json
sudo install -o root -g root -m 0644 \
  /path/to/staging/validator-access.json \
  /etc/cathedral/validator-access/.validator-access.json.new
sudo mv \
  /etc/cathedral/validator-access/.validator-access.json.new \
  /etc/cathedral/validator-access/validator-access.json
```

A snapshot is valid for 900 seconds with the commands above. The maximum is
3600 seconds. A worker refuses a snapshot that was generated more than 3600
seconds ago. An expired snapshot closes protected routes. A failed refresh
leaves the last valid file in place.

Repeat capture, transfer, and the final atomic install every five minutes, or
install the two timers described at the end of this step.

For one machine, install this as
`/etc/cathedral/validator-access/fleet.json` with owner `root`, group `root`,
and mode `0644`:

```json
{
  "schema": "cathedral_worker_fleet_v1",
  "worker_hotkey": "YOUR_PUBLIC_HOTKEY",
  "endpoints": []
}
```

#### Keep the snapshot fresh with two timers

The snapshot proves itself: it carries your signature, so it may cross any
channel, and the seed never has to leave the control host. Two example units in
`examples/systemd` automate the loop above.

- **Control host, `cathedral-validator-access-refresh.timer`**, every two
  minutes. It runs `scripts/cathedral_validator_access.py refresh` as a
  dedicated `cathedral-access` account that owns the seed. Each run signs a
  fresh finalized view and verifies it against `snapshot-keys.json` and its
  pinned digest. It then atomically replaces the published
  `validator-access.json`. The lifetime must be at least 600 seconds.
  `generated_at` is set 30 seconds in the past, so workers still accept it
  when the control host's clock runs up to 30 seconds fast.
- **Each worker, `cathedral-validator-access-fetch.timer`**, every two minutes.
  It runs `scripts/cathedral_validator_access.py fetch` as `root` with no
  capabilities and no Unix-domain sockets. It holds no seed and reads no
  chain. It pulls the published file from an `https://` URL or from a local
  path that your own transfer writes, reading at most 256 KiB. It verifies the
  file against the pinned `snapshot-keys.json` and the configured network,
  subnet, and stake floor. It then installs it as `root:root` mode `0644` by an
  atomic rename. The running worker picks it up without a restart.

Both commands refuse a snapshot for another network, subnet, or stake floor,
an older block, or a changed validator set at the same block. Both leave the
file untouched on any failure.

On the control host, give the seed to the service account, publish the output
directory, and enable the refresh timer. Install the path checker from
[docs/PRIVILEGED_PATHS.md](PRIVILEGED_PATHS.md) and a root-owned checkout
at `/opt/cathedral-validator-access` first, as shown for the worker below, but
with `'/opt/cathedral-validator-access[enrollment-operator]'`. The service
account then holds the only copy of the seed:

```bash
sudo useradd --system --home-dir /var/lib/cathedral-validator-access \
  --shell /usr/sbin/nologin cathedral-access
sudo install -d -o cathedral-access -g cathedral-access -m 0755 \
  /var/lib/cathedral-validator-access \
  /var/lib/cathedral-validator-access/publish
sudo install -d -o cathedral-access -g cathedral-access -m 0700 \
  /var/lib/cathedral-validator-access/signer
sudo install -o cathedral-access -g cathedral-access -m 0600 \
  cathedral-validator-access-state/snapshot.seed \
  /var/lib/cathedral-validator-access/signer/snapshot.seed
sudo install -o cathedral-access -g cathedral-access -m 0644 \
  cathedral-validator-access-state/snapshot-keys.json \
  /var/lib/cathedral-validator-access/snapshot-keys.json
shred --remove cathedral-validator-access-state/snapshot.seed
```

`shred` cannot guarantee erasure on a copy-on-write or flash-backed
filesystem. There, keep `cathedral-validator-access-state` on encrypted
storage. From now on, run any manual `capture` as `cathedral-access` with the
new seed path.

Copy `validator-access-refresh.env.example` to
`/etc/cathedral/validator-access-refresh.env` as `root:root` mode `0600` and
fill it in. Install the refresh service and timer in `/etc/systemd/system`,
run the service once, then enable the timer. Serve
`/var/lib/cathedral-validator-access/publish` over HTTPS, or push its one file
to each worker yourself.

On each worker, install the refresher checkout, the path checker, and the fetch
units. The worker needs only the base package, not the chain client:

```bash
REFRESHER_REVISION='REVISION_FROM_SN94_SNP_MINER_IMAGE_MD'
sudo git clone https://github.com/cathedralai/cathedral-sandbox.git \
  /opt/cathedral-validator-access
sudo git -C /opt/cathedral-validator-access checkout --detach "$REFRESHER_REVISION"
sudo python3.12 -m venv /opt/cathedral-validator-access/.venv
sudo /opt/cathedral-validator-access/.venv/bin/pip install \
  /opt/cathedral-validator-access
sudo install -o root -g root -m 0755 \
  /opt/cathedral-validator-access/cathedral/privileged_paths.py \
  /usr/local/libexec/cathedral-privileged-paths.py

sudo install -o root -g root -m 0600 \
  /opt/cathedral-validator-access/examples/systemd/validator-access-fetch.env.example \
  /etc/cathedral/validator-access-fetch.env
sudoedit /etc/cathedral/validator-access-fetch.env
sudo install -o root -g root -m 0644 \
  /opt/cathedral-validator-access/examples/systemd/cathedral-validator-access-fetch.service \
  /opt/cathedral-validator-access/examples/systemd/cathedral-validator-access-fetch.timer \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start cathedral-validator-access-fetch.service
sudo systemctl enable --now cathedral-validator-access-fetch.timer
```

In both env files, replace the `<NETWORK>` and `<NETUID>` placeholders for
`CATHEDRAL_VALIDATOR_ACCESS_NETWORK` and `CATHEDRAL_VALIDATOR_ACCESS_NETUID`
with the chain network and subnet the worker image checks: `finney` and `94`
for the mainnet images. Neither has a default, and both commands refuse the
placeholders. Set `CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST` to the
`keys_digest` value. On the worker, set `CATHEDRAL_VALIDATOR_ACCESS_SOURCE` to
the published URL or path. A local-path source must be world-readable and
outside `/home`. The fetch service cannot use `nss-resolve`, which needs a
Unix-domain socket. Its lookups therefore go through the classic `dns` module,
so `hosts:` in `/etc/nsswitch.conf` must list `dns`, as in the usual
`files resolve [!UNAVAIL=return] dns`. Otherwise use an IP-literal URL or a
local path. The first `systemctl start` creates `validator-access.json`, so run
it before step 5. The example SNP miner unit in `examples/systemd` already
starts after the fetch service at boot.

Install the alarm hook on the control host and on every worker. This step is
required: without it the alarm is only a journal line. Both units start
`cathedral-validator-access-alert@.service` through `OnFailure=`, and that
template runs `/usr/local/sbin/cathedral-validator-access-page` with the failed
unit's name. Replace the `sendmail` line with your own pager, webhook, or mail
command:

```bash
sudo install -o root -g root -m 0644 \
  /opt/cathedral-validator-access/examples/systemd/cathedral-validator-access-alert@.service \
  /etc/systemd/system/
sudo install -o root -g root -m 0755 /dev/stdin \
  /usr/local/sbin/cathedral-validator-access-page <<'EOF'
#!/bin/sh
printf 'Subject: %s raised the validator-access expiry alarm\n\njournalctl -u %s\n' \
  "$1" "$1" | /usr/sbin/sendmail YOUR_ALERT_ADDRESS
EOF
sudo systemctl daemon-reload
sudo systemctl start cathedral-validator-access-alert@test.service
```

The last command must reach you. Each service logs to the journal. Exit status
1 logs `ERROR validator_access_refresh_failed` or
`ERROR validator_access_fetch_failed`. One run failed, for example because the
chain or source was unreachable. The file still has time left, the next run
retries, and nothing pages. Exit status 3, with
`ERROR validator_access_expiry_alarm`, is the expiry alarm. It fails the unit
and pages. It means the file expires soon, or is missing, expired, bound to
another subnet, or does not verify. On a worker it can fire after a good
fetch, when the control host has stopped publishing newer files.

The default threshold is one third of the snapshot lifetime: 300 seconds for a
900-second snapshot. Raise `CATHEDRAL_VALIDATOR_ACCESS_ALARM_BELOW_SECONDS`
for more warning. At expiry every protected route closes until a fresh
snapshot arrives.

#### Recover from a large clock step

The worker keeps replay records in
`/var/lib/cathedral/validator-access/validator-access.sqlite`. It tolerates a
backward clock step of up to 135 seconds. After a larger step it refuses every
signed request and logs the step size. Correct the host clock first. Then stop
the worker, reset the replay clock with your miner image, and start the worker
again. `REVIEWED_WORKER_IMAGE` is the image reference that you run:

```bash
sudo docker run --rm --pull never --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges=true \
  --mount type=bind,src=/var/lib/cathedral/validator-access,dst=/var/lib/cathedral/validator-access \
  --entrypoint python REVIEWED_WORKER_IMAGE -I -m cathedral.cli \
  worker reset-replay-clock \
  --validator-access-state /var/lib/cathedral/validator-access/validator-access.sqlite
```

The reset refuses while a worker holds the state. It does not lower the replay
floor, so requests can stay refused until `requests_resume_at`. The reset and
the worker print `replay_floor` and `requests_resume_at`. Both reviewed images
include this command.

Before step 5: both timers run, and the worker holds a fresh
`validator-access.json` and the `snapshot-keys.json` that matches your
`keys_digest`.

### 5. Start the miner

Take the image reference from
[SN94 AMD SEV-SNP miner image](SN94_SNP_MINER_IMAGE.md). That file is the only
place that lists the current digest. Do not copy a digest from any other page.
Mainnet images have no suffix. Testnet images end in `-test584`; use them only
on netuid 584.

Follow [Start the miner](AMD_SEV_SNP_FRIEND_TEST.md#start-the-miner). It
installs the root-owned launcher and the systemd unit. The launcher reads
`/etc/cathedral/sn94-snp-miner.env`. Set these four values in that file:

| Variable | Value |
|---|---|
| `SN94_SNP_MINER_IMAGE` | The image reference from the image page |
| `CATHEDRAL_MINER_HOTKEY` | Your public hotkey |
| `CATHEDRAL_PUBLIC_ENDPOINT` | `https://YOUR_PUBLIC_IPV4:8081` |
| `CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST` | The `keys_digest` value from step 4, with `sha256:` |

The worker contains no wallet and no Cathedral API credential.

From a machine outside the guest, prove the TLS worker is reachable before
you pay to register. The SNP worker answers only signed validator requests.
The deliberate unsigned request must return HTTP 401 and the exact safe
error:

```bash
HEALTH_BODY="$(mktemp)"
HEALTH_STATUS="$(curl --insecure --silent --show-error \
  --connect-timeout 5 \
  --output "$HEALTH_BODY" \
  --write-out '%{http_code}' \
  --header 'Content-Type: application/json' \
  --data '{}' \
  https://YOUR_PUBLIC_IPV4:8081/v1/evidence)"
test "$HEALTH_STATUS" = 401
grep -Fx '{"error":"unauthorized"}' "$HEALTH_BODY"
rm -f "$HEALTH_BODY"
```

This proves only that the intended HTTPS worker answers. It does not prove
SEV-SNP, channel binding, SAT, weight, or emission.

Before step 6: the service stays running and the check above passes.

### 6. Register and announce the hotkey

Use the separate wallet machine. Never copy the wallet into the guest.

Registration burns TAO. The cost was 0.0005 TAO on 2026-10-23. Read the live
cost before you register. SN94 is full, so a new UID replaces the lowest
non-immune UID.

Do not register with the SN94 owner coldkey: the owner incentive is burned.
Never use `//Alice` on mainnet.

```bash
btcli subnets register --netuid 94 --network finney \
  -w YOUR_WALLET -H YOUR_HOTKEY

btcli axon set --netuid 94 --network finney \
  -w YOUR_WALLET -H YOUR_HOTKEY \
  --ip YOUR_PUBLIC_IPV4 --port 8081
```

`YOUR_WALLET` is the wallet name that holds your coldkey. `btcli axon set`
records the endpoint on chain. It does not start the server.

Before step 7: the subnet shows your hotkey at that IP and port `8081`.

### 7. Confirm chain state

These read-only `btcli` commands show the assigned miner UID and all
validator weight rows:

```bash
btcli --network finney query uid \
  --netuid 94 --hotkey YOUR_PUBLIC_HOTKEY
btcli --network finney --json query weights --netuid 94
```

After the Cathedral validator submits its weights and the commit-reveal delay
ends, its row must contain your miner UID with a positive fraction.

All of these must also be true:

- the process stays running and logs `cathedral_effective_startup_v1`;
- the access snapshot refreshes before it expires;
- SN94 shows your hotkey at the expected public IP and port `8081`;
- the validator reports fresh SEV-SNP verification, same-SPKI binding, and
  SAT pass;
- the on-chain weight row changes only after the validator submits it.

There is not yet a public validator-result feed for the evidence, SPKI, and
SAT checks. Ask the validator operator for that result. This is an open
self-service gap.

A healthy server is not proof of weight. A weight is not proof of emission.

## Add more machines to one UID

Each additional machine is its own physical host with its own SNP guest. Do
steps 1 to 3 for it. Admit its measurement if that differs from your first
machine.

Use the existing control host to capture a fresh snapshot. Transfer the
existing public-key file and that snapshot to the new guest as described in
step 4. Do not create a second signing key. With the timers, install only the
fetch timer on the new guest, pointed at the same published source. Give the
new guest an empty local `fleet.json`, then do step 5 with the same public
miner hotkey and the new guest's own public endpoint. Each guest keeps its own
access files, replay-state directory, running image, SEV-SNP evidence, and
in-guest TLS key. Do not register a second hotkey or axon for those guests.

Keep the chain axon as the first machine. On that primary only, replace
`/etc/cathedral/validator-access/fleet.json` with the additional origins:

```json
{
  "schema": "cathedral_worker_fleet_v1",
  "worker_hotkey": "YOUR_PUBLIC_HOTKEY",
  "endpoints": [
    "https://SECOND_MACHINE_PUBLIC_IPV4:8081"
  ]
}
```

Save that JSON as `/path/to/staging/fleet.json`, then install it on the primary:

```bash
sudo install -o root -g root -m 0644 \
  /path/to/staging/fleet.json \
  /etc/cathedral/validator-access/.fleet.json.new
sudo mv \
  /etc/cathedral/validator-access/.fleet.json.new \
  /etc/cathedral/validator-access/fleet.json
```

No restart is needed. The running worker checks `fleet.json` on each fleet
request and loads it again when the file changes. It prints
`fleet manifest ... loaded` to stderr when it serves the new list. If the new
file fails a check (symlink, group- or world-writable, wrong owner, over
64 KiB, or bad JSON or fields), the worker keeps serving the last good list and
prints one `WARNING` line for that change. It does the same if the file is
removed. To go back to one machine, write `"endpoints": []`; do not delete the
file. A worker still refuses to start with a bad or missing `fleet.json`.
Add up to 31 secondary origins. Reusing an endpoint, hardware
identity, or TLS key causes every verified claimant in that collision to score
zero for the round.

## Run one Intel TDX machine (legacy)

The Intel TDX path is legacy. New miners use AMD SEV-SNP. Keep these steps for
an existing TDX miner.

This is not yet a one-command unattended installation. You must supply two
ordinary operations pieces outside this repository: a recurring secure
transfer for the signed validator-access snapshot, and a process supervisor
which restarts the fixed root-owned launcher. If you do not have both, stop
before registration. The commands below install and run one foreground worker.

Do the TDX steps below in this order: TDX step 1, step 4 above, TDX step 2.
Then do steps 6 and 7 above. In step 4, set `SOURCE_COMMIT` to the TDX
revision in TDX step 1.

To inspect the published TDX image without starting it:

```bash
TDX_IMAGE='ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:7f32aaa75cf2feecde572ff8c9d9985bb9601871b99d68a25a9148bbc3746b4b'
docker pull --platform linux/amd64 "$TDX_IMAGE"
test "$(docker image inspect "$TDX_IMAGE" --format '{{.Os}}/{{.Architecture}}')" = \
  linux/amd64
test "$(docker image inspect "$TDX_IMAGE" --format \
  '{{index .Config.Labels "org.opencontainers.image.revision"}}')" = \
  a22fb1df124ed3e4414335f109f30624152ff548
test "$(docker image inspect "$TDX_IMAGE" --format \
  '{{index .Config.Labels "org.cathedral.sn94.runtime-contract"}}')" = \
  signed-validator-fleet-v1
```

This check proves only the image metadata in the local Docker store. It does
not start a worker or prove TDX.

### TDX step 1. Check the host

The pinned checkout below supplies reviewed runtime code only. Its local
README and MINING files are older copies of this guide. Keep following this
current GitHub mining guide after the checkout.

```bash
git clone https://github.com/cathedralai/cathedral-sandbox.git cathedral-runtime
git -C cathedral-runtime checkout --detach a22fb1df124ed3e4414335f109f30624152ff548
test "$(git -C cathedral-runtime rev-parse HEAD)" = \
  a22fb1df124ed3e4414335f109f30624152ff548
test -z "$(git -C cathedral-runtime status --porcelain)"

python3.12 -m venv cathedral-runtime/.venv
cathedral-runtime/.venv/bin/pip install -e \
  'cathedral-runtime[validator-access-worker]'
cathedral-runtime/.venv/bin/cathedral census
sudo test -r /sys/kernel/config/tsm/report \
  -a -w /sys/kernel/config/tsm/report

sudo install -d -o root -g root -m 0755 /usr/local/libexec/cathedral
sudo install -o root -g root -m 0755 \
  cathedral-runtime/scripts/run_sn94_signed_fleet_miner.sh \
  /usr/local/libexec/cathedral/run-sn94-miner
printf '%s  %s\n' \
  bad027acb1a46915723fc51ec2fa537bd632148b5715477223e2eddb6ab67c25 \
  /usr/local/libexec/cathedral/run-sn94-miner | sudo sha256sum --check
```

Stop if the census does not report Intel TDX or the TSM report path is not
readable and writable.

### TDX step 2. Start the reviewed image

The TDX image is immutable:

```text
ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:7f32aaa75cf2feecde572ff8c9d9985bb9601871b99d68a25a9148bbc3746b4b
```

```bash
export SN94_AUDIT_MINER_IMAGE='ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:7f32aaa75cf2feecde572ff8c9d9985bb9601871b99d68a25a9148bbc3746b4b'
export CATHEDRAL_MINER_HOTKEY='YOUR_PUBLIC_HOTKEY'
export CATHEDRAL_PUBLIC_ENDPOINT='https://YOUR_PUBLIC_IPV4:8081'
export CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST='PASTE_KEYS_DIGEST_VALUE'

sudo --preserve-env=SN94_AUDIT_MINER_IMAGE,CATHEDRAL_MINER_HOTKEY,CATHEDRAL_PUBLIC_ENDPOINT,CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST \
  /usr/local/libexec/cathedral/run-sn94-miner
```

This image is the current migration bridge. Fleet discovery and non-public
routes require signed validator requests. Fresh evidence and canonical audit
SAT remain public temporarily for compatibility. The worker contains no wallet
and no Cathedral API credential.

From a second terminal, prove the TLS worker is reachable before paying to
register. The deliberate invalid request must return the exact safe error:

```bash
HEALTH_BODY="$(mktemp)"
HEALTH_STATUS="$(curl --insecure --silent --show-error \
  --connect-timeout 5 \
  --output "$HEALTH_BODY" \
  --write-out '%{http_code}' \
  --header 'Content-Type: application/json' \
  --data '{}' \
  https://YOUR_PUBLIC_IPV4:8081/v1/evidence)"
test "$HEALTH_STATUS" = 400
grep -Fx '{"error":"invalid evidence schema"}' "$HEALTH_BODY"
rm -f "$HEALTH_BODY"
```

This proves only that the intended HTTPS worker answers. It does not prove TDX,
channel binding, SAT, weight, or emission.

Register only after this check passes. In step 7, read "SEV-SNP" as "TDX".

## Reference

GPU mining is not qualified. Its development-only contracts and blockers are in
[GPU work](GPU_WORK.md) and [GPU attestation](GPU_ATTESTATION.md), not an alternate
CPU mining installation path.

Start with the [documentation map](README.md). It separates current miner
instructions from protocol, release, product-library, and retained compatibility
material.

## Stop and get help

Stop before registration if a checksum, image label, census result, TEE device
check, exact health response, snapshot refresh, or local rehearsal differs from
this guide. Open a
[cathedral-sandbox issue](https://github.com/cathedralai/cathedral-sandbox/issues)
with the repository commit, image digest, CPU and TEE type, the exact failing
step, and redacted output. Do not paste a coldkey, seed phrase, wallet file,
snapshot signing seed, TLS private key, bearer token, raw attestation report,
or unredacted environment.

License: [MIT](../LICENSE).

# Cathedral Sandbox

**Bittensor SN94**

**Racing to build the fastest sandbox fleet on earth**

**With machines that prove their hardware and work**

[cathedral.computer](https://cathedral.computer/) · [Run a validator](https://github.com/cathedralai/cathedral-validator)

This repository contains the Cathedral compute worker, its Intel TDX verifier,
and the protocol used by validators to test miner machines.

## How mining works

Cathedral's validator reads every serving non-validator miner from SN94. It
does not download weights from Cathedral and it does not use a weight relay.

For each UID, the validator:

1. reads the miner's on-chain HTTPS endpoint;
2. verifies fresh evidence and the live TLS key for a CPU path enabled in that validator release;
3. reads its fleet list through the verified channel;
4. verifies fresh evidence and the live TLS key for each added machine;
5. zeroes every claimant involved in a duplicate endpoint, hardware identity,
   or TLS key;
6. sends one bounded SAT task to each remaining machine; and
7. assigns weight from the verified work those machines returned.

The Cathedral validator uses zero burn. Registration, uptime, a quote, or a
self-reported machine count earns nothing by itself. Weight also does not
guarantee TAO. The subnet must have positive emission.

## Current support

| Path | Status | Weight |
|---|---|---|
| Intel TDX on Linux | Mainnet live testing | Eligible after fresh TDX and SAT verification |
| More Intel TDX machines on one UID | Mainnet live testing | Each distinct verified machine adds to that UID's score |
| AMD SEV-SNP on Linux | Validator path merged, live hardware policy pending | Eligible after that validator's policy admits the measurement and TCB, then fresh evidence and SAT pass |

The current direct validator source supports Intel TDX and AMD SEV-SNP. Each
validator owns its SNP measurement and TCB allowlist. An AMD machine earns zero
from that validator until its live hardware run is admitted by the policy and
fresh evidence and SAT pass. UID30's first live AMD policy still waits for the
friend-hardware run.

For AMD, the validator proves an admitted guest measurement, distinct hardware,
the live HTTPS key, and returned SAT work. It does not remotely attest the OCI
image digest or continuous runtime integrity after boot.

This repository serves SNP evidence and SAT work. The separate
[Cathedral validator](https://github.com/cathedralai/cathedral-validator)
performs the deadline-bounded verification and scoring. The retained legacy
runtime in this repository is not the SN94 weight-writing path.

## What you need

- A Linux Intel TDX confidential VM with `/sys/kernel/config/tsm/report`, or an
  AMD SEV-SNP guest with `/dev/sev-guest`.
- Git, Python 3.12 with `venv`, Docker, `nft`, and `curl` inside the guest.
- A public IPv4 address with TCP `8081` open.
- One public Bittensor hotkey which you will register on Finney SN94 only after
  the worker passes its local startup check.
- Bittensor CLI `11.1.0` on the separate wallet machine.
- The ability to announce that public IP and port `8081` as the hotkey's axon.
- A miner-owned control host which refreshes and delivers the list of current
  validator-permit hotkeys. It also needs Git and Python 3.12 with `venv`.

Keep the coldkey and wallet off every worker. The worker needs only its public
hotkey. Each machine creates its own TLS private key inside its confidential guest.

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

If Docker and registry access are available, inspect the published Intel image
without starting it:

```bash
TDX_IMAGE='ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99'
docker pull --platform linux/amd64 "$TDX_IMAGE"
test "$(docker image inspect "$TDX_IMAGE" --format '{{.Os}}/{{.Architecture}}')" = \
  linux/amd64
test "$(docker image inspect "$TDX_IMAGE" --format \
  '{{index .Config.Labels "org.opencontainers.image.revision"}}')" = \
  78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8
test "$(docker image inspect "$TDX_IMAGE" --format \
  '{{index .Config.Labels "org.cathedral.sn94.runtime-contract"}}')" = \
  signed-validator-fleet-v1

SNP_IMAGE='ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:0dc8db081dc35a993e8d59936c3ad036b39e68da84751282d9bba4ef16db2255'
docker pull --platform linux/amd64 "$SNP_IMAGE"
test "$(docker image inspect "$SNP_IMAGE" --format '{{.Os}}/{{.Architecture}}')" = \
  linux/amd64
test "$(docker image inspect "$SNP_IMAGE" --format \
  '{{index .Config.Labels "org.opencontainers.image.revision"}}')" = \
  8dde6eaca27116eed53386a1fa33ec70b74a01fb
test "$(docker image inspect "$SNP_IMAGE" --format \
  '{{index .Config.Labels "org.cathedral.sn94.runtime-contract"}}')" = \
  snp-signed-validator-fleet-v1
```

These checks prove only the pinned Intel and AMD image metadata in the local
Docker store. They do not start a worker or prove TDX or SEV-SNP. The published
image digest does not receive weight. A machine started from the SNP image
contributes to its UID only when a validator runs the matching contract, admits
the machine's live measurement and TCB, and verifies fresh evidence and SAT.

## Run one AMD SEV-SNP machine

AMD SEV-SNP uses its own fixed image and launcher. It needs native
`/dev/sev-guest`, not ordinary AMD SEV or a vTPM. The validator will count it
only after its configured owner-controlled SNP policy admits the exact
measurement and TCB, then verifies fresh HTTPS-bound evidence and canonical SAT. Follow
[AMD SEV-SNP miner](docs/AMD_SEV_SNP_FRIEND_TEST.md). The published image pin
does not prove that a specific SNP host is online or receiving weight.

The launcher checks the immutable image locally. That image digest is not a
field in the remote SNP report.

## Run one Intel TDX machine

This is not yet a one-command unattended installation. You must supply two
ordinary operations pieces outside this repository: a recurring secure
transfer for the signed validator-access snapshot, and a process supervisor
which restarts the fixed root-owned launcher. If you do not have both, stop
before registration. The commands below install and run one foreground worker.

### 1. Check the host

The pinned checkout below supplies reviewed runtime code only. Its local
README and MINING files predate the direct validator and are obsolete. Keep
following this current GitHub README after the checkout.

```bash
git clone https://github.com/cathedralai/cathedral-sandbox.git cathedral-runtime
git -C cathedral-runtime checkout --detach 78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8
test "$(git -C cathedral-runtime rev-parse HEAD)" = \
  78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8
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

### 2. Refresh validator access from a control host

The worker admits any hotkey with a current SN94 validator permit. You create
and keep the small Ed25519 key used to sign that chain snapshot. Cathedral does
not issue a credential and no Cathedral API is involved.

On a separate miner-controlled machine, use the same exact source revision.
This checkout also supplies code only. Ignore its local README and MINING
files and keep following this current GitHub README.

```bash
git clone https://github.com/cathedralai/cathedral-sandbox.git cathedral-access
git -C cathedral-access checkout --detach 78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8
test "$(git -C cathedral-access rev-parse HEAD)" = \
  78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8
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

Repeat capture, transfer, and the final atomic install every five minutes, or
install the two timers described at the end of this step. A failed refresh
leaves the last valid file in place. An expired snapshot closes protected
routes.

The worker keeps its signed-request replay records in
`/var/lib/cathedral/validator-access/validator-access.sqlite`. While it runs it
holds a lock on `validator-access.sqlite.lock` beside that file. It tolerates a
backward clock step of up to 135 seconds: one request lifetime plus the
allowed validator clock skew. After a larger step it refuses every signed
request and logs the step size. Correct the host clock first. Then stop the
worker, reset the replay clock with the reviewed image, and start the worker
again:

```bash
sudo docker run --rm --pull never --network none --read-only \
  --cap-drop ALL --security-opt no-new-privileges=true \
  --mount type=bind,src=/var/lib/cathedral/validator-access,dst=/var/lib/cathedral/validator-access \
  --entrypoint python REVIEWED_WORKER_IMAGE -I -m cathedral.cli \
  worker reset-replay-clock \
  --validator-access-state /var/lib/cathedral/validator-access/validator-access.sqlite
```

The reset refuses while a worker holds the state. It fixes one thing: a
replay clock high-water that is ahead of the host clock. It does not always
restore service. The worker also keeps a replay floor, the latest expiry of
any replay record it has deleted. Only requests that expire after the floor
are accepted. The reset cannot and must not lower the floor, and it keeps
every replay record, so an accepted request is still refused if it is sent
again. If the clock ran far ahead before it was corrected, the floor can be
far ahead too. Requests then stay refused until about `requests_resume_at`,
which is the floor minus the 120-second maximum request lifetime. The reset
prints `replay_floor` and `requests_resume_at`, and the worker logs both,
at most once a minute, while it refuses. Only images built from a revision
that includes `cathedral worker reset-replay-clock` have this command. The
image pinned in step 3 predates it.

The `init-key` command prints `keys_digest sha256:...`. Keep the value after
`keys_digest` for step 3.

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
an older block, or a changed validator set at the same block. At the same block
they also refuse one that expires sooner than the file it would replace. A
newer block always wins once it verifies, even if it expires sooner. Both leave
the file untouched on any failure. The key and the decision stay yours:
Cathedral still does not issue a credential.

On the control host, give the seed to the service account, publish the output
directory, and enable the refresh timer. Install the path checker from
[docs/PRIVILEGED_PATHS.md](docs/PRIVILEGED_PATHS.md) and a root-owned checkout
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
REFRESHER_REVISION='REVIEWED_REVISION_THAT_SHIPS_THE_REFRESHER'
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
with the chain network and subnet the worker image checks. Neither has a
default, and both commands refuse the placeholders. Set
`CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST` to the `keys_digest` value. On the
worker, set `CATHEDRAL_VALIDATOR_ACCESS_SOURCE` to the published URL or path. A
local-path source must be world-readable and outside `/home`. The fetch service
cannot use `nss-resolve`, which needs a Unix-domain socket. Its lookups
therefore go through the classic `dns` module, so `hosts:` in
`/etc/nsswitch.conf` must list `dns`, as in the usual
`files resolve [!UNAVAIL=return] dns`. Otherwise use an IP-literal URL or a
local path. The first `systemctl start` creates `validator-access.json`, so run
it before step 3. The example SNP miner unit in `examples/systemd` already
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
1 logs an error-priority `ERROR validator_access_refresh_failed` or
`ERROR validator_access_fetch_failed` line. It means one run failed, for
example an unreachable chain or source, or a refused rollback. The file still
has time left and the next run retries. It does not fail the unit and does not
page. Exit status 3, with an `ERROR validator_access_expiry_alarm` line, is the
expiry alarm. It fails the unit and pages. The file's own `expires_at` is less
than the alarm threshold away, or the file is missing, expired, bound to
another subnet, or does not verify. On a worker this can fire after a
successful fetch, when the control host has stopped publishing anything newer.

The default threshold is one third of the snapshot's lifetime, 300 seconds for
a 900-second snapshot. With the two-minute fetch timer, the first alarm leaves
at least about 130 seconds before expiry; raise
`CATHEDRAL_VALIDATOR_ACCESS_ALARM_BELOW_SECONDS` for more. At expiry every
protected route closes until a fresh snapshot arrives.

### 3. Start the reviewed image

The current live-testing image is immutable:

```text
ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99
```

```bash
export SN94_AUDIT_MINER_IMAGE='ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99'
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

### 4. Register and announce the hotkey

Only after the worker stays running and the reachability check passes, use the
separate wallet machine:

```bash
btcli --network finney \
  --wallet YOUR_WALLET \
  --wallet-hotkey YOUR_HOTKEY \
  subnet register --netuid 94

btcli --network finney \
  --wallet YOUR_WALLET \
  --wallet-hotkey YOUR_HOTKEY \
  axon set --netuid 94 --ip YOUR_PUBLIC_IPV4 --port 8081
```

`btcli axon set` records the endpoint on chain. It does not start the server.
Never copy the wallet into the TDX guest.

### 5. Confirm chain state

These read-only Bittensor CLI 11.1.0 commands show the assigned miner UID and
all validator weight rows:

```bash
btcli --network finney query uid \
  --netuid 94 --hotkey YOUR_PUBLIC_HOTKEY
btcli --network finney --json query weights --netuid 94
```

After UID 30 submits and any commit-reveal delay completes, row `"30"` must
contain your miner UID with a positive fraction.

All of these must also be true:

- the process stays running and logs `cathedral_effective_startup_v1`;
- the access snapshot refreshes before its 15-minute expiry;
- SN94 shows your hotkey at the expected public IP and port `8081`;
- a validator reports fresh TDX verification, same-SPKI binding, and SAT pass;
- the on-chain weight row changes only after the validator submits it.

There is not yet a public validator-result feed for the TDX, SPKI, and SAT
checks. Until the private telemetry projection reaches the Cathedral
leaderboard, a miner must ask the validator operator for that final result.
This is an open self-service gap.

A healthy server is not proof of weight. A weight is not proof of emission.

## Add more machines to one UID

On every additional TDX guest, repeat step 1. Use the existing control host to
capture a fresh snapshot, then transfer the existing public-key file and that
snapshot to the new guest as described in step 2. Do not create a second
signing key. With the timers, install only the fetch timer on the new guest,
pointed at the same published source. Give the new guest an empty local
`fleet.json`, then run step 3 and the reachability check with the same public
miner hotkey and the new guest's own public endpoint. Each guest keeps its own access files, replay-state
directory, running image, TDX evidence, and in-guest TLS key. Do not register a
second hotkey or axon for those guests.

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

## AMD SEV-SNP

AMD SEV-SNP is a scored path in the current direct validator source. Each
validator owns its measurement and TCB policy. Start with the hardware proof in
[AMD SEV-SNP miner](docs/AMD_SEV_SNP_FRIEND_TEST.md). Do not register or
announce the hotkey until the local proof passes and the validators you expect
to score the machine confirm their policies admit the observed measurement and
TCB. Registration and admission do not prove a finalized weight row.

## GPU miners

The first planned G4 miner fleet is eight Google Spot `g4-standard-48` VMs,
each with one RTX PRO 6000 Blackwell Server Edition GPU and AMD SEV. G4
Confidential VM support does not extend to the eight-GPU machine shape. See
the [bounded, dry-run fleet plan](docs/G4_FLEET_PLAN.md) and
[G4 operator trust proposal](docs/G4_OPERATOR_TRUST.md). No hardware is rented
by these commands. G4 is a distinct provider-trusted guest path with no CPU
attestation and no private customer work; it cannot use the native TDX command
below. Its explicit `serve-g4` startup and trust requirements are in the
[G4 operator guide](docs/G4_OPERATOR_TRUST.md#start-one-worker).

`cathedral worker serve-gpu` enables authenticated GPU capability listing,
composite evidence collection and fixed CUDA work. It reuses the signed
validator-access snapshot, native TLS key and fleet configuration above. CPU
endpoints retain their existing formats. GPU registration is not verified
admission or an earning claim.

The separate native worker contract requires Intel TDX plus NVIDIA confidential-GPU
evidence. It runs a fixed integer-vector kernel through the CUDA driver on the
exact configured GPU UUID set, with a 30-second child-process deadline and no
CPU fallback. Validators must independently verify both vendor evidence and
the approved worker measurement before trusting completion.

Install this checkout and the signed-access dependency into the worker image:

```sh
python3 -m pip install -e '.[validator-access-worker]'
```

With the real composite collector installed, native CUDA driver present, and
the existing signed-access/TLS files provisioned, launch the explicit posture:

```sh
export CATHEDRAL_GPU_COLLECT_CMD=/opt/cathedral/bin/gpu-collector
cathedral worker serve-gpu \
  --hotkey "$CATHEDRAL_MINER_HOTKEY" --host 0.0.0.0 --port 8081 \
  --gpu-profile-id "$CATHEDRAL_GPU_PROFILE_ID" \
  --gpu-device-uuid "$CATHEDRAL_GPU_UUID" \
  --tls-certificate /run/cathedral/worker.crt \
  --tls-private-key /run/cathedral/worker.key \
  --validator-access-snapshot /etc/cathedral/validator-access/validator-access.json \
  --validator-access-keys /etc/cathedral/validator-access/snapshot-keys.json \
  --validator-access-keys-digest "$CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST" \
  --validator-access-state /var/lib/cathedral/validator-access.sqlite \
  --validator-minimum-stake-rao 0 \
  --validator-network "$CATHEDRAL_NETWORK" --validator-netuid "$CATHEDRAL_NETUID" \
  --public-endpoint "$CATHEDRAL_PUBLIC_ENDPOINT"
```

Repeat `--gpu-device-uuid` for each device. Add `--fleet-manifest` to the same
command for additional machine candidates. The network and subnet must match
the signed access snapshot. A signed validator discovers machines through
`POST /v1/fleet`, reads each machine's declared GPU capability through
`POST /v1/gpu-capabilities` with `{}`, and uses `/v1/gpu-evidence` and
`/v1/gpu-work` for verification. These GPU routes reject unsigned and bearer-only
requests. Capability output says `registered` and `verified: false`; only the
validator can establish qualification.

**Current hardware blocker:** this repository does not yet ship a working
vendor adapter for the native composite collector/verifier contract. The path
above is the installation location for an actual adapter, not a provided
binary. The historical Google Confidential Space implementation in
[PR #42](https://github.com/cathedralai/cathedral-sandbox/pull/42) uses a different
Google token protocol and cannot be installed under that name as a substitute.
Until a matching adapter, signed profile and real hardware run are available,
listing can establish registration but cannot establish GPU qualification.
See [GPU work contract](docs/GPU_WORK.md) and [#73](https://github.com/cathedralai/cathedral-sandbox/issues/73).

## Reference

Start with the [documentation map](docs/README.md). It separates current miner
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

License: [MIT](LICENSE).

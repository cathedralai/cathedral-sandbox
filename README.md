# Cathedral Sandbox

**Bittensor SN39**

**Racing to build the fastest sandbox fleet on earth**

**With machines that prove their hardware and work**

[cathedral.computer](https://cathedral.computer/) · [Run a validator](https://github.com/cathedralai/cathedral-validator)

This repository contains the Cathedral compute worker, its Intel TDX verifier,
and the protocol used by validators to test miner machines.

## How mining works

Cathedral's validator reads every serving non-validator miner from SN39. It
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
| AMD SEV-SNP on Linux | Validator path merged, live hardware policy pending | Eligible after that validator's SNP policy admits fresh evidence and SAT |

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
runtime in this repository is not the SN39 weight-writing path.

## What you need

- A Linux Intel TDX confidential VM with `/sys/kernel/config/tsm/report`, or an
  AMD SEV-SNP guest with `/dev/sev-guest`.
- Git, Python 3.12 with `venv`, Docker, `nft`, and `curl` inside the guest.
- A public IPv4 address with TCP `8081` open.
- One public Bittensor hotkey which you will register on Finney SN39 only after
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
  .venv-rehearsal/bin/python scripts/rehearse_sn39_miner.py
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
  '{{index .Config.Labels "org.cathedral.sn39.runtime-contract"}}')" = \
  signed-validator-fleet-v1

SNP_IMAGE='ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:0dc8db081dc35a993e8d59936c3ad036b39e68da84751282d9bba4ef16db2255'
docker pull --platform linux/amd64 "$SNP_IMAGE"
test "$(docker image inspect "$SNP_IMAGE" --format '{{.Os}}/{{.Architecture}}')" = \
  linux/amd64
test "$(docker image inspect "$SNP_IMAGE" --format \
  '{{index .Config.Labels "org.opencontainers.image.revision"}}')" = \
  8dde6eaca27116eed53386a1fa33ec70b74a01fb
test "$(docker image inspect "$SNP_IMAGE" --format \
  '{{index .Config.Labels "org.cathedral.sn39.runtime-contract"}}')" = \
  snp-signed-validator-fleet-v1
```

These checks prove only the pinned Intel and AMD image metadata in the local
Docker store. They do not start a worker or prove TDX or SEV-SNP. The published
SNP image receives weight only from validators which run the matching contract,
admit its live measurement and TCB, and verify fresh evidence and SAT.

## Run one AMD SEV-SNP machine

AMD SEV-SNP uses its own fixed image and launcher. It needs native
`/dev/sev-guest`, not ordinary AMD SEV or a vTPM. The validator will count it
only after its released SNP policy admits the exact measurement and TCB, then
verifies fresh HTTPS-bound evidence and canonical SAT. Follow
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
  cathedral-runtime/scripts/run_sn39_signed_fleet_miner.sh \
  /usr/local/libexec/cathedral/run-sn39-miner
printf '%s  %s\n' \
  d56a82bb76eb2d976edfcd4574ff6ed19a41532ffa50d01a2411df51a002b615 \
  /usr/local/libexec/cathedral/run-sn39-miner | sudo sha256sum --check
```

Stop if the census does not report Intel TDX or the TSM report path is not
readable and writable.

### 2. Refresh validator access from a control host

The worker admits any hotkey with a current SN39 validator permit. You create
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
  --netuid 39 \
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

Repeat capture, transfer, and the final atomic install every five minutes. A
failed refresh leaves the last valid file in place. An expired snapshot closes
protected routes. The repository does not ship a provider-neutral transfer
service, so use your existing secure provisioning channel.

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

### 3. Start the reviewed image

The current live-testing image is immutable:

```text
ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99
```

```bash
export SN39_AUDIT_MINER_IMAGE='ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99'
export CATHEDRAL_MINER_HOTKEY='YOUR_PUBLIC_HOTKEY'
export CATHEDRAL_PUBLIC_ENDPOINT='https://YOUR_PUBLIC_IPV4:8081'
export CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST='PASTE_KEYS_DIGEST_VALUE'

sudo --preserve-env=SN39_AUDIT_MINER_IMAGE,CATHEDRAL_MINER_HOTKEY,CATHEDRAL_PUBLIC_ENDPOINT,CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST \
  /usr/local/libexec/cathedral/run-sn39-miner
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
  subnet register --netuid 39

btcli --network finney \
  --wallet YOUR_WALLET \
  --wallet-hotkey YOUR_HOTKEY \
  axon set --netuid 39 --ip YOUR_PUBLIC_IPV4 --port 8081
```

`btcli axon set` records the endpoint on chain. It does not start the server.
Never copy the wallet into the TDX guest.

### 5. Confirm chain state

These read-only Bittensor CLI 11.1.0 commands show the assigned miner UID and
all validator weight rows:

```bash
btcli --network finney query uid \
  --netuid 39 --hotkey YOUR_PUBLIC_HOTKEY
btcli --network finney --json query weights --netuid 39
```

After UID 30 submits and any commit-reveal delay completes, row `"30"` must
contain your miner UID with a positive fraction.

All of these must also be true:

- the process stays running and logs `cathedral_effective_startup_v1`;
- the access snapshot refreshes before its 15-minute expiry;
- SN39 shows your hotkey at the expected public IP and port `8081`;
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
signing key. Give the new guest an empty local `fleet.json`, then run step 3 and
the reachability check with the same public miner hotkey and the new guest's
own public endpoint. Each guest keeps its own access files, replay-state
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

Restart the primary worker through your supervisor, or stop its
foreground launcher and rerun step 3. The worker reads `fleet.json` only at
startup. Add up to 31 secondary origins. Reusing an endpoint, hardware
identity, or TLS key causes every verified claimant in that collision to score
zero for the round.

## AMD SEV-SNP

AMD SEV-SNP is a source-ready scored path. It becomes production-eligible only
after a released validator pins this exact contract and its policy admits the
observed measurement and TCB. Start with the hardware proof in
[AMD SEV-SNP miner](docs/AMD_SEV_SNP_FRIEND_TEST.md). Do not register or
announce the hotkey until the matching validator release exists and both local
and validator evidence pass. Neither result proves a finalized weight row.

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

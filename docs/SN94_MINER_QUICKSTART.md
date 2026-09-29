# SN94 miner quickstart

One page, in order, from rented machine to announced SN94 miner: Intel TDX
first, then AMD SEV-SNP. Every value is filled in for Finney subnet 94. The
repository [README](../README.md) stays the reference for why each step exists
and for multi-machine fleets. If this page and the README ever disagree, the
README wins; open an issue.

The chain counts, registration costs and hyperparameters below are observations
at the cited blocks. Recheck them before registration; they are not current
quotes or launch evidence. This guide is the existing SAT lane, not the
[customer sandbox delivery executor](SN94_DELIVERY_CONTRACT.md).

## Status: what works today

- **Miner side: ready.** The pinned images compile Finney netuid 94
  (`cathedral/audit_miner_entrypoint.py`, `VALIDATOR_NETUID = 94`) and every
  command below matches the source revision they were built from.
- **Scoring requires the validator cutover.** No deployed SN94 validator scoring
  Cathedral miners is proved by this source. A miner that finishes this page
  still needs the items in
  [Validator-side dependencies](#validator-side-dependencies-not-live-until-the-validator-cutover)
  to be qualified. This guide does not establish current earnings.
- **Intel TDX needs no per-miner validator action.** A validator checks the
  Intel quote, the live TLS key, and SAT work; it keeps no TDX measurement
  allowlist.
- **AMD SEV-SNP needs each validator to admit your machine by hand.** See
  [AMD SEV-SNP](#amd-sev-snp).

## Pinned values

| Item | Value |
|---|---|
| Network and subnet | `finney`, netuid `94`, validator stake floor `0` |
| Source revision | `a66d7c4ca970487026c130610ee9efefa0416a07` |
| Intel TDX image | `ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:e7f8b1b2d8ffb3f7a3a2f006e39d036c7631ae0fb01e7e30d56f483f25dd8503` |
| AMD SEV-SNP image | `ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:d477a68dffe1213ef31c86248dbc12bd1c10508cf3cf0d591694cff1ce16eda0` |
| TDX launcher SHA-256 | `bad027acb1a46915723fc51ec2fa537bd632148b5715477223e2eddb6ab67c25` |
| SNP launcher SHA-256 | `1c8d17a40fa8cd27cd9ed9c10be3e20f094cc361a7abf2bef1e85faab2941b6f` |

The GHCR package names still say `sn39`. The images inside are the SN94 build:
both carry the OCI revision label `a66d7c4ca970487026c130610ee9efefa0416a07`,
and a worker started from either refuses a validator request that names any
other subnet (`cathedral/validator_access.py`, "validator request subnet does
not match").

## What you need

Three roles. Keep them on separate machines.

1. **Worker.** One of:
   - an Intel TDX confidential VM with `/sys/kernel/config/tsm/report`, whose
     Intel TCB status is `UpToDate` with no advisory IDs for the platform, the
     TDX module, and the quoting enclave. The validator's pinned verifier
     refuses any other status (`cmd/cathedral-tdx-verifier/main.go`,
     `validateCurrentCollateralLevels`). Ask your provider before renting;
   - an AMD SEV-SNP guest, see [AMD SEV-SNP](#amd-sev-snp).

   Inside the guest: systemd, Git, Python 3.12 with `venv`, Docker, `nft`,
   `flock`, and `curl`; a public IPv4 address with inbound TCP `8081` open.
2. **Control host.** Any small Linux machine with systemd, Git, Python 3.12
   with `venv`, and outbound access to the Finney RPC. It reads the chain,
   signs the list of current SN94 validator-permit hotkeys with a key only you
   hold, and publishes that signed file for your workers. No Cathedral API or
   credential is involved.
3. **Wallet machine.** Bittensor CLI `11.1.0`, your coldkey, and the miner
   hotkey. The wallet never goes on the worker or the control host.

Run each machine's commands in one shell session. Set these first on every
machine where a later block uses them:

```bash
SOURCE=a66d7c4ca970487026c130610ee9efefa0416a07
MINER_HOTKEY='YOUR_PUBLIC_MINER_HOTKEY_SS58'
PUBLIC_IPV4='YOUR_WORKER_PUBLIC_IPV4'
```

## Part 1: control host (once)

### 1.1 Install the reviewed code as root-owned files

The refresh service refuses to run code that a non-root user could change, so
the checkout, its virtual environment, and the path checker are root-owned.

```bash
sudo git clone https://github.com/cathedralai/cathedral-sandbox.git \
  /opt/cathedral-validator-access
sudo git -C /opt/cathedral-validator-access checkout --detach "$SOURCE"
test "$(sudo git -C /opt/cathedral-validator-access rev-parse HEAD)" = "$SOURCE"
test -z "$(sudo git -C /opt/cathedral-validator-access status --porcelain)"
sudo python3.12 -m venv /opt/cathedral-validator-access/.venv
sudo /opt/cathedral-validator-access/.venv/bin/pip install \
  '/opt/cathedral-validator-access[enrollment-operator]'
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 \
  /opt/cathedral-validator-access/cathedral/privileged_paths.py \
  /usr/local/libexec/cathedral-privileged-paths.py
```

`enrollment-operator` installs the Bittensor 10 chain client used for the
finalized metagraph read.

### 1.2 Create the snapshot signing key

A dedicated account owns the seed. The seed never leaves this host.

```bash
sudo useradd --system --home-dir /var/lib/cathedral-validator-access \
  --shell /usr/sbin/nologin cathedral-access
sudo install -d -o cathedral-access -g cathedral-access -m 0755 \
  /var/lib/cathedral-validator-access \
  /var/lib/cathedral-validator-access/publish
sudo install -d -o cathedral-access -g cathedral-access -m 0700 \
  /var/lib/cathedral-validator-access/signer
sudo -u cathedral-access /opt/cathedral-validator-access/.venv/bin/python -I \
  /opt/cathedral-validator-access/scripts/cathedral_validator_access.py init-key \
  --signing-key-id cathedral-validator-access-1 \
  --signing-key-out /var/lib/cathedral-validator-access/signer/snapshot.seed \
  --keys-out /var/lib/cathedral-validator-access/snapshot-keys.json
KEYS_DIGEST="sha256:$(sha256sum /var/lib/cathedral-validator-access/snapshot-keys.json | cut -d' ' -f1)"
echo "$KEYS_DIGEST"
```

The `keys_digest` line that `init-key` prints must equal `$KEYS_DIGEST`.
Record it; every worker pins it. `snapshot-keys.json` is public and goes to
every worker.

### 1.3 Refresh the signed snapshot every two minutes

```bash
sudo install -d -o root -g root -m 0755 /etc/cathedral
sudo install -o root -g root -m 0600 /dev/stdin \
  /etc/cathedral/validator-access-refresh.env <<EOF
CATHEDRAL_VALIDATOR_ACCESS_NETUID=94
CATHEDRAL_VALIDATOR_ACCESS_NETWORK=finney
CATHEDRAL_VALIDATOR_ACCESS_MINIMUM_STAKE_RAO=0
CATHEDRAL_VALIDATOR_ACCESS_SIGNING_KEY_ID=cathedral-validator-access-1
CATHEDRAL_VALIDATOR_ACCESS_SIGNING_KEY_FILE=/var/lib/cathedral-validator-access/signer/snapshot.seed
CATHEDRAL_VALIDATOR_ACCESS_KEYS=/var/lib/cathedral-validator-access/snapshot-keys.json
CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST=${KEYS_DIGEST}
CATHEDRAL_VALIDATOR_ACCESS_OUT=/var/lib/cathedral-validator-access/publish/validator-access.json
CATHEDRAL_VALIDATOR_ACCESS_VALID_SECONDS=900
CATHEDRAL_VALIDATOR_ACCESS_ALARM_BELOW_SECONDS=auto
EOF
sudo install -o root -g root -m 0644 \
  /opt/cathedral-validator-access/examples/systemd/cathedral-validator-access-refresh.service \
  /opt/cathedral-validator-access/examples/systemd/cathedral-validator-access-refresh.timer \
  /opt/cathedral-validator-access/examples/systemd/cathedral-validator-access-alert@.service \
  /etc/systemd/system/
```

Install the alarm hook. Replace the `sendmail` line with your own pager,
webhook, or mail command; without a hook the expiry alarm is only a journal
line:

```bash
sudo install -o root -g root -m 0755 /dev/stdin \
  /usr/local/sbin/cathedral-validator-access-page <<'EOF'
#!/bin/sh
printf 'Subject: %s raised the validator-access expiry alarm\n\njournalctl -u %s\n' \
  "$1" "$1" | /usr/sbin/sendmail YOUR_ALERT_ADDRESS
EOF
sudo systemctl daemon-reload
sudo systemctl start cathedral-validator-access-alert@test.service
```

The test alert must reach you. Then run one refresh and enable the timer:

```bash
sudo systemctl start cathedral-validator-access-refresh.service
sudo journalctl -u cathedral-validator-access-refresh.service -n 20 --no-pager
sudo systemctl enable --now cathedral-validator-access-refresh.timer
/opt/cathedral-validator-access/.venv/bin/python -I \
  /opt/cathedral-validator-access/scripts/cathedral_validator_access.py verify \
  --snapshot /var/lib/cathedral-validator-access/publish/validator-access.json \
  --keys /var/lib/cathedral-validator-access/snapshot-keys.json \
  --keys-digest "$KEYS_DIGEST" \
  --network finney --netuid 94 --minimum-stake-rao 0
```

The journal must show `outcome installed`, and `verify` must print
`qualified_validators` with the number of current SN94 validator permits
(13 at block 9171839). `systemctl start` succeeds even when a refresh fails,
because exit 1 means "retry next run", so always read the journal.

### 1.4 Publish the snapshot to your workers

The file is signed, so any transport works. Pick one:

- **HTTPS pull.** Serve `/var/lib/cathedral-validator-access/publish` from an
  HTTPS server whose certificate a stock Python trusts. The worker's source is
  then `https://YOUR_HOST/validator-access.json`. It must answer `200`, stay
  under 256 KiB, and redirect only to `https://`.
- **Push.** After each refresh, copy the file to each worker at an absolute
  path outside `/home`, readable by everyone, for example
  `/var/lib/cathedral-validator-access-inbox/validator-access.json`. The
  worker's source is then that path.

Each worker sets this source as `SNAPSHOT_SOURCE` in step 2.3.

## Part 2: Intel TDX worker

### 2.1 Check the guest and install the reviewed code

```bash
sudo git clone https://github.com/cathedralai/cathedral-sandbox.git \
  /opt/cathedral-validator-access
sudo git -C /opt/cathedral-validator-access checkout --detach "$SOURCE"
test "$(sudo git -C /opt/cathedral-validator-access rev-parse HEAD)" = "$SOURCE"
test -z "$(sudo git -C /opt/cathedral-validator-access status --porcelain)"
sudo python3.12 -m venv /opt/cathedral-validator-access/.venv
sudo /opt/cathedral-validator-access/.venv/bin/pip install \
  /opt/cathedral-validator-access
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0755 \
  /opt/cathedral-validator-access/cathedral/privileged_paths.py \
  /usr/local/libexec/cathedral-privileged-paths.py
/opt/cathedral-validator-access/.venv/bin/cathedral census --json | grep -F '"tdx": true'
sudo test -r /sys/kernel/config/tsm/report -a -w /sys/kernel/config/tsm/report
sudo sh -c 'for tool in docker nft flock curl; do command -v "$tool" || echo "MISSING $tool"; done'
```

Stop if the census does not print `"tdx": true`, the TSM check fails, or a
tool is missing.

### 2.2 Install the fixed launcher

```bash
sudo install -d -o root -g root -m 0755 /usr/local/libexec/cathedral
sudo install -o root -g root -m 0755 \
  /opt/cathedral-validator-access/scripts/run_sn94_signed_fleet_miner.sh \
  /usr/local/libexec/cathedral/run-sn94-miner
printf '%s  %s\n' \
  bad027acb1a46915723fc51ec2fa537bd632148b5715477223e2eddb6ab67c25 \
  /usr/local/libexec/cathedral/run-sn94-miner | sudo sha256sum --check
```

### 2.3 Install validator access

Copy `snapshot-keys.json` from the control host to this worker. Set
`KEYS_DIGEST` to the value from step 1.2 and `SNAPSHOT_SOURCE` to the source
from step 1.4, then install:

```bash
KEYS_DIGEST='sha256:PASTE_THE_KEYS_DIGEST_FROM_STEP_1_2'
SNAPSHOT_SOURCE='https://YOUR_HOST/validator-access.json'
sudo install -d -o root -g root -m 0700 \
  /etc/cathedral/validator-access \
  /var/lib/cathedral/validator-access
sudo install -o root -g root -m 0644 \
  /path/to/copied/snapshot-keys.json \
  /etc/cathedral/validator-access/snapshot-keys.json
test "sha256:$(sudo sha256sum /etc/cathedral/validator-access/snapshot-keys.json | cut -d' ' -f1)" = "$KEYS_DIGEST"
sudo install -o root -g root -m 0600 /dev/stdin \
  /etc/cathedral/validator-access-fetch.env <<EOF
CATHEDRAL_VALIDATOR_ACCESS_SOURCE=${SNAPSHOT_SOURCE}
CATHEDRAL_VALIDATOR_ACCESS_NETUID=94
CATHEDRAL_VALIDATOR_ACCESS_NETWORK=finney
CATHEDRAL_VALIDATOR_ACCESS_MINIMUM_STAKE_RAO=0
CATHEDRAL_VALIDATOR_ACCESS_KEYS=/etc/cathedral/validator-access/snapshot-keys.json
CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST=${KEYS_DIGEST}
CATHEDRAL_VALIDATOR_ACCESS_OUT=/etc/cathedral/validator-access/validator-access.json
CATHEDRAL_VALIDATOR_ACCESS_ALARM_BELOW_SECONDS=auto
EOF
sudo install -o root -g root -m 0644 \
  /opt/cathedral-validator-access/examples/systemd/cathedral-validator-access-fetch.service \
  /opt/cathedral-validator-access/examples/systemd/cathedral-validator-access-fetch.timer \
  /opt/cathedral-validator-access/examples/systemd/cathedral-validator-access-alert@.service \
  /etc/systemd/system/
```

Install the same alarm hook as step 1.3 on this worker, then fetch once and
enable the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl start cathedral-validator-access-fetch.service
sudo journalctl -u cathedral-validator-access-fetch.service -n 20 --no-pager
sudo test -f /etc/cathedral/validator-access/validator-access.json
sudo systemctl enable --now cathedral-validator-access-fetch.timer
```

The journal must show `outcome installed`. The fetch service reaches the
network without `nss-resolve`, so for an `https://` source with a host name,
`hosts:` in `/etc/nsswitch.conf` must list `dns`, as in
`files resolve [!UNAVAIL=return] dns`.

Declare this machine as a one-machine fleet:

```bash
sudo install -o root -g root -m 0644 /dev/stdin \
  /etc/cathedral/validator-access/fleet.json <<EOF
{
  "schema": "cathedral_worker_fleet_v1",
  "worker_hotkey": "${MINER_HOTKEY}",
  "endpoints": []
}
EOF
```

### 2.4 Start the miner under systemd

```bash
sudo install -o root -g root -m 0600 /dev/stdin \
  /etc/cathedral/sn94-tdx-miner.env <<EOF
SN94_AUDIT_MINER_IMAGE=ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:e7f8b1b2d8ffb3f7a3a2f006e39d036c7631ae0fb01e7e30d56f483f25dd8503
CATHEDRAL_MINER_HOTKEY=${MINER_HOTKEY}
CATHEDRAL_PUBLIC_ENDPOINT=https://${PUBLIC_IPV4}:8081
CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST=${KEYS_DIGEST}
EOF
sudo install -o root -g root -m 0644 /dev/stdin \
  /etc/systemd/system/cathedral-sn94-tdx-miner.service <<'EOF'
[Unit]
Description=Cathedral SN94 Intel TDX miner
After=network-online.target docker.service cathedral-validator-access-fetch.service
Wants=network-online.target docker.service cathedral-validator-access-fetch.service
ConditionPathIsDirectory=/sys/kernel/config/tsm/report
ConditionPathExists=/etc/cathedral/sn94-tdx-miner.env
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/cathedral/sn94-tdx-miner.env
ExecStart=/usr/local/libexec/cathedral/run-sn94-miner
Restart=always
RestartSec=15s
SuccessExitStatus=129 130 143
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=/etc/cathedral/validator-access
ReadWritePaths=/var/lib/cathedral/validator-access /run
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now cathedral-sn94-tdx-miner.service
sudo journalctl -u cathedral-sn94-tdx-miner.service -n 50 --no-pager
```

This unit is the repository's SNP miner unit with the TDX launcher, env file,
and TSM condition in place of the SNP ones. It takes `Restart=always` from the
repository's TDX audit-miner unit, whose notes record that the launcher exits
143 after a Docker daemon restart; `Restart=on-failure` would treat that as
success and leave the miner stopped. The first start pulls the image, so give
it a minute. The journal must then show one `cathedral_effective_startup_v1`
line with `"tee": "tdx"` and `"signed_validator_access": true`.

### 2.5 Prove the worker is reachable

From another machine, such as the control host:

```bash
HEALTH_BODY="$(mktemp)"
HEALTH_STATUS="$(curl --insecure --silent --show-error \
  --connect-timeout 5 \
  --output "$HEALTH_BODY" \
  --write-out '%{http_code}' \
  --header 'Content-Type: application/json' \
  --data '{}' \
  "https://${PUBLIC_IPV4}:8081/v1/evidence")"
test "$HEALTH_STATUS" = 400
grep -Fx '{"error":"invalid evidence schema"}' "$HEALTH_BODY"
rm -f "$HEALTH_BODY"
```

This proves only that the HTTPS worker answers. It does not prove TDX, SAT,
weight, or emission.

## Part 3: register and announce (wallet machine)

Register only after the reachability check passes and you recheck current
registration cost, occupied UIDs and immunity on the chain. The prior handoff
recorded 256 occupied UIDs and 5000 immunity blocks; those are historical
observations, not this run's verified current parameters.

```bash
btcli --network finney subnets burn-cost 94
btcli --network finney \
  --wallet YOUR_WALLET \
  --wallet-hotkey YOUR_HOTKEY \
  subnet register --netuid 94
btcli --network finney \
  --wallet YOUR_WALLET \
  --wallet-hotkey YOUR_HOTKEY \
  axon set --netuid 94 --ip YOUR_WORKER_PUBLIC_IPV4 --port 8081
```

The burn was `τ0.0005` at block 9171836, fully burned (collateral lock share
`0`). `axon set` is signed by the hotkey and only records the endpoint on
chain. Announce exactly the IPv4 and port in `CATHEDRAL_PUBLIC_ENDPOINT`: a
validator treats the chain axon as your primary machine.

## Part 4: confirm

```bash
btcli --network finney query uid --netuid 94 --hotkey YOUR_PUBLIC_MINER_HOTKEY
btcli --network finney --json query metagraph --netuid 94 | python3 -c '
import ipaddress, json, sys
d = json.load(sys.stdin); hotkey = sys.argv[1]
uid = d["hotkeys"].index(hotkey); a = d["axons"][uid]
print(uid, ipaddress.ip_address(a["ip"]), a["port"])' YOUR_PUBLIC_MINER_HOTKEY
btcli --network finney --json query weights --netuid 94 | python3 -c '
import json, sys
uid = sys.argv[1]
for validator, row in json.load(sys.stdin).items():
    if uid in row:
        print("validator", validator, "weight", row[uid])' YOUR_UID
```

The second command must print your UID, your public IPv4, and `8081`. The third
prints nothing until a validator scores you. The prior handoff recorded
commit-reveal with a one-epoch delay. Recheck the current settings; a row
changes only after the applicable reveal completes. There is no public validator-result
feed yet; ask the validator operator for your machine's result.

## What you see before the cutover

- The worker logs its startup line and then nothing. It does not log requests
  (`cathedral/worker.py`, `log_message`).
- Connection counters show traffic on port 8081:
  `sudo nft list table inet cathedral_sn94` (SNP: `cathedral_sn94_snp`).
- No weight row names your UID.
- A validator still running the SN39 build never reads SN94, so it never
  contacts an SN94-only miner. If you point an SN39 axon at this worker, every
  request from that validator gets HTTP 401: the request names netuid 39, and
  its hotkey is not in your SN94 snapshot. Do not move an earning SN39 miner to
  these images before the cutover.

## AMD SEV-SNP

Same control host, same Part 3 and Part 4. The worker differs, and admission
is manual.

### Hardware the verifier accepts

- Native `/dev/sev-guest` in the guest; not plain SEV, not a vTPM or paravisor.
- AMD report versions 3, 4, or 5; Milan, Genoa-family, or Turin.
- VMPL 0, debug off, migration agent off, CHIP_ID not masked, and a
  VCEK-signed report (`cathedral/verify/snp.py`). VLEK-signed reports are
  refused.
- **Single socket.** A validator requires the guest's SINGLE_SOCKET policy bit
  (bit 20) unless its operator sets `require_single_socket` to `false` for all
  SNP miners at once. KVM cannot set that bit on a host with more than one
  populated socket, so a dual-socket host needs that validator-wide decision.
- One SNP guest per physical host. Every guest on a host reports the same
  CHIP_ID, and a validator zeroes every machine that shares one.

### S1. Prove the hardware

Inside the guest, as a normal user:

```bash
git clone https://github.com/cathedralai/cathedral-sandbox.git cathedral-snp-proof
cd cathedral-snp-proof
git checkout --detach "$SOURCE"
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
git diff --exit-code
SNP_GUEST_DOWNLOAD="$(mktemp /tmp/cathedral-snpguest-download.XXXXXXXX)"
curl --fail --location \
  https://github.com/virtee/snpguest/releases/download/v0.10.0/snpguest \
  --output "$SNP_GUEST_DOWNLOAD"
printf '%s  %s\n' \
  70e700465e3523e67dd5104583dc36cd11eef630c6f04c5b9ccafd6ba2e76ca0 \
  "$SNP_GUEST_DOWNLOAD" | sha256sum --check -
chmod 0500 "$SNP_GUEST_DOWNLOAD"
test -r /dev/sev-guest -a -w /dev/sev-guest
TRANSCRIPT_PATH="/tmp/amd-sev-snp-transcript-$(date -u +%Y%m%dT%H%M%SZ).json"
REVIEW_CHALLENGE='PASTE_64_HEX_CHALLENGE_FROM_THE_VALIDATOR_OPERATOR'
CATHEDRAL_SNPGUEST="$SNP_GUEST_DOWNLOAD" \
  .venv/bin/cathedral-snp-friend-probe \
  --challenge "$REVIEW_CHALLENGE" \
  --output "$TRANSCRIPT_PATH"
python3 -c 'import json, sys
report = json.load(open(sys.argv[1]))["report"]
print("SINGLE_SOCKET", bool(int(report["guest_policy_hex"], 16) & (1 << 20)))' "$TRANSCRIPT_PATH"
```

The probe must write a transcript with `"status": "LOCAL_PASS"`. Run it once
per challenge: it contacts AMD KDS, and fast retries risk rate limiting. The
last command must print `SINGLE_SOCKET True`, unless every validator you
expect to score you has set `require_single_socket` to `false`. Details:
[AMD SEV-SNP miner](AMD_SEV_SNP_FRIEND_TEST.md).

### S2. Ask each validator operator to admit the machine

This is manual. Send each operator you expect to score you the transcript, your
processor generation, and your host facts (EPYC model, socket count, SEV
firmware, host kernel, QEMU and OVMF). Each adds your measurement and a TCB
floor to their own SNP policy. That floor applies to the current, reported,
committed, and launch TCB, component by component. The transcript at this
revision carries only the reported TCB; draft
[#222](https://github.com/cathedralai/cathedral-sandbox/pull/222) adds all
four values and the ready-made policy entry. Do not register until the
operators confirm.

### S3. Run the SNP worker

Do Part 2 steps 2.1 and 2.3 on the SNP guest, with two changes in 2.1: the
census must print `"sev_snp": true` instead of `"tdx": true`, and the device
check is `sudo test -c /dev/sev-guest -a -r /dev/sev-guest -a -w /dev/sev-guest`
instead of the TSM check. Then install the SNP launcher and start it:

```bash
sudo install -o root -g root -m 0700 \
  /opt/cathedral-validator-access/scripts/run_sn94_snp_miner.sh \
  /usr/local/sbin/cathedral-run-sn94-snp-miner
printf '%s  %s\n' \
  1c8d17a40fa8cd27cd9ed9c10be3e20f094cc361a7abf2bef1e85faab2941b6f \
  /usr/local/sbin/cathedral-run-sn94-snp-miner | sudo sha256sum --check
sudo install -o root -g root -m 0600 /dev/stdin \
  /etc/cathedral/sn94-snp-miner.env <<EOF
SN94_SNP_MINER_IMAGE=ghcr.io/cathedralai/cathedral-sn39-snp-miner@sha256:d477a68dffe1213ef31c86248dbc12bd1c10508cf3cf0d591694cff1ce16eda0
CATHEDRAL_MINER_HOTKEY=${MINER_HOTKEY}
CATHEDRAL_PUBLIC_ENDPOINT=https://${PUBLIC_IPV4}:8081
CATHEDRAL_VALIDATOR_ACCESS_KEYS_DIGEST=${KEYS_DIGEST}
EOF
sudo install -o root -g root -m 0644 /dev/stdin \
  /etc/systemd/system/cathedral-sn94-snp-miner.service <<'EOF'
[Unit]
Description=Cathedral SN94 AMD SEV-SNP miner
After=network-online.target docker.service cathedral-validator-access-fetch.service
Wants=network-online.target docker.service cathedral-validator-access-fetch.service
ConditionPathExists=/dev/sev-guest
ConditionPathExists=/etc/cathedral/sn94-snp-miner.env
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=/etc/cathedral/sn94-snp-miner.env
ExecStart=/usr/local/sbin/cathedral-run-sn94-snp-miner
Restart=always
RestartSec=15s
SuccessExitStatus=129 130 143
TimeoutStopSec=30s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadOnlyPaths=/etc/cathedral/validator-access
ReadWritePaths=/var/lib/cathedral/validator-access /run
LockPersonality=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now cathedral-sn94-snp-miner.service
sudo journalctl -u cathedral-sn94-snp-miner.service -n 50 --no-pager
```

Write the env file as shown. The `sn94-snp-miner.env.example` file at this
source revision still names an older image.

The SNP worker requires a validator signature on every route, so its
reachability check expects `401`:

```bash
HEALTH_BODY="$(mktemp)"
HEALTH_STATUS="$(curl --insecure --silent --show-error \
  --connect-timeout 5 \
  --output "$HEALTH_BODY" \
  --write-out '%{http_code}' \
  --header 'Content-Type: application/json' \
  --data '{}' \
  "https://${PUBLIC_IPV4}:8081/v1/evidence")"
test "$HEALTH_STATUS" = 401
grep -Fx '{"error":"unauthorized"}' "$HEALTH_BODY"
rm -f "$HEALTH_BODY"
```

Then register and confirm as in Parts 3 and 4, after the validator operators
confirm admission.

## Validator-side dependencies (not live until the validator cutover)

None of these is a miner action. Until all hold for a validator, it cannot
score you.

1. **An SN94 validator release.** The published validator release channel
   was recorded as the SN39 build (commit `1ab0530`) in the reviewed handoff.
   Inspect the signed channel at installation. A signed release built for
   netuid 94 must be published and installed.
2. **Weight writes under the current chain policy.** The handoff recorded
   commit-reveal enabled. Verify the current policy and qualify a writer that
   supports it.
3. **A registered validator with a permit.** The Cathedral validator's hotkey
   must be registered on SN94 and hold a validator permit, or your snapshot
   will not list it and your worker refuses its requests.
4. **Consensus and emissions.** A positive submitted weight alone does not
   prove emission. Inspect finalized consensus and actual miner emissions
   after the applicable reveal and epoch boundaries.
5. **SNP only: admission.** Each validator adds each SNP measurement and TCB
   floor to its own policy by hand. Setting `require_single_socket` to `false`
   through validator setup needs a newer signed validator bootstrap.

When 1 to 4 hold, a TDX miner that followed this page needs no change: the
refresh and fetch timers pick up the validator's permit within a few minutes.

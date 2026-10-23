# Cathedral Sandbox

This repository is for miners on Cathedral, Bittensor subnet 94 (SN94).
Cathedral runs on SN94; SN39 is legacy. The testnet mirror is netuid 584.
For validator operators, use
[Cathedral Validator](https://github.com/cathedralai/cathedral-validator).

Miners run AMD SEV-SNP machines. The Cathedral validator checks each machine's
hardware evidence, runs a bounded SAT task on it, and scores the result.
This mining path is not a customer sandbox API.

## Current support

| Machine | Status |
|---|---|
| AMD SEV-SNP guest (EPYC Milan, Genoa or Turin; one socket) | The SN94 miner path. The validator must admit your measurement and TCB. This repository records no SN94 mainnet admission. |
| More machines on one UID | Each must pass verification. Duplicate hardware scores zero. |
| Intel TDX confidential VM | Legacy. The steps are at the end of the [mining guide](docs/MINING.md#run-one-intel-tdx-machine-legacy). |
| GPU | Not a qualified mining path. See the [development contract](docs/GPU_WORK.md). |

A machine quote does not remotely prove its container image digest or
continuous runtime integrity after boot. See the
[mining guide](docs/MINING.md#current-support) for the evidence boundary.

## What you need

- An AMD EPYC server with SEV-SNP on in the BIOS and the kernel. On the host,
  `kvm_amd` reports `sev_snp=Y` and `/dev/sev` exists.
- One SNP guest on that host with `/dev/sev-guest`. Ordinary SEV and a vTPM are
  not SNP.
- Python 3.12 with `venv`, Git, Docker, `nft`, and `curl` inside the guest.
- Public IPv4 and inbound TCP `8081`.
- A control host that you own, with Python 3.12 and Git, to sign
  validator-access snapshots.
- A wallet machine with `btcli` 11.x, a coldkey with TAO for the registration
  burn, and a public hotkey.

Keep the coldkey and wallet off every worker. Workers need only the public
hotkey. Each worker creates its own TLS private key inside its guest.

## Start

Follow the [mining guide](docs/MINING.md) in order:

1. [Rehearse locally](docs/MINING.md#rehearse-before-renting-or-registering)
   three times. Python 3.11+ is enough. The rehearsal uses synthetic evidence.
   It proves protocol wiring, not hardware.
2. [Run one AMD SEV-SNP machine](docs/MINING.md#run-one-amd-sev-snp-machine):
   check and prove the hardware, get admitted, set up validator access, start
   the miner, register, and confirm.
3. [Add more machines](docs/MINING.md#add-more-machines-to-one-uid) to the same
   UID. Reuse the signer, not a second hotkey or a second signing key.

This is not a one-command unattended install. You need a recurring secure
snapshot delivery and a process supervisor. Stop before registration if either
is missing.

## Pay

See [Pay](docs/MINING.md#pay) in the mining guide.

## Verify

A rehearsal pass, an image digest, or a health response is not evidence of
admission, weight, or earnings. Follow
[Confirm chain state](docs/MINING.md#7-confirm-chain-state) to check your
registration and the validator's weight row.

## Stop and get help

Stop if a checksum, image label, device check, health response, snapshot
refresh, or rehearsal differs from the guide. Open an
[issue](https://github.com/cathedralai/cathedral-sandbox/issues) with the
repository commit, image digest, CPU and TEE type, failing step, and redacted
output. Do not paste a coldkey, seed phrase, wallet file, snapshot signing
seed, TLS private key, bearer token, raw attestation report, or unredacted
environment.

More help is in the
[mining guide](docs/MINING.md#stop-and-get-help). Protocol and development
references are in the [documentation map](docs/README.md).

License: [MIT](LICENSE).

# Eight-GPU Spot fleet plan

First target: eight NVIDIA RTX PRO 6000 Blackwell Server Edition GPUs under one
miner hotkey, supplied as **eight single-GPU `g4-standard-48` Spot VMs**.
Each device has 96 GB of GPU memory. They serve independent jobs; this is not
one shared-memory or NVLink-connected training machine.

Google currently supports Confidential VM only on the one-GPU G4 shape.
The eight-GPU `g4-standard-384` is not an equivalent confidential configuration.
G4 uses AMD SEV. This does not establish a TDX or SEV-SNP guest quote, and this
track does not independently attest the G4 CPU host.

Sources: [G4 configurations](https://docs.cloud.google.com/compute/docs/accelerator-optimized-machines#g4_vms),
[confidential GPU setup](https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/create-a-confidential-vm-instance-with-gpu).

## Generate a plan without renting hardware

```sh
python3 scripts/plan_g4_miner_fleet.py \
  --project YOUR_PROJECT \
  --zone YOUR_SUPPORTED_ZONE \
  --prefix YOUR_MINER_PREFIX \
  --boot-image projects/YOUR_PROJECT/global/images/YOUR_REVIEWED_IMAGE \
  --network projects/YOUR_PROJECT/global/networks/YOUR_MINER_NETWORK \
  --max-run-hours 1 > g4-fleet-plan.json
```

This script only writes JSON. It does not authenticate to Google, create VMs,
register a miner or enable rewards. The eight `instances` objects are Google
Compute instance request bodies for the selected project and zone.

The plan enables SEV and Secure Boot, selects Spot explicitly, requests automatic
boot-disk deletion and VM deletion at the bounded run duration, and attaches no
guest service account. It never falls back to on-demand or automatically
replaces an interrupted instance. The required image is an explicit image
resource, not a moving image family. Its contents must include the reviewed GPU
worker, compatible driver and NVIDIA verifier installation.

The chosen network still needs a firewall rule for authenticated validator TLS
traffic to the worker port. Project-wide SSH keys are blocked. An approved
operator must configure any administrative access deliberately and retain
control of the guest and its per-instance signing key. Do not distribute a
shared image-baked private key to miners.

## Cost and qualification

An hour-long plan bounds this attempt to eight GPU-hours, subject to the
provider's lifecycle behavior. It is **not a dollar quote or billing proof**.
Obtain current Spot VM, disk, external-IP, confidential-computing and NVIDIA
license prices for the selected zone before applying it. GPU availability and
quota also need a fresh provider check. Unused capacity has no promised earnings.

Each replacement VM requires a new approved instance binding and fresh GPU
admission. A complete miner fleet requires eight distinct accepted devices;
missing, duplicate or substituted devices cannot receive full-fleet credit.
The operator-trusted G4 profile is separate from native TDX composite evidence
and from private-customer routing.

Code acceptance is hardware-free:

```sh
python3 -m pytest -q tests/test_g4_fleet_plan.py
```

Actual VM creation, authenticated access, NVIDIA verification, CUDA execution,
Spot interruption and deletion remain hardware acceptance steps. This code-only
delivery makes no claim that those have run.

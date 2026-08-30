# SN39 miner image operations

This is a release reference, not a second mining guide. Start with the
repository [README](../README.md).

## Current image

```text
Source: 78e588eeb8ad4d9fa5c7c23bba0205c08fc28ba8
Image: ghcr.io/cathedralai/cathedral-sn39-audit-miner@sha256:c73070da9bef25d1fad1769c8f14878a5537964663545deaf377bf34f2644d99
Platform: linux/amd64
Listener: native TLS on TCP 8081
```

GitHub Actions run
[`33266307118`](https://github.com/cathedralai/cathedral-sandbox/actions/runs/33266307118)
published this digest with build provenance. Publication proves the image
artifact exists. It does not prove a miner is online or receiving weight.

## Fixed behavior

- Intel TDX only.
- Finney SN39 only.
- One public hotkey and one public HTTPS axon origin.
- A miner-owned, short-lived snapshot of current validator-permit hotkeys.
- A persistent replay and snapshot high-water database.
- An optional fleet manifest with at most 31 machines beyond the chain axon.
- No wallet, coldkey, chain RPC, snapshot-signing seed, or Cathedral API key in
  the guest.

The current image is a bounded migration bridge. Fleet discovery and protected
routes require signed validator requests. Fresh evidence and canonical audit
SAT remain public temporarily. Removing that bridge requires a new immutable
image and a reviewed rollback plan.

## One UID, several machines

The chain axon is always candidate one. Every additional entry must be a
canonical public HTTPS origin. Validators independently require a distinct
endpoint, TDX platform identity, and TLS SPKI for every counted machine.

One machine claimed through several addresses creates a hardware-identity
collision. Several machines sharing one TLS private key create a channel
collision. In either case, every verified claimant in that collision scores
zero for the round.

## Stop conditions

Do not start or keep the worker online when any of these are true:

- the image is not the exact immutable digest above;
- the host is not an Intel TDX guest with a usable configfs TSM report path;
- the validator snapshot is missing, invalid, or expired;
- the public-key file no longer matches its pinned digest;
- the replay database is missing or reset after its first successful creation,
  or is not owner-controlled;
- the chain axon does not match the worker hotkey, public IP, port, and protocol;
- a fleet entry reuses a hardware identity or TLS key;
- native TLS on port `8081` is not reachable; or
- the process stops refreshing evidence or answering canonical SAT.

There is no supported instruction to fall back to an older public image. Fix or
publish a reviewed replacement instead of reviving an obsolete launch mode.

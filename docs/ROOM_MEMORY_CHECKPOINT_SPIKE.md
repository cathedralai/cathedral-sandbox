# Spike: save and restore a room's memory with gVisor checkpoint

Board card AB#672. Measured 13 Nov 2026 on a development machine, not on a
sealed machine. Everything below that depends on TDX or SEV-SNP is listed
under "Not measured".

## Answer

- **It works under our room flags.** `runsc checkpoint` and `runsc restore`
  ran under `--platform=systrap --overlay2=none --net-raw`
  (`room-kit/sealed/build-guest.sh:220`), with the pinned gVisor
  `20261026.0` (`room-kit/versions.lock:2`) and with `20261109.0`. The
  processes kept running, memory was intact and loopback connections held.
  A Docker-in-Docker room also came back with its inner container running.
- **The cost scales with memory in use, not with the room's size.** The image
  is close to used memory (an idle 4 GiB room gives a 5 MB image; a full
  8 GiB room gives 7.5 GB). Restore returns in under 0.5 s and the room runs
  again within 1.5 s. Pages then load in the background.
- **The trap is the room's memory limit.** The sandbox writes the image from
  inside the room's memory cgroup. A room near its `--memory` limit takes
  35 to 80 s to checkpoint and 30 to 40 s to load all its pages. With
  headroom it takes 1.9 s (4 GiB) and 3.9 s (8 GiB) to checkpoint, and 2.5
  to 2.7 s to load everything. The product must give the cgroup room for the
  image while it saves and restores, or write it with O_DIRECT.
- **A restore needs the same runsc release, the same `--directfs`, and the
  same host files.** A version mismatch in either direction is refused. TCP
  connections to the outside break. Monotonic clocks do not see the time the
  room was off.
- **Same-machine restore is ready for a product prototype. Cross-machine
  restore is not**: it needs the image and the container's disk layer carried
  together, re-encrypted, to a machine running the identical runsc.

## How it was measured

- Machine: AMD EPYC 9224 (48 threads), Linux 7.0, 122 GiB RAM. Other jobs
  were running, at load 15 to 40, so treat times as order of magnitude.
- Images went to tmpfs, to take the disk out of the number. The local disk
  writes at 117 MB/s with O_DIRECT, so on disk a checkpoint is disk-bound:
  44 s for the 4 GiB room, against 34.6 s on tmpfs.
- The Docker daemon was not running here, so the bench drives `runsc`
  directly with an OCI bundle. The bundle uses the same flags Docker would
  pass. It has a memory cgroup limit equal to the room size, a `/work` bind,
  and a network namespace with a veth to the host, the shape the room bridge
  gives.
- The workload is `python3` holding N GiB of random bytes (incompressible,
  worst case). It also holds a loopback TCP pair and a TCP connection to an
  echo server on the host, and logs both clocks every second.
- Scripts: `scripts/checkpoint_spike/` (`trial.sh` for the timings,
  `variant.sh` for the break tests, `mkdind.py` for the Docker-in-Docker
  room). Run them as root on a test machine.

## Numbers

| Room | Memory used | Image | Checkpoint, at limit | Checkpoint, with headroom | `runsc restore` returns | Room runs again | All pages back, at limit | All pages back, with headroom |
|---|---|---|---|---|---|---|---|---|
| 4 GiB, idle | 23 MB | 5.3 MB | 0.05 s | n/a | 0.06 s | 0.63 s | n/a | n/a |
| 4 GiB, 3.5 GiB filled | 3.8 GB | 3.76 GB | 34.6 s | 1.9 s | 0.26 to 0.45 s | 0.9 to 1.5 s | 28.9 s | 2.5 s |
| 8 GiB, 7 GiB filled | 7.6 GB | 7.52 GB | 77.6 to 80.8 s | 3.9 s | 0.26 to 0.34 s | 1.1 to 1.5 s | 30.0 to 41.1 s | 2.7 s |
| Docker-in-Docker, one inner container | not read | 59 MB | 0.05 s | n/a | 0.05 s | under 4 s | n/a | n/a |

- "At limit" is the room started with `--memory` equal to its size, as
  `cathedral/sandbox_guest.py:759` does. The cgroup hit `memory.max` 3454
  times during the 8 GiB checkpoint. "With headroom" means `memory.max` was
  raised to twice the size just before the checkpoint.
- "All pages back" is the time from restore until the process has read every
  page of its memory once.
- `--compression=flate-best-speed` gave no size gain on random data
  (3.76 GB). It also turns off background loading, so restore blocked for
  52.9 s. Real rooms hold more compressible memory; this was not measured.
- `--leave-running` (checkpoint while the room keeps going, the basis for
  fork) paused a 2 GiB room for 1.1 s. The room then kept running, with its
  outside TCP connection intact.
- What lands in the image: process memory, `/tmp` and `/dev/shm` (gVisor
  tmpfs, in sandbox memory), and rootfs writes when the room runs a
  `--overlay2=root:self` or `root:memory` tunable variant. A 300 MB write
  added 300 MB to the image. Under the sealed default `--overlay2=none`, rootfs
  writes go to Docker's overlay2 layer on the host disk and are not in the
  image. Bind mounts (`/work`, workspaces, `/run/secrets`, `resolv.conf`) are
  never in the image.

## What breaks

| Case | Result | Evidence |
|---|---|---|
| Different runsc release at restore, either direction | Refused | `runsc version does not match across checkpoint restore, checkpoint: release-20261026.0 current: release-20261109.0` |
| `--directfs` differs at restore (a tunable variant) | Refused | `"UIDMappings" does not match across checkpoint restore` |
| `--overlay2` or `--num-network-channels` differs at restore | Restored | read-only rootfs in the bench; a writable `root:self` rootfs was not tried across a flag change |
| Loopback TCP inside the room | Survives | pings continue after restore |
| TCP to the outside | Broken | first send after restore gets `EPIPE`; the host side is never told and stays half-open |
| `CLOCK_MONOTONIC` | Frozen while off | 4.056 s before, 5.060 s after, across 39 s of wall time |
| Wall clock | Jumps to real time | timeouts based on it fire at once; anything with an expiry (tokens, TLS sessions, leases) sees the gap |
| A `/work` file appended to between save and restore | Restored | file handles reopen by path |
| A `/work` file the room had open, removed before restore | Refused | `failed to walk "state.log" ... in mount "__no_name_0:/work": no such file or directory` |
| Docker-in-Docker (dockerd 29.1.3 in the room, vfs storage, inner container on `--network none`) | Restored | the inner container's counter kept counting; dockerd answered `docker ps` |

## Same machine, then cross machine

Same machine, which is what the next step needs:

- Keep the stopped container, its overlay2 layer and its bind paths in place.
  Restore from the image with the same runsc and the same runtime entry.
- Give the cgroup headroom during save and restore, or measure O_DIRECT
  (`checkpoint --direct`, `restore --direct-io=on`) on the sealed disk.
- The room daemon has no `"experimental": true` (`room-kit/install.sh:216`),
  so `docker checkpoint create` is not available today. Either enable it and
  test the containerd shim path, or have the room agent call `runsc` for the
  room's container.
- Re-register the room with the egress daemon after restore. The policy is
  keyed by container id and pinned to the room's bridge address
  (`room-kit/room_egress.py`). Tell the customer that outside connections
  drop.

Cross machine would also need:

- The identical runsc release on both machines. A runsc bump invalidates
  every saved image, so images either expire at a bump or the old runsc is
  kept around to restore them.
- The container's disk layer shipped with the image: `docker commit`, as
  snapshots already do (`cathedral/sandbox_guest.py:1064`), plus `/work` and
  workspace data at the same paths.
- Re-encryption for transport and storage. The sealed scratch disk is keyed
  from `/dev/urandom` at every boot (`room-kit/sealed/guest-boot.sh:39`), so
  an image left there is unreadable after the guest reboots.
- A matching CPU. This was not tested.

## Hard parts for the product (not the spike)

- The image holds the room's memory in the clear, including secrets from
  `/run/secrets` that the process has read (docs/SEALED_SECRETS.md). It must
  stay on encrypted storage inside the sealed machine and be deleted with the
  room.
- It needs the same owner rule as snapshots
  (docs/AB650_PART2_IMAGE_SCOPING.md). A restore is a create from a
  customer-owned artifact.
- Receipts must say that a room was restored, from which image, and that its
  monotonic clock skipped the gap.
- Auto-sleep (AB#476) gets its saving only if the image goes to disk and the
  room's memory is freed. Pause (docs/evidence/SEALED_FREEZE_THAW_PROOF_20261026T164341Z.md)
  keeps memory allocated.
- docs/TEE_BOX.md:151 says "tied to a runsc version and one box". This spike
  confirms that, with numbers.

## Not measured

- Anything on a sealed TDX or SEV-SNP guest: systrap under a TD, disk
  writes through the dm-crypt scratch on virtio-blk with
  `iommu_platform=true` (`room-kit/sealed/launch-guest.sh:70`), and bounce
  buffer cost. Expect the checkpoint on a sealed machine to be bound by
  scratch disk speed: image size divided by write throughput.
- The Docker path (`docker checkpoint`, containerd shim) and real room
  containers with an overlay2 rootfs on xfs with project quota.
- Restore with the egress daemon, an allowlist policy or the egress proxy in
  the path.
- Docker-in-Docker with the production dockerd arguments
  (`room-kit/profiles/v1.sh`), overlay storage, networked inner containers or
  an image pull in flight.
- Fork: restoring a copy while the original keeps running (same address,
  same container name).
- Compressible real workloads, several rooms checkpointing at once, and GPU
  rooms (room-kit has no GPU path).
- Cross-machine restore.

## Next step on a sealed test machine

1. Install the same runsc as the room daemon. Copy `scripts/checkpoint_spike/`
   into the guest.
2. `bash net.sh up`, then start `python3 echo_server.py 10.231.0.1` in the
   background.
3. `IMGROOT=/srv/room-sealed/ckspike bash trial.sh r4 3.5 4`, then
   `bash trial.sh r8 7 8`, then each again with `BUMP=1`. Record the RESULT
   lines.
4. Repeat one size with `CKPT_EXTRA=--direct` to see whether O_DIRECT avoids
   the cgroup cost on the scratch disk.
5. Post the table on AB#672. Then decide whether auto-sleep (AB#476) builds on
   same-machine restore.

# TEE box end-to-end harness for a real Intel TDX guest (T6b2)

> **TEST HARNESS ONLY: NOT A PRODUCTION LAUNCHER.** It injects the MRCONFIGID
> binding and overwrites `/usr/share/cathedral/central-root-keys.json` with a
> throwaway root. `harness.py` and `serve_worker.py` refuse to run unless
> `setup.sh prepare` has marked the current boot as a disposable test box. The
> marker is `/run/cathedral-tee-e2e/TEST_BOX`, on tmpfs, so it goes away at
> reboot. In local mode (`--local` or `E2E_LOCAL=1`) they refuse on any machine
> that has `/dev/tdx_guest`.

This harness runs the real TEE box worker on an Intel TDX guest and talks to it
the way Cathedral's control plane and customers would. The worker is
`cathedral worker serve` with the TEE box flags, described in
[docs/TEE_BOX_SERVICE.md](../../docs/TEE_BOX_SERVICE.md). The harness mints
root-signed delegations with `scripts/cathedral_central_access.py`, signs each
central request and binds it to the worker's TLS key, and calls the worker over
HTTPS. It checks storage, auth, sandboxes, RTMR3, egress, one customer per
boot, and scopes.

It first ran on 2026-09-30, and all seven required checks passed. See
[docs/TEE_BOX_TDX_E2E_RESULTS.md](../../docs/TEE_BOX_TDX_E2E_RESULTS.md).

## What it proves, and what it cannot

| Check | What the harness shows on the TD |
|---|---|
| a. storage and measured root | Startup refuses Docker's data root on plain ext4. It accepts the data root on a LUKS2 mapping with `--integrity hmac-sha256`. It refuses central state on disk and accepts it on tmpfs. It needs swap off and runsc with systrap. The real TDREPORT reader refuses a zero MRCONFIGID, and a binding for another root key file refuses. |
| b. revocation freshness gate | With no list pushed, every route but `GET /v1/box` gets `409 revocation_list_required`. A stale list gets `409 revocations_stale`. A fresh list opens the routes. |
| c. sandbox lifecycle | Lease, image import by digest, create under runsc (`docker inspect`, gVisor's `dmesg`), exec, list and delete. |
| d. RTMR3 and admission | RTMR3 reads zero before the first lease, and a fresh configfs-tsm quote passes the pinned strict verifier and `admit(require_fresh_boot=True)`. After the lease RTMR3 holds `RTMR3_CONSUMED`, the quote carries it, and admission refuses for `boot_consumed` only. |
| e. egress | An `internet` sandbox gets a verified tc cap, and cannot reach the cloud metadata server, the VPC gateway, the box's own address or the bridge gateway. It can reach 1.1.1.1. |
| f. one customer per boot | After customer A releases, customer B gets `409 relaunch_required`. A can lease again, and RTMR3 is not extended a second time. |
| g. scope and revocation | Routes outside a delegation's scopes, and a request signed for another route, get `401`. So does a revoked delegation, while a sibling delegation keeps working. |

**One piece is injected.** A rented TD such as a Polaris "Sealed CPU" sandbox
has its launch values chosen by the provider, and its MRCONFIGID is all zero.
So the harness cannot launch with MRCONFIGID bound to its root. It installs a
throwaway root key file at `/usr/share/cathedral/central-root-keys.json`, as
an image would. It then passes the service's test hook, `build_tee_box_api`'s
`read_binding`, a reader that returns `mrconfigid_for_root_keys` of that file
(`serve_worker.py`). Check a.2 runs the real TDREPORT reader and shows it
refuses on such a launch.

**Everything else is real:**
- runsc with systrap;
- the egress enforcer's nft table and tc caps;
- the LUKS2 integrity mount under Docker's data root;
- RTMR3 through sysfs, and quotes through configfs-tsm checked with the pinned
  verifier;
- central-access signatures, and HTTPS to the worker. The client runs on the TD
  itself, on 127.0.0.1.

**What it does not prove:**
- **The MRCONFIGID binding itself.** A launch with MRCONFIGID set to our root
  must start and any other value must refuse. That needs our own measured
  image, and so do the dm-verity root and a real appliance boot step. The
  harness's `setup.sh` does the boot step by hand, after boot, on a loop-backed
  file, and keeps the worker's TLS key on disk.
- **That the measurement is an approved one.** d.2 and d.5 build their policy
  from the quote itself. They allowlist the quote's own measurement, TCB status
  and advisories, because a rented TD has no approved image to compare against.
  So these checks prove the quote's signature and collateral, the REPORT_DATA
  binding, and the RTMR3 and `require_fresh_boot` logic. They do not prove the
  measurement is one Cathedral approved.
- **Items outside the run.** SEV-SNP, relaunch between customers and its
  timing, the egress lapse drill, disk quotas (the worker runs with
  `--tee-box-no-disk-quota`), the tc cap's measured rate, and integrity write
  throughput.

## Run it

You need:
- **On your machine:** bash, ssh, scp, git, curl, sha256sum and python3; a
  cathedral-sandbox checkout (this one); and a cathedral-validator checkout.
  By default the validator checkout is `../cathedral-validator` next to this
  one.
- **The box:** a FRESH Intel TDX guest with Linux 6.16 or later (for the RTMR3
  sysfs register), configfs-tsm, Docker at `/usr/bin/docker`, apt, outbound
  internet, and an SSH user with passwordless sudo. The recorded run used
  4 vCPU and 14 GiB. The worker is told it has 3 vCPU, 6 GiB and 4 GiB of disk.

```bash
cd scripts/tee_box_tdx_e2e
SSH_KEY=~/.ssh/id_ed25519 HOST=ubuntu@203.0.113.7 ./run.sh
```

**Use a fresh TD for every run.** RTMR3 can only be extended, so a second run
in the same boot finds it already consumed. It then skips the "RTMR3 reads
zero" checks (d.1 and d.2) and the plain-ext4 refusal (a.1), because Docker is
already on the LUKS mount. To get a full result, relaunch the VM. Treat the
box as disposable: `setup.sh` changes Docker's `daemon.json` and data root,
turns swap off, and leaves test keys under `/var/lib/cathedral-e2e`.

`run.sh` ships the `origin/main` of both repositories. `SANDBOX_REF` and
`VALIDATOR_REF` pick other refs, and `NO_FETCH=1` skips `git fetch`. Each step
can also run on its own:
`./run.sh preflight|ship|setup|harness|tests|collect|summary`. Remote steps run
detached on the box. If SSH drops, re-run the same step to resume polling. The
header of `run.sh` lists every option.

## Results

Everything lands under `out/` next to the scripts, which git ignores. Set
`E2E_OUT` to put it elsewhere. Each run writes
`out/results/<host>-<time>/RESULTS.txt`, next to the raw logs, the harness's
JSON reports (`harness-pre-luks.json`, `harness-main.json`) and
`work-logs.tgz` with the worker logs and quotes.

The exit status is 0 only when every harness check and both test suites pass.
On 2026-09-30 the validator suite had 24 failures that also fail on a
developer machine, so that run exited 1 with every check passing. Read
RESULTS.txt. The "box-only failures" line counts failures on the TD that do not
happen locally.

That line needs a local baseline of the same commits:

```bash
d=$(mktemp -d)   # owner-only, as the suites require
OUT=out/baseline VENVS=out/venvs TEST_TMPDIR="$d" \
  SB=/path/to/cathedral-sandbox VA=/path/to/cathedral-validator \
  ./run_tests.sh all
```

`run.sh` reads it from `out/baseline` (or from `BASELINE_DIR`) when that
directory exists.

## Time and cost

A run takes about 7 minutes from `./run.sh` to RESULTS.txt. On 2026-09-30 it
took 412 s:

| Step | Time |
|---|---|
| ship | 6 s |
| `setup.sh prepare` | 47 s |
| pre-luks harness | 7 s |
| LUKS2 setup | 25 s (18 s of it formatting 2 GiB with the full integrity wipe) |
| main harness | 91 s |
| both test suites, in parallel | 228 s |

Add the provider's boot time and a minute or so for SSH to come up. On a
Polaris "Sealed CPU Small" sandbox that run cost about $0.04. Delete the box as
soon as `collect` has finished. `SKIP_TESTS=1` saves about 4 minutes but drops
the suite results.

## Pinned downloads

- **The TDX verifier.** `cathedral-tdx-verifier` is not kept in the
  repository. `run.sh` downloads `cathedral-tdx-verifier-linux-amd64` from the
  `cathedral-tdx-verifier-v1.0.0` release, checks it against sha256
  `4b6fbaf12def5e4284b54f557c5c29e472d7666f0160a11a5472fdcf462db148`, caches it
  in `out/cache/`, and ships it to the box (see
  [docs/TDX_VERIFIER_RELEASE.md](../../docs/TDX_VERIFIER_RELEASE.md)).
  `TDX_VERIFIER=/path/to/it` uses a local copy instead, which is checked the
  same way.
- **runsc.** `setup.sh` downloads gVisor `20261005.0` as `gvisor.tar.zstd`,
  extracts `runsc`, and checks sha256 `210b437a…` (same pin as
  `Dockerfile.tee-box-runsc` and the Cherry measured tee-box images).
- **The test image.** The image is `docker.io/library/alpine`, pulled by
  digest. `IMAGE_REF` and `IMAGE_DIGEST` change it.

The LUKS key is 64 random bytes made on the box. It is held in a ramfs only
until `cryptsetup open`, then shredded and the ramfs unmounted. An EXIT trap
does the same when `luksFormat` or `open` fails, or on a signal. The key is
never printed: the key field of the dm table is masked in every log.

## Files

| File | Role |
|---|---|
| `run.sh` | Runs on your machine: bundles, ships, runs each step over SSH, collects and summarises. |
| `setup.sh` | Runs as root on the TD. `prepare`: the test-box marker, packages, pinned runsc registered with Docker (systrap), tmpfs for the central state, swap off, the harness venv. `luks`: the LUKS2 integrity scratch device, Docker's data root moved onto it, the test image pulled. |
| `harness.py` | Checks a to g, in two phases: `pre-luks` (the ext4 refusal) and `main`. It prints one line per check and writes a JSON report. |
| `serve_worker.py` | Starts the real worker CLI with the injected MRCONFIGID reader, the only change. |
| `run_tests.sh` | Runs the cathedral-sandbox suite and the cathedral-validator suites against sandbox main, then re-runs failures once to separate flakes. |
| `summarize.py` | Writes RESULTS.txt from a collected results directory. |
| `local_fakes.py` | For developing the harness only (`harness.py --local`): runc instead of runsc, and fake RTMR3, storage, nft and tc. It needs a quote saved on a TD (`--local-quote`) and proves nothing about a TD. |

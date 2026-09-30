# TEE box sandbox service (T6a, T6b1, T7, T8, T9, T11)

Status: **off by default**. T6a added the library, and T6b1 adds the worker
flags, the egress enforcer, in-sandbox exec kills, disk quotas and an opt-in
runsc image layer. T7 moves caller authorization to central access, with the
root keys in measured state (see "Caller authorization"). T8 keeps writable
storage in guest memory or on dm-crypt with integrity, and starts images by
content address (see "Storage (T8)"). T9 serves one customer per boot: the
VM is relaunched between customers. Against a tenant with guest root, the
box-side guard, the boot id and admission's `attestation_predates_release`
prove nothing; the owner's guarantee rests only on the RTMR3 extend before
each boot's first lease plus `require_fresh_boot` admission, both of which
have run on a real TDX guest (see "Relaunch between customers (T9)"). T11
reads the owner's one signed measurement list, the existing signed policy
registry, for admission and for the validator's #256 file (see "The
measurement list (T11)").
The service has run end to end on a real TDX guest (a Polaris TDX sandbox,
2026-09-30; results in `docs/TEE_BOX_TDX_E2E_RESULTS.md`, harness in
`scripts/tee_box_tdx_e2e/README.md`). The real worker ran with Docker on a
LUKS2 integrity mount, sandboxes under runsc, and the egress enforcer. The run
covered the RTMR3 extend at the first lease, fresh-boot admission, one
customer per boot, the revocation freshness gate, and scope and revocation
checks. Only the MRCONFIGID binding was injected, because the provider chooses
the launch values. The rest of T6b2 needs our own measured image (see "Done on
hardware" and "Not done" below). SEV-SNP is untested. The design is
`docs/TEE_BOX.md` (sections 2 to 4 and "Owner decisions for v1").
Citations are `file:line` in this repository.

## What T6a adds

`cathedral/tee_box/` holds four parts.

- **Executor protocol** (`cathedral/tee_box/executor.py:190-213`): image
  import by digest, create from an image with a shape, get, list, expiry,
  delete, sync exec, background exec with poll and stop, and file read,
  write, stat and tar.
  - `FakeExecutor` (`cathedral/tee_box/executor.py:284`) keeps everything in
    memory for tests.
  - `RunscExecutor` (`cathedral/tee_box/executor.py:595`) drives
    `docker run --runtime=runsc`. It builds argv lists only, with no host
    shell (`_check_argv`, `cathedral/tee_box/executor.py:444`), and caps every
    captured output. The Docker daemon must register runsc with
    `--platform=systrap` (`cathedral/tee_box/executor.py:710-720`).
  - Each sandbox is one container that runs `sleep infinity`
    (`cathedral/tee_box/executor.py:791`). Exec, files and tar run inside it
    through `/bin/sh` scripts that take paths as positional arguments
    (`cathedral/tee_box/executor.py:563-570`). They run inside because
    gVisor's in-sandbox overlay hides writes from the host. Images therefore
    need `sh`, `sleep`, `cat`, `stat` and `tar`, as Harbor's own upload
    fallback already assumes.
  - **Orphan cleanup by label.** Before `docker run`, every container gets
    a deterministic name (`cathsbx-<sandbox id>`), the box label
    `org.cathedral.tee-box.box=<box id>` and its sandbox label
    (`cathedral/tee_box/executor.py:39-41`).
    - A create that fails is removed by name. A create that times out is
      also kept pending cleanup for 300 s, since the daemon may still start
      it (`cathedral/tee_box/executor.py:1063`).
    - `sweep` (`cathedral/tee_box/executor.py:1272`) lists the box's
      containers with `docker ps --filter label=...`. It removes every one
      the table does not track, except creates still in flight, and
      reports what it could not confirm gone.
    - The drain and the reaper both sweep. No new customer is leased the
      box until a sweep confirms that none of the box's containers remain
      and none are pending cleanup. This holds after a worker restart too
      (see the drain guarantee below).
  - **Background exec bounds.** Background exec records, running or
    finished, are capped at 16 per sandbox and 32 per box
    (`cathedral/tee_box/executor.py:34-38`). With at most 1 MiB kept per
    output stream, the box retains at most 64 MiB of exec output.
    - The cap check and the slot reservation are one step under the lock.
    - A finished record is evicted 60 s after its result is first read, or
      600 s after it finished if never read. At a cap, the oldest finished
      record goes first (`cathedral/tee_box/executor.py:1352`).
  - **Uploads.** An upload's stdin is written from its own thread
    (`cathedral/tee_box/executor.py:466`). A target that never reads, such
    as a FIFO, times out and is killed under the transfer timeout. The
    write script also refuses an existing target that is not a regular file
    with `409` (`cathedral/tee_box/executor.py:1456`).
- **Egress policy** (`cathedral/tee_box/egress.py`). `build_egress_policy`
  (`cathedral/tee_box/egress.py:208`) returns the deny list and a
  per-sandbox bandwidth cap (default 100 Mbit/s). The deny list has three
  parts:
  - IPv4 (`cathedral/tee_box/egress.py:30`): "this network", RFC 1918, CGNAT
    100.64/10, loopback, link-local 169.254/16, the IETF, TEST-NET and
    benchmarking blocks, the 6to4 relay block, multicast and 240/4;
  - IPv6 (`cathedral/tee_box/egress.py:47`): unspecified, loopback,
    IPv4-mapped, NAT64, discard, Teredo, documentation, 6to4, ULA,
    link-local, site-local and multicast;
  - cloud metadata, listed on its own (`cathedral/tee_box/egress.py:65`):
    169.254.169.254, 169.254.170.2, 100.100.100.200, Azure WireServer
    168.63.129.16, 192.0.0.192 and fd00:ec2::254.

  The box's own addresses are required and are added to the deny list
  (`cathedral/tee_box/egress.py:240`).

  The policy renders two things as text, which the T6b1 enforcer applies
  (see "Egress enforcement" below):
  - an `nft` ruleset (`cathedral/tee_box/egress.py:102`) that drops
    forwarded packets from the sandbox bridge to denied ranges, and every
    packet from the bridge to the box itself;
  - `tc` argv lists for one sandbox's veth (`cathedral/tee_box/egress.py:139`).

  `deny_all` maps to `--network none`, and `internet` maps to the sandbox
  bridge.
- **Customer lease** (`cathedral/tee_box/lease.py:75`). One central caller
  key holds the box at a time. The caller is `central:` plus the sha256 of
  the delegated central key, so it stays the same when the root re-delegates
  that key.
  - A lease lasts 60 s to 24 h and can be renewed.
  - Every other caller gets `409` with reason `box_busy`. A caller with no
    lease gets `409` with reason `lease_required`.
  - Once a lease has been granted in a boot, a different caller also needs
    the VM relaunched: after the lease ends it gets `409` with reason
    `relaunch_required` (see "Relaunch between customers (T9)"). The drain
    below still runs, and still gates the same customer's next lease.
  - **Drain guarantee.** Release or expiry
    (`cathedral/tee_box/lease.py:117`) ends the lease and drains it
    (`cathedral/tee_box/service.py:354`). The drain deletes the customer's
    sandboxes and then sweeps every untracked box container. It succeeds
    only when none of the customer's sandboxes is still listed and the sweep
    reports nothing left.
  - Until the drain succeeds, the box is **draining**. Every lease request
    and every sandbox call, from the old customer or a new one, gets `409`
    with reason `box_draining` (`cathedral/tee_box/lease.py:191`).
  - The drain runs outside the lease lock, because the box is already
    marked draining (`cathedral/tee_box/lease.py:132`). A slow container
    daemon therefore holds up only the call that runs the drain.
  - Ordinary calls retry the drain at most every 2 s. The reaper retries it
    on every tick (`cathedral/tee_box/service.py:395`).
  - **A worker starts draining** (`cathedral/tee_box/lease.py:113`). A new
    process does not know what an earlier one left running. So no customer
    is leased the box until the first sweep reports that none of the box's
    labelled containers remain and none are pending cleanup. A restart
    therefore cannot skip a stuck drain.
  - **Stuck draining.** While the container daemon is down, or a container
    cannot be removed, the sweep never comes back clean. The box stays
    draining and refuses every caller. The operator should:
    1. list the leftovers with
       `docker ps --all --filter label=org.cathedral.tee-box.box=<box id>`;
    2. fix the daemon, or remove the container by hand with
       `docker rm --force <name>`.

    The box clears on the next sweep, within about 5 s.
  - A delete in `RunscExecutor` runs `docker rm --force`, then
    `docker kill --signal KILL`, then `rm` again. It counts as done only
    when `rm` succeeds or the daemon reports the container missing
    (`cathedral/tee_box/executor.py:1047`).
  - A create holds the lease lock, so a drain cannot miss it
    (`cathedral/tee_box/service.py:765-766`).
  - A worker thread runs every 5 s, and once at start
    (`cathedral/worker.py:1871`). It checks expiry, retries the drain, and
    sweeps orphans.
- **API** (`cathedral/tee_box/service.py:314`). The routes are listed in
  `cathedral/tee_box/service.py:88`, and the central-access scope each needs
  in `cathedral/tee_box/service.py:123`. Only `GET /v1/box`, the revocation
  push and the lease routes run without a lease
  (`cathedral/tee_box/service.py:473`).

| Call | Route | Scope |
|---|---|---|
| Box contract | `GET /v1/box` | `tee-box:box` |
| Revocation list | `POST /v1/box/revocations` (the root-signed list) | `tee-box:revocations` |
| Lease | `GET`, `POST` (`ttl_seconds`), `DELETE /v1/lease` | `tee-box:lease` |
| Image import | `POST /v1/images/import` (`digest`, `reference`), `GET /v1/images/{digest}` | `tee-box:image-import` |
| Create | `POST /v1/sandboxes` (`image_id`, `network`, `lifetime_seconds`, optional `shape`, `labels`, `env`) | `tee-box:create` |
| List | `GET /v1/sandboxes?label=k=v` | `tee-box:list` |
| Get | `GET /v1/sandboxes/{id}` | `tee-box:get` |
| Delete | `DELETE /v1/sandboxes/{id}` | `tee-box:delete` |
| Lifetime | `POST .../lifetime` (`extend_by_seconds` or `lifetime_seconds`) | `tee-box:lifetime` |
| Exec | `POST .../exec` (up to 45 s); `POST .../execs` or `.../processes`, then `GET .../execs/{exec_id}?wait=N` and `DELETE` | `tee-box:exec` |
| Files | `PUT`/`GET .../files?path=&mode=`, `PUT`/`GET .../tar?path=&exclude=`, `GET .../stat?path=` | `tee-box:files` |

v1 has no snapshot, fork, port or Docker-in-Docker routes.

Every sandbox reports `"hardware": "standard"`
(`cathedral/tee_box/service.py:430`). Exec takes `env`, `user`, `cwd` and
`timeout_seconds`. Background execs may run up to 14,400 s
(`cathedral/tee_box/service.py:71-72`).

A create is admitted only while the sum of sandbox shapes fits the configured
capacity. Otherwise it gets `409` with reason `box_capacity_full`
(`cathedral/tee_box/service.py:771`), the reason Harbor already waits on.

`GET /v1/box` lists the network modes the box offers now, and its `egress`
object says whether the egress rules are enforced, with the last error
(`cathedral/tee_box/service.py:558`).

## Caller authorization

Callers use central access (`cathedral/central_access.py`, from #225, #228
and #241), with the root keys in measured state. The design is `docs/TEE_BOX.md`,
section 3, "Callers: central access, with its root in measured
state".

- **Why not the validator-access snapshot.** T6b1 took caller keys from a
  signed snapshot in the validator-access format. The miner's own operator
  key signs that snapshot, and the miner picks the trusted key file and its
  pin (`cathedral/validator_access.py:3-5`,
  `cathedral/audit_miner_entrypoint.py:266-270`). The miner could have
  minted its own caller key and reached the current customer's sandboxes.
  The snapshot path and its flags are gone.
- **Root keys.** The box reads them from a fixed path inside the image,
  `/usr/share/cathedral/central-root-keys.json`
  (`cathedral/tee_box/measured_root.py:38`). The file has the key-file format
  that the offline root tool's `keygen --keys-out` writes
  (`scripts/cathedral_central_access.py`, from #239):
  one canonical JSON object of key id to base64 Ed25519 public key.
  - **TDX.** MRCONFIGID is `sha256(root key file)` followed by 16 zero bytes
    (`mrconfigid_for_root_keys`, `cathedral/tee_box/measured_root.py:160`).
    The Cathedral TDX value covers MRCONFIGID (`docs/MRTD.md`), so a box
    launched with another root key file cannot match a published measurement.
    At start the box asks the TDX module for a TDREPORT through
    `/dev/tdx_guest` (`TDX_CMD_GET_REPORT0`,
    `cathedral/tee_box/measured_root.py:64`). It checks the report type and
    the random REPORTDATA it sent, takes MRCONFIGID from it, and loads the
    file only if its sha256 matches
    (`cathedral/tee_box/measured_root.py:127`). The box does not use a
    configfs-tsm quote here: the host's quoting service writes those bytes,
    and the guest does not verify them.
  - **SEV-SNP.** HOST_DATA would be the binding, but the SNP report code does
    not read it, so `serve-snp` with the TEE box flags refuses to start
    (`cathedral/tee_box/measured_root.py:95`).
  - Nothing reads the root, its digest or MRCONFIGID from a flag, an
    environment variable or a writable config file. A missing device, a
    zero or malformed MRCONFIGID, or a file that does not match refuses
    startup (`cathedral/tee_box/configure.py:305`). The startup line reports
    the root digest and key ids.
- **Delegations and scopes.** The offline root signs a delegation of at most
  24 h naming one central key, the subnet (`--validator-network` and
  `--validator-netuid`) and the scopes it may call. The scopes are
  `TEE_BOX_CENTRAL_SCOPES` (`cathedral/central_access.py:83`), which join
  `CENTRAL_ROUTES` (`:99`); the table above maps each route to its scope.
  A `/v1/capabilities` delegation does not reach the sandbox API, and a
  scope is never a path route.
- **Requests.** Requests carry a central request in
  `X-Cathedral-Central-Request`. The central key signs the method, the full
  target (query included, so file paths are covered), the body digest, a
  nonce, the worker hotkey, the subnet and the worker's TLS key.
- **Worker.** The worker maps the method and target to a scope with
  `route_scope` (`cathedral/tee_box/service.py:180`). Before it reserves a
  slot or reads the body, it verifies the delegation against the measured
  root, its expiry, its scope and the revocation list, then the request's
  signature and expiry (`cathedral/worker.py:796`). After the body is read,
  it checks the body digest, the revocation list again and replay
  (`cathedral/worker.py:817`). Replay and the delegation high-water live in
  the `--tee-box-central-state` file.
- **Separate from the `--central-*` flags.** The worker's own central
  access, for `/v1/capabilities`, trusts root keys the miner names by flag.
  The TEE box builds its own authorizer from the measured root, and
  `WorkerServer` refuses to share that authorizer or its state
  (`cathedral/worker.py:1776-1783`).
- **Revocation list.** State starts empty on a fresh box, so the control
  plane pushes the root-signed revocation list to `POST /v1/box/revocations`
  after every start (`cathedral/tee_box/service.py:615`). Until it has, only
  `GET /v1/box` and the push are served; every other route gets `409` with
  reason `revocation_list_required`. A list older than the one in force, a
  different list under the same sequence, or one the root did not sign is
  refused (`revocations_refused`). Pushing the list in force again is
  accepted.
  - **Freshness.** The push accepts only a list whose signed `issued_at` is
    at most 24 h old (`MAX_REVOCATIONS_AGE_SECONDS`, the longest a
    delegation lives) and at most 15 s ahead of the box clock; any other
    gets `409` with reason `revocations_stale` and is not installed. The gate
    re-checks on every call: once the pushed list is older than 24 h, every
    route but `GET /v1/box` and the push gets `409` with reason
    `revocation_list_stale` until a freshly signed list is pushed. The
    offline root therefore signs a new list (a higher sequence) at least
    every 24 h, as it already re-signs delegations.
  - **Why.** After a relaunch or a wipe of the state file, the sequence check
    compares against nothing. Without freshness, a stolen delegation revoked
    under list 2 could push the older list 1 and open every route until the
    delegation expired, since the miner controls the network and can drop
    the control plane's own push.
  - **What the control plane must do.** Push the current list right after
    every relaunch, and whenever it changes. Do not trust
    `revocations.pushed` alone: compare `GET /v1/box` `revocations.sequence`
    and `revocations.issued_at` with the current list, and check
    `revocations.fresh`. Route no customer to a box that reports an older
    list, and push again.
  - **Residual risk: lists that are still fresh.** A list signed less than
    24 h ago is accepted even if a newer one exists. A delegation revoked by
    list N can still reopen a relaunched box with list N-1 while N-1 is
    fresh, until the control plane's push of N lands or the delegation
    expires. Issuing lists more often does not narrow this: it only keeps
    list N-1 fresh for longer after N. A shorter
    `MAX_REVOCATIONS_AGE_SECONDS` narrows it, at the cost of the root
    re-signing the list more often.
  - **Trusted clock.** Freshness is judged against the box clock, as
    delegation and request expiry already are. Its source (for example NTP
    over the host network) must be trusted; a host that sets the box clock
    back can make a stale list look fresh.
  - **Residual risk: the delegation high-water resets.** The high-water that
    refuses a delegation older than one already accepted lives in the same
    state, so after a relaunch a superseded but unexpired, unrevoked
    delegation works again, for at most its remaining lifetime (24 h). A
    revoked one is still refused once the current list is pushed. Closing
    this needs a signed floor. **Proposed follow-up for #241:** a
    `min_delegation_sequence` field in the root-signed revocation list, which
    the worker applies as its high-water floor when it installs the list.
    Until then, the root should revoke, not merely supersede, a delegation
    that must stop working.
- `GET /v1/box` reports `revocations.pushed`, `sequence`, `issued_at` (epoch
  seconds) and `fresh`.
- **Refusals.** Each of these gets `401`: no header or two, a validator
  header beside it, a delegation the pinned root did not sign, an expired
  delegation or request, a revoked delegation, one older than a delegation
  already accepted, a delegation for another subnet or a request for another
  worker or TLS key, a scope the delegation does not grant, a bad request
  signature, a signature over a different method, target or body, a replay,
  and an unknown route.

## Relaunch between customers (T9)

Owner decision 1, amended 2026-09-29: the confidential VM is relaunched and
re-attested between customer allocations, so a gVisor escape by one customer
cannot persist into the next. The design is `docs/TEE_BOX.md`,
decisions 1 and 8 and sections 4 to 6.

**What the guarantee rests on.** A tenant that escapes gVisor has root in
the guest kernel for the rest of its allocation (design section 4, "Residual
risk"). Against guest root, the box-side guard, the boot id, `booted_at`,
the boot record and admission's `attestation_predates_release` prove
**nothing**: guest root can rewrite or fake each of them. The guarantee rests
on two things only:

- **The RTMR3 lease extend.** Before the first lease of a boot, the box
  extends TDX RTMR3 once with a fixed event. No guest code, root included,
  can undo an extend; only a new TD starts with RTMR3 at zero.
- **`require_fresh_boot` admission.** Before each new customer, the control
  plane admits the box with `admit(..., require_fresh_boot=True)`, which
  refuses any quote whose RTMR3 is not all zeros (docs/CAPACITY.md,
  "Admission"), and pins that admission's TLS SPKI for the customer's
  connection.

The rest catches a miner who skips the relaunch while the guest kernel is
intact, and gives the control plane clear answers. The extend has run on a
TD (2026-09-30, `docs/TEE_BOX_TDX_E2E_RESULTS.md`). The worker extended RTMR3
at the first lease, and the next quote carried `RTMR3_CONSUMED`. Admission
with `require_fresh_boot=True` then refused that quote for `boot_consumed`
only, where before the lease it had admitted a quote with RTMR3 at zero.

This replaces #236's proposal of no RTMR3 extends (design section 3); #236
is updated separately.

### Lifecycle

1. **Boot.** The appliance boots with a new tmpfs (so empty central state and
   no boot record), a new dm-crypt key for scratch, a new TLS key, and RTMR3
   at zero. The worker checks RTMR3, starts draining and sweeps (see "Drain
   guarantee"). `GET /v1/box` reports the new `boot.boot_id`,
   `boot.booted_at` and `boot.rtmr3`, with `consumed` and `needs_relaunch`
   false. Until a revocation list is pushed, only `GET /v1/box` and the push
   are served.
2. **Re-attest.** The control plane (or the prober) attests the box on a new
   connection with a fresh nonce, and calls `admit(...,
   require_fresh_boot=True, last_released_at=...)`. It pins the SPKI of that
   connection. It also checks, as a guard against mistakes rather than
   against guest root, that the `boot_id` differs from the previous boot's
   and that the SPKI differs from the previous allocation's.
3. **Revocations push.** The control plane pushes the current revocation list
   (see "Revocation list"). Only now are the lease and sandbox routes served.
4. **Available.** The control plane routes one customer to the box, over the
   pinned SPKI.
5. **Lease.** Before the customer's first lease is granted, the box extends
   RTMR3 (`cathedral/tee_box/boot.py:385`) and then records the customer
   (`cathedral/tee_box/boot.py:427`, called at
   `cathedral/tee_box/lease.py:197`). From here on, every quote of this boot
   carries the consumed RTMR3, and `require_fresh_boot` admission refuses it.
   The same customer may renew, release and lease again, with no second
   extend.
6. **Release.** Release or expiry ends the lease and drains it, as before.
   The box now reports `needs_relaunch: true` and `last_released_at`. Every
   other caller gets `409` with reason `relaunch_required`, on
   `POST /v1/lease` and on every sandbox route
   (`cathedral/tee_box/lease.py:126`, `cathedral/tee_box/service.py:487`),
   however long it waits. While the lease is live, other callers still get
   `box_busy`.
7. **Relaunch.** The control plane asks the miner to relaunch the VM, and
   waits until `GET /v1/box` shows a new `boot_id`. Then back to step 1.

### The RTMR3 extend

- **Interface.** The kernel's TSM measurement registers (Linux 6.16 and
  later, `drivers/virt/coco/tdx-guest`):
  `/sys/devices/virtual/misc/tdx_guest/measurements/rtmr3:sha384`
  (`TDX_RTMR3_PATH`, `cathedral/tee_box/boot.py:56`; `/sys/class/misc/tdx_guest`
  links there). Per the kernel's ABI document, a write must be exactly 48
  bytes at offset 0, and the driver passes it unchanged to
  TDG.MR.RTMR.EXTEND; a read returns the 48-byte register. The kernel has
  no RTMR extend ioctl (`/dev/tdx_guest` offers only `TDX_CMD_GET_REPORT0`).
  `SysfsRtmr3` (`cathedral/tee_box/boot.py:88`) implements it; tests
  replace it with a fake.
- **Value.** The event is `LEASE_EVENT = b"cathedral tee-box lease granted
  v1"`. The box writes `SHA-384(LEASE_EVENT)`, and the TDX module sets
  RTMR3 to SHA-384(old RTMR3 ‖ written bytes). From zero:

  ```
  RTMR3_CONSUMED = SHA-384(0x00 * 48 || SHA-384("cathedral tee-box lease granted v1"))
  ```

  exported as `RTMR3_CONSUMED`, with `rtmr_extend(value, digest)` for the
  computation (`cathedral/tee_box/boot.py:59-73`).
- **Once per boot.** The box extends only while RTMR3 is still zero, so a
  consumed boot always holds exactly `RTMR3_CONSUMED`. After the extend it
  reads RTMR3 back and must see that value.
- **Fails closed.**
  - An extend that fails refuses the lease with `503` and reason
    `rtmr_extend_failed`. If RTMR3 is still zero, a later lease retries; if
    the extend landed anyway, it is not repeated.
  - RTMR3 left at any value but zero or `RTMR3_CONSUMED` closes the box
    until the next boot: every caller gets `relaunch_required`.
  - At start, RTMR3 and the boot record must agree: zero with no customer,
    or `RTMR3_CONSUMED` with one. Anything else closes the box
    (`cathedral/tee_box/boot.py:245`). This covers a crash between the
    extend and the record write.
  - The worker refuses to start when RTMR3 cannot be read, and on SEV-SNP
    (`cathedral/tee_box/configure.py:317-319`), which has no RTMR. The SNP
    equivalent (a vTPM PCR) is open.
- **Two measurements per image.** The Cathedral TDX measurement covers the
  RTMRs (`cathedral/verify/tdx_quote.py:91-104`), so each image has a fresh
  and a consumed measurement. The published list holds both, derived from
  one approved image (see "The measurement list (T11)"), so a
  re-attestation during an allocation still verifies and pays; only
  `require_fresh_boot` tells them apart (docs/CAPACITY.md, "Admission").
- **Nothing else may extend RTMR3.** A box whose RTMR3 is not zero at start,
  and has no record, is closed until relaunched.

### Who counts as one customer

- The caller is `central:` plus the sha256 of the delegated central key (see
  "Customer lease"). So the control plane must give each customer its own
  central key, and should give each allocation its own. One key shared by
  two customers makes them one customer to the box, and the box-side guard
  cannot separate them (RTMR3 still shows the boot was used).
- **Same customer, no relaunch.** The owner asked for a relaunch between
  customers, so the caller that consumed the boot may lease again after a
  release or an expiry, without a relaunch. A gVisor escape during its own
  earlier lease then reaches only its own later lease.
- **Key rotation.** Re-delegating the same central key keeps the caller the
  same. Rotating to a new central key in the middle of an allocation makes a
  new caller, which gets `relaunch_required` once the old key's lease has
  ended. Rotate central keys between allocations, not during one.

### The boot record

- **Where.** In memory, and in `<central state>.boot`, next to
  `--tee-box-central-state` on the same tmpfs
  (`cathedral/tee_box/configure.py:322`). The storage check covers the file
  like the SQLite side files. A worker restart within one boot keeps it; a
  relaunch empties the tmpfs.
- **Keyed to the boot.** It names the `boot_id` from
  `/proc/sys/kernel/random/boot_id` it was written in. A file for another
  boot id is ignored (`cathedral/tee_box/boot.py:280`), and the boot id is
  read again on every check (`cathedral/tee_box/boot.py:355`), so a file that
  somehow survived a relaunch does not carry over.
- **Written first.** The customer is recorded (owner-only, written to a
  temporary file and renamed) after the RTMR3 extend and before its first
  lease is granted. When the same customer leases again, the record's
  release time is cleared, and written, before that lease is granted too. If
  a write fails, the lease is refused with `503` and reason
  `boot_record_unavailable`, and the record does not change
  (`cathedral/tee_box/boot.py:427`).
- **Fails closed.** A record that cannot be read or parsed, or a symlink,
  counts as consumed by an unknown caller: every caller gets
  `relaunch_required` until the next boot. So does a release (or a restart)
  whose write fails, since the file would then disagree with memory
  (`cathedral/tee_box/boot.py:339`), and a boot id that can no longer be
  read. The worker refuses to start if the boot id or the boot time cannot
  be read at all.
- **Restart with a live lease.** A worker that restarts loses its lease
  table. The record keeps the customer, and `last_released_at` becomes the
  restart time, since the lease ended no later than that.

`GET /v1/box` now has a `boot` object (`cathedral/tee_box/boot.py:463`). All
of it is informational: a quote is what shows RTMR3, and guest root can
change every field here.

| Field | Meaning |
|---|---|
| `boot_id` | the kernel's boot id, or `null` when it cannot be read |
| `booted_at` | `btime` from `/proc/stat`, epoch seconds, by the guest clock |
| `consumed` | a customer has leased the box in this boot |
| `consumed_by_caller` | that customer is the caller |
| `needs_relaunch` | consumed and no lease is live: no other customer until a relaunch |
| `last_released_at` | when the customer's last lease ended, epoch seconds rounded up, or `null` (also while its lease is live again) |
| `rtmr3` | RTMR3 read now, 96 hex, or `null` when it cannot be read |
| `rtmr3_extended` | the box has extended RTMR3 in this boot |

`DELETE /v1/lease` also returns `needs_relaunch`.

### No reboot route

The box offers no route for the control plane to reboot the guest:

- **It would not relaunch anything.** TDX has no in-place TD reset: a guest
  reboot ends the TD, and only the host's VMM can build a new one. SEV-SNP is
  the same. The miner's host has to act anyway, and a reboot request from the
  guest proves nothing. The control plane still has to see a fresh-boot
  quote.
- **It adds a privileged action to the network API.** A leaked delegation
  with that scope could take boxes down. RTMR3 and the guard already keep the
  next customer out until the relaunch happens, so the miner has a reason to
  relaunch.
- **Unknown behaviour.** What the VMM does on a guest reboot of a TD (stop,
  or rebuild) depends on the host's QEMU and must be qualified on hardware.

### What REPORT_DATA binds

The quote binds `report_data_v2(nonce, miner_hotkey, TLS SPKI)`
(`cathedral/common.py:260`): a domain tag, version 2 and exactly four fields,
byte for byte what cathedral-validator's `collect.py`, admission (#240) and
receipt evidence (#237) recompute. The boot id is not added: that would need
a new REPORT_DATA version on every side, and it would prove nothing against
guest root, which picks the boot id. RTMR3 is in the quote already, outside
REPORT_DATA, and is what shows a fresh boot. The TLS key is bound per quote;
for the control plane's SPKI check across relaunches to mean anything, the
appliance must generate the TLS key at each boot, in guest memory. Today the
worker reads `--tls-private-key` from a file, so the appliance boot step must
write it to tmpfs at boot (T6b2).

### The prober is not exempt

- **Attestation needs no lease.** Getting a quote and reading `GET /v1/box`
  do not take a lease, so they do not extend RTMR3 or consume the boot. The
  prober can attest a freshly relaunched box, and the control plane's
  `require_fresh_boot` admission can use that same attestation.
- **A functional probe consumes the boot.** A probe that runs the capacity
  challenge in a sandbox leases the box like any caller, with its own
  central key, so it extends RTMR3 and consumes the boot. The box then needs
  another relaunch before a customer. So a probe right after the relaunch
  (design section 5) costs a second relaunch per customer. Schedule probes
  accordingly; exempting the prober would need a scope the box trusts, which
  central access does not have, and would let a prober escape reach the next
  customer.

## The measurement list (T11)

Owner decision (2026-09-29, design decision 4): the owner publishes one
signed measurement list, and validators, admission, routing and the prober
all consume it. It replaces each validator's local cathedral-validator #256
file as the source of truth; during rollout that file mirrors it.

**The list is the signed policy registry** (`cathedral/policy_registry.py`,
docs/MRTD.md): Ed25519 under a pinned owner key, monotonic releases with a
durable high-water mark, and per-profile revocation. No new signed format.
`cathedral/capacity/measurement_list.py` reads it.

**TEE box entries.** A `cpu_tdx` (or `cpu_snp`) profile is a TEE box profile
when its signed `metadata` carries a `tee_box` object. The registry refuses
unknown profile keys (`cathedral/policy_registry.py:373`), so metadata is the
backward-compatible place: an older verifier accepts the release unchanged.

```json
"metadata": {"tee_box": {"schema": "cathedral_tee_box_images_v1", "images": [
  {"id": "appliance-v1-c3-176",
   "td_attributes": "<16 hex>", "xfam": "<16 hex>", "mrtd": "<96 hex>",
   "mrconfigid": "<96 hex>", "mrowner": "<96 hex>", "mrownerconfig": "<96 hex>",
   "rtmr0": "<96 hex>", "rtmr1": "<96 hex>", "rtmr2": "<96 hex>"}]}}
```

One entry per image and VM shape (RTMR0 can vary with the shape). An SNP
image is `{"id", "measurement": "<96 hex>"}`.

**Consumed values are derived, not listed.** The Cathedral measurement is a
SHA-256 over TD_ATTRIBUTES, XFAM, MRTD, MRCONFIGID, MROWNER, MROWNERCONFIG and
RTMR0-3 (docs/MRTD.md; #256's `reference_measurement`). A hash cannot be
turned into another, so the entry carries the fields and both values follow:
RTMR3 all zero (fresh) and RTMR3 = `RTMR3_CONSUMED` (after the lease extend).
The owner approves one image; the pair cannot be listed unpaired or
mismatched. The profile's own `measurements` must equal exactly the derived
values of its images, so the registry's other readers (`to_policy`, the
verifier's own allowlist) see the same set. A release that breaks this is
refused before the high-water mark moves. A TD_ATTRIBUTES with the debug bit
set is refused.

**MRCONFIGID.** Every TDX image must bind a central-access root (see "Caller
authorization"): `root_digest_from_mrconfigid`
(`cathedral/tee_box/measured_root.py:112`) must accept it, that is SHA-256
of the root key file followed by 16 zero bytes, and not zero. An image with
no root binding is refused. `accept_release(expected_root_digest=)`, and the
export's `--expected-root-digest`, also pin which root.

**Security controls.** A TEE box `cpu_tdx` profile is still a `cpu_tdx`
profile, and `to_policy` requires every eligible one to share min_tcb, TCB
statuses, advisories and firmware. A release where `to_policy` raises is
refused, so a box profile can never break worker admission. Those controls
are the pinned verifier's to apply: `verifier_policy(release)` is its strict
`Policy` from the same release, and the prober verifies a box's quote with
it. `admission.admit` does not recheck them: it has no input for them, and
checks only that the verdict is a complete strict verification. A caller
that verifies with another policy is not held to the list's controls.

**What each consumer calls.**

- `accept_release(data, trusted_keys, state)` verifies the signature with the
  trusted owner keys, the validity window and staleness, validates every TEE
  box entry and the worker policy, then `state.accept` refuses a lower or
  equivocated release. Its `before_commit` callback runs inside that
  transaction after every check and before the commit
  (`PolicyRegistryState.accept(before_commit=)`), so anything published from
  the release is written before the high-water mark moves, and a failure
  records nothing. Only it makes an `AcceptedRelease`; the functions below
  refuse anything else.
- `verifier_policy(release)` is the verifier's strict `Policy` (above).
- `measurement_policy(release, kind=, mode=)` is the `MeasurementPolicy`
  `admission.admit` takes. It lists both values of each eligible TEE box
  image, and only TEE box images: a worker image approved for other CPU work
  is never admitted as a box. Before each new customer, `admit(...,
  require_fresh_boot=True)` refuses the consumed value by RTMR3.
- `eligible_images(release, kind=)` gives routing and the prober each image's
  `fresh` and `consumed` values and MRCONFIGID.
- Only profiles eligible now contribute (active, or retiring before
  `retire_at`, inside validity). A measurement any `revoked` profile lists is
  excluded even if another profile lists it, and revoking either value of an
  image drops the whole image.

**The validator mirror.**

```bash
cathedral policy-registry export-measurement-policy \
  --registry registry.json --trusted-keys keys.json \
  --trusted-keys-digest sha256:<hex of keys.json> \
  --state /var/lib/cathedral/measurement-mirror.sqlite3 --min-release <n> \
  --mode shadow --scope all --out tdx-measurement-policy.json
```

It writes #256's policy file (`{"schema", "mode", "allowed_measurements"}`,
deterministic bytes, mode 0644 before umask) and
`tdx-measurement-policy.json.source.json`. #256's loader refuses any other
key, so the list's release and digest go in the source record, bound to the
policy file by its SHA-256. That is the `policy_digest` #256 logs and puts in
its evidence, so a validator's reported digest names the release it mirrors;
for the same release and mode, admission records the same digest. `--kind
sev_snp` writes the sandbox's SNP schema instead (the validator's SNP policy
is a different, per-generation format).

- **`--scope` is required, with no default.** `box` lists only TEE box
  images; `all` also lists every other eligible CPU profile of the kind. Under
  enforce, `box` stops paying every non-box TDX miner, so it must be chosen
  on purpose.
- **Deny all.** Under enforce with nothing eligible (release 2 revokes the
  only box profile, say), the file lists one all-zero
  `tdx-measurement-sha256:` value (96 zero hex for SNP). #256 loads it and
  it allows no real quote. The old file is not left in place, and not
  deleted either: #256 refuses an empty enforcing list, and a missing file
  stops it validating.
- **Order.** The files are written inside the state's accept transaction:
  the policy file atomically, then the source record atomically, then the
  high-water commit. A failed write moves nothing. A crash between the two
  writes leaves a record whose `policy_digest` does not match the file,
  which the next export (same or higher release) rewrites.
- **Rollback without state.** If the state file is lost or recreated, an
  existing `<out>.source.json` still refuses a lower release, or the same
  release with another digest. An unreadable record is refused; remove it
  deliberately to start over.
- **The mode is the operator's flag, not yet signed.** Once validators read
  the list directly, the enforce switch belongs in the signed list, for
  example a per-kind `enforce_from` time in registry metadata, so the owner
  flips every validator at once.

Install it as #256 documents (`install -o root -g cathedral-validator -m 0440`)
and restart the validator. The exported file has no expiry of its own:
regenerate it for every release, and before `registry_valid_until` in the
source record.

## How to enable it (T6b1)

`cathedral worker serve` (TDX) and `cathedral worker serve-snp` take the TEE
box flags (`cathedral/tee_box/configure.py:99`, registered at
`cathedral/cli.py:4479` and `:4503`). The development, migration and GPU
commands do not offer them.

| Flag | Required | Meaning |
|---|---|---|
| `--tee-box-central-state` | yes | owner-only SQLite replay state for central callers, separate from the validator-access and `--central-access-state` files, in a directory on tmpfs or ramfs (see "Storage (T8)") |
| `--tee-box-executor runsc` | yes | the only executor |
| `--tee-box-capacity V,M,D` | yes | vCPUs, memory MiB and disk MiB for all sandboxes together |
| `--tee-box-default-shape V,M,D` | yes | shape of a sandbox created without one; must fit the capacity |
| `--tee-box-address IP` (repeat) or `--tee-box-detect-addresses` | exactly one | the box's own addresses, denied to sandboxes |
| `--tee-box-bandwidth-mbit` | no (100) | per-sandbox cap |
| `--tee-box-docker-path` | no (`/usr/bin/docker`) | docker CLI in the guest |
| `--tee-box-runtime`, `--tee-box-runtime-path` | no (`runsc`, `/usr/local/bin/runsc`) | the daemon's runtime entry |
| `--tee-box-id` | no (`default`) | container label for this box |
| `--tee-box-no-disk-quota` | no | run without per-sandbox disk quotas |

No flag names the callers or their root keys; see "Caller authorization".

- **All or nothing.** With no TEE box flag, the worker passes no API and
  serves no sandbox routes. Giving any flag, even an optional one, requires
  every required flag and one address source, or the worker refuses to
  start (`cathedral/tee_box/configure.py:172`, called at
  `cathedral/cli.py:1391`).
- **Attested TLS only.** The flags need `--tls-certificate` and
  `--tls-private-key` (`cathedral/cli.py:1397`). The API then binds the
  worker's TLS key and hotkey, the key REPORT_DATA binds (design section 3);
  `WorkerServer` checks this again (`cathedral/worker.py:1763-1775`).
- **Detected addresses** are every address in `ip -json address show`,
  plus the `--public-endpoint` host when it is an IP literal. On a cloud
  guest behind 1:1 NAT the public address is not on an interface, so pass
  it with `--tee-box-address` instead.
- **Startup refuses** (`cathedral/tee_box/configure.py:258`) when the root
  key file does not match the measured binding, or on SEV-SNP (`:309`);
  when the central state is not on tmpfs or ramfs, or any swap is on (`:310-316`); when
  the kernel's boot id, boot time or RTMR3 cannot be read, or the TEE is not TDX
  (`:317-324`, see "Relaunch between customers (T9)"); when the central state is unusable (`:325-335`); when
  the daemon does not register the runtime at the runtime path with
  `--platform=systrap` (`:353`); when Docker's data root is neither in guest
  memory nor on dm-crypt with integrity (`:354-358`); or when disk quotas
  are unsupported without `--tee-box-no-disk-quota` (`:359-367`). No flag
  relaxes the storage checks (see "Storage (T8)").
- **Startup does not refuse** when the egress rules fail to apply
  (`:368`). The box then serves `deny_all` only, and the startup line's
  `tee_box.egress` field reports the error. The egress thread re-applies
  every 60 s, and reads an applied table back every 5 s.

The guest must also provide: a Docker daemon with the runsc runtime entry
(`daemon_runtime_config`, `cathedral/tee_box/executor.py:710`), the docker
CLI, `nft`, `tc`, `ip` and `nsenter` at `/usr/sbin/nft`, `/usr/sbin/tc`,
`/usr/sbin/ip` and `/usr/bin/nsenter`, and the privileges to use them. No
shipped image provides all of that yet (see "Packaging").

The sandbox routes have their own request pool of 8
(`cathedral/worker.py:137`). Request bodies may be up to 8 MiB, under the
worker's request deadline.

## Egress enforcement (T6b1)

`EgressEnforcer` (`cathedral/tee_box/enforce.py:302`) applies the policy
inside the confidential VM. Every command is an argv list with no shell and
a 15 s timeout.

- **Attachment point.** Every `internet` sandbox joins one dedicated Docker
  bridge network. The network and its Linux bridge share one name,
  `cathsbx0`, so `docker run --network cathsbx0` and the nft `iifname` match
  name the same thing. The enforcer creates it with
  `com.docker.network.bridge.name=cathsbx0` and
  `com.docker.network.bridge.enable_icc=false`, and refuses an existing
  network with other settings (`cathedral/tee_box/enforce.py:474`).
- **The table.** `apply` (`cathedral/tee_box/enforce.py:498`) replaces
  `inet cathedral_tee_box_egress` in one `nft -f -` transaction. `verify`
  (`cathedral/tee_box/enforce.py:529`) reads it back with
  `nft --json list table` and compares the parsed sets, chains and rules
  with the policy: the same collapsed deny ranges, hooks, priorities and
  rules, and nothing else (`table_matches`,
  `cathedral/tee_box/enforce.py:224`). The executor verifies again before
  every `internet` create (`cathedral/tee_box/executor.py:1076`).
- **Per-sandbox cap.** `attach` (`cathedral/tee_box/enforce.py:698`) finds
  the sandbox's host-side veth from its network namespace: Docker's
  `SandboxKey`, then `eth0@ifN` inside it through `nsenter`, then the
  `cathsbx0` port with index N (`find_veth`,
  `cathedral/tee_box/enforce.py:632`). It applies the `tc` commands and
  reads them back: the root `tbf` rate, the ingress qdisc, and the matchall
  policer's rate and drop action. `detach`
  (`cathedral/tee_box/enforce.py:717`) deletes both qdiscs, and runs only
  after `docker rm` has confirmed the container gone
  (`cathedral/tee_box/executor.py:1138`). A remove that fails or times out
  leaves the sandbox running with its cap in place; the orphan sweep also
  detaches only what it confirmed removed. It treats a veth already gone as
  removed.
- **Re-checked on its own thread.** The worker runs the egress check on a
  thread of its own (`cathedral/worker.py:1885`), apart from the reaper, whose
  expiry deletes and drain wait on docker. It starts a check every 5 s
  (`cathedral/worker.py:141`), or at once if the last one overran. Each
  check runs `check_egress` (`cathedral/tee_box/executor.py:1145`), which
  calls `maintain` (`cathedral/tee_box/enforce.py:548`): one
  `nft --json list table` read-back while the table is active, bounded by
  the enforcer's 15 s command timeout, with no docker call.
- **A lapse ends running internet sandboxes.** When a read-back fails (for
  example after `nft flush ruleset` from an nftables reload), enforcement
  turns off at once and the enforcer counts a lapse. A lapse can be found
  by the egress check, by a create's read-back before `docker run`, or by
  `attach`'s read-back after it. In every case `end_lapsed_sandboxes`
  (`cathedral/tee_box/executor.py:1164`) runs before any re-apply (which
  calls docker): the egress check calls it first on every tick
  (`cathedral/tee_box/executor.py:1145`), and both create paths call it
  when they refuse. It marks every `internet` sandbox that was running,
  cuts the bridge off, and starts removing those sandboxes, as a delete
  does, even when the re-apply then succeeds: they ran unprotected for an
  unknown time.
  - **Calls refused.** From that moment every call on a marked sandbox
    (exec, processes, files, tar, stat, lifetime) gets `409` with reason
    `sandbox_network_lapsed` (`cathedral/tee_box/executor.py:1251`). Get,
    list and delete still work.
  - **Bridge quarantined.** `quarantine`
    (`cathedral/tee_box/enforce.py:592`) installs a separate nft table,
    `inet cathedral_tee_box_lapse`, that drops every packet to or from
    `cathsbx0`. It is one `nft -f` call (15 s timeout) with no docker, and
    it does not depend on the egress table that just lapsed. It is
    re-installed on every check while any marked sandbox remains, in case it
    was flushed too, and removed once none is left. While it is in place
    the box offers no `internet` mode and refuses `internet` creates.
    `/v1/box` reports a quarantine that fails to install. Marking a
    sandbox, deciding to install or lift the quarantine, and the nft call
    itself run under one lock, so a lapse found by a create cannot be
    undone by a lift the egress thread had already decided on.
  - **Left by an earlier run.** If the worker stops during a lapse, the
    quarantine table stays in the kernel. `apply` (at startup and on every
    re-apply) adopts it: the box reports not enforced, with the reason, and
    offers no `internet` mode. It is lifted only after the orphan sweep
    comes back clean, since the earlier run's sandboxes may still be
    running until then.
  - **Removal.** Removals run on their own threads, at most 4 at once.
    Each docker call has a 15 s timeout, so one removal takes at most about
    60 s (four docker calls) plus 30 s for the two `tc` deletes. With up to
    64 sandboxes and docker hanging on every call, the last removal can end
    about 16 x 90 s, some 24 minutes, after detection. A removal that
    fails is retried on the next check, and `/v1/box` reports it as the
    egress error.
  - Removal was chosen over `docker network disconnect` because it does
    not depend on how runsc treats an interface that disappears under it.
    A successful re-apply lets new `internet` sandboxes start only after
    the quarantine is lifted; it never brings back the removed ones, whose
    callers then get `404`.
  - **Bound.** A change to the table is detected within one check interval
    plus two read-back timeouts (5 s + 2 x 15 s = 35 s) when nft hangs; when
    nft answers promptly, within about 5 s. From detection, calls on the
    affected sandboxes are refused (`409`), and the quarantine cuts their
    traffic within one more nft call (at most 15 s). Only if nft itself
    fails do processes already running in them keep the network until
    their containers are removed (the removal bound above). So an
    `internet` sandbox serves calls only while its cap verified at create
    and every read-back of the table since has matched.
- **Fail closed.** Until apply and verify succeed, and after any later
  verify fails, `active` is false and `status()` carries the error.
  `RunscExecutor` then offers `deny_all` only
  (`cathedral/tee_box/executor.py:684`) and refuses `internet` with `409`
  before `docker run`. After `docker run`, a sandbox whose cap fails to
  apply or verify is removed at once (`cathedral/tee_box/executor.py:1098`).
- **Injection safety.** Box addresses reach nft only as `ipaddress`
  objects. Detection parses every value with `ipaddress` and refuses the
  whole listing on any other value (`cathedral/tee_box/enforce.py:108`).
  The enforcer refuses a policy holding anything else
  (`cathedral/tee_box/enforce.py:90`). Interface names must match a strict
  pattern.
- **Tests.** `tests/test_tee_box_enforce.py` mocks every command for apply,
  verify, failure and teardown. When the host allows unprivileged user and
  network namespaces, it also runs the real `nft`, `tc`, `ip` and `nsenter`
  against a bridge and veth, so the read-back parsers are checked against
  real output.

## Exec timeouts (T6b1)

A customer exec runs through a wrapper that writes its pid to
`/tmp/.cathedral-exec-<random>.pid` inside the sandbox and then execs the
command in place (`cathedral/tee_box/executor.py:574`). When a sync or
background exec times out, or a background exec is stopped, the executor
first runs a kill script as root in the sandbox
(`cathedral/tee_box/executor.py:579`, `:1318`). The script stops the
recorded process and every descendant it finds in `/proc`, repeating until
no new one appears, and then kills them all. Only then is the host-side
`docker exec` client killed. The kill has its own 30 s timeout.

Limits: a command run as a user who cannot write `/tmp` has no pid file,
so only its client is killed. A process that leaves the tree (a daemon that
double-forks) survives until the sandbox is deleted.

## Disk quota (T6b1)

Each container gets `--storage-opt size=<disk_mib>m`
(`cathedral/tee_box/executor.py:784`). Docker supports this on btrfs, zfs,
devicemapper, and overlay2 on xfs mounted with `pquota`. At startup the
worker reads the storage driver from `docker info`
(`cathedral/tee_box/executor.py:919`) and refuses to start on any other
driver unless the operator passes `--tee-box-no-disk-quota`. Docker checks
`pquota` only when a container starts, so on xfs without it every create
fails; creates never run unbounded.

## Packaging (T6b1)

`Dockerfile.tee-box-runsc` is a separate, opt-in build. It takes an SN94
TDX or SNP miner image pinned by digest (`MINER_IMAGE`, no default) and adds
gVisor `runsc` from release `20260817.0`, the last weekly release that
publishes runsc as a single binary. The build fetches it from Google's
release bucket and refuses any file whose sha256 differs from the pinned
one. `tests/test_tee_box_packaging.py` checks the pins.

The production `Dockerfile.sn94-audit-miner` and `Dockerfile.sn94-snp-miner`,
their publishers and their runtime contracts are unchanged. Adding runsc to
them before T6b2 qualification would change every miner's measured image for
a feature no miner can use yet. The runtime also has to sit with the Docker
daemon that runs it, which the miner container does not hold, so the layer
does not yet make a miner container a working box. The measured appliance
image (design plan step 2) is where runsc, the daemon and the host tools
belong.

## Storage (T8)

Owner decision 7 (design, "Owner decisions for v1", 2026-09-29): all
writable storage lives in guest memory, or on dm-crypt with integrity (AEAD)
under a key made inside the TD at boot; images are verified on read, with no
time-of-check gap between import and `runsc run`; and the host cannot roll
state back. The design's split (section 4, "Storage"): images read through
dm-verity; overlays, uploads and scratch on dm-crypt with integrity; the
replay, high-water and revocation state in guest memory only.

The TEE box runs only in TEE mode (the flags exist only on `worker serve`
and `serve-snp`), so every check below applies whenever the box is enabled,
and no flag relaxes it. `FakeExecutor`, the library API used directly, and
every worker without the TEE box flags are unaffected. The checks are in
`cathedral/tee_box/storage.py`, each probe injectable (`StorageProbe`,
`:119`) for tests; startup reports what it found in `tee_box.storage`.

### Images: started by content address

- **Import** (`cathedral/tee_box/executor.py:945`) runs
  `docker pull reference@digest`; Docker checks the manifest and every
  layer blob against the digest while it pulls. It then runs
  `docker image inspect reference@digest` (`:961`) for the local image id,
  the sha256 of the image config, and refuses unless that is a sha256 id
  and the image's `RepoDigests` name this reference at this digest (Docker
  Hub names are compared in Docker's short form). The id is kept in the
  executor's memory.
- **Create** re-checks right before `docker run` (`verified_image`,
  `:989`, called at `:1081`): `reference@digest` must still resolve to the
  recorded id and still be in `RepoDigests`. Otherwise the create gets
  `409` (`executor_refused`) and the image is forgotten, so it must be
  imported, and verified, again. A failed inspect gets `502` and keeps the
  image.
- **Start.** `docker run` takes the recorded id (`sha256:<config digest>`)
  with `--pull never` (`:749`, `:791`), and the create uses the image
  recorded at import whatever the caller's spec carries. No tag, path or
  `reference@digest` mapping sits between the check and the start, so a
  re-tag or a rewritten reference store after the check changes nothing.
- **The gap that remains.** The id pins the image config: Docker's classic
  image store re-hashes the config file against its id on every read, and
  the config lists the layers' diff ids. Docker does not re-hash layer
  contents when it builds a container's root filesystem. It maps diff ids
  to directories under its data root (`image/<driver>/layerdb`,
  `<driver>/<cache id>/diff`), and runsc reads files from them. So layer
  bytes are checked when pulled, not when read. What keeps the host from
  changing them after import is the storage under them: the data root is
  in guest memory or on dm-crypt with integrity (below). On dm-crypt the
  host can neither read nor forge a sector, but it can replay an older
  sector written under the same boot key: here, data the guest itself wrote
  to that sector earlier in the same boot, such as blocks of an image
  deleted earlier in the allocation. The design's dm-verity images close
  this, since every block is checked against a root hash when read. They
  need the central builder to emit verity images, which does not exist
  yet, so v1 still imports from a registry.
- The containerd image store (`driver-type io.containerd.snapshotter.v1`)
  keeps content outside the data root, so the worker refuses it
  (`cathedral/tee_box/storage.py:407`). The reasoning above is for the
  classic graphdriver store. Recent Docker releases enable the containerd
  store by default on new installs, so the appliance sets
  `"features": {"containerd-snapshotter": false}` in `daemon.json`.

### State: guest memory only

The central state (`--tee-box-central-state`) holds the replay cache, the
delegation high-water and the pushed revocation list
(`cathedral/central_access.py:168`). The lease and executor tables are
process memory already.

- **Decision: keep the file, require it on tmpfs or ramfs.** Relaunch
  between customers already empties it, and #244's freshness gate handles
  the empty state. Dropping the file in TEE mode would also empty it on a
  worker restart within one boot, while the worker's TLS key, which each
  central request is bound to, comes from a file and survives the restart:
  a request captured before the restart could then be replayed until it
  expires. On tmpfs the state survives a worker restart and is gone at
  relaunch, and the host cannot roll back guest memory. The state class
  also refuses `:memory:` by design: its lock file keeps an operator reset
  and a running worker apart.
- **Check** (`cathedral/tee_box/storage.py:154`, called at
  `cathedral/tee_box/configure.py:313` before the state is opened, since
  opening creates it): statfs(2) must report tmpfs (`0x01021994`) or ramfs
  (`0x858458f6`) for the state's directory, before and after resolving
  symlinks, and for every existing state file, its `.lock`, its SQLite
  `-journal`, `-wal` and `-shm` files, and the boot record `.boot` (see
  "Relaunch between customers (T9)"). A missing directory refuses: mount
  the tmpfs before the worker starts.
- **Why not dm-crypt for state.** Its sector tags do not stop the host
  replaying an older version of a sector written under the same key, which
  would roll the file back within one boot.
- **Swap.** tmpfs pages can be swapped out, so the worker refuses while
  any swap is on (`require_no_swap`, `cathedral/tee_box/configure.py:314`):
  `/proc/swaps` must hold only its header line. That includes swap on
  dm-crypt, which would bring the sector replay back, and zram, whose
  `backing_dev` writes idle pages to a disk in the clear. No device or file
  name is trusted to mean memory.

### Scratch: Docker's data root

Everything a sandbox writes lands under Docker's data root: container
layers, gVisor's root overlay (runsc's default `--overlay2=root:self` keeps
the upper layer in a file in the container's root directory), and `files`
and `tar` uploads, which go through `docker exec` into that overlay; so do
the imported layers. The worker asks the daemon for `DockerRootDir`
(`cathedral/tee_box/executor.py:1014`) and refuses
(`cathedral/tee_box/storage.py:391`) unless the mount serving it, and every
mount below it in `/proc/self/mountinfo`, is either of the two kinds below.
The serving mount is found by device, not by path: the last listed mount
whose major:minor is the `st_dev` that stat(2) reports for the data root,
and whose mount point contains it. A filesystem mounted later over a parent
of the data root hides a deeper mount, which then no longer serves the path,
so the longest matching mount point would be the wrong answer. The two
kinds:

- tmpfs or ramfs; or
- a device-mapper device whose sysfs `dm/uuid` starts with `CRYPT-`
  (cryptsetup's mapping; `CRYPT-SUBDEV-`, the dm-integrity device under a
  LUKS2 volume, does not count) and whose `dmsetup table` is all `crypt`
  segments carrying `integrity:<tag bytes>:aead`, or `:hmac(sha256)` or
  `:hmac(sha512)` (`parse_crypt_table`, `dm_crypt_integrity_check`), and
  whose cipher is allowed for that type. With `aead`:
  `capi:authenc(hmac(sha256|sha512),xts(aes))` with a `-random` or
  `-plain64` IV, or `capi:gcm(aes)` or `capi:rfc7539(chacha20,poly1305)`
  with `-random` only (with `-plain64` their nonce is the sector number, so
  a rewritten sector repeats it and the host could forge sectors); with an
  HMAC type: `aes-xts` or `capi:xts(aes)`, `-random` or `-plain64`. Any cipher
  containing `null` or `ecb` (`digest_null`, `cipher_null`) refuses, as
  does any other cipher, a table with no integrity parameter, an unkeyed
  one (`crc32c`, `none`), or any other target. With `--integrity hmac-sha256` and aes-xts,
  cryptsetup builds an `authenc(hmac(sha256),xts(aes))` AEAD cipher. With
  `aes-xts-plain64` the table shows it as `integrity:32:aead` (seen on a TD,
  2026-09-30); a `-random` IV also keeps the IV in the tag
  (`integrity:48:aead`).

Below the root, nsfs mounts hold no data and are skipped. An overlay mount
below the root (a running container's root filesystem) passes only when its
`upperdir`, `workdir` and every `lowerdir` (including `lowerdir+` and
`datadir+`) resolve, symlinks followed, under the data root, whose mounts
are all checked; relative layer paths, as Docker's overlay2 driver passes
them, are resolved from `<data root>/overlay2`. A layer anywhere else, such
as an upper directory on an unencrypted disk, refuses, and so does an
overlay with no lower layer. An overlay serving the root itself (a worker
inside a container) refuses: the worker must see the data root in the daemon's mount
namespace, as the appliance runs both. sysfs gives the dm uuid and name to
anyone but not the table, and `dmsetup table` needs CAP_SYS_ADMIN (the
device-mapper ioctl). The worker already runs as guest root for docker, nft
and tc; one that cannot read the table refuses. It runs
`/usr/sbin/dmsetup table <name>` as an argv list with a 15 s timeout, the
name read from sysfs and checked against a strict pattern.

The checks run once, at startup. The appliance must not change these mounts
or turn swap on afterwards. Checking only at startup is accepted for v1.

### The appliance boot step

No boot script in this repository sets up a TEE box guest. The SN94 miner
images are containers started by `scripts/run_sn94_signed_fleet_miner.sh`,
and the measured appliance image (design plan step 2) does not exist yet.
Before its Docker daemon and worker start, the appliance boot must:

1. Mount a tmpfs for the central state, for example
   `mount -t tmpfs -o mode=0700,size=64m tmpfs /run/cathedral-tee-box`, and
   pass `--tee-box-central-state /run/cathedral-tee-box/central.sqlite`.
2. Leave all swap off, zram included.
3. Make a random key inside the TD, never written out, and open the scratch
   disk with integrity (`/dev/urandom` in a TD is seeded by the guest
   kernel from RDRAND and RDSEED, not by the host):

   ```sh
   key_dir=$(mktemp -d /run/cathedral-key.XXXXXX)
   mount -t ramfs -o mode=0700 ramfs "$key_dir"     # never swapped
   head -c 64 /dev/urandom > "$key_dir/key"
   cryptsetup luksFormat --batch-mode --type luks2 \
     --cipher aes-xts-plain64 --key-size 512 --integrity hmac-sha256 \
     --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
     --key-file "$key_dir/key" /dev/<scratch disk>
   cryptsetup open --type luks2 --key-file "$key_dir/key" \
     /dev/<scratch disk> cathedral-scratch
   shred -u "$key_dir/key"; umount "$key_dir"; rmdir "$key_dir"
   mkfs.xfs -f /dev/mapper/cathedral-scratch
   mount -o pquota /dev/mapper/cathedral-scratch /var/lib/docker
   ```

   The LUKS2 header on the host's disk holds the volume key wrapped under a
   random passphrase that exists only in guest memory during boot, and
   every boot formats the disk again. A weak key derivation is enough for a
   random 64-byte passphrase. By default `luksFormat --integrity` writes the
   whole device to initialise the tags, which takes a while on a large disk;
   `--integrity-no-wipe` skips that, and sectors never written then fail to
   read, which T6b2 must qualify with the filesystem. xfs with `pquota`
   keeps the per-sandbox `--storage-opt size=` quota working. A data root on
   tmpfs also passes, sized from the box's memory reserve.
4. Set `"features": {"containerd-snapshotter": false}` in the Docker
   daemon's `daemon.json` (see "Images" above).

## Done on hardware (T6b2, 2026-09-30)

`scripts/tee_box_tdx_e2e/README.md` describes a harness that runs the real
worker (`cathedral worker serve` with the TEE box flags) on an Intel TDX
guest. It calls the worker over HTTPS as a central-access client, using
root-signed delegations and signed requests. It ran on a Polaris "Sealed CPU
Small" guest (GCP, Linux 6.17) against this repository at 40f818b. All seven
required checks passed. The results are in `docs/TEE_BOX_TDX_E2E_RESULTS.md`.

The provider launches with MRCONFIGID all zero. So the harness replaced one
piece, the measured-root binding reader: it used `build_tee_box_api`'s
`read_binding` hook to return `mrconfigid_for_root_keys` of the root key file
it installed. The following ran for real on the TD:

- **Measured root, fail-closed half.** The real TDREPORT reader refused the
  zero MRCONFIGID ("the launch bound no central root"). A binding for another
  root key file refused too.
- **Storage (T8).** Startup refused Docker's data root on plain ext4. It
  accepted the data root on a LUKS2 mapping made with `--integrity
  hmac-sha256`: the `CRYPT-LUKS2-` uuid, and the table
  `capi:authenc(hmac(sha256),xts(aes))-plain64 … integrity:32:aead`. It
  refused central state on a disk path and accepted it on tmpfs. There was no
  swap. Images were imported by digest and started by content address.
- **runsc.** Sandboxes ran under runsc with systrap, checked with `docker
  inspect` and gVisor's `dmesg`. Exec, list by label and delete worked.
- **Egress (T6b1).** The table was applied and verified at startup. An
  `internet` sandbox had its tc cap attached and verified, so Docker's
  `SandboxKey` and `eth0` held for runsc with `--network=sandbox`. The
  sandbox got no answer from four addresses: the GCP metadata server, the VPC
  gateway, the box's own address and the bridge gateway. It reached 1.1.1.1.
  The metadata server and the box's own listener did answer the TD itself.
  The VPC gateway answered neither HTTP nor ping from the TD, so that probe
  shows little.
- **RTMR3 and fresh-boot admission (T9).** RTMR3 read zero before the first
  lease, in sysfs and in `GET /v1/box`. A fresh quote from configfs-tsm
  passed the pinned strict verifier (TCB `UpToDate`), and
  `admit(require_fresh_boot=True)` admitted it. The policy allowlisted the
  quote's own measurement, since a rented TD has no approved image, so this
  does not show the measurement is an approved one. The first lease extended RTMR3
  to `RTMR3_CONSUMED`, and the next quote carried that value at body 472:520.
  Admission then refused it for `boot_consumed` only, and admitted it without
  `require_fresh_boot`.
- **One customer per boot (T9).** After customer A released, the box reported
  `needs_relaunch`. Customer B, holding another delegated key, got
  `409 relaunch_required`. A could lease again, and RTMR3 was not extended a
  second time.
- **Revocation freshness gate (T7).** Before any list was pushed, routes
  other than `GET /v1/box` got `409 revocation_list_required`. A list issued
  25 hours earlier got `409 revocations_stale`, both before and after a
  fresh one. A fresh list opened the routes.
- **Scope and revocation (T7).** Routes outside a delegation's scopes got
  `401`, and so did a request signed for another route. A revoked delegation
  got `401`, while a sibling delegation minted before it still worked.

The sandbox suite also passed in full on the TD.

## Not done (T6b2 and later)

What T6b2 still needs is our own measured image, SEV-SNP, and relaunch
orchestration by the control plane.

- **Our own measured image.**
  - **MRCONFIGID binding.** A launch with MRCONFIGID set to
    `mrconfigid_for_root_keys(file)` must start, and any other value must
    refuse. On hardware, the TDREPORT read works: on 2026-09-29, MRCONFIGID
    matched the kernel's `measurements/mrconfigid`. The refusing half also
    works (above). The starting half needs a launch whose MRCONFIGID we
    choose. The appliance image must install the root key file at
    `/usr/share/cathedral/central-root-keys.json`. No image does yet, and the
    Cathedral root has not been minted.
  - **dm-verity root.** The root key file, the worker and runsc must sit in
    the listed dm-verity root (design section 3). See also "dm-verity images"
    below.
  - **The appliance boot step.** The harness's `setup.sh` makes the tmpfs,
    turns swap off and builds the LUKS2 scratch by hand after boot, on a
    loop-backed file. The image must do this at boot, on its own scratch disk.
    It must also make the TLS key at each boot, on tmpfs. The harness keeps
    the key on disk. Nothing in the image but the worker may extend RTMR3.
  - **Image measurement.** No measured image ships runsc, the daemon runtime
    entry, the host tools and the worker together. The opt-in layer is not
    measured or published. Measurement approval follows the design's plan
    steps 2 to 7.
- **SEV-SNP.** An SNP box refuses to start. To fix that, either read
  HOST_DATA from the SNP report, or rely on the root key file sitting inside
  the listed dm-verity root (design section 3). The design notes that
  `MEASUREMENT` does not cover HOST_DATA, so admission would have to check it
  separately. SNP also needs its own mark in place of RTMR3 (a vTPM PCR). And
  runsc has not run under an SNP guest.
- **Relaunch orchestration (control plane, T9).** Ask the miner to relaunch
  after `needs_relaunch`. Before each new customer, admit with
  `require_fresh_boot=True` (and `last_released_at`) and pin that admission's
  SPKI. Take the measurement policy from the signed list
  (`measurement_policy`, T11) and push revocations. Give each customer (or
  better, each allocation) its own central key. Measure relaunch-to-admission
  time against the design's 5 minute target, and find out what the host's
  VMM does on a guest reboot.
- **Admission.** Admission (T3) must check that the listed measurement fixes
  MRCONFIGID to the Cathedral root. The control plane must push the current
  revocation list after every start and check what the box reports (see
  "Revocation list").
- **Signed high-water floor.** See the proposed `min_delegation_sequence`
  follow-up for #241 under "Revocation list".
- **Left open by the 2026-09-30 run.**
  - **DNS inside the sandbox.** A name lookup from inside gVisor on the
    user-defined bridge failed (`wget: bad address 'one.one.one.one'`). Egress
    to an IP address worked. Qualify DNS, or state that sandboxes get none.
  - **Egress cap and lapse drill.** The cap was verified in tc but its rate
    was not measured. On a box, flush the ruleset under a running `internet`
    sandbox and show the lapse path end to end: detection within the bound,
    `409` on calls, the quarantine cutting the sandbox's traffic at once, and
    the removal.
  - **Disk quota under runsc.** The harness ran with
    `--tee-box-no-disk-quota`. Confirm that runsc's root overlay counts
    against the `--storage-opt` quota on the qualified storage driver.
  - **Storage costs.** Measure what integrity costs in write throughput. The
    dm-integrity journal doubles writes; `--integrity-no-journal` avoids that,
    at the cost of crash consistency, which a one-boot scratch disk may not
    need. Also qualify `--integrity-no-wipe` with the filesystem. The full
    wipe of a 2 GiB device took 18 s. Check `RepoDigests` for every registry
    used; only Docker Hub was tried.
  - **gVisor overhead and sizing.** On 2026-09-29, against runc, CPU-bound
    work was about 2% slower under runsc, `stat` about 2× slower, and 64-byte
    writes about 7× slower. Capacity sizing and the guest reserve are not
    settled.
- **Measurement list (T11).** `scripts/cathedral_measurement_approval.py`
  adds one bare measurement to a profile, and `accept_release` refuses that
  on a TEE box profile. The approval tooling needs a mode that takes an
  image's fields (from a live quote) and writes the `tee_box` entry. The
  validator side (#256 reading the source record, or the signed list
  directly) and routing's use of `eligible_images` are not built.
- **dm-verity images.** Images come from a registry and are checked when
  pulled, not on every read (see "The gap that remains"). The central
  builder's verity images would close that.
- **State across restarts.** The executor tables live in memory. A restarted
  worker forgets its sandboxes and leases, and starts draining. Its sweep
  removes every container with the box label, so an earlier customer's
  sandboxes end rather than being adopted. The box is leasable only once that
  sweep comes back clean.

# Reliquary exclusive Workers deployment

Status: implementation candidate. Do not infer a tested release from these files. Test suites, live deployment and qualification are deferred at Fred's request. No host is selected and no customer allocation is enabled by this package.

The trial uses one dedicated machine running the unchanged Reliquary executor at revision 0be0cda0c9a73dc3f08e3af2a07dda9407635aa7. Its pool and physical admission ceiling are both 50. Every completed candidate batch retires its runsc sandbox. This package does not deploy the separate persistent Box product or the experimental multi-host dispatcher.

## Prepare the machine decision

Record the machine identity, architecture, CPU model and topology, whole-machine RAM, disk, kernel, Docker/Compose versions, access path and reservation owner. Reserve the complete execution machine for this allocation. The public API remains a shared control service.

Use Linux amd64. Choose kvm only when this host exposes a usable /dev/kvm. Otherwise choose systrap, as in the earlier VM compatibility experiment. Do not run the executor inside an existing gVisor Box. No unsandboxed fallback is configured.

CPU quota applies to the entire executor, shared among its 50 slots. It does not give each slot one dedicated physical core. Choose the quota from the machine's available CPU after host overhead. Size memory from whole-executor measurements in the deferred qualification. Fifty 256 MiB address-space limits total 12.5 GiB, but this is not resident memory sizing. The preparation tool's 16 GiB minimum is a configuration guard, not proof of sufficiency.

## Build the unchanged image

Use a clean checkout of the pinned source and an explicitly selected approved Docker build context. Local arm64 builders need amd64 emulation. The source builder rejects links and archives only the pinned revision into a fresh build context. It does not run a sandbox or a test workload. Dockerfile dependency and checksum assertions are part of the upstream image construction.

    python3 deploy/reliquary-workers/build.py --source /path/to/reliquary --docker-context APPROVED_BUILD_CONTEXT --output /path/to/new-image-package

The output contains executor-image.tar, image-id.txt and manifest.json. The manifest records the source revision, immutable image ID, worker/policy runtime digest, platform and artifact hashes. Qualification is explicitly NOT_RUN. An image ID is a local immutable content identifier. This flow does not require a registry or publish customer source to one.

The runtime digest is Reliquary's worker.py plus bundle/config.json digest. It does not attest the complete image, host or transport. Preserve the separate source revision and image ID in the deployment record.

## Issue separate TLS identities

Once the executor's stable address is known, issue the operator TLS package on a trusted machine. Use a new private output directory. Do not put keys in Git or the customer archive.

    python3 deploy/reliquary-workers/issue-pki.py --endpoint https://EXECUTOR_HOST:8443 --output /private/path/new-pki

The executor package contains only the server key, certificate and CA. The API package contains a separate client key, certificate and CA. The issuer directory retains the CA signing key under operator custody. Do not copy the issuer directory to either server. The default validity is 14 days. Record expiry and rotate before it. Certificates do not grant a customer entitlement.

## Render one disabled deployment

Resolve the customer owner UUID from the real Cathedral account or team. Do not substitute an email, miner UID or browser display name. Use the exact endpoint covered by the server certificate and a specific bind interface protected by firewall rules. Supply the selected machine's resource budget explicitly.

    python3 deploy/reliquary-workers/prepare.py \
      --manifest /path/to/new-image-package/manifest.json \
      --pki /private/path/new-pki \
      --output /private/path/new-deployment \
      --allocation-id reliquary-trial \
      --owner-id CUSTOMER_OR_TEAM_UUID \
      --endpoint https://EXECUTOR_HOST:8443 \
      --bind-address EXECUTOR_INTERFACE_IP \
      --host-name HOST_INVENTORY_ID \
      --cpus CPU_QUOTA --memory-gib MEMORY_LIMIT \
      --platform kvm \
      --expires-at 2026-09-11T18:00:00Z

Replace every placeholder and use the chosen trial expiry. The tool creates host/, api/, a systemd unit and allocation-record.json. All generated material is private. The API grant starts disabled. Prepare a new directory for each revision so earlier packages remain available.

## Install during the final deployment phase

These steps are not executed by preparation.

1. Configure the host firewall before starting the executor. Permit its mTLS port only from the API's verified egress addresses. Keep management access restricted. The executor's separate metrics listener binds 127.0.0.1:9876. Do not expose it through a public proxy. The inner runsc command uses --network=none. Qualification must independently exercise trusted-network and metadata access.
2. Transfer executor-image.tar to the host. Compare its SHA-256 with the manifest, then load the image using Docker. It is referenced by immutable image ID with pulling disabled.
3. Copy host/ into a new /etc/cathedral-workers/ALLOCATION_ID directory, with root ownership, directory mode 0700 and private file modes. Copy cathedral-reliquary@.service into /etc/systemd/system. Adjust /usr/bin/docker in the unit only if the selected distribution uses another installation path.
4. Run systemctl daemon-reload, then enable and start cathedral-reliquary@ALLOCATION_ID. The unit supervises Compose, restarts the service after failure, and waits up to 140 seconds for container shutdown. The container has one executor process, pool size 50, max inflight 50, reuse disabled, an immutable root filesystem, private PID/IPC namespaces and explicit CPU, RAM, PID and temporary-space budgets. It needs privileged runsc access on the dedicated host. Do not mount a Docker socket or trusted grader credentials into it.
5. Copy only api/pki/ to /etc/polaris/workers/ALLOCATION_ID/pki on each serving API instance. The API service user needs read access to the client material. Do not send it to the customer. Mount the whole directory if the API runs in a container, so atomic credential rotation is visible.
6. Set POLARIS_WORKERS_GRANTS_FILE to the durable API grant file. Use a shared or consistently replicated configuration directory for every API replica. A process-local file with diverging contents does not revoke access on another replica. Mount the directory, not a single inode replaced by atomic writes. Missing configuration grants no access. Malformed configuration fails closed.
7. Run the admission tool as the grant-file owner to merge the prepared disabled allocation. It preserves unrelated entries, refuses to replace existing IDs, takes a writer lock, keeps a private backup and replaces the file atomically.

    python3 deploy/reliquary-workers/admission.py install --store /path/to/workers-grants.json --package /private/path/new-deployment/api/grants.json

8. Deploy the coordinated API, CLI and site candidates through the normal repository release paths. The site needs exactly the Workers execute, capacity and health routes plus CLI login start/poll. Newly minted keys need workers:submit. Existing keys need reissue. Keep the static Workers routes before /v1/workers/{worker_id}.
9. Configure every reverse proxy and process manager for the full batch deadline. Reliquary accepts batches up to 120 seconds. The API uses a 130-second total bound and ctcli uses 135 seconds. The default origin timeout of a proxy in between must not truncate valid batches. Resolve this before the long-deadline acceptance case. No receipt or attestation service is added.

The API reports degraded process health during normal worker replacement. Its execution path still validates runtime, pool size and retirement policy but leaves bounded physical admission to the executor. Persistent loss of workers remains an operational fault, visible through health and metrics. No mechanism silently reduces the promised allocation to 32 slots.

## Enable only for the final qualification phase

The operator enables the prepared allocation after the deployment is ready for the deferred final suite. Enabling access does not record a test pass.

    python3 deploy/reliquary-workers/admission.py enable --store /path/to/workers-grants.json --allocation-id reliquary-trial

Complete the installed-client login, one known result, 32/50 load rows, observed physical occupancy, overload, timeout, containment, cleanup, failure and recovery cases documented in the delivery plan. Use the exact built artifact and host. Keep Reliquary's grader in shadow mode until its own archived-corpus qualification passes. Do not send trial access on the basis of these build files alone.

## Disable, drain and roll back

    python3 deploy/reliquary-workers/admission.py disable --store /path/to/workers-grants.json --allocation-id reliquary-trial

Disabling is allocation-specific and preserves the grant history. Apply the same snapshot to all serving API replicas. Requests already dispatched continue until their physical execution finishes. API reservation counters are not a drain authority.

After confirming admission is disabled on every API replica, use the trusted operator client certificate against the executor:

    python3 deploy/reliquary-workers/drain.py --endpoint https://EXECUTOR_HOST:8443 --pki /private/path/new-pki/api --runtime-id RUNTIME_ID

The helper waits for zero actual inflight over a ten-second quiet period. It fails if health is unavailable or the runtime differs. This reports HTTP execution drained, not completed security or cleanup qualification. Record final cleanup counters separately, then stop the systemd instance. Preserve logs and the previous deployment package. Do not force-stop a busy executor and label it a successful drain.

For rollback, restore the previous tested host package and coordinated API/site release, keeping admission disabled until its identity is confirmed. Do not restore an old grants file over unrelated customers. Re-enable only the intended allocation. Rotate/revoke the affected TLS and customer credential separately if required.

This trial package does not create Google resources, change subnet registration or validator weights, buy bundles, or enable paid billing.

# Intel TDX launch measurement

This file keeps its historical name, but Cathedral's approved value is not a
bare Intel MRTD.

The released verifier emits:

```text
tdx-measurement-sha256:<64 lowercase hex characters>
```

It is SHA-256 over the domain separator
`cathedral-tdx-measurement-v1\0` followed by these quote-body fields, in order:

```text
TD_ATTRIBUTES || XFAM || MRTD || MRCONFIGID || MROWNER || MROWNERCONFIG
              || RTMR0 || RTMR1 || RTMR2 || RTMR3
```

Both `cmd/cathedral-tdx-verifier/main.go` and
`cathedral/verify/tdx_quote.py` implement this exact contract.

## Why this is not MRTD

MRTD measures the initial trust domain. Cathedral's value also includes all
four runtime measurement registers. RTMR1 commonly includes the kernel and
initrd. A package install or upgrade that rebuilds initramfs can therefore
change Cathedral's value while MRTD stays unchanged.

Historical GCP TDX testing observed:

- `apt full-upgrade` plus Docker installation changed the Cathedral value;
- ordinary reboots without software changes kept it byte-identical; and
- two stop/start cycles also kept it byte-identical.

Those observations do not prove stability across a provider TDVF rollout.
Treat every changed value as unapproved until it is investigated. Do not infer
host placement from an ephemeral public IP change.

A matching value also does not, by itself, prove a particular OCI image. That
claim needs the image loader to extend the image identity into quoted measured
state or a separate reviewed binding.

## Policy use

The released QVL verifies the quote and emits the measurement. The sandbox
library's strict policy path then checks it against `Policy.allowed_measurements`
derived from a verified signed policy registry. An empty or missing allowlist
admits nothing.

The current direct SN39 validator does not consult this registry, retain the
emitted measurement, or use it as a weight gate. It consumes the QVL verdict
and verified stable platform identity. This section documents only the retained
sandbox strict-policy library.

Strict Intel TDX admission uses the typed `tcb_status` and advisory claims from
the same verified quote. Raw `tee_tcb_svn` is retained for audit and is not
numerically ordered. `min_tcb` remains a compatibility field, not the strict
Intel TDX production decision.

Within this policy path, the narrow claim is:

> SN39 mainnet: validated Intel TDX CPU compute.

The claim still requires fresh evidence, current collateral, allowed TCB
status, no unapproved advisories, debug disabled, exact REPORTDATA and TLS-SPKI
binding, and the expected work result. A registry entry or an old receipt is
not current eligibility.

## Approving a changed measurement

Never hand-edit a signed registry. Capture and propose a candidate with:

```bash
python scripts/cathedral_measurement_approval.py approve --help
```

The command requires the exact active `cpu_tdx` profile, an operator identity,
a reason, live evidence through the pinned verifier, and the registry signing
key. It writes an append-only approval record and emits a new monotonic signed
registry release. It does not deploy the release.

Before approval, determine whether the change came from an intended guest
update, an unexpected initramfs change, or provider firmware. A provider must
never approve its own machine automatically. Freeze boot-critical packages if
your operating policy requires a stable measurement.

## Rollback and revocation

- To withdraw a measurement, publish a higher signed registry release that
  marks it revoked.
- To correct a bad policy release, publish a corrected higher release.
- Never edit a signed release in place or move a release number or timestamp
  backwards.
- Durable high-water state rejects an older release after a newer one has been
  observed.

If fresh evidence has an unknown or revoked measurement, strict policy returns
failure. If current evidence is unavailable, report `NOT_PROVEN`; do not reuse
an earlier pass.

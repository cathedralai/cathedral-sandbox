# Intel TDX launch measurement

This file keeps its historical name, but Cathedral's approved value is not a
bare Intel MRTD. There are two values: the v1 launch measurement and the v2
image identity. Policy should list the v2 image identity (see "Image identity").

## Launch measurement (v1)

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
`cathedral/verify/tdx_quote.py` implement this exact contract. It is kept for
audit and for policies that already list it.

## Image identity (v2)

The verifier also emits `image_measurement` (verifier releases after
`cathedral-tdx-verifier-v1.0.0`; older releases omit it):

```text
tdx-image-sha256:<64 lowercase hex characters>
```

It is SHA-256 over the domain separator `cathedral-tdx-image-v1\0` followed by:

```text
TD_ATTRIBUTES || XFAM || MRTD || RTMR0 || RTMR1 || RTMR2 || RTMR3
```

`imageMeasurementID` in `cmd/cathedral-tdx-verifier/main.go` and
`ParsedTdxQuote.image_measurement` in `cathedral/verify/tdx_quote.py`
implement it. Both are tested against the same real GCP quotes and vectors in
`cmd/cathedral-tdx-verifier/testdata/gcp-mrowner/`.

Why the owner fields are left out (cathedral-sandbox #265):

- **MROWNER** is set by whoever launches the TD, not measured from the guest.
  On GCP (c3-standard-8, us-central1-a, 2026-10-02, 5+ VMs) it differed on
  every VM, including two VMs booted from one image on one host, so the v1
  value is a per-instance value there and a v1 allowlist in `enforce` refuses
  every new honest VM. Every other register was identical across those VMs.
  This is a small sample on one provider; other providers are not yet checked.
- **MROWNERCONFIG** is set by the launcher in the same way. It was all zero on
  GCP, but nothing in the guest image fixes it.
- **MRCONFIGID** is also launcher-set. It was all zero on GCP, where the guest
  owner cannot choose it. Cathedral only gives it meaning where Cathedral itself
  sets it: the TEE box binds its central-access root there
  (docs/TEE_BOX.md section 6). That binding is checked by the TEE box
  measurement list, which stays on v1 values with MRCONFIGID pinned per image;
  a v2 value alone does not prove it.

What v2 still covers: TD_ATTRIBUTES (including the debug bit), XFAM, the
initial TD (MRTD, the firmware), and RTMR0-3. On GCP RTMR1 holds the UKI's
Authenticode digest, so the kernel, initrd, command line and dm-verity root
hash are in it; a one-byte command-line change moved RTMR1 and the v2 value
exactly as predicted offline. RTMR0 can still vary with the VM shape, so list
one v2 value per image and shape. Data outside the measured boot chain (a
model file on a dm-verity disk, say) is not in either value; it relies on the
guest's own integrity checks.

**Policy use.** A strict policy may list v1 values, v2 values or both. The
Python verifier admits a quote when its v1 value is listed, or else when its
v2 value is listed; the verdict's `Attested.measurement` names the identity
that matched (v1 first, so a v1 policy behaves exactly as before), and
`Attested.launch_measurement` and `Attested.image_measurement` keep both for
audit. TEE box admission (`cathedral/capacity/admission.py`) and its policy
file accept `tdx-image-sha256:` entries in the same way (docs/CAPACITY.md). To
approve a v2 value, run `scripts/cathedral_measurement_approval.py approve
--identity image` with a verifier release that emits it.

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

The current direct SN94 validator does not consult this registry, retain the
emitted measurement, or use it as a weight gate. It consumes the QVL verdict
and verified stable platform identity. This section documents only the retained
sandbox strict-policy library.

Strict Intel TDX admission uses the typed `tcb_status` and advisory claims from
the same verified quote. Raw `tee_tcb_svn` is retained for audit and is not
numerically ordered. `min_tcb` remains a compatibility field, not the strict
Intel TDX production decision.

Within this policy path, the narrow claim is:

> SN94 mainnet: validated Intel TDX CPU compute.

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

## The TEE box measurement list

The owner's one signed measurement list (TEE box design decision 4,
2026-09-29) is this registry. A `cpu_tdx` profile whose signed `metadata`
has a `tee_box` object lists TEE box images by their quote-body fields
except RTMR3. Each image has two Cathedral values, derived rather than
listed: RTMR3 all zero on a fresh boot, and RTMR3 =
`SHA-384(0^48 || SHA-384("cathedral tee-box lease granted v1"))` once the
boot has served a lease (`RTMR3_CONSUMED`, `cathedral/tee_box/boot.py`). The
profile's `measurements` must be exactly those values, every image's
MRCONFIGID must bind a central root, and the release must still give the
worker policy (`to_policy`), so a box profile cannot change the shared TCB
controls.

`cathedral/capacity/measurement_list.py` verifies a release, checks those
entries, advances the high-water mark, and gives TEE box admission its
policy. `cathedral policy-registry export-measurement-policy` writes
cathedral-validator #256's local policy file from the same release, with a
`.source.json` record of the release and digest; `--scope box|all` is
required, and an enforcing list with nothing eligible is written as deny
all. The rules below apply unchanged. See docs/TEE_BOX_SERVICE.md, "The measurement list (T11)".

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

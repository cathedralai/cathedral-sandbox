# Launch owner runbook — generate the SNP HOST_DATA stamp

**Audience:** the person who can start SNP guests (hypervisor / cathedral-1/2
operator / WildCommunist / Contabo bare-metal owner).  
**Goal:** one honest boot where the guest’s live SNP report `host_data` equals
Cathedral’s official root digest — evidence for issue **#274**.  
**Not your job:** inventing a root, claiming PASS from test injects, or
shipping miner self-attestation.

Related: `SNP_HOST_DATA_LAUNCH.md`, `CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md`,
`TEE_HONESTY_STACK.md`.

---

## 1. What you are doing (plain)

AMD SEV-SNP puts a 32-byte field called **HOST_DATA** into every attestation
report (offset `0xC0`). The **hypervisor** chooses that value **at guest
create/boot**. The guest can only *read* it; it cannot invent a trusted stamp.

Cathedral’s rule:

```text
HOST_DATA  =  sha256( bytes of central-root-keys.json )
```

That file must be the **same** file installed inside the guest at:

```text
/usr/share/cathedral/central-root-keys.json
```

If those match, anyone verifying a quote can say: “this guest was launched
bound to Cathedral’s official root.” If they don’t match (or HOST_DATA is
zero / a test inject), sealed SNP acceptance stays **blocked**.

TDX does the same idea with **MRCONFIGID** (first 32 bytes = same digest,
16 zero pad). This runbook is the **SNP** launch path.

---

## 2. Where this happens (machines / seats)

You need **three different places**. A Turin KVM *guest* IP (e.g. a rented VM
without `/dev/sev`) is **not** enough.

| Place | What it is | Why |
| --- | --- | --- |
| **A. Root ceremony store** | Offline / HSM location holding the official `central-root-keys.json` (public file the guest will serve) | Stamp must pin *something* owned by Cathedral |
| **B. Launch host (hypervisor)** | Bare AMD Genoa/Turin (or Milan) with SEV-SNP **enabled in BIOS**, host kernel SNP support, and a VMM that can set `host-data` (QEMU SEV-SNP, cloud-hypervisor, or your internal launcher) | **Only here** can you set HOST_DATA at boot |
| **C. SNP guest** | The confidential VM you boot (cathedral-1 / cathedral-2 / production tee-box guest) with `/dev/sev-guest`, the tee-box image, and that root file at `/usr/share/cathedral/...` | Where you **read** the report and prove the stamp |

**Wrong place (will fail):** logging into a normal KVM guest and hoping to
“set host-data” — that machine *is* the guest; it has no VMM stamp API.

**Right place:** SSH/console on the **hypervisor** (or the cloud API that
creates SNP VMs with a host-data parameter).

### Seats you must know before you start

| Seat | Gives you | Without them |
| --- | --- | --- |
| **Root owner** | Official `central-root-keys.json` + its sha256 | Nothing trusted to pin |
| **Image owner** | Guest image that embeds that exact file + measurement-list id | Boot may run wrong root |
| **You (launch owner)** | Ability to pass `host-data` on create and reboot | Stamp never lands |

Fill names in `CATHEDRAL_ROOT_AND_IMAGE_OWNERSHIP.md` before calling #274 done.

---

## 3. How — step by step

### Step 0 — Preconditions (stop if any fail)

On the **launch host (B)**:

```bash
# SNP capable host (examples; adjust to your distro)
ls /dev/sev                    # should exist on bare SNP host
dmesg | grep -i sev            # SEV-SNP enabled
# CPU should be EPYC Milan / Genoa / Turin with SNP; not a nested KVM guest
# without nested SNP
```

You must also have:

- Official root file from Root owner (not a laptop test file).
- Guest disk/image from Image owner that installs that file at  
  `/usr/share/cathedral/central-root-keys.json`.
- VMM docs for **your** stack’s `host-data` flag (name varies; value is always
  the same 32 bytes).

### Step 1 — Get the official root file

From Root owner (secure channel — not Discord paste of secrets; the **public**
`central-root-keys.json` is fine to copy for hashing):

```bash
# On a trusted builder (laptop or bastion with cathedral-sandbox checked out)
scp root-owner:/secure/cathedral/central-root-keys.json ./central-root-keys.json
sha256sum central-root-keys.json
# Record: sha256:<hex>  — this is the "file digest"
```

### Step 2 — Compute HOST_DATA (do not invent it)

```bash
cd /path/to/cathedral-sandbox
# branch with host_data_cli: feat/tee-box-snp-startup-gates (or main once merged)
python -m cathedral.tee_box.host_data_cli --root-keys ./central-root-keys.json
```

Output: **64 hex characters** (32 bytes). Example shape:

```text
a1b2c3d4...   # 64 hex chars, no 0x prefix
```

Rules:

- Hash the **file bytes** once. Do **not** hash the hex again.
- Do **not** pad, truncate, or zero-extend.
- That hex **is** what the VMM must put in HOST_DATA.

Sanity: `sha256sum` of the file (raw) should equal this CLI hex.

### Step 3 — Install the same file into the guest image

Image owner / you ensure the guest filesystem contains **byte-identical** file:

```text
/usr/share/cathedral/central-root-keys.json
```

If the guest has a different file, boot will fail measured-root startup or
admit will see a bind mismatch.

### Step 4 — Launch the SNP guest with host-data set

On the **hypervisor**, create/boot the guest with your VMM’s host-data
parameter set to the **exact** CLI hex from Step 2.

Conceptual (flag names differ by VMM — use your platform’s docs):

```text
# Conceptual — NOT a copy-paste for every stack
VMM create-snp-guest \
  --image <cathedral-tee-box-snp-image> \
  --host-data <64-hex-from-host_data_cli> \
  ...other SNP policy: no debug, no migration agent, VMPL0, etc.
```

What “set host-data” means in AMD terms: the launch configuration that becomes
the attestation report field at offset `0xC0`. If your cloud only exposes
“create confidential VM” with **no** host-data API, that cloud **cannot** close
this bolt until they add it or you use bare metal + QEMU/CH that can.

Record for evidence:

- VMM product + version  
- Exact flag / API field you set  
- Hex you passed  

### Step 5 — Boot and prove from inside the guest

SSH into the **guest (C)** (cathedral-1/2). Confirm devices and root file:

```bash
ls -la /dev/sev-guest
sha256sum /usr/share/cathedral/central-root-keys.json
# Must equal Step 1 / Step 2 digest
```

Collect a fresh report and read HOST_DATA (pinned snpguest path preferred;
see `AMD_SEV_SNP_FRIEND_TEST.md` for install):

```bash
# Example shape — use Cathedral's pinned snpguest where required
snpguest report ./attestation-report.bin ./request-data.bin --vmpl 0
# Then extract bytes at offset 0xC0 length 32, as hex:
python3 - <<'PY'
from pathlib import Path
r = Path("attestation-report.bin").read_bytes()
assert len(r) >= 0xE0
print(r[0xC0:0xE0].hex())
PY
```

Or, with cathedral-sandbox on the guest:

```bash
python - <<'PY'
from cathedral.verify.snp import parse_snp_report
from pathlib import Path
print(parse_snp_report(Path("attestation-report.bin").read_bytes()).host_data.hex())
PY
```

**Pass condition:** printed hex **==** Step 2 CLI hex character-for-character.

Also confirm tee-box measured-root startup succeeds (guest refuses to start
services if HOST_DATA ≠ file digest when SNP measured root is enabled).

### Step 6 — Post evidence on #274

Fill and attach (no secrets beyond the public root file hash):

```text
HOST_DATA evidence — cathedral-N — YYYY-MM-DD

Root owner: ________
Image owner: ________
Launch owner: ________

central-root-keys.json sha256:
host_data_cli hex:
VMM host-data hex actually launched:
SNP report host_data hex:
Match CLI == report? YES/NO
Image id / measurement-list rev:
Inject used? NO (required)

Attached: snp report dump / snpguest output
Hypervisor: <host name / SKU / VMM version>
```

**Done when:** Match=YES, Inject=NO, seats named. Optional follow-up: SNP e2e
**without** `E2E_HOST_DATA_HEX`.

---

## 4. What “success” vs “fake” looks like

| Outcome | Honest? |
| --- | --- |
| CLI hex == live report `host_data`; guest root file same digest; no inject | **Yes** — HOST_DATA bolt green |
| `E2E_HOST_DATA_HEX` / test `read_binding` override | **No** — wiring only |
| Guest is plain KVM, no `/dev/sev-guest` | **Impossible** here |
| Different root file in guest than hashed for launch | **No** — mismatch |
| Cloud VM API with no host-data parameter | **Blocked** until API or bare VMM exists |

---

## 5. How this ties to software already in-repo

After you stamp:

- Guest startup: `cathedral.tee_box.measured_root` reads HOST_DATA and checks
  the root file.
- Remote admit: `admit(..., expected_root_digest="sha256:...")` refuses wrong
  bind (TDX uses MRCONFIGID the same way).
- Eng **cannot** finish this from GitHub alone; they already built read/verify.

Your stamp is the missing physical/launch step.

---

## 6. If you do not have a launch host yet

You cannot generate an honest stamp. Options:

1. **Provision bare Genoa/Turin** with SNP + QEMU/CH (or vendor SNP stack).  
2. **Use a cloud** that documents SNP create + host-data (or equivalent).  
3. **Partner** who already runs the VMM (they become Launch owner; you still
   supply official root + image).

Until then: keep SAT + TDX/sealed sales as the live story; do **not** claim
#274 PASS.

---

## 7. Checklist to hand the teammate

```text
[ ] I am Launch owner (can set VMM host-data on SNP create)
[ ] Root owner gave me official central-root-keys.json + sha256
[ ] Image owner confirmed guest image embeds that exact file
[ ] I ran host_data_cli and saved the 64-hex output
[ ] I launched guest with that exact host-data (no re-hash)
[ ] Inside guest: report host_data == CLI hex
[ ] Inject = NO
[ ] Evidence pack posted on cathedral-sandbox #274
```

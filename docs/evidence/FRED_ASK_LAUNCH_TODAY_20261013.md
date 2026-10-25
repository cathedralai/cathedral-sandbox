# Fred — need these to launch SNP staging today

**Date:** 2026-10-13  
**From:** Toby (staging owner)  
**Goal today:** create → exec → native-evidence → usage → delete → independent guest-gone on real AMD

## Already done (no action needed)

- Adapters from your `66deb72e` complete bundle integrated (hashes match)
- Isolated SQL broker claim proved (`systrap-snp-customer-v1`)
- Owned staging URL + minted staging key (`/v1/account` 200)
- AMD create fail-closed proved: `503 snp_customer_path_unqualified` (unbilled) until qualified install
- Boot draft ready for **new** guest on free ports `:2226` / `:8444`
- Existing guests `:2222` / `:2224` / `:2225` untouched
- Canary script ready

We are **not** blocking on Railway `acaa2961` or key `b30b7437` secret — owned isolated staging is the launch path.

---

## Need from you today

### 1. Image / policy accept

Candidate: `cathedral-staging-snp-0029cec5-20261013`

- raw SHA-256: `a7ad573bc5801d404525823ef670f632860fe2d41174c58a0df0c2ceac7abae5`
- Also accept dependency pins: CPython 3.13.9 + sr25519 `0.2.2` (as in addendum)

### 2. Exact boot inputs (do not guess)

Please send:

| Input | Why |
|-------|-----|
| Full kernel `append` / `roothash=…` | Measured boot; draft has placeholder |
| `host-data` (Cathedral root digest, base64) | SNP `sev-snp-guest` object |
| Confirm ports `:2226` (SSH) + `:8444` (HTTPS) | Free on Cherry; preserves existing guests |

Host: `84.32.220.48` · draft: `snp-staging-boot-draft-20261013.md`

### 3. 15-minute central grant (after guest HTTPS is up)

- Intended smoke TTL: **900 seconds**
- We will send the review packet (TLS pin / measurement / scopes) as soon as the guest is up
- Please be ready to sign the same day

### 4. Install / prober secrets (secure channel — not Discord/chat)

| Material | Use |
|----------|-----|
| Journal cipher for staging install | Encrypted operation journal |
| Independent prober key (≠ worker / caller) | `central_guest_gone` absence proof |
| Accepted policy / verifier pin to bind | `TobySandboxes.from_qualified_workers` |

---

## What we do in parallel

1. Staging `install` scaffold (fail-closed until qualified inputs present)
2. Finalize boot script from the draft (launch only after 1+2)
3. Keep canary hot:
   ```bash
   export STAGING_BASE_URL="$(cat /tmp/cathedral-snp-staging-url.txt)"
   export STAGING_API_KEY="$(cat /tmp/cathedral-snp-staging-api-key)"
   ./cathedral-sandbox/scripts/snp_staging_canary.sh
   ```

---

## Copy/paste message

Fred — launching SNP staging today on the owned isolated API. Adapters from your `66deb72e` complete bundle are integrated; broker claim, staging URL/key, and fail-closed AMD create are proved.

Need from you today:

1. **Image/policy accept** for `cathedral-staging-snp-0029cec5-20261013` (raw `a7ad573b…` + CPython 3.13.9 / sr25519 pins)
2. **Exact boot inputs:** full `roothash`/append, `host-data` root digest (b64), confirm new guest on `:2226`/`:8444` only
3. **15-min central grant** after guest HTTPS is up — we’ll send the review packet immediately; please be ready to sign
4. **Prober/install secrets** on a secure channel: journal cipher, independent prober key, accepted policy/verifier pin

Optional: skip Railway/`b30b7437` — we’re on isolated staging with our own key.

We’ll parallel the install scaffold + boot script + canary. Ping when (1)+(2) clear and we boot immediately.

Success target today: create → exec → native-evidence → usage → delete → independent guest-gone on real AMD.

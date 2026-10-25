# 15-minute central grant packet (staging SNP)

## When to fill
Only **after**:
1. Corrected image (not `a7ad573b`) is booted on `:2226` / `:8444`
2. Guest HTTPS is up and TLS SPKI is pinned
3. Native quote / measurement / root digests are verified

## How
1. Copy `snp-staging-grant-packet.template.json` → a working file (not secrets in git if filled with live values)
2. Fill `staging_context.*` measured fields
3. Align public review fields with Fred’s current root/caller parameters (see handoff `PUBLIC_SIGNING_REVIEW.json` shape)
4. Leave `signature` / `issued_at` / `expires_at` / `sequence` **null** until Fred signs
5. Send packet on the **secure / review channel** Fred uses — assistants never hold root seed
6. Intended TTL: **900 seconds**

## After signature
- Install grant materials into the qualification dir / central signer
- Set `SNP_STAGING_INSTALL=1` and restart isolated API
- Run canary immediately (grant window is short)

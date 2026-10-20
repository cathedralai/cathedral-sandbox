# Discord → Fred (staging policy signer — copy/paste as normal message)

@wallscaler Clarifying seats: I own staging (API/caller/observer/diagnostic boot). I was missing only the **policy-registry** signing seat. Sky is unreachable, so I’ve minted a **staging/pilot** policy signer for trust-bootstrap — not a claim on production image-owner authority.

**Staging policy-signing key (public only — private stays with me)**
- `signing_key_id`: `snp-staging-policy-20261014`
- Ed25519 pubkey b64: `Xo4QRPomjFg1j4fcd0WYRSSx+3JoJfDJJcfxtcLEWDg=`
- pubkey hex: `5e8e1044fa268c58358f87dc7745984524b1fb726825f0c925c7f1b5c2c45838`
- pubkey sha256: `c3533129d8e45a73f6104ba048da35138b53f5cda8910abd3c69c8725b0b3b3f`

Please accept this pin in the staging trust-bootstrap / trusted-keys set for the diagnostic→customer path. I will not reuse the older `:2225` guest acceptance. No new image rebuild required for this step — current verity diagnostic candidate remains the artifact; what’s missing is signed policy/checkpoint against a known key.

Diagnostic boot report earlier still stands. Customer qualification still waits on your acceptance of this pin + signed policy/checkpoint + grant after HTTPS.

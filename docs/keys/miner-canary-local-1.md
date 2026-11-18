# miner-canary-local-1

Miner release signing key, canary channel only. Local interim key on the
Cathedral ops server; it moves to AWS KMS (AB#799). See
`docs/MINER_AUTO_UPDATE.md`, "Committed trust root: local interim custody".

| Field | Value |
|---|---|
| Algorithm | Ed25519 |
| Purpose | `miner_canary` (miner release records, channel `canary`) |
| Public key (hex) | `a805f5e29a058372d51122e9c5b2554c97e485199c7273a6966d6c838296d1e1` |
| Public key (PEM) | `miner-canary-local-1.pub.pem` |
| Fingerprint | `sha256:4bb720a31355306392d9545a42873501c11dad8e663664be086efcac6e4237f0` (SHA-256 of the 32 raw bytes) |
| Trust root | `deploy/miner-update/release-keys.json`, SHA-256 `4e91dec00701f7cc579a43012ae12a6a3e26bebb005f5460b8f8b0b57fa06976` |
| not_before | 2026-11-17T15:59:33Z (generation) |
| not_after | 2027-02-15T00:00:00Z (planned retire date, advisory) |

The window is advisory. The `cathedral_miner_release_keys_v1` trust root
carries no time window, so a miner host trusts this key until a signed
release drops it or the host is bootstrapped again from a root without it.
AB#799 must ship a canary release that drops or rotates this key before
2027-02-15. The KMS rotation moves `not_after` to rotation start + 1 h.

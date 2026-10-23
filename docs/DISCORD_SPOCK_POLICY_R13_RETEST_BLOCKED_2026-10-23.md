Mr Spock — Eng ack policy **r13** + tip `a8f77a30` healthy. Roster refresh **POSTED** (`sha256:0dc2cd80…`, seq `1792772071`, UID5 `.46:8081`).

**Blocked on guest, not policy.** After roster + supply bump, no waiting offer for 10m. Railway join discovery still `ConnectError` every ~60s (not `JoinRejected`). Eng laptop: TCP open on `.46:8081`/`:8444`, but TLS handshake fails (alert 40 / EOF; no peer cert). Sealed create → `503 snp_capacity_unavailable` / `no_verified_supply`.

Need Cherry guest TLS back (`cathedral-customer-guest-cherry46` restart historically fixed dead TLS). Once `:8444` answers (404 OK) and discovery seals a waiting offer, Eng reruns Join + IDE + Ditto + Reliquary create→exec→delete. Noted: lease ≤ policy_sign + 24h → ask you for **r14** tomorrow if leases fail.

Evidence: `docs/evidence/STAGING_SEALED_RETEST_20261023T161428Z.md`

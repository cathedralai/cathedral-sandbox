# Retired enrollment library

This is a developer note for code which remains covered by tests. It is not a
current SN39 mining step.

The old enrollment service accepted signed miner submissions and restricted
them with an operator-signed coldkey allowlist. The current direct validator
does not call that service. It discovers serving miner axons from SN39 and
authenticates worker requests with the validator-access protocol described in
the repository [README](../README.md).

The retained library has separate dependency roles:

```bash
pip install -e '.[enrollment-service]'
pip install -e '.[enrollment-operator]'
```

`scripts/cathedral_enroll_allowlist.py` remains the producer and verifier for
legacy fixtures. `preflight_signature_verifier` must succeed before its
service opens a listener.

Do not deploy this service, expose `/v1/enroll`, or add its allowlist to the
current miner instructions.

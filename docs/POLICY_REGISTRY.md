# Retained policy-registry library

This file is not a miner or validator guide.

The current direct SN39 validator does not consume Cathedral's signed policy
registry, receipt epochs, evidence exporter, signed weight vector, or freshness
republisher. Miners do not need a policy signer, registry timer, publisher, or
Cathedral API.

The `cathedral.policy_registry` module and its examples remain for product
library compatibility and historical artifact verification. Do not deploy the
example republisher as part of current SN39 mining.

Current miners start at the repository [README](../README.md). Developers who
maintain the retained library should use its source and tests as the contract.

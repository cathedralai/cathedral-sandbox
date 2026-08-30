# Retained lifecycle library

This file is not a miner or validator guide.

The current direct SN39 validator does not use Cathedral's central enrollment
database, lifecycle states, reenrollment commands, frozen epochs, or receipts.
It discovers serving miners from the chain and verifies fresh evidence and work
in each scoring round.

The `cathedral.lifecycle` and `cathedral.enroll` modules remain for product
library compatibility and historical tests. Do not run `cathedral lifecycle`
to start, repair, or retire a current SN39 miner.

Current miners start at the repository [README](../README.md). Developers who
maintain the retained library should use its source and tests as the contract.

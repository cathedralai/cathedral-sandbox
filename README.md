# Signed miner release channel

Machine-readable only. Each file is one signed release record consumed by
`cathedral-sn39-miner-update`. Records are verified by Ed25519 signature,
product, schema, channel, sequence and expiry before a miner acts on them, so
this branch is a transport and not a trust boundary.

Do not edit by hand. Records are produced offline by
`deploy/miner-update/build_signed_miner_release.py`.

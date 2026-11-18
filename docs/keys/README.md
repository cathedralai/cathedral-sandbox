# Published signing keys

Public keys only. Private keys never enter this repository, a room, a CI log
or secret, or the website. Fingerprints are SHA-256 of the 32 raw Ed25519
public key bytes, lowercase hex.

## sealed-hotels-local-1 (AB#382 signed sealed hotel measurement list)

- Purpose: signs `cathedral_sealed_hotels_v1` releases (`docs/SEALED_HOTELS_V1.md`).
- Algorithm: Ed25519.
- Public key (raw hex): `fce2eb94433c0d0766be0c9c186de252e7fa99d6956ff1850f3159af6002e358`
- Public key (base64): `/OLrlEM8DQdmvgycGG3iUuf6mdaVb/GFDzFZr2AC41g=`
- Fingerprint (SHA-256 of raw key): `626c66e4c5ccacf20da7a95ef519f6372903ddcdadbe816d234e0932b7087f92`
- PEM: `sealed-hotels-local-1.pub.pem`
- Pin window (enforced by verifiers): `not_before` 2026-11-17T15:59:33Z (generation), `not_after` 2027-02-15T00:00:00Z.
- Pin file: `sealed-hotels-pins.json` (`cathedral_sealed_hotels_pins_v1`); the same pin is built into `room-kit/verify_sealed_hotels.py`.
- Custody: local interim key, encrypted PEM on the Cathedral ops server (root only). It moves to AWS KMS (`sealed-hotels-kms-1`); at that rotation this key's `not_after` is shortened to rotation start + 1 hour and a new pin is published here. Root on that server can sign with this key until then.

The website copy (`https://cathedral.computer/signing-keys.json`) is served from
the same site as the signed list, so it is not an independent trust root:
compare the fingerprint above (and on the AB#382 card) out of band.

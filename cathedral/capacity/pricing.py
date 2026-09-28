"""Market-price value of verified capacity, and the consumer minimum shapes.

A box earns the market value of what the prober verified: its vCPUs at the
vCPU rate for its kind (TEE or bare metal) plus its memory at the memory rate.
The rates come from a price table the SN94 owner signs and validators pin, so
weights follow market prices, never hard-coded multipliers. A box smaller than
every consumer subnet's minimum shape (for example SN81 or SN120) earns zero,
because no customer job could run on it.

Amounts are integers in micro-units of ``currency`` per hour, so the same
inputs give the same value on every validator. Each table carries a
``sequence``; a validator keeps the highest it has verified and that table's
``table_digest``, so whoever serves tables cannot roll it back to an older
signed one, nor swap in a different table signed at the same sequence.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from cathedral.capacity.challenge import MAX_LANES
from cathedral.capacity.receipt import BOX_KINDS, canonical_bytes

SCHEMA = "cathedral_capacity_price_table_v1"
_PROFILE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
_KEY_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}")
_HEX64 = re.compile(r"[0-9a-f]{64}")
MAX_MICRO = 10**12
MAX_PROFILE_MEMORY_GIB = 4096


class PriceTableError(ValueError):
    """A price table is malformed or not signed by a pinned key."""


@dataclass(frozen=True)
class Rate:
    vcpu_hour: int
    gib_hour: int


@dataclass(frozen=True)
class Shape:
    vcpus: int
    memory_gib: int


@dataclass(frozen=True)
class PriceTable:
    currency: str
    rates: Mapping[str, Rate]
    consumer_profiles: Mapping[str, Shape]
    effective_from: datetime
    key_id: str
    sequence: int
    digest: str  # table_digest of the signed body: pin it with the sequence

    def fits_any_profile(self, vcpus: int, memory_gib: int) -> bool:
        return any(
            vcpus >= shape.vcpus and memory_gib >= shape.memory_gib
            for shape in self.consumer_profiles.values()
        )

    def value(self, *, kind: str, vcpus: int, memory_gib: int) -> int:
        """Micro-units per hour this capacity is worth; zero below every profile."""

        if kind not in self.rates:
            raise PriceTableError(f"no rate for box kind {kind!r}")
        for name, value in (("vcpus", vcpus), ("memory_gib", memory_gib)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise PriceTableError(f"{name} must be a positive integer")
        if not self.fits_any_profile(vcpus, memory_gib):
            return 0
        rate = self.rates[kind]
        return vcpus * rate.vcpu_hour + memory_gib * rate.gib_hour


def _micro(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_MICRO:
        raise PriceTableError(f"{name} must be an integer from 0 to {MAX_MICRO}")
    return value


def table_digest(table: Mapping[str, Any]) -> str:
    """SHA-256 of a table's canonical body (any signature left out): what a
    validator pins beside the sequence to refuse a different same-sequence table."""

    return hashlib.sha256(
        canonical_bytes({key: value for key, value in table.items() if key != "signature"})
    ).hexdigest()


def _body(table: Mapping[str, Any]) -> PriceTable:
    if set(table) != {
        "schema",
        "currency",
        "rates",
        "consumer_profiles",
        "effective_from",
        "key_id",
        "sequence",
    }:
        raise PriceTableError("price table has the wrong fields")
    if table["schema"] != SCHEMA:
        raise PriceTableError("price table schema is unsupported")
    currency = table["currency"]
    if not isinstance(currency, str) or not re.fullmatch(r"[a-z]{3,8}", currency):
        raise PriceTableError("currency must be a short lowercase code, such as usd")
    rates_in = table["rates"]
    if not isinstance(rates_in, Mapping) or set(rates_in) != set(BOX_KINDS):
        raise PriceTableError("rates must price exactly tee and bare_metal")
    rates: dict[str, Rate] = {}
    for kind, rate in rates_in.items():
        if not isinstance(rate, Mapping) or set(rate) != {"vcpu_hour", "gib_hour"}:
            raise PriceTableError(f"rate {kind} must have vcpu_hour and gib_hour")
        rates[kind] = Rate(
            _micro(rate["vcpu_hour"], f"{kind}.vcpu_hour"),
            _micro(rate["gib_hour"], f"{kind}.gib_hour"),
        )
    profiles_in = table["consumer_profiles"]
    if not isinstance(profiles_in, Mapping) or not profiles_in:
        raise PriceTableError("consumer_profiles must name at least one consumer")
    profiles: dict[str, Shape] = {}
    for name, shape in profiles_in.items():
        if not isinstance(name, str) or _PROFILE.fullmatch(name) is None:
            raise PriceTableError("consumer profile names are short lowercase identifiers")
        if not isinstance(shape, Mapping) or set(shape) != {"min_vcpus", "min_memory_gib"}:
            raise PriceTableError(f"profile {name} must have min_vcpus and min_memory_gib")
        vcpus, memory = shape["min_vcpus"], shape["min_memory_gib"]
        # no profile may ask for more vCPUs than the challenge can prove
        for label, value, top in (
            ("min_vcpus", vcpus, MAX_LANES),
            ("min_memory_gib", memory, MAX_PROFILE_MEMORY_GIB),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= top:
                raise PriceTableError(f"profile {name} {label} must be from 1 to {top}")
        profiles[name] = Shape(vcpus, memory)
    effective = table["effective_from"]
    if not isinstance(effective, str) or not re.fullmatch(
        r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", effective
    ):
        raise PriceTableError("effective_from must be YYYY-MM-DDTHH:MM:SSZ")
    try:
        effective_from = datetime.strptime(effective, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:  # the right shape, but no such date or time
        raise PriceTableError("effective_from is not a real date and time") from exc
    key_id = table["key_id"]
    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise PriceTableError("key_id is malformed")
    sequence = table["sequence"]
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise PriceTableError("sequence must be a positive integer")
    return PriceTable(
        currency=currency,
        rates=rates,
        consumer_profiles=profiles,
        effective_from=effective_from.replace(tzinfo=timezone.utc),
        key_id=key_id,
        sequence=sequence,
        digest=table_digest(table),
    )


def sign_price_table(table: Mapping[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    _body(table)
    return {
        **table,
        "signature": base64.b64encode(private_key.sign(canonical_bytes(table))).decode(),
    }


def load_price_table(
    signed: Mapping[str, Any] | str | bytes,
    *,
    owner_keys: Mapping[str, Ed25519PublicKey],
    now: datetime,
    minimum_sequence: int,
    pinned_digest: str | None = None,
) -> PriceTable:
    """Verify a signed table against the pinned owner keys and parse it. A table
    that is not yet effective, or older than ``minimum_sequence`` (the highest
    this validator has already verified), is refused. With ``pinned_digest``
    (that table's ``digest``), a table at ``minimum_sequence`` must be that same
    table."""

    if not isinstance(now, datetime) or now.utcoffset() is None:
        raise PriceTableError("now must be a timezone-aware datetime")
    if (
        not isinstance(minimum_sequence, int)
        or isinstance(minimum_sequence, bool)
        or minimum_sequence < 1
    ):
        raise PriceTableError("minimum_sequence must be a positive integer")
    if pinned_digest is not None and (
        not isinstance(pinned_digest, str) or _HEX64.fullmatch(pinned_digest) is None
    ):
        raise PriceTableError("pinned_digest must be 64 lowercase hex characters")
    if isinstance(signed, (str, bytes)):
        try:
            signed = json.loads(signed)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise PriceTableError("price table is not JSON") from exc
    if not isinstance(signed, Mapping) or "signature" not in signed:
        raise PriceTableError("price table is not a signed object")
    body = {key: value for key, value in signed.items() if key != "signature"}
    table = _body(body)
    key = owner_keys.get(table.key_id)
    if key is None:
        raise PriceTableError("price table is signed by an unknown key")
    try:
        key.verify(base64.b64decode(signed["signature"], validate=True), canonical_bytes(body))
    except (InvalidSignature, binascii.Error, TypeError, ValueError) as exc:
        raise PriceTableError("price table signature does not verify") from exc
    if table.effective_from > now:
        raise PriceTableError("price table is not effective yet")
    if table.sequence < minimum_sequence:
        raise PriceTableError("price table is older than one already verified")
    if (
        pinned_digest is not None
        and table.sequence == minimum_sequence
        and table.digest != pinned_digest
    ):
        raise PriceTableError("price table differs from the one pinned at its sequence")
    return table

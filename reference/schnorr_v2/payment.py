"""PaymentBinding V1 structure + V2 TAG_PAYMENT hash (experimental)."""

from __future__ import annotations

from typing import Any

from reference import cbor
from reference.payment_binding import build_payment_binding, encode_payment_binding
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.tags import TAG_PAYMENT


def make_fixture_payment_binding(
    script_pubkey: bytes | None = None,
) -> dict[int, Any]:
    """Minimal bitcoin method PaymentBinding (V1 shape)."""
    # P2WPKH-like 22-byte script fixture (not a real address claim)
    spk = script_pubkey or (bytes([0x00, 0x14]) + b"\x11" * 20)
    return build_payment_binding([("bitcoin", spk)])


def payment_hash_v2(binding: dict[int, Any]) -> bytes:
    """TaggedHash(TAG_PAYMENT, CanonicalCBOR(PaymentBindingV1))."""
    payload = encode_payment_binding(binding)
    # encode_payment_binding uses V1 cbor.dumps — same bytes as CanonicalCBOR
    assert payload == cbor.dumps(binding)
    return tagged_hash_msg(TAG_PAYMENT, payload)

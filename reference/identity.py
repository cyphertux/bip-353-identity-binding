"""Identity Binding cryptographic constructions (experimental V0.4)."""

from __future__ import annotations

from typing import Any

# Re-export payment + anchor helpers so M1–M3 call sites keep working.
from reference.bitcoin_anchor import (  # noqa: F401
    build_anchor_message_a as build_anchor_message,
    identity_commitment,
)
from reference.constants import (
    DOMAIN_SEPARATOR_IDENTITY,
    KEY_CREATED_AT,
    KEY_DOMAIN,
    KEY_EXPIRES_AT,
    KEY_IDENTIFIER,
    KEY_PAYMENT_HASH,
    KEY_PROTOCOL_VERSION,
    KEY_ROOT_FINGERPRINT,
    KEY_SEQUENCE,
    KEY_SIGNATURE,
    KEY_SIGNING_FINGERPRINT,
    PROTOCOL_VERSION,
)
from reference.payment_binding import (  # noqa: F401
    build_payment_binding,
    payment_hash,
)
from reference import cbor


def provisional_op_return_payload(commitment: bytes) -> bytes:
    """Compatibility wrapper returning tag||ver||commitment (no OP_RETURN opcode)."""
    from reference.bitcoin_anchor import (
        DEFAULT_OP_RETURN_TAG,
        DEFAULT_OP_RETURN_VERSION,
    )

    if len(commitment) != 32:
        raise ValueError("commitment must be 32 bytes")
    return DEFAULT_OP_RETURN_TAG + bytes([DEFAULT_OP_RETURN_VERSION]) + commitment


def build_signed_identity_document(
    *,
    domain: str,
    identifier: str,
    root_fingerprint: bytes,
    signing_fingerprint: bytes,
    created_at: int,
    expires_at: int,
    payment_hash_value: bytes,
    sequence: int,
) -> dict[int, Any]:
    return {
        KEY_PROTOCOL_VERSION: PROTOCOL_VERSION,
        KEY_DOMAIN: domain,
        KEY_IDENTIFIER: identifier,
        KEY_ROOT_FINGERPRINT: root_fingerprint,
        KEY_SIGNING_FINGERPRINT: signing_fingerprint,
        KEY_CREATED_AT: created_at,
        KEY_EXPIRES_AT: expires_at,
        KEY_PAYMENT_HASH: payment_hash_value,
        KEY_SEQUENCE: sequence,
    }


def identity_signing_message(signed_doc: dict[int, Any]) -> bytes:
    return DOMAIN_SEPARATOR_IDENTITY + cbor.dumps(signed_doc)


def build_identity_document(
    signed_doc: dict[int, Any], signature: bytes
) -> dict[int, Any]:
    doc = dict(signed_doc)
    doc[KEY_SIGNATURE] = signature
    return doc


def strip_signature(identity_document: dict[int, Any]) -> dict[int, Any]:
    return {k: v for k, v in identity_document.items() if k != KEY_SIGNATURE}

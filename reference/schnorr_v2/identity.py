"""IdentityDocument experimental protocol_version=2."""

from __future__ import annotations

from typing import Any

from reference import cbor
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.key import SchnorrKeyPair, validate_xonly_pubkey, verify_msg32
from reference.schnorr_v2.tags import TAG_IDENTITY

PROTOCOL_VERSION = 2

K_VERSION = 0
K_DOMAIN = 1
K_IDENTIFIER = 2
K_ROOT = 3
K_SIGNING = 4
K_CREATED = 5
K_EXPIRES = 6
K_PAYMENT_HASH = 7
K_SEQUENCE = 8
K_SIGNATURE = 9


class IdentityError(ValueError):
    pass


def _check_domain_identifier(domain: str, identifier: str) -> None:
    if not isinstance(domain, str) or not domain or "@" in domain:
        raise IdentityError("INVALID_DOMAIN")
    if not isinstance(identifier, str) or not identifier.endswith("@" + domain):
        raise IdentityError("IDENTIFIER_MISMATCH")


def build_signed_map(
    *,
    domain: str,
    identifier: str,
    root_pubkey: bytes,
    signing_pubkey: bytes,
    created_at: int,
    expires_at: int,
    payment_hash: bytes,
    sequence: int | None = None,
) -> dict[int, Any]:
    _check_domain_identifier(domain, identifier)
    validate_xonly_pubkey(root_pubkey)
    validate_xonly_pubkey(signing_pubkey)
    if expires_at < created_at:
        raise IdentityError("INVALID_IDENTITY_DOCUMENT")
    if not isinstance(payment_hash, (bytes, bytearray)) or len(payment_hash) != 32:
        raise IdentityError("payment_hash must be 32 bytes")
    doc: dict[int, Any] = {
        K_VERSION: PROTOCOL_VERSION,
        K_DOMAIN: domain,
        K_IDENTIFIER: identifier,
        K_ROOT: bytes(root_pubkey),
        K_SIGNING: bytes(signing_pubkey),
        K_CREATED: created_at,
        K_EXPIRES: expires_at,
        K_PAYMENT_HASH: bytes(payment_hash),
    }
    if sequence is not None:
        if not isinstance(sequence, int) or sequence < 0:
            raise IdentityError("sequence must be non-negative int")
        doc[K_SEQUENCE] = sequence
    return doc


def signed_map_cbor(signed_map: dict[int, Any]) -> bytes:
    if K_SIGNATURE in signed_map:
        raise IdentityError("signature must not be in signed map")
    return cbor.dumps(signed_map)


def identity_digest(signed_map: dict[int, Any]) -> bytes:
    return tagged_hash_msg(TAG_IDENTITY, signed_map_cbor(signed_map))


def sign_identity(signing: SchnorrKeyPair, signed_map: dict[int, Any]) -> bytes:
    if signed_map.get(K_SIGNING) != signing.pubkey:
        raise IdentityError("signing_pubkey mismatch")
    return signing.sign_msg32(identity_digest(signed_map))


def attach_signature(signed_map: dict[int, Any], signature: bytes) -> dict[int, Any]:
    if len(signature) != 64:
        raise IdentityError("signature must be 64 bytes")
    out = dict(signed_map)
    out[K_SIGNATURE] = bytes(signature)
    return out


def verify_identity_signature(document: dict[int, Any]) -> None:
    if document.get(K_VERSION) != PROTOCOL_VERSION:
        raise IdentityError("UNSUPPORTED_VERSION")
    sig = document.get(K_SIGNATURE)
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
        raise IdentityError("INVALID_IDENTITY_SIGNATURE")
    signed = {k: v for k, v in document.items() if k != K_SIGNATURE}
    _check_domain_identifier(signed[K_DOMAIN], signed[K_IDENTIFIER])
    validate_xonly_pubkey(signed[K_ROOT])
    validate_xonly_pubkey(signed[K_SIGNING])
    digest = identity_digest(signed)
    if not verify_msg32(signed[K_SIGNING], digest, bytes(sig)):
        raise IdentityError("INVALID_IDENTITY_SIGNATURE")

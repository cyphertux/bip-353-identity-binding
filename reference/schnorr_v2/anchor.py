"""AnchorMessage Option A + experimental OP_RETURN B353S2."""

from __future__ import annotations

from typing import Any

from reference import cbor
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.key import validate_xonly_pubkey
from reference.schnorr_v2.tags import OP_RETURN_TAG, OP_RETURN_VERSION, TAG_ANCHOR

ANCHOR_VERSION = 1

A_VERSION = 0
A_DOMAIN = 1
A_IDENTIFIER = 2
A_ROOT = 3


class AnchorError(ValueError):
    pass


def build_anchor_message(
    *,
    domain: str,
    identifier: str,
    root_pubkey: bytes,
    version: int = ANCHOR_VERSION,
) -> dict[int, Any]:
    if not domain or "@" in domain:
        raise AnchorError("INVALID_DOMAIN")
    if not identifier.endswith("@" + domain):
        raise AnchorError("IDENTIFIER_MISMATCH")
    validate_xonly_pubkey(root_pubkey)
    return {
        A_VERSION: version,
        A_DOMAIN: domain,
        A_IDENTIFIER: identifier,
        A_ROOT: bytes(root_pubkey),
    }


def anchor_commitment(anchor: dict[int, Any]) -> bytes:
    return tagged_hash_msg(TAG_ANCHOR, cbor.dumps(anchor))


def build_opreturn_script(commitment: bytes) -> bytes:
    """OP_RETURN <payload> with payload = B353S2 || 0x01 || 32-byte commitment."""
    if len(commitment) != 32:
        raise AnchorError("commitment must be 32 bytes")
    payload = OP_RETURN_TAG + bytes([OP_RETURN_VERSION]) + commitment
    if len(payload) != 39:
        raise AnchorError("experimental payload must be 39 bytes")
    # scriptPubKey: OP_RETURN (0x6a) + push39 (0x27) + payload
    return bytes([0x6A, 0x27]) + payload


def extract_commitment_from_opreturn(script: bytes) -> bytes:
    if len(script) < 2 or script[0] != 0x6A:
        raise AnchorError("ANCHOR_MISMATCH")
    # single push
    push = script[1]
    payload = script[2:]
    if push != len(payload):
        raise AnchorError("ANCHOR_MISMATCH")
    if len(payload) != 39:
        raise AnchorError("ANCHOR_MISMATCH")
    if payload[:6] != OP_RETURN_TAG or payload[6] != OP_RETURN_VERSION:
        raise AnchorError("ANCHOR_MISMATCH")
    return payload[7:39]


def verify_anchor_logical(
    *,
    domain: str,
    identifier: str,
    root_pubkey: bytes,
    opreturn_script: bytes,
) -> bytes:
    """Recompute commitment; ensure OP_RETURN carries it; root matches message."""
    anchor = build_anchor_message(
        domain=domain, identifier=identifier, root_pubkey=root_pubkey
    )
    commitment = anchor_commitment(anchor)
    extracted = extract_commitment_from_opreturn(opreturn_script)
    if extracted != commitment:
        raise AnchorError("ANCHOR_MISMATCH")
    if anchor[A_ROOT] != root_pubkey:
        raise AnchorError("ANCHOR_MISMATCH")
    return commitment

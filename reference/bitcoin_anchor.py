"""Bitcoin identity anchor commitment + provisional OP_RETURN encoding (M4).

Candidate comparison (see MILESTONE_4_BITCOIN.md):
  A) domain + identifier + KROOT          ← RETAINED
  B) A + payment_hash
  C) A + KSIGN + payment_hash
"""

from __future__ import annotations

import hashlib
from typing import Any

from reference import cbor
from reference.constants import (
    ANCHOR_DOMAIN,
    ANCHOR_IDENTIFIER,
    ANCHOR_ROOT,
    ANCHOR_VERSION,
    DOMAIN_SEPARATOR_ANCHOR,
    PROTOCOL_VERSION,
)

# V1 FROZEN (M7): B353ID is the normative tag for this protocol version.
OP_RETURN_CANDIDATES = {
    "B353ID": b"B353ID",  # FROZEN V1
    "BIP353": b"BIP353",  # historical candidate — NOT V1
    "B353I\x01": b"B353I\x01",  # historical candidate — NOT V1
}

DEFAULT_OP_RETURN_TAG = OP_RETURN_CANDIDATES["B353ID"]
DEFAULT_OP_RETURN_VERSION = 0x01

# Bitcoin standardness: OP_RETURN data carrier typically ≤ 80 bytes (policy).
MAX_OP_RETURN_DATA = 80


def build_anchor_message_a(
    *,
    domain: str,
    identifier: str,
    root_fingerprint: bytes,
    version: int = PROTOCOL_VERSION,
) -> dict[int, Any]:
    """Candidate A — stable across KSIGN and payment rotations."""
    return {
        ANCHOR_VERSION: version,
        ANCHOR_DOMAIN: domain,
        ANCHOR_IDENTIFIER: identifier,
        ANCHOR_ROOT: root_fingerprint,
    }


def build_anchor_message_b(
    *,
    domain: str,
    identifier: str,
    root_fingerprint: bytes,
    payment_hash_value: bytes,
    version: int = PROTOCOL_VERSION,
) -> dict[int, Any]:
    """Candidate B — re-anchors on every payment destination change."""
    msg = build_anchor_message_a(
        domain=domain,
        identifier=identifier,
        root_fingerprint=root_fingerprint,
        version=version,
    )
    msg[4] = payment_hash_value  # provisional key
    return msg


def build_anchor_message_c(
    *,
    domain: str,
    identifier: str,
    root_fingerprint: bytes,
    signing_fingerprint: bytes,
    payment_hash_value: bytes,
    version: int = PROTOCOL_VERSION,
) -> dict[int, Any]:
    """Candidate C — re-anchors on KSIGN or payment change."""
    msg = build_anchor_message_b(
        domain=domain,
        identifier=identifier,
        root_fingerprint=root_fingerprint,
        payment_hash_value=payment_hash_value,
        version=version,
    )
    msg[5] = signing_fingerprint
    return msg


def identity_commitment(anchor_message: dict[int, Any]) -> bytes:
    return hashlib.sha256(
        DOMAIN_SEPARATOR_ANCHOR + cbor.dumps(anchor_message)
    ).digest()


def build_op_return_script(
    commitment: bytes,
    *,
    tag: bytes = DEFAULT_OP_RETURN_TAG,
    version: int = DEFAULT_OP_RETURN_VERSION,
) -> bytes:
    """Build scriptPubKey: OP_RETURN <push payload>.

    Payload = tag || version || 32-byte commitment.
    """
    if len(commitment) != 32:
        raise ValueError("commitment must be 32 bytes")
    payload = tag + bytes([version]) + commitment
    if len(payload) > MAX_OP_RETURN_DATA:
        raise ValueError(f"OP_RETURN payload {len(payload)} exceeds {MAX_OP_RETURN_DATA}")
    # OP_RETURN = 0x6a; pushdata for len < 76 is single-byte length
    if len(payload) < 76:
        return b"\x6a" + bytes([len(payload)]) + payload
    raise ValueError("payload too large for single-byte push")


def parse_op_return_commitment(
    script: bytes,
    *,
    tag: bytes = DEFAULT_OP_RETURN_TAG,
    version: int = DEFAULT_OP_RETURN_VERSION,
) -> bytes | None:
    """Extract commitment from an OP_RETURN scriptPubKey, or None.

    Requires exact payload layout: tag || version || 32-byte commitment.
    Extra bytes after the commitment → None (reject).
    Truncation / wrong length → None.
    """
    if not script or script[0] != 0x6A:
        return None
    if len(script) < 2:
        return None
    push_len = script[1]
    if push_len >= 76:
        return None  # only support short pushes for V1 provisional
    if len(script) != 2 + push_len:
        return None  # no trailing script bytes
    payload = script[2 : 2 + push_len]
    expected_prefix = tag + bytes([version])
    expected_len = len(expected_prefix) + 32
    if len(payload) != expected_len:
        return None
    if not payload.startswith(expected_prefix):
        return None
    return payload[len(expected_prefix) :]


class CommitmentExtractError(ValueError):
    """Raised when OP_RETURN identity commitment extraction fails."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(f"{code}:{detail}" if detail else code)


def extract_identity_commitment(
    raw_tx: bytes,
    *,
    tag: bytes = DEFAULT_OP_RETURN_TAG,
    version: int = DEFAULT_OP_RETURN_VERSION,
) -> bytes:
    """Extract the unique V1 B353ID commitment from a raw Bitcoin transaction.

    V1 multi-OP_RETURN policy (Option 1 — reject ambiguous):
      - Non-OP_RETURN outputs are ignored.
      - OP_RETURN outputs that do not match tag||version||32 are ignored
        (wrong tag / version / length / extra bytes).
      - If zero matching B353ID v1 outputs → NO_B353ID_OUTPUT.
      - If more than one matching B353ID v1 output → AMBIGUOUS_B353ID_OUTPUTS.
      - If exactly one match → return that 32-byte commitment.

    Order of outputs does not matter; only the count of matching payloads does.
    Multiple *different* commitments in one tx are rejected (no silent pick).
    """
    from reference.bitcoin_tx import TxParseError, parse_transaction

    try:
        tx = parse_transaction(raw_tx)
    except TxParseError as exc:
        raise CommitmentExtractError("TX_PARSE_ERROR", str(exc)) from exc

    matches: list[bytes] = []
    for out in tx.outputs:
        c = parse_op_return_commitment(out.script_pubkey, tag=tag, version=version)
        if c is not None:
            matches.append(c)

    if len(matches) == 0:
        raise CommitmentExtractError("NO_B353ID_OUTPUT")
    if len(matches) > 1:
        # Even if all equal, V1 rejects ambiguity (interop: wallets must not
        # disagree on "which" output is authoritative).
        raise CommitmentExtractError(
            "AMBIGUOUS_B353ID_OUTPUTS", f"count={len(matches)}"
        )
    return matches[0]


def opreturn_size_analysis(tag: bytes = DEFAULT_OP_RETURN_TAG) -> dict[str, Any]:
    payload_len = len(tag) + 1 + 32
    script_len = 1 + 1 + payload_len  # OP_RETURN + push + payload
    return {
        "tag": tag.decode("ascii", errors="replace"),
        "tag_hex": tag.hex(),
        "payload_bytes": payload_len,
        "script_bytes": script_len,
        "within_80_byte_policy": payload_len <= MAX_OP_RETURN_DATA,
        "notes": [
            "Standard relay policy historically allows ≤80 bytes of OP_RETURN data.",
            "Tag is a provisional namespace collision hedge — not IANA/BIP-assigned.",
            "Version byte allows future commitment layouts without new tags.",
        ],
    }

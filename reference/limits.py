"""Provisional V1 resource limits (M6).

Normative intent: prevent trivial DoS from oversized proofs while remaining
compatible with BIP-353 identifiers and OpenPGP certificates.

Status: PROVISIONAL — may be revised before BIP freeze with interoperability data.
"""

from __future__ import annotations

from typing import Any

# --- String / document bounds ---
MAX_DOMAIN_BYTES = 253  # DNS wire practical bound
MAX_IDENTIFIER_BYTES = 320  # local-part@domain with margin
MAX_IDENTITY_DOCUMENT_BYTES = 16_384
MAX_PAYMENT_BINDING_BYTES = 8_192
MAX_PAYMENT_METHODS = 32

# --- Bitcoin proof bounds ---
MAX_RAW_TX_BYTES = 100_000  # aligned with reference.bitcoin_tx
MAX_MERKLE_BRANCH_DEPTH = 32  # Bitcoin merkle depth << 32 in practice
MAX_PROOF_BUNDLE_BYTES = 256_000
MAX_BLOCK_HEADER_BYTES = 80

LIMITS: dict[str, dict[str, Any]] = {
    "domain": {
        "maximum": MAX_DOMAIN_BYTES,
        "unit": "UTF-8 bytes",
        "reason": "DNS label practical limit; prevents pathological strings",
        "security_impact": "DoS / memory",
        "interop_impact": "All legal DNS names fit",
        "status": "PROVISIONAL",
    },
    "identifier": {
        "maximum": MAX_IDENTIFIER_BYTES,
        "unit": "UTF-8 bytes",
        "reason": "BIP-353 user@domain with generous margin",
        "security_impact": "DoS",
        "interop_impact": "Normal payment names fit",
        "status": "PROVISIONAL",
    },
    "identity_document": {
        "maximum": MAX_IDENTITY_DOCUMENT_BYTES,
        "unit": "bytes CBOR",
        "reason": "Signed document excluding large unrelated blobs",
        "security_impact": "Parse DoS",
        "interop_impact": "OpenPGP sig + fingerprints fit easily",
        "status": "PROVISIONAL",
    },
    "payment_binding": {
        "maximum": MAX_PAYMENT_BINDING_BYTES,
        "unit": "bytes CBOR",
        "reason": "Destination list bound",
        "security_impact": "Hash/parse DoS",
        "interop_impact": "Many on-chain methods still fit",
        "status": "PROVISIONAL",
    },
    "payment_method_count": {
        "maximum": MAX_PAYMENT_METHODS,
        "unit": "entries",
        "reason": "Bound binding size and UI complexity",
        "security_impact": "CPU/memory",
        "interop_impact": "May need raise if multi-path wallets proliferate",
        "status": "PROVISIONAL",
    },
    "raw_transaction": {
        "maximum": MAX_RAW_TX_BYTES,
        "unit": "bytes",
        "reason": "Below pathological sizes; above standard OP_RETURN anchor txs",
        "security_impact": "Parse DoS",
        "interop_impact": "Standard single/few-input anchor txs fit",
        "status": "PROVISIONAL",
    },
    "merkle_branch_depth": {
        "maximum": MAX_MERKLE_BRANCH_DEPTH,
        "unit": "siblings",
        "reason": "Bitcoin trees are shallow; cap prevents abuse",
        "security_impact": "CPU",
        "interop_impact": "No impact on real blocks",
        "status": "PROVISIONAL",
    },
    "proof_bundle": {
        "maximum": MAX_PROOF_BUNDLE_BYTES,
        "unit": "bytes",
        "reason": "Aggregate cap for wallet fetch",
        "security_impact": "Network/memory DoS",
        "interop_impact": "Includes cert + docs + proof",
        "status": "PROVISIONAL",
    },
}

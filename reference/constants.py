"""Protocol constants for BIP-353 Identity Binding & Continuity — V1 FROZEN (M7).

Any change to these values requires a new protocol version.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Domain separators — FROZEN V1 (exact bytes)
# ---------------------------------------------------------------------------
# Identity: 17 bytes = ASCII "BIP353-IDENTITY" || 0x00 || 0x01
DOMAIN_SEPARATOR_IDENTITY = b"BIP353-IDENTITY\x00\x01"
DOMAIN_SEPARATOR_PAYMENT = b"BIP353-IDENTITY/PAYMENT/v1"
DOMAIN_SEPARATOR_ANCHOR = b"BIP353-IDENTITY/ANCHOR/v1"

# ---------------------------------------------------------------------------
# OP_RETURN identity anchor payload — FROZEN V1
# Payload = tag (6) || version (1) || commitment (32) = 39 bytes
# ---------------------------------------------------------------------------
OP_RETURN_TAG = b"B353ID"
OP_RETURN_VERSION = 0x01

# Identity document CBOR integer keys
KEY_PROTOCOL_VERSION = 0
KEY_DOMAIN = 1
KEY_IDENTIFIER = 2
KEY_ROOT_FINGERPRINT = 3
KEY_SIGNING_FINGERPRINT = 4
KEY_CREATED_AT = 5
KEY_EXPIRES_AT = 6
KEY_PAYMENT_HASH = 7
KEY_SEQUENCE = 8
KEY_SIGNATURE = 9

# Payment binding keys
PAY_VERSION = 0
PAY_METHODS = 1
METHOD_TYPE = 0
METHOD_DESTINATION = 1

# Anchor message keys
ANCHOR_VERSION = 0
ANCHOR_DOMAIN = 1
ANCHOR_IDENTIFIER = 2
ANCHOR_ROOT = 3

PROTOCOL_VERSION = 1

# Fingerprint raw bstr lengths (OpenPGP)
FINGERPRINT_LEN_V4 = 20
FINGERPRINT_LEN_V6 = 32
ALLOWED_FINGERPRINT_LENGTHS = frozenset({FINGERPRINT_LEN_V4, FINGERPRINT_LEN_V6})

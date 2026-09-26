"""Exact TaggedHash tags and experimental OP_RETURN tag (Phase 3).

EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1 — NOT FROZEN
"""

from __future__ import annotations

# BIP-340 TaggedHash tag strings (ASCII, no trailing NUL) — mini-spec §3
TAG_SUBKEY_BINDING = "BIP353-IDENTITY/V2/SUBKEY-BINDING"
TAG_IDENTITY = "BIP353-IDENTITY/V2/IDENTITY"
TAG_PAYMENT = "BIP353-IDENTITY/V2/PAYMENT"
TAG_ANCHOR = "BIP353-IDENTITY/V2/ANCHOR"

# Experimental on-chain OP_RETURN tag — DISTINCT from V1 `B353ID`
# ASCII "B353S2" = BIP-353 Schnorr experimental identity (v2 lab)
# Must NEVER equal V1 tag bytes 42 33 35 33 49 44 ("B353ID")
OP_RETURN_TAG = b"B353S2"
OP_RETURN_VERSION = 0x01

assert OP_RETURN_TAG != b"B353ID"
assert len(OP_RETURN_TAG) == 6
assert len(TAG_SUBKEY_BINDING.encode("ascii")) == 33
assert len(TAG_IDENTITY.encode("ascii")) == 27
assert len(TAG_PAYMENT.encode("ascii")) == 26
assert len(TAG_ANCHOR.encode("ascii")) == 25

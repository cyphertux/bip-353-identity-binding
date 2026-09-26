"""BIP-340 TaggedHash helpers for experimental V2.

Construction (BIP-340):
  TaggedHash(tag, msg) = SHA256( SHA256(tag) || SHA256(tag) || msg )

Application signing message:
  msg32 = TaggedHash(TAG_*, CanonicalCBOR(...))   # 32 bytes
  sig   = BIP-340 Sign(sk, msg32)                 # 64 bytes
"""

from __future__ import annotations

from embit.hashes import tagged_hash


def tagged_hash_msg(tag: str, payload: bytes) -> bytes:
    """Return 32-byte BIP-340 TaggedHash digest used as Sign/Verify message."""
    digest = tagged_hash(tag, payload)
    if len(digest) != 32:
        raise ValueError(f"TaggedHash must be 32 bytes, got {len(digest)}")
    return digest

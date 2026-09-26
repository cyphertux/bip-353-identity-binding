"""BIP-340 x-only key generation and validation (experimental V2)."""

from __future__ import annotations

import os
from dataclasses import dataclass

from embit import ec


class KeyErrorV2(ValueError):
    pass


def _validate_secret(sk: bytes) -> bytes:
    if not isinstance(sk, (bytes, bytearray)) or len(sk) != 32:
        raise KeyErrorV2("secret key must be 32 bytes")
    try:
        return bytes(ec.PrivateKey(bytes(sk)).secret)
    except Exception as exc:  # noqa: BLE001 — surface as KeyErrorV2
        raise KeyErrorV2(f"invalid secret key: {exc}") from exc


def validate_xonly_pubkey(pk: bytes) -> bytes:
    """Reject if not a 32-byte BIP-340-liftable x-only public key."""
    if not isinstance(pk, (bytes, bytearray)) or len(pk) != 32:
        raise KeyErrorV2("x-only public key must be exactly 32 bytes")
    try:
        ec.PublicKey.from_xonly(bytes(pk))
    except Exception as exc:  # noqa: BLE001
        raise KeyErrorV2(f"invalid x-only public key: {exc}") from exc
    return bytes(pk)


@dataclass(frozen=True)
class SchnorrKeyPair:
    secret: bytes  # 32 bytes
    pubkey: bytes  # 32-byte x-only

    def sign_msg32(self, msg32: bytes) -> bytes:
        if len(msg32) != 32:
            raise KeyErrorV2("BIP-340 application message must be 32 bytes here")
        sk = ec.PrivateKey(self.secret)
        sig = sk.schnorr_sign(msg32)
        out = sig.serialize()
        if len(out) != 64:
            raise KeyErrorV2(f"signature must be 64 bytes, got {len(out)}")
        return out


def verify_msg32(pubkey: bytes, msg32: bytes, signature: bytes) -> bool:
    validate_xonly_pubkey(pubkey)
    if len(msg32) != 32:
        raise KeyErrorV2("message must be 32 bytes")
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        raise KeyErrorV2("signature must be 64 bytes")
    pub = ec.PublicKey.from_xonly(pubkey)
    sig = ec.SchnorrSig(bytes(signature))
    return bool(pub.schnorr_verify(sig, msg32))


def generate_keypair(entropy: bytes | None = None) -> SchnorrKeyPair:
    secret = _validate_secret(entropy if entropy is not None else os.urandom(32))
    sk = ec.PrivateKey(secret)
    pubkey = validate_xonly_pubkey(sk.get_public_key().xonly())
    return SchnorrKeyPair(secret=secret, pubkey=pubkey)


def keypair_from_secret(secret: bytes) -> SchnorrKeyPair:
    secret = _validate_secret(secret)
    sk = ec.PrivateKey(secret)
    return SchnorrKeyPair(secret=secret, pubkey=validate_xonly_pubkey(sk.get_public_key().xonly()))

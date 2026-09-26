"""Root → signing SubkeyBinding (Option B / TaggedHash)."""

from __future__ import annotations

from typing import Any

from reference import cbor
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.key import SchnorrKeyPair, validate_xonly_pubkey, verify_msg32
from reference.schnorr_v2.tags import TAG_SUBKEY_BINDING

# Binding object version (mini-spec): experimental 1
BINDING_VERSION = 1

KEY_VERSION = 0
KEY_ROOT = 1
KEY_SIGNING = 2
KEY_CREATED = 3
KEY_EXPIRES = 4


class BindingError(ValueError):
    pass


def build_binding_body(
    *,
    root_pubkey: bytes,
    signing_pubkey: bytes,
    created_at: int,
    expires_at: int,
    version: int = BINDING_VERSION,
) -> dict[int, Any]:
    validate_xonly_pubkey(root_pubkey)
    validate_xonly_pubkey(signing_pubkey)
    if expires_at < created_at:
        raise BindingError("expires_at must be >= created_at")
    return {
        KEY_VERSION: version,
        KEY_ROOT: root_pubkey,
        KEY_SIGNING: signing_pubkey,
        KEY_CREATED: created_at,
        KEY_EXPIRES: expires_at,
    }


def binding_body_cbor(body: dict[int, Any]) -> bytes:
    return cbor.dumps(body)


def binding_digest(body: dict[int, Any]) -> bytes:
    return tagged_hash_msg(TAG_SUBKEY_BINDING, binding_body_cbor(body))


def sign_binding(root: SchnorrKeyPair, body: dict[int, Any]) -> bytes:
    if body.get(KEY_ROOT) != root.pubkey:
        raise BindingError("binding root_pubkey must match signing root key")
    return root.sign_msg32(binding_digest(body))


def verify_binding(
    *,
    root_pubkey: bytes,
    body: dict[int, Any],
    binding_signature: bytes,
    now: int | None = None,
) -> None:
    """Raise BindingError / KeyErrorV2 on failure."""
    validate_xonly_pubkey(root_pubkey)
    if body.get(KEY_VERSION) != BINDING_VERSION:
        raise BindingError("UNSUPPORTED_VERSION")
    if body.get(KEY_ROOT) != root_pubkey:
        raise BindingError("INVALID_SUBKEY_BINDING")
    validate_xonly_pubkey(body[KEY_SIGNING])
    if body[KEY_EXPIRES] < body[KEY_CREATED]:
        raise BindingError("INVALID_SUBKEY_BINDING")
    if now is not None and not (body[KEY_CREATED] <= now <= body[KEY_EXPIRES]):
        raise BindingError("INVALID_SUBKEY_BINDING")
    digest = binding_digest(body)
    if not verify_msg32(root_pubkey, digest, binding_signature):
        raise BindingError("INVALID_SUBKEY_BINDING")

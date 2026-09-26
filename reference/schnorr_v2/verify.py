"""Minimal experimental V2 verifier."""

from __future__ import annotations

from typing import Any

from reference.schnorr_v2 import anchor as anchor_mod
from reference.schnorr_v2 import binding as binding_mod
from reference.schnorr_v2 import identity as identity_mod
from reference.schnorr_v2 import payment as payment_mod
from reference.schnorr_v2.key import KeyErrorV2, validate_xonly_pubkey


class VerifyError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(code if not detail else f"{code}: {detail}")


def verify(
    *,
    root_pubkey: bytes,
    signing_pubkey: bytes,
    binding_body: dict[int, Any],
    binding_signature: bytes,
    identity_document: dict[int, Any],
    payment_binding: dict[int, Any],
    opreturn_script: bytes | None,
    now: int,
) -> dict[str, bool | list[str]]:
    """Return claim flags; raise VerifyError on hard failure."""
    errors: list[str] = []

    try:
        validate_xonly_pubkey(root_pubkey)
    except KeyErrorV2 as exc:
        raise VerifyError("INVALID_ROOT_PUBKEY", str(exc)) from exc
    try:
        validate_xonly_pubkey(signing_pubkey)
    except KeyErrorV2 as exc:
        raise VerifyError("INVALID_SIGNING_PUBKEY", str(exc)) from exc

    # Binding
    try:
        binding_mod.verify_binding(
            root_pubkey=root_pubkey,
            body=binding_body,
            binding_signature=binding_signature,
            now=now,
        )
    except binding_mod.BindingError as exc:
        code = str(exc) if str(exc) in {
            "UNSUPPORTED_VERSION",
            "INVALID_SUBKEY_BINDING",
        } else "INVALID_SUBKEY_BINDING"
        raise VerifyError(code) from exc

    if binding_body[binding_mod.KEY_SIGNING] != signing_pubkey:
        raise VerifyError("INVALID_SUBKEY_BINDING")
    if identity_document.get(identity_mod.K_ROOT) != root_pubkey:
        raise VerifyError("INVALID_SUBKEY_BINDING")
    if identity_document.get(identity_mod.K_SIGNING) != signing_pubkey:
        raise VerifyError("INVALID_SUBKEY_BINDING")

    # Payment
    expected_hash = payment_mod.payment_hash_v2(payment_binding)
    if identity_document.get(identity_mod.K_PAYMENT_HASH) != expected_hash:
        raise VerifyError("PAYMENT_BINDING_MISMATCH")

    # Identity signature + fields
    try:
        identity_mod.verify_identity_signature(identity_document)
    except identity_mod.IdentityError as exc:
        msg = str(exc)
        if msg in {"UNSUPPORTED_VERSION", "INVALID_DOMAIN", "IDENTIFIER_MISMATCH"}:
            raise VerifyError(msg) from exc
        raise VerifyError("INVALID_IDENTITY_SIGNATURE") from exc

    created = identity_document[identity_mod.K_CREATED]
    expires = identity_document[identity_mod.K_EXPIRES]
    if not (created <= now <= expires):
        raise VerifyError("INVALID_IDENTITY_SIGNATURE", "outside validity window")

    identity_verified = True
    payment_verified = True

    identity_anchored = False
    continuity_verified = False
    if opreturn_script is not None:
        try:
            anchor_mod.verify_anchor_logical(
                domain=identity_document[identity_mod.K_DOMAIN],
                identifier=identity_document[identity_mod.K_IDENTIFIER],
                root_pubkey=root_pubkey,
                opreturn_script=opreturn_script,
            )
            identity_anchored = True
            continuity_verified = True
        except anchor_mod.AnchorError as exc:
            raise VerifyError("ANCHOR_MISMATCH", str(exc)) from exc

    return {
        "identity_verified": identity_verified,
        "payment_verified": payment_verified,
        "identity_anchored": identity_anchored,
        "continuity_verified": continuity_verified,
        "errors": errors,
    }

"""Minimal experimental V2 verifier."""

from __future__ import annotations

from typing import Any

from reference.schnorr_v2 import anchor as anchor_mod
from reference.schnorr_v2 import binding as binding_mod
from reference.schnorr_v2 import identity as identity_mod
from reference.schnorr_v2 import payment as payment_mod
from reference.schnorr_v2.bitcoin_proof import (
    BitcoinProofError,
    proof_from_jsonable,
    verify_bitcoin_anchor_proof_v2,
)
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
    now: int,
    bitcoin_proof: dict[str, Any] | None = None,
    opreturn_script: bytes | None = None,
) -> dict[str, bool | list[str]]:
    """Return claim flags; raise VerifyError on hard failure.

    ``identity_anchored`` / ``continuity_verified`` require a full dual-binding
    ``bitcoin_proof`` (raw_tx → txid → Merkle → header AND raw_tx → B353S2).

    A lone ``opreturn_script`` is accepted only as a logical consistency check
    helper and does **not** set ``identity_anchored`` (F-S1 hardening).
    """
    errors: list[str] = []

    try:
        validate_xonly_pubkey(root_pubkey)
    except KeyErrorV2 as exc:
        raise VerifyError("INVALID_ROOT_PUBKEY", str(exc)) from exc
    try:
        validate_xonly_pubkey(signing_pubkey)
    except KeyErrorV2 as exc:
        raise VerifyError("INVALID_SIGNING_PUBKEY", str(exc)) from exc

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

    expected_hash = payment_mod.payment_hash_v2(payment_binding)
    if identity_document.get(identity_mod.K_PAYMENT_HASH) != expected_hash:
        raise VerifyError("PAYMENT_BINDING_MISMATCH")

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

    # Optional logical OP_RETURN consistency (does not grant identity_anchored)
    if opreturn_script is not None:
        try:
            anchor_mod.verify_anchor_logical(
                domain=identity_document[identity_mod.K_DOMAIN],
                identifier=identity_document[identity_mod.K_IDENTIFIER],
                root_pubkey=root_pubkey,
                opreturn_script=opreturn_script,
            )
        except anchor_mod.AnchorError as exc:
            raise VerifyError("ANCHOR_MISMATCH", str(exc)) from exc

    identity_anchored = False
    continuity_verified = False
    if bitcoin_proof is not None:
        expected_commitment = anchor_mod.anchor_commitment(
            anchor_mod.build_anchor_message(
                domain=identity_document[identity_mod.K_DOMAIN],
                identifier=identity_document[identity_mod.K_IDENTIFIER],
                root_pubkey=root_pubkey,
            )
        )
        try:
            proof_obj = proof_from_jsonable(bitcoin_proof)
            verify_bitcoin_anchor_proof_v2(
                proof_obj, expected_commitment=expected_commitment
            )
        except BitcoinProofError as exc:
            raise VerifyError(exc.code, str(exc)) from exc
        identity_anchored = True
        continuity_verified = True

    return {
        "identity_verified": identity_verified,
        "payment_verified": payment_verified,
        "identity_anchored": identity_anchored,
        "continuity_verified": continuity_verified,
        "errors": errors,
    }

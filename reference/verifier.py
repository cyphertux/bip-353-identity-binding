"""Reference verifier for BIP-353 Identity Binding Proof Bundles."""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from reference import cbor
from reference.constants import (
    KEY_CREATED_AT,
    KEY_DOMAIN,
    KEY_EXPIRES_AT,
    KEY_IDENTIFIER,
    KEY_PAYMENT_HASH,
    KEY_PROTOCOL_VERSION,
    KEY_ROOT_FINGERPRINT,
    KEY_SEQUENCE,
    KEY_SIGNATURE,
    KEY_SIGNING_FINGERPRINT,
    PROTOCOL_VERSION,
)
from reference.identity import (
    build_anchor_message,
    identity_commitment,
    identity_signing_message,
    payment_hash,
    strip_signature,
)
from reference.openpgp_util import (
    OpenPGPError,
    get_primary_and_signing,
    import_certificate,
    verify_detach_sign,
    verify_subkey_binding,
)


@dataclass
class VerificationResult:
    payment_verified: bool | None = None
    identity_verified: bool = False
    identity_anchored: bool = False
    continuity_verified: bool = False
    freshness: str = "unknown"
    freshness_status: str = "unknown"
    rollback_resistance: str = "not_provided"
    revocation_status: str = "unknown"
    trust_state: str = "first_seen"
    revoked: bool = False
    human_verified: bool = False  # ALWAYS false from this protocol alone
    freshness_detail: dict[str, Any] = field(
        default_factory=lambda: {"status": "unknown"}
    )
    revocation: dict[str, Any] = field(
        default_factory=lambda: {
            "status": "unknown",
            "policy": "unknown_by_design",
        }
    )
    trust: dict[str, Any] = field(
        default_factory=lambda: {"status": "first_seen"}
    )
    errors: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _fail(result: VerificationResult, code: str, check: str | None = None) -> VerificationResult:
    result.errors.append(code)
    if check:
        result.checks[check] = False
    return result


def verify_proof_bundle(
    *,
    identity_document_cbor: bytes,
    payment_binding_cbor: bytes,
    anchor_message_cbor: bytes,
    root_certificate_path: Path,
    gnupghome: Path,
    requested_identifier: str,
    expected_commitment: bytes | None = None,
    now: int | None = None,
    check_payment: bool = True,
) -> VerificationResult:
    """Verify a Proof Bundle. Returns structured results (never a bare bool)."""
    result = VerificationResult()
    now = int(time.time()) if now is None else now

    # --- Step 1: Parse ---
    try:
        doc = cbor.loads(identity_document_cbor)
        payment = cbor.loads(payment_binding_cbor)
        anchor = cbor.loads(anchor_message_cbor)
    except Exception as exc:
        return _fail(result, f"PARSE_ERROR:{exc}", "parse")
    result.checks["parse"] = True

    if not isinstance(doc, dict):
        return _fail(result, "IDENTIFIER_MISMATCH:not_a_map", "parse")

    # --- Step 2: Protocol version ---
    if doc.get(KEY_PROTOCOL_VERSION) != PROTOCOL_VERSION:
        return _fail(result, "UNSUPPORTED_VERSION", "version")
    result.checks["version"] = True

    # --- Step 3: Identifier ---
    identifier = doc.get(KEY_IDENTIFIER)
    if identifier != requested_identifier:
        return _fail(result, "IDENTIFIER_MISMATCH", "identifier")
    result.checks["identifier"] = True

    domain = doc.get(KEY_DOMAIN)
    if not isinstance(domain, str) or "@" in domain:
        return _fail(result, "INVALID_DOMAIN", "domain")
    # Basic consistency: identifier must end with @domain
    if not isinstance(identifier, str) or not identifier.endswith("@" + domain):
        return _fail(result, "DOMAIN_IDENTIFIER_INCONSISTENT", "domain")
    result.checks["domain"] = True

    root_fpr = doc.get(KEY_ROOT_FINGERPRINT)
    sign_fpr = doc.get(KEY_SIGNING_FINGERPRINT)
    signature = doc.get(KEY_SIGNATURE)
    pay_hash = doc.get(KEY_PAYMENT_HASH)
    created = doc.get(KEY_CREATED_AT)
    expires = doc.get(KEY_EXPIRES_AT)
    sequence = doc.get(KEY_SEQUENCE)

    for name, val, typ in [
        ("root_fingerprint", root_fpr, bytes),
        ("signing_fingerprint", sign_fpr, bytes),
        ("signature", signature, bytes),
        ("payment_hash", pay_hash, bytes),
        ("created_at", created, int),
        ("expires_at", expires, int),
        ("sequence", sequence, int),
    ]:
        if not isinstance(val, typ):
            return _fail(result, f"FIELD_TYPE:{name}", name)

    # --- Step 4/5: OpenPGP certificates & fingerprints ---
    try:
        infos = import_certificate(root_certificate_path, gnupghome)
        root_info, sign_info = get_primary_and_signing(infos)
    except OpenPGPError as exc:
        return _fail(result, f"OPENPGP_IMPORT:{exc}", "openpgp")

    if root_info.fingerprint != root_fpr:
        return _fail(result, "ROOT_KEY_MISMATCH", "root_fingerprint")
    result.checks["root_fingerprint"] = True

    if sign_info.fingerprint != sign_fpr:
        return _fail(result, "SIGNING_KEY_MISMATCH", "signing_fingerprint")
    result.checks["signing_fingerprint"] = True

    if root_info.revoked or sign_info.revoked:
        result.revoked = True
        result.revocation_status = "revoked"
        result.revocation = {
            "status": "revoked",
            "policy": "unknown_by_design",
            "note": "Revocation material was present in the offered certificate",
        }
        return _fail(result, "IDENTITY_REVOKED", "revocation")
    # V1 policy: UNKNOWN BY DESIGN — absence of revocation in the offered
    # certificate does NOT prove keys are unrevoked (no mandatory channel).
    result.revocation_status = "unknown"
    result.revocation = {
        "status": "unknown",
        "policy": "unknown_by_design",
        "note": "OpenPGP revocation honored if present; otherwise unknown",
    }
    result.checks["revocation"] = False  # not affirmatively verified clear


    # --- Step 5: OpenPGP binding KROOT → KSIGN ---
    if not verify_subkey_binding(root_certificate_path, root_fpr, sign_fpr, gnupghome):
        return _fail(result, "INVALID_ROOT_BINDING", "root_binding")
    result.checks["root_binding"] = True

    # --- Step 6: Identity signature ---
    signed_doc = strip_signature(doc)
    # Re-encode to ensure canonical form matches what was signed
    try:
        # Must match exact field set 0..8
        message = identity_signing_message(signed_doc)
    except Exception as exc:
        return _fail(result, f"CANONICALIZE:{exc}", "identity_signature")

    if not verify_detach_sign(
        message,
        signature,
        gnupghome=gnupghome,
        expected_signer_fpr=sign_fpr,
    ):
        return _fail(result, "INVALID_IDENTITY_SIGNATURE", "identity_signature")
    result.checks["identity_signature"] = True

    # --- Step 7: Validity ---
    if not (created <= now <= expires):
        return _fail(result, "IDENTITY_EXPIRED", "validity")
    result.checks["validity"] = True

    # --- Step 8: Payment hash ---
    if check_payment:
        computed_pay = payment_hash(payment)
        if computed_pay != pay_hash:
            result.payment_verified = False
            return _fail(result, "PAYMENT_BINDING_MISMATCH", "payment_binding")
        result.checks["payment_binding"] = True
        result.payment_verified = True
    else:
        result.payment_verified = None
        result.checks["payment_binding"] = False

    # --- Step 9/10: Bitcoin commitment ---
    expected_anchor = build_anchor_message(
        domain=domain,
        identifier=identifier,
        root_fingerprint=root_fpr,
    )
    # Compare canonical encoding of provided anchor vs expected structure
    try:
        provided_commitment = identity_commitment(anchor)
        expected_c = identity_commitment(expected_anchor)
    except Exception as exc:
        return _fail(result, f"ANCHOR_COMPUTE:{exc}", "anchor")

    if provided_commitment != expected_c:
        return _fail(result, "ANCHOR_MISMATCH", "anchor")

    # Optionally compare against an externally supplied commitment (e.g. from OP_RETURN)
    if expected_commitment is not None and expected_commitment != expected_c:
        return _fail(result, "ANCHOR_MISMATCH:external", "anchor")

    # Structural check: anchor fields must match document
    from reference.constants import (
        ANCHOR_DOMAIN,
        ANCHOR_IDENTIFIER,
        ANCHOR_ROOT,
        ANCHOR_VERSION,
    )

    if (
        anchor.get(ANCHOR_VERSION) != PROTOCOL_VERSION
        or anchor.get(ANCHOR_DOMAIN) != domain
        or anchor.get(ANCHOR_IDENTIFIER) != identifier
        or anchor.get(ANCHOR_ROOT) != root_fpr
    ):
        return _fail(result, "ANCHOR_MISMATCH:fields", "anchor")

    result.checks["anchor"] = True
    result.identity_anchored = True

    # Continuity relative to KROOT: if anchor matches KROOT, continuity of root holds.
    # Freshness remains unknown without a transparency log.
    result.continuity_verified = True
    result.identity_verified = True
    result.freshness = "unknown"
    result.freshness_status = "unknown"
    result.freshness_detail = {"status": "unknown"}
    result.rollback_resistance = "not_provided"
    result.trust_state = "first_seen"
    result.trust = {"status": "first_seen"}
    result.human_verified = False
    result.checks["continuity"] = True
    result.checks["freshness"] = False
    # Never set current=true / freshness=fresh without an external freshness source.

    return result


def verify_vector_dir(vector_dir: Path, gnupghome: Path) -> VerificationResult:
    expected_path = vector_dir / "expected.json"
    expected = json.loads(expected_path.read_text())
    return verify_proof_bundle(
        identity_document_cbor=(vector_dir / "identity-document.cbor").read_bytes(),
        payment_binding_cbor=(vector_dir / "payment-binding.cbor").read_bytes(),
        anchor_message_cbor=(vector_dir / "anchor-message.cbor").read_bytes(),
        root_certificate_path=vector_dir / "root.asc",
        gnupghome=gnupghome,
        requested_identifier=expected["identifier"],
        expected_commitment=bytes.fromhex(expected["identity_commitment"]),
        now=expected.get("verification_time"),
    )

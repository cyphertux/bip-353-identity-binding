#!/usr/bin/env python3
"""Generate experimental Schnorr V2 vectors (run manually; tests must not call this).

EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from reference import cbor
from reference.payment_binding import encode_payment_binding
from reference.schnorr_v2 import anchor as anchor_mod
from reference.schnorr_v2 import binding as binding_mod
from reference.schnorr_v2 import identity as identity_mod
from reference.schnorr_v2 import payment as payment_mod
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.key import keypair_from_secret
from reference.schnorr_v2.tags import (
    OP_RETURN_TAG,
    TAG_ANCHOR,
    TAG_IDENTITY,
    TAG_PAYMENT,
    TAG_SUBKEY_BINDING,
)
from reference.schnorr_v2.verify import verify

# Fixed unix time for determinism
NOW = 1_700_000_000
DOMAIN = "example.test"
IDENTIFIER = "alice@example.test"

# TEST VECTOR ONLY — NOT A SECRET — NOT FOR PRODUCTION
ROOT_SK = bytes.fromhex("01" * 32)
SIGNING_SK = bytes.fromhex("02" * 32)
ALT_SK = bytes.fromhex("03" * 32)

OUT_DIR = Path(__file__).resolve().parents[2] / "vectors" / "schnorr"

WARNING = (
    "TEST VECTOR ONLY — private keys are NOT secrets — NOT FOR PRODUCTION"
)


def hx(b: bytes) -> str:
    return b.hex()


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def base_valid() -> dict[str, Any]:
    root = keypair_from_secret(ROOT_SK)
    signing = keypair_from_secret(SIGNING_SK)

    body = binding_mod.build_binding_body(
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        created_at=NOW - 60,
        expires_at=NOW + 86400 * 365,
    )
    body_cbor = binding_mod.binding_body_cbor(body)
    body_hash = binding_mod.binding_digest(body)
    binding_sig = binding_mod.sign_binding(root, body)

    pay = payment_mod.make_fixture_payment_binding(
        script_pubkey=bytes([0x00, 0x14]) + bytes(range(20))
    )
    pay_cbor = encode_payment_binding(pay)
    pay_hash = payment_mod.payment_hash_v2(pay)

    signed_map = identity_mod.build_signed_map(
        domain=DOMAIN,
        identifier=IDENTIFIER,
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        created_at=NOW - 60,
        expires_at=NOW + 86400 * 365,
        payment_hash=pay_hash,
    )
    signed_cbor = identity_mod.signed_map_cbor(signed_map)
    id_hash = identity_mod.identity_digest(signed_map)
    id_sig = identity_mod.sign_identity(signing, signed_map)
    document = identity_mod.attach_signature(signed_map, id_sig)
    doc_cbor = cbor.dumps(document)

    am = anchor_mod.build_anchor_message(
        domain=DOMAIN, identifier=IDENTIFIER, root_pubkey=root.pubkey
    )
    am_cbor = cbor.dumps(am)
    commitment = anchor_mod.anchor_commitment(am)
    opreturn = anchor_mod.build_opreturn_script(commitment)

    return {
        "root": root,
        "signing": signing,
        "body": body,
        "body_cbor": body_cbor,
        "body_hash": body_hash,
        "binding_sig": binding_sig,
        "pay": pay,
        "pay_cbor": pay_cbor,
        "pay_hash": pay_hash,
        "signed_map": signed_map,
        "signed_cbor": signed_cbor,
        "id_hash": id_hash,
        "id_sig": id_sig,
        "document": document,
        "doc_cbor": doc_cbor,
        "am": am,
        "am_cbor": am_cbor,
        "commitment": commitment,
        "opreturn": opreturn,
    }


def valid_001(b: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": "V2-VALID-001",
        "version": 2,
        "description": "Complete experimental Schnorr identity proof (binding+payment+doc+anchor).",
        "warning": WARNING,
        "encoding": "hex-lowercase",
        "now": NOW,
        "domain": DOMAIN,
        "identifier": IDENTIFIER,
        "tags": {
            "SUBKEY_BINDING": TAG_SUBKEY_BINDING,
            "IDENTITY": TAG_IDENTITY,
            "PAYMENT": TAG_PAYMENT,
            "ANCHOR": TAG_ANCHOR,
            "OP_RETURN_ASCII": OP_RETURN_TAG.decode("ascii"),
        },
        "root_private_key": hx(ROOT_SK),
        "root_pubkey": hx(b["root"].pubkey),
        "signing_private_key": hx(SIGNING_SK),
        "signing_pubkey": hx(b["signing"].pubkey),
        "subkey_binding_cbor": hx(b["body_cbor"]),
        "subkey_binding_hash": hx(b["body_hash"]),
        "subkey_binding_signature": hx(b["binding_sig"]),
        "payment_binding_cbor": hx(b["pay_cbor"]),
        "payment_hash": hx(b["pay_hash"]),
        "identity_signed_cbor": hx(b["signed_cbor"]),
        "identity_message_hash": hx(b["id_hash"]),
        "identity_signature": hx(b["id_sig"]),
        "identity_document_cbor": hx(b["doc_cbor"]),
        "anchor_message_cbor": hx(b["am_cbor"]),
        "anchor_commitment": hx(b["commitment"]),
        "op_return": hx(b["opreturn"]),
        "expected": {
            "result": "valid",
            "error_code": None,
            "identity_verified": True,
            "payment_verified": True,
            "identity_anchored": True,
            "continuity_verified": True,
        },
    }


def invalid_001(b: dict[str, Any]) -> dict[str, Any]:
    """Substitute signing_pubkey in binding without new root signature."""
    alt = keypair_from_secret(ALT_SK)
    bad_body = dict(b["body"])
    bad_body[binding_mod.KEY_SIGNING] = alt.pubkey
    bad_body_cbor = binding_mod.binding_body_cbor(bad_body)
    # keep original binding signature (over old body)
    v = valid_001(b)
    v.update(
        {
            "id": "V2-INVALID-001",
            "description": "signing_pubkey substituted in SubkeyBinding without re-signing under root.",
            "signing_pubkey": hx(alt.pubkey),
            "subkey_binding_cbor": hx(bad_body_cbor),
            "subkey_binding_hash": hx(binding_mod.binding_digest(bad_body)),
            "subkey_binding_signature": hx(b["binding_sig"]),  # stale
            "mutation": {
                "field": "subkey_binding.signing_pubkey",
                "from": hx(b["signing"].pubkey),
                "to": hx(alt.pubkey),
                "binding_signature_recomputed": False,
            },
            "expected": {
                "result": "invalid",
                "error_code": "INVALID_SUBKEY_BINDING",
            },
        }
    )
    return v


def invalid_002(b: dict[str, Any]) -> dict[str, Any]:
    """Mutate created_at in document after signature (minimal bit-level semantic change)."""
    bad_doc = dict(b["document"])
    old = bad_doc[identity_mod.K_CREATED]
    bad_doc[identity_mod.K_CREATED] = old + 1
    bad_doc_cbor = cbor.dumps(bad_doc)
    v = valid_001(b)
    v.update(
        {
            "id": "V2-INVALID-002",
            "description": "IdentityDocument created_at incremented by 1 after signature (payment_hash unchanged).",
            "identity_document_cbor": hx(bad_doc_cbor),
            "identity_signature": hx(b["id_sig"]),  # unchanged
            "mutation": {
                "field": "identity_document.created_at",
                "from": old,
                "to": old + 1,
                "identity_signature_recomputed": False,
            },
            "expected": {
                "result": "invalid",
                "error_code": "INVALID_IDENTITY_SIGNATURE",
            },
        }
    )
    return v


def invalid_003(b: dict[str, Any]) -> dict[str, Any]:
    """OP_RETURN commits to a different root_pubkey than the presented identity."""
    alt_root = keypair_from_secret(ALT_SK)
    am_alt = anchor_mod.build_anchor_message(
        domain=DOMAIN, identifier=IDENTIFIER, root_pubkey=alt_root.pubkey
    )
    bad_opreturn = anchor_mod.build_opreturn_script(anchor_mod.anchor_commitment(am_alt))
    v = valid_001(b)
    v.update(
        {
            "id": "V2-INVALID-003",
            "description": "Anchor/OP_RETURN commitment is for a different root_pubkey than the document.",
            "op_return": hx(bad_opreturn),
            "anchor_message_cbor_wrong_root": hx(cbor.dumps(am_alt)),
            "anchor_commitment_wrong_root": hx(anchor_mod.anchor_commitment(am_alt)),
            "mutation": {
                "field": "op_return / anchor root_pubkey",
                "document_root": hx(b["root"].pubkey),
                "anchored_root": hx(alt_root.pubkey),
            },
            "expected": {
                "result": "invalid",
                "error_code": "ANCHOR_MISMATCH",
            },
        }
    )
    return v


def invalid_004(b: dict[str, Any]) -> dict[str, Any]:
    """PaymentBinding destination changed without updating document payment_hash."""
    bad_pay = payment_mod.make_fixture_payment_binding(
        script_pubkey=bytes([0x00, 0x14]) + bytes(range(20, 40))
    )
    bad_pay_cbor = encode_payment_binding(bad_pay)
    v = valid_001(b)
    v.update(
        {
            "id": "V2-INVALID-004",
            "description": "PaymentBinding scriptPubKey changed; document payment_hash not updated.",
            "payment_binding_cbor": hx(bad_pay_cbor),
            "payment_hash_of_mutated_binding": hx(payment_mod.payment_hash_v2(bad_pay)),
            "mutation": {
                "field": "payment_binding.methods[0].destination",
                "document_payment_hash_unchanged": hx(b["pay_hash"]),
            },
            "expected": {
                "result": "invalid",
                "error_code": "PAYMENT_BINDING_MISMATCH",
            },
        }
    )
    return v


def invalid_005(b: dict[str, Any]) -> dict[str, Any]:
    """Identity signature created under a wrong TaggedHash tag."""
    wrong_tag = "BIP353-IDENTITY/V2/WRONG"
    wrong_digest = tagged_hash_msg(wrong_tag, b["signed_cbor"])
    wrong_sig = b["signing"].sign_msg32(wrong_digest)
    bad_doc = identity_mod.attach_signature(b["signed_map"], wrong_sig)
    v = valid_001(b)
    v.update(
        {
            "id": "V2-INVALID-005",
            "description": "Identity signature produced with wrong TaggedHash tag; verify uses TAG_IDENTITY.",
            "wrong_tag": wrong_tag,
            "identity_signature": hx(wrong_sig),
            "identity_document_cbor": hx(cbor.dumps(bad_doc)),
            "mutation": {
                "field": "identity signature domain tag",
                "used_tag": wrong_tag,
                "expected_tag": TAG_IDENTITY,
            },
            "expected": {
                "result": "invalid",
                "error_code": "INVALID_IDENTITY_SIGNATURE",
            },
        }
    )
    return v


def assert_valid_verifies(b: dict[str, Any]) -> None:
    # Logical OP_RETURN alone: identity/payment only (F-S1 / Phase 9)
    result = verify(
        root_pubkey=b["root"].pubkey,
        signing_pubkey=b["signing"].pubkey,
        binding_body=b["body"],
        binding_signature=b["binding_sig"],
        identity_document=b["document"],
        payment_binding=b["pay"],
        opreturn_script=b["opreturn"],
        now=NOW,
    )
    assert result["identity_verified"] and result["payment_verified"]
    assert result["identity_anchored"] is False
    assert result["continuity_verified"] is False


def generate_all() -> list[Path]:
    b = base_valid()
    assert_valid_verifies(b)

    # Determinism: rebuild once and compare critical bytes
    b2 = base_valid()
    for k in ("body_cbor", "body_hash", "binding_sig", "pay_hash", "id_sig", "commitment", "opreturn"):
        assert b[k] == b2[k], k

    vectors = [
        valid_001(b),
        invalid_001(b),
        invalid_002(b),
        invalid_003(b),
        invalid_004(b),
        invalid_005(b),
    ]

    paths: list[Path] = []
    for vec in vectors:
        path = OUT_DIR / f"{vec['id']}.json"
        write_json(path, vec)
        paths.append(path)

    # checksums
    lines = [
        "# Experimental Schnorr V2 vector checksums",
        "# EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1",
        "# Format: <sha256_hex>  <path-relative-to-repo-root>",
        "# Do not modify vectors/M7_CHECKSUMS.txt",
        "",
    ]
    for path in sorted(paths):
        rel = path.relative_to(OUT_DIR.parents[1])
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {rel.as_posix()}")
    (OUT_DIR / "SCHNORR_V2_CHECKSUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate experimental Schnorr V2 vectors")
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write vectors to vectors/schnorr/ (default: dry-run print ids only)",
    )
    args = parser.parse_args()
    if not args.write:
        b = base_valid()
        assert_valid_verifies(b)
        print("dry-run OK — pass --write to emit fixtures")
        return
    paths = generate_all()
    print("wrote:")
    for p in paths:
        print(" ", p)


if __name__ == "__main__":
    main()

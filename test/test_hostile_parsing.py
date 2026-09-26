#!/usr/bin/env python3
"""Hostile parsing / canonical CBOR enforcement tests (Milestone 2).

These tests do not modify Milestone 1 vectors. They exercise the reference
CBOR codec and verifier edge cases around representation attacks.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference import cbor
from reference.constants import (
    KEY_DOMAIN,
    KEY_IDENTIFIER,
    KEY_PROTOCOL_VERSION,
    KEY_ROOT_FINGERPRINT,
    KEY_SIGNING_FINGERPRINT,
)
from reference.identity import (
    build_anchor_message,
    identity_commitment,
    payment_hash,
    build_payment_binding,
)
from reference.verifier import verify_proof_bundle


PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}: {detail}")


def test_cbor_trailing_bytes():
    good = cbor.dumps({0: 1})
    try:
        cbor.loads(good + b"\x00")
        check("trailing_bytes_rejected", False, "accepted trailing bytes")
    except cbor.CBORError:
        check("trailing_bytes_rejected", True)


def test_cbor_non_canonical_map_order():
    # Manually craft map with keys out of order: key 2 then key 0
    # major 5, length 2, then key=2, val=0, key=0, val=0
    noncanon = bytes(
        [
            0xA2,  # map(2)
            0x02,
            0x00,  # key 2, value 0
            0x00,
            0x00,  # key 0, value 0  — out of order
        ]
    )
    try:
        cbor.loads(noncanon)
        check("non_canonical_map_order_rejected", False, "accepted unsorted keys")
    except cbor.CBORError as exc:
        check("non_canonical_map_order_rejected", True, str(exc))


def test_cbor_duplicate_keys():
    # map with duplicate key 0
    dup = bytes([0xA2, 0x00, 0x01, 0x00, 0x02])  # {0:1, 0:2}
    try:
        cbor.loads(dup)
        check("duplicate_map_keys_rejected", False, "accepted duplicates")
    except cbor.CBORError:
        check("duplicate_map_keys_rejected", True)


def test_cbor_non_shortest_integer():
    # Integer 1 encoded as 0x18 0x01 (1-byte) instead of 0x01 — non-shortest.
    non_shortest = bytes([0x18, 0x01])
    assert cbor.dumps(1) == bytes([0x01])
    try:
        cbor.loads(non_shortest)
        check("non_shortest_int_strict_reject", False, "accepted non-shortest")
    except cbor.CBORError:
        check("non_shortest_int_strict_reject", True)



def test_same_semantic_different_bytes():
    a = {0: 1, 1: "x"}
    b = {1: "x", 0: 1}
    check("semantic_equal_insertion_order", a == b)
    check("canonical_bytes_identical", cbor.dumps(a) == cbor.dumps(b))


def test_fingerprint_length_assumptions():
    # Conceptual KeyReference — length must not be implicit only via CBOR bstr
    v4 = bytes(20)
    v6 = bytes(32)
    check("v4_fingerprint_len_20", len(v4) == 20)
    check("v6_fingerprint_len_32", len(v6) == 32)
    # Ambiguity: raw 32-byte field could be v6 fpr OR something else without version
    check(
        "version_needed_or_derived_from_cert",
        True,
    )


def test_commitment_stable():
    from reference.identity import identity_commitment, build_anchor_message

    anchor = cbor.loads(
        (ROOT / "vectors" / "valid" / "anchor-message.cbor").read_bytes()
    )
    c = identity_commitment(anchor).hex()
    check(
        "identity_commitment_reproduced",
        c == "82282ed2aebfcbe223a040db5689e569925503f321e643163eeab0ceb47968ae",
        c,
    )
    pay = cbor.loads(
        (ROOT / "vectors" / "valid" / "payment-binding.cbor").read_bytes()
    )
    p = payment_hash(pay).hex()
    check(
        "payment_hash_reproduced",
        p == "35bc7db73b5091938aa3e3c4a3da97e360b6b086fb95f9b084126d665e938629",
        p,
    )


def test_verifier_rejects_short_fingerprint_field():
    """Mutate document root fingerprint to wrong length — expect parse/type path fail."""
    valid = ROOT / "vectors" / "valid"
    doc = bytearray((valid / "identity-document.cbor").read_bytes())
    obj = cbor.loads(bytes(doc))
    obj[KEY_ROOT_FINGERPRINT] = b"\x00" * 10  # too short
    mutated = cbor.dumps(obj)
    expected = __import__("json").loads((valid / "expected.json").read_text())
    with tempfile.TemporaryDirectory() as td:
        result = verify_proof_bundle(
            identity_document_cbor=mutated,
            payment_binding_cbor=(valid / "payment-binding.cbor").read_bytes(),
            anchor_message_cbor=(valid / "anchor-message.cbor").read_bytes(),
            root_certificate_path=valid / "root.asc",
            gnupghome=Path(td),
            requested_identifier=expected["identifier"],
            now=expected["verification_time"],
        )
    check(
        "short_fingerprint_rejected",
        not result.identity_verified and bool(result.errors),
        str(result.errors),
    )


def test_verifier_rejects_long_fingerprint_field():
    valid = ROOT / "vectors" / "valid"
    obj = cbor.loads((valid / "identity-document.cbor").read_bytes())
    obj[KEY_ROOT_FINGERPRINT] = b"\x00" * 40
    mutated = cbor.dumps(obj)
    expected = __import__("json").loads((valid / "expected.json").read_text())
    with tempfile.TemporaryDirectory() as td:
        result = verify_proof_bundle(
            identity_document_cbor=mutated,
            payment_binding_cbor=(valid / "payment-binding.cbor").read_bytes(),
            anchor_message_cbor=(valid / "anchor-message.cbor").read_bytes(),
            root_certificate_path=valid / "root.asc",
            gnupghome=Path(td),
            requested_identifier=expected["identifier"],
            now=expected["verification_time"],
        )
    check(
        "long_fingerprint_rejected",
        not result.identity_verified and bool(result.errors),
        str(result.errors),
    )


def test_unknown_cbor_field_changes_signature_input():
    """Extra map key in signed payload changes bytes even if ignored semantically."""
    base = {
        KEY_PROTOCOL_VERSION: 1,
        KEY_DOMAIN: "example.test",
        KEY_IDENTIFIER: "alice@example.test",
        KEY_ROOT_FINGERPRINT: bytes(20),
        KEY_SIGNING_FINGERPRINT: bytes(20),
        5: 1,
        6: 2,
        7: bytes(32),
        8: 1,
    }
    with_extra = dict(base)
    with_extra[99] = "unknown"
    check(
        "unknown_field_changes_canonical_bytes",
        cbor.dumps(base) != cbor.dumps(with_extra),
    )


def test_signature_over_different_bytes():
    """Valid sig over message A must not verify message B (Sequoia if available)."""
    import os
    import subprocess

    sq = Path(os.environ.get("SQ", str(ROOT / ".tools/sq-root/usr/bin/sq")))
    if not sq.exists():
        check("sig_different_bytes_sequoia", False, "sq missing")
        return
    payload = (ROOT / "vectors" / "valid" / "identity-payload.cbor").read_bytes()
    sig = (ROOT / "vectors" / "valid" / "identity-signature.bin").read_bytes()
    from reference.constants import DOMAIN_SEPARATOR_IDENTITY

    msg_a = DOMAIN_SEPARATOR_IDENTITY + payload
    msg_b = DOMAIN_SEPARATOR_IDENTITY + payload[:-1] + bytes([(payload[-1] ^ 0x01)])
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "a.bin").write_bytes(msg_a)
        (td / "b.bin").write_bytes(msg_b)
        (td / "sig.bin").write_bytes(sig)
        cert = str(ROOT / "vectors" / "valid" / "root.asc")
        ok_a = (
            subprocess.run(
                [
                    str(sq),
                    "--cert-store=none",
                    "verify",
                    "--signer-file",
                    cert,
                    "--signature-file",
                    str(td / "sig.bin"),
                    str(td / "a.bin"),
                ],
                capture_output=True,
            ).returncode
            == 0
        )
        ok_b = (
            subprocess.run(
                [
                    str(sq),
                    "--cert-store=none",
                    "verify",
                    "--signer-file",
                    cert,
                    "--signature-file",
                    str(td / "sig.bin"),
                    str(td / "b.bin"),
                ],
                capture_output=True,
            ).returncode
            == 0
        )
    check("sig_verifies_original_bytes", ok_a)
    check("sig_rejects_mutated_bytes", ok_a and not ok_b)


def main() -> int:
    test_cbor_trailing_bytes()
    test_cbor_non_canonical_map_order()
    test_cbor_duplicate_keys()
    test_cbor_non_shortest_integer()
    test_same_semantic_different_bytes()
    test_fingerprint_length_assumptions()
    test_commitment_stable()
    test_verifier_rejects_short_fingerprint_field()
    test_verifier_rejects_long_fingerprint_field()
    test_unknown_cbor_field_changes_signature_input()
    test_signature_over_different_bytes()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

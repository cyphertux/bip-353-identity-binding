"""Negative tests for experimental Schnorr V2 (not frozen vectors)."""

from __future__ import annotations

import time

from reference.schnorr_v2 import anchor as anchor_mod
from reference.schnorr_v2 import binding as binding_mod
from reference.schnorr_v2 import identity as identity_mod
from reference.schnorr_v2 import payment as payment_mod
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.key import generate_keypair, verify_msg32
from reference.schnorr_v2.tags import TAG_IDENTITY, TAG_SUBKEY_BINDING
from reference.schnorr_v2.verify import VerifyError, verify


def _fresh_bundle():
    now = int(time.time())
    root = generate_keypair()
    signing = generate_keypair()
    body = binding_mod.build_binding_body(
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        created_at=now - 10,
        expires_at=now + 3600,
    )
    binding_sig = binding_mod.sign_binding(root, body)
    pay = payment_mod.make_fixture_payment_binding()
    pay_hash = payment_mod.payment_hash_v2(pay)
    signed_map = identity_mod.build_signed_map(
        domain="example.test",
        identifier="alice@example.test",
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        created_at=now - 10,
        expires_at=now + 3600,
        payment_hash=pay_hash,
    )
    id_sig = identity_mod.sign_identity(signing, signed_map)
    document = identity_mod.attach_signature(signed_map, id_sig)
    am = anchor_mod.build_anchor_message(
        domain="example.test",
        identifier="alice@example.test",
        root_pubkey=root.pubkey,
    )
    opreturn = anchor_mod.build_opreturn_script(anchor_mod.anchor_commitment(am))
    return {
        "now": now,
        "root": root,
        "signing": signing,
        "body": body,
        "binding_sig": binding_sig,
        "pay": pay,
        "document": document,
        "opreturn": opreturn,
    }


def test1_signing_pubkey_substituted() -> None:
    b = _fresh_bundle()
    other = generate_keypair()
    bad_body = dict(b["body"])
    bad_body[binding_mod.KEY_SIGNING] = other.pubkey
    # keep old signature → binding must fail
    try:
        verify(
            root_pubkey=b["root"].pubkey,
            signing_pubkey=other.pubkey,
            binding_body=bad_body,
            binding_signature=b["binding_sig"],
            identity_document=b["document"],
            payment_binding=b["pay"],
            opreturn_script=b["opreturn"],
            now=b["now"],
        )
        raise AssertionError("expected failure")
    except VerifyError as exc:
        assert exc.code == "INVALID_SUBKEY_BINDING", exc.code
    print("TEST 1 PASS (INVALID_SUBKEY_BINDING)")


def test2_document_mutated_after_sign() -> None:
    b = _fresh_bundle()
    bad_doc = dict(b["document"])
    bad_doc[identity_mod.K_DOMAIN] = "evil.test"
    bad_doc[identity_mod.K_IDENTIFIER] = "alice@evil.test"
    try:
        verify(
            root_pubkey=b["root"].pubkey,
            signing_pubkey=b["signing"].pubkey,
            binding_body=b["body"],
            binding_signature=b["binding_sig"],
            identity_document=bad_doc,
            payment_binding=b["pay"],
            opreturn_script=None,
            now=b["now"],
        )
        raise AssertionError("expected failure")
    except VerifyError as exc:
        assert exc.code in {"INVALID_IDENTITY_SIGNATURE", "IDENTIFIER_MISMATCH"}, exc.code
    print("TEST 2 PASS (INVALID_IDENTITY_SIGNATURE / domain)")


def test3_wrong_signing_key() -> None:
    b = _fresh_bundle()
    other = generate_keypair()
    signed = {k: v for k, v in b["document"].items() if k != identity_mod.K_SIGNATURE}
    # resign with other key but leave document claiming original signing pubkey
    digest = identity_mod.identity_digest(signed)
    bad_sig = other.sign_msg32(digest)
    bad_doc = identity_mod.attach_signature(signed, bad_sig)
    try:
        verify(
            root_pubkey=b["root"].pubkey,
            signing_pubkey=b["signing"].pubkey,
            binding_body=b["body"],
            binding_signature=b["binding_sig"],
            identity_document=bad_doc,
            payment_binding=b["pay"],
            opreturn_script=None,
            now=b["now"],
        )
        raise AssertionError("expected failure")
    except VerifyError as exc:
        assert exc.code == "INVALID_IDENTITY_SIGNATURE", exc.code
    print("TEST 3 PASS (INVALID_IDENTITY_SIGNATURE)")


def test4_payment_binding_modified() -> None:
    b = _fresh_bundle()
    bad_pay = payment_mod.make_fixture_payment_binding(script_pubkey=bytes([0x00, 0x14]) + b"\x22" * 20)
    try:
        verify(
            root_pubkey=b["root"].pubkey,
            signing_pubkey=b["signing"].pubkey,
            binding_body=b["body"],
            binding_signature=b["binding_sig"],
            identity_document=b["document"],
            payment_binding=bad_pay,
            opreturn_script=None,
            now=b["now"],
        )
        raise AssertionError("expected failure")
    except VerifyError as exc:
        assert exc.code == "PAYMENT_BINDING_MISMATCH", exc.code
    print("TEST 4 PASS (PAYMENT_BINDING_MISMATCH)")


def test5_root_key_modified_anchor() -> None:
    b = _fresh_bundle()
    other_root = generate_keypair()
    # OP_RETURN still commits to original root; verify with other root → ANCHOR_MISMATCH
    try:
        verify(
            root_pubkey=other_root.pubkey,
            signing_pubkey=b["signing"].pubkey,
            binding_body=b["body"],
            binding_signature=b["binding_sig"],
            identity_document=b["document"],
            payment_binding=b["pay"],
            opreturn_script=b["opreturn"],
            now=b["now"],
        )
        raise AssertionError("expected failure")
    except VerifyError as exc:
        assert exc.code in {"INVALID_SUBKEY_BINDING", "ANCHOR_MISMATCH"}, exc.code
        print(f"TEST 5 PASS ({exc.code})")


def test6_wrong_tag_domain_separator() -> None:
    b = _fresh_bundle()
    signed = {k: v for k, v in b["document"].items() if k != identity_mod.K_SIGNATURE}
    # Sign under wrong tag; verify under correct tag must fail
    wrong_digest = tagged_hash_msg("BIP353-IDENTITY/V2/WRONG", identity_mod.signed_map_cbor(signed))
    wrong_sig = b["signing"].sign_msg32(wrong_digest)
    # confirm wrong tag verify would pass with wrong tag
    assert verify_msg32(b["signing"].pubkey, wrong_digest, wrong_sig)
    # correct identity digest must not verify
    good_digest = tagged_hash_msg(TAG_IDENTITY, identity_mod.signed_map_cbor(signed))
    assert not verify_msg32(b["signing"].pubkey, good_digest, wrong_sig)
    # binding wrong tag similarly
    wrong_b = tagged_hash_msg("BIP353-IDENTITY/V2/WRONG", binding_mod.binding_body_cbor(b["body"]))
    bad_bsig = b["root"].sign_msg32(wrong_b)
    good_b = tagged_hash_msg(TAG_SUBKEY_BINDING, binding_mod.binding_body_cbor(b["body"]))
    assert not verify_msg32(b["root"].pubkey, good_b, bad_bsig)
    print("TEST 6 PASS (wrong tag → signature verification failure)")


def main() -> None:
    test1_signing_pubkey_substituted()
    test2_document_mutated_after_sign()
    test3_wrong_signing_key()
    test4_payment_binding_modified()
    test5_root_key_modified_anchor()
    test6_wrong_tag_domain_separator()
    print("NEGATIVE TESTS: PASS")


if __name__ == "__main__":
    main()

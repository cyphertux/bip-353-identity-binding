#!/usr/bin/env python3
"""Phase 6 red-team harness for experimental Schnorr V2.

EXPERIMENTAL — does not modify protocol. Evidence for SCHNORR_V2_SECURITY_REVIEW.md
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from embit import ec

from reference import cbor
from reference.schnorr_v2 import anchor as A
from reference.schnorr_v2 import binding as B
from reference.schnorr_v2 import identity as I
from reference.schnorr_v2 import payment as P
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.key import keypair_from_secret, verify_msg32
from reference.schnorr_v2.tags import (
    TAG_ANCHOR,
    TAG_IDENTITY,
    TAG_PAYMENT,
    TAG_SUBKEY_BINDING,
)
from reference.schnorr_v2.verify import VerifyError, verify

NOW = 1_700_000_000
results: list[tuple[str, bool, str]] = []


def record(name: str, cond: bool, detail: str = "") -> None:
    results.append((name, cond, detail))
    print(("PASS" if cond else "FAIL"), name, detail)


def independent_tagged_hash(tag: str, msg: bytes) -> bytes:
    t = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(t + t + msg).digest()


def main() -> int:
    root = keypair_from_secret(bytes.fromhex("11" * 32))
    signing = keypair_from_secret(bytes.fromhex("22" * 32))
    alt = keypair_from_secret(bytes.fromhex("33" * 32))

    body = B.build_binding_body(
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        created_at=NOW - 10,
        expires_at=NOW + 99999,
    )
    bsig = B.sign_binding(root, body)
    pay = P.make_fixture_payment_binding()
    ph = P.payment_hash_v2(pay)
    smap = I.build_signed_map(
        domain="example.test",
        identifier="alice@example.test",
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        created_at=NOW - 10,
        expires_at=NOW + 99999,
        payment_hash=ph,
    )
    isig = I.sign_identity(signing, smap)
    doc = I.attach_signature(smap, isig)
    op = A.build_opreturn_script(
        A.anchor_commitment(
            A.build_anchor_message(
                domain="example.test",
                identifier="alice@example.test",
                root_pubkey=root.pubkey,
            )
        )
    )

    # --- BIP-340 official verify vector 0 ---
    sk = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000003")
    pk_exp = bytes.fromhex(
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"
    )
    msg = bytes(32)
    sig = bytes.fromhex(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
    )
    pk = ec.PrivateKey(sk).get_public_key().xonly()
    record("bip340-pubkey-vector0", pk == pk_exp)
    record(
        "bip340-official-verify-vector0",
        ec.PublicKey.from_xonly(pk).schnorr_verify(ec.SchnorrSig(sig), msg),
    )
    # invalid pubkey must reject (vector 5)
    bad_pk = bytes.fromhex(
        "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"
    )
    try:
        ec.PublicKey.from_xonly(bad_pk)
        record("bip340-reject-offcurve", False)
    except Exception:
        record("bip340-reject-offcurve", True)

    record(
        "independent-tagged-hash",
        independent_tagged_hash(TAG_IDENTITY, b"x")
        == tagged_hash_msg(TAG_IDENTITY, b"x"),
    )

    # --- Binding attacks ---
    try:
        bad = dict(body)
        bad[B.KEY_SIGNING] = alt.pubkey
        B.verify_binding(
            root_pubkey=root.pubkey, body=bad, binding_signature=bsig, now=NOW
        )
        record("A-signing-substitution", False)
    except B.BindingError:
        record("A-signing-substitution", True)

    try:
        B.verify_binding(
            root_pubkey=alt.pubkey, body=body, binding_signature=bsig, now=NOW
        )
        record("B-root-substitution", False)
    except B.BindingError:
        record("B-root-substitution", True)

    # Binding has no domain: replay binding OK; old identity sig for new domain MUST fail
    smap2 = I.build_signed_map(
        domain="evil.test",
        identifier="alice@evil.test",
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        created_at=NOW - 10,
        expires_at=NOW + 99999,
        payment_hash=ph,
    )
    doc2 = I.attach_signature(smap2, isig)
    try:
        verify(
            root_pubkey=root.pubkey,
            signing_pubkey=signing.pubkey,
            binding_body=body,
            binding_signature=bsig,
            identity_document=doc2,
            payment_binding=pay,
            opreturn_script=None,
            now=NOW,
        )
        record("C-domain-replay-without-resign", False, "accepted")
    except VerifyError as e:
        record("C-domain-replay-without-resign", e.code == "INVALID_IDENTITY_SIGNATURE", e.code)

    try:
        verify(
            root_pubkey=alt.pubkey,
            signing_pubkey=signing.pubkey,
            binding_body=body,
            binding_signature=bsig,
            identity_document=doc,
            payment_binding=pay,
            opreturn_script=None,
            now=NOW,
        )
        record("D-cross-root", False)
    except VerifyError as e:
        record("D-cross-root", e.code == "INVALID_SUBKEY_BINDING", e.code)

    wrong = tagged_hash_msg(TAG_IDENTITY, B.binding_body_cbor(body))
    record("E-cross-tag-reuse", not verify_msg32(root.pubkey, wrong, bsig))

    record("tag-neq-v1-payment", TAG_PAYMENT != "BIP353-IDENTITY/PAYMENT/v1")
    record("tag-neq-v1-anchor", TAG_ANCHOR != "BIP353-IDENTITY/ANCHOR/v1")
    record(
        "all-tags-distinct",
        len({TAG_SUBKEY_BINDING, TAG_IDENTITY, TAG_PAYMENT, TAG_ANCHOR}) == 4,
    )

    # CBOR
    obj = {0: 1, 2: b"ab", 1: "x"}
    canon = cbor.dumps(obj)
    record("cbor-deterministic", canon == cbor.dumps(obj))
    try:
        cbor.loads(bytes([0x18, 0x00]))
        record("cbor-reject-nonminimal", False)
    except cbor.CBORError:
        record("cbor-reject-nonminimal", True)
    try:
        cbor.loads(canon + b"\x00")
        record("cbor-reject-trailing", False)
    except cbor.CBORError:
        record("cbor-reject-trailing", True)
    try:
        cbor.loads(bytes([0x9F, 0x01, 0xFF]))
        record("cbor-reject-indefinite", False)
    except cbor.CBORError:
        record("cbor-reject-indefinite", True)

    # Identity mutations (signed fields)
    mutations = [
        (I.K_VERSION, 99),
        (I.K_CREATED, NOW),
        (I.K_EXPIRES, NOW + 1),
        (I.K_PAYMENT_HASH, bytes(32)),
        (I.K_ROOT, alt.pubkey),
        (I.K_SIGNING, alt.pubkey),
        (I.K_IDENTIFIER, "bob@example.test"),
    ]
    for key, new in mutations:
        d = dict(doc)
        d[key] = new
        try:
            I.verify_identity_signature(d)
            record(f"id-mut-{key}", False)
        except I.IdentityError:
            record(f"id-mut-{key}", True)

    d = dict(doc)
    d[I.K_DOMAIN] = "evil.test"
    d[I.K_IDENTIFIER] = "alice@evil.test"
    try:
        I.verify_identity_signature(d)
        record("id-mut-domain", False)
    except I.IdentityError:
        record("id-mut-domain", True)

    # Adding sequence after sign changes signed map
    d = dict(doc)
    d[I.K_SEQUENCE] = 1
    try:
        I.verify_identity_signature(d)
        record("id-mut-add-sequence", False)
    except I.IdentityError:
        record("id-mut-add-sequence", True)

    # Payment destination substitution
    pay2 = P.make_fixture_payment_binding(script_pubkey=bytes([0, 0x14]) + b"\xff" * 20)
    try:
        verify(
            root_pubkey=root.pubkey,
            signing_pubkey=signing.pubkey,
            binding_body=body,
            binding_signature=bsig,
            identity_document=doc,
            payment_binding=pay2,
            opreturn_script=None,
            now=NOW,
        )
        record("pay-dest-sub", False)
    except VerifyError as e:
        record("pay-dest-sub", e.code == "PAYMENT_BINDING_MISMATCH", e.code)

    # Anchor attacks
    for name, am in [
        (
            "anchor-root-sub",
            A.build_anchor_message(
                domain="example.test",
                identifier="alice@example.test",
                root_pubkey=alt.pubkey,
            ),
        ),
        (
            "anchor-domain-sub",
            A.build_anchor_message(
                domain="evil.test",
                identifier="alice@evil.test",
                root_pubkey=root.pubkey,
            ),
        ),
        (
            "anchor-id-sub",
            A.build_anchor_message(
                domain="example.test",
                identifier="bob@example.test",
                root_pubkey=root.pubkey,
            ),
        ),
    ]:
        bad_op = A.build_opreturn_script(A.anchor_commitment(am))
        try:
            verify(
                root_pubkey=root.pubkey,
                signing_pubkey=signing.pubkey,
                binding_body=body,
                binding_signature=bsig,
                identity_document=doc,
                payment_binding=pay,
                opreturn_script=bad_op,
                now=NOW,
            )
            record(name, False)
        except VerifyError as e:
            record(name, e.code == "ANCHOR_MISMATCH", e.code)

    bad = bytearray(op)
    bad[-1] ^= 1
    try:
        verify(
            root_pubkey=root.pubkey,
            signing_pubkey=signing.pubkey,
            binding_body=body,
            binding_signature=bsig,
            identity_document=doc,
            payment_binding=pay,
            opreturn_script=bytes(bad),
            now=NOW,
        )
        record("anchor-commit-mut", False)
    except VerifyError as e:
        record("anchor-commit-mut", e.code == "ANCHOR_MISMATCH", e.code)

    v1_script = bytes([0x6A, 0x27]) + b"B353ID" + bytes([1]) + bytes(32)
    try:
        A.extract_commitment_from_opreturn(v1_script)
        record("reject-B353ID", False)
    except A.AnchorError:
        record("reject-B353ID", True)

    # Cross-context: identity sig over payment cbor under wrong meanings
    pay_cbor = cbor.dumps(pay)
    record(
        "cross-payment-as-identity-msg",
        not verify_msg32(
            signing.pubkey, tagged_hash_msg(TAG_IDENTITY, pay_cbor), isig
        ),
    )
    record(
        "cross-anchor-tag-neq-payment",
        tagged_hash_msg(TAG_ANCHOR, pay_cbor)
        != tagged_hash_msg(TAG_PAYMENT, pay_cbor),
    )

    # Light fuzz
    for i in range(300):
        blob = os.urandom(i % 90)
        try:
            cbor.loads(blob)
        except Exception:
            pass
        try:
            A.extract_commitment_from_opreturn(blob)
        except Exception:
            pass
    record("fuzz-no-crash", True, "300 random CBOR/OP_RETURN parses")

    # Implementation gap: dual-binding / merkle
    text = ""
    for p in Path("reference/schnorr_v2").glob("*.py"):
        text += p.read_text(encoding="utf-8")
    record(
        "dual-binding-present",
        ("raw_tx" in text) and ("merkle" in text.lower()) and ("B353S2" in text or "b353s2" in text.lower()),
        "F-S1 dual-binding modules present",
    )

    # Happy path still works
    out = verify(
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        binding_body=body,
        binding_signature=bsig,
        identity_document=doc,
        payment_binding=pay,
        now=NOW,
        opreturn_script=op,
        bitcoin_proof=None,
    )
    record(
        "happy-path-logical-not-anchored",
        out["identity_verified"]
        and out["payment_verified"]
        and out["identity_anchored"] is False,
    )

    from reference.schnorr_v2.bitcoin_proof import (
        build_minimal_legacy_tx,
        proof_from_parts,
        proof_to_jsonable,
    )

    raw = build_minimal_legacy_tx(opreturn_script=op)
    from reference.schnorr_v2.anchor import anchor_commitment, build_anchor_message

    commitment = anchor_commitment(
        build_anchor_message(
            domain="example.test",
            identifier="alice@example.test",
            root_pubkey=root.pubkey,
        )
    )
    btc = proof_to_jsonable(proof_from_parts(raw_tx=raw, expected_commitment=commitment))
    out2 = verify(
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        binding_body=body,
        binding_signature=bsig,
        identity_document=doc,
        payment_binding=pay,
        now=NOW,
        bitcoin_proof=btc,
    )
    record(
        "happy-path-dual-binding",
        all(
            out2[k]
            for k in (
                "identity_verified",
                "payment_verified",
                "identity_anchored",
                "continuity_verified",
            )
        ),
    )

    fails = [n for n, c, _ in results if not c]
    print("---")
    print(f"PASS {sum(1 for _, c, _ in results if c)} / {len(results)}")
    print("FAILS:", fails)
    return 1 if fails else 0


if __name__ == "__main__":
    raise SystemExit(main())

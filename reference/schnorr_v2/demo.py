"""End-to-end demo for experimental Schnorr identity V2."""

from __future__ import annotations

import json
import time

from reference import cbor
from reference.schnorr_v2 import anchor as anchor_mod
from reference.schnorr_v2 import binding as binding_mod
from reference.schnorr_v2 import identity as identity_mod
from reference.schnorr_v2 import payment as payment_mod
from reference.schnorr_v2.key import generate_keypair
from reference.schnorr_v2.tags import (
    OP_RETURN_TAG,
    TAG_ANCHOR,
    TAG_IDENTITY,
    TAG_PAYMENT,
    TAG_SUBKEY_BINDING,
)
from reference.schnorr_v2.verify import verify


def run() -> dict:
    now = int(time.time())
    root = generate_keypair()
    signing = generate_keypair()

    body = binding_mod.build_binding_body(
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        created_at=now - 60,
        expires_at=now + 86400,
    )
    # CBOR determinism check
    assert cbor.dumps(body) == cbor.dumps(dict(body))
    binding_sig = binding_mod.sign_binding(root, body)
    binding_mod.verify_binding(
        root_pubkey=root.pubkey, body=body, binding_signature=binding_sig, now=now
    )

    pay = payment_mod.make_fixture_payment_binding()
    pay_hash = payment_mod.payment_hash_v2(pay)

    signed_map = identity_mod.build_signed_map(
        domain="example.test",
        identifier="alice@example.test",
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        created_at=now - 60,
        expires_at=now + 86400,
        payment_hash=pay_hash,
    )
    id_sig = identity_mod.sign_identity(signing, signed_map)
    document = identity_mod.attach_signature(signed_map, id_sig)
    identity_mod.verify_identity_signature(document)

    am = anchor_mod.build_anchor_message(
        domain="example.test",
        identifier="alice@example.test",
        root_pubkey=root.pubkey,
    )
    commitment = anchor_mod.anchor_commitment(am)
    opreturn = anchor_mod.build_opreturn_script(commitment)

    result = verify(
        root_pubkey=root.pubkey,
        signing_pubkey=signing.pubkey,
        binding_body=body,
        binding_signature=binding_sig,
        identity_document=document,
        payment_binding=pay,
        opreturn_script=opreturn,
        now=now,
    )

    return {
        "library": "embit==0.8.0",
        "tags": {
            "SUBKEY_BINDING": TAG_SUBKEY_BINDING,
            "IDENTITY": TAG_IDENTITY,
            "PAYMENT": TAG_PAYMENT,
            "ANCHOR": TAG_ANCHOR,
            "OP_RETURN": OP_RETURN_TAG.decode("ascii"),
        },
        "root_pubkey": root.pubkey.hex(),
        "signing_pubkey": signing.pubkey.hex(),
        "payment_hash": pay_hash.hex(),
        "commitment": commitment.hex(),
        "opreturn_script": opreturn.hex(),
        "verify": result,
    }


if __name__ == "__main__":
    out = run()
    print(json.dumps(out, indent=2))
    assert out["verify"]["identity_verified"] is True
    assert out["verify"]["payment_verified"] is True
    assert out["verify"]["identity_anchored"] is True
    assert out["verify"]["continuity_verified"] is True
    print("END-TO-END: PASS")

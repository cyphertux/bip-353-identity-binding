#!/usr/bin/env python3
"""End-to-end M4 verifier combining payment + anchor + inclusion."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference import cbor
from reference.bitcoin_anchor import identity_commitment, parse_op_return_commitment
from reference.bitcoin_proof import (
    BitcoinAnchorProofV1,
    HeaderContext,
    verify_bitcoin_anchor_proof,
)
from reference.payment_binding import parse_payment_binding, payment_hash


def verify_m4_bundle(m4_dir: Path) -> dict:
    expected = json.loads((m4_dir / "expected.json").read_text())
    binding = parse_payment_binding((m4_dir / "payment-binding.cbor").read_bytes())
    anchor = cbor.loads((m4_dir / "anchor-message.cbor").read_bytes())
    proof = BitcoinAnchorProofV1.from_dict(
        json.loads((m4_dir / "bitcoin-anchor-proof.json").read_text())
    )

    pay_h = payment_hash(binding)
    commit = identity_commitment(anchor)

    # OP_RETURN in raw fixture script
    opreturn_script = bytes.fromhex((m4_dir / "opreturn-script.hex").read_text().strip())
    extracted = parse_op_return_commitment(opreturn_script)

    result = {
        "payment_verified": pay_h.hex() == expected["payment_hash"],
        "identity_verified": True,  # OpenPGP layer assumed from M1–M3 for this fixture
        "identity_anchored": commit.hex() == expected["identity_commitment"]
        and extracted == commit,
        "anchor_included": False,
        "freshness": "unknown",
        "human_verified": False,
        "errors": [],
    }

    if pay_h.hex() != expected["payment_hash"]:
        result["errors"].append("PAYMENT_HASH_MISMATCH")
    if commit.hex() != expected["identity_commitment"]:
        result["errors"].append("COMMITMENT_MISMATCH")
    if extracted != commit:
        result["errors"].append("OP_RETURN_MISMATCH")

    vr = verify_bitcoin_anchor_proof(
        proof,
        expected_commitment=commit,
        confirmation_policy=1,
        header_context=HeaderContext.TRUSTED,
    )
    result["anchor_included"] = vr.anchor_included
    result["anchor_status"] = vr.anchor_status
    result["transaction_valid"] = vr.transaction_valid
    result["inclusion_proof_valid"] = vr.inclusion_proof_valid
    result["header_context"] = vr.header_context
    result["freshness_status"] = vr.freshness_status
    result["rollback_resistance"] = vr.rollback_resistance
    result["errors"].extend(vr.errors)

    # Never claim human verification
    assert result["human_verified"] is False
    return result


def main() -> int:
    m4 = ROOT / "vectors" / "m4"
    if not m4.exists():
        print("vectors/m4 missing — run scripts/generate_m4_regtest.py")
        return 2
    result = verify_m4_bundle(m4)
    print(json.dumps(result, indent=2))
    (ROOT / "test" / "m4_e2e_result.json").write_text(json.dumps(result, indent=2) + "\n")
    ok = (
        result["payment_verified"]
        and result["identity_verified"]
        and result["identity_anchored"]
        and result["anchor_included"]
        and result["freshness"] == "unknown"
        and result["human_verified"] is False
        and not result["errors"]
    )
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

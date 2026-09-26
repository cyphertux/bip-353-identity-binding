#!/usr/bin/env python3
"""M6 regression: F-J2 — mutate OP_RETURN commitment inside raw_tx → REJECT.

Expected: WRONG_TX_COMMITMENT (extracted commitment ≠ expected).
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reference.bitcoin_proof import (  # noqa: E402
    BitcoinAnchorProofV1,
    HeaderContext,
    verify_bitcoin_anchor_proof,
)
from reference.bitcoin_tx import txid_from_raw  # noqa: E402

OUT = Path(__file__).resolve().parent / "fj2_regression_result.json"


def main() -> int:
    m4 = ROOT / "vectors" / "m4"
    proof = BitcoinAnchorProofV1.from_dict(
        json.loads((m4 / "bitcoin-anchor-proof.json").read_text())
    )
    expected = json.loads((m4 / "expected.json").read_text())
    commitment = bytes.fromhex(expected["identity_commitment"])

    # Valid baseline
    ok = verify_bitcoin_anchor_proof(
        proof,
        expected_commitment=commitment,
        header_context=HeaderContext.TRUSTED,
    )
    assert ok.identity_anchored and ok.anchor_included and not ok.errors

    # J2: flip one bit in OP_RETURN commitment inside raw_tx only
    p = copy.deepcopy(proof)
    raw = bytearray(p.raw_tx)
    tag = b"B353ID"
    idx = bytes(raw).find(tag)
    assert idx >= 0
    raw[idx + len(tag) + 1] ^= 0x01
    p.raw_tx = bytes(raw)
    # Optionally align proof.txid with mutated raw so failure is commitment-specific
    p.txid = txid_from_raw(p.raw_tx)
    # Keep proof.commitment = original expected (auxiliary lie)

    r = verify_bitcoin_anchor_proof(
        p,
        expected_commitment=commitment,
        header_context=HeaderContext.TRUSTED,
    )
    blocked = (
        any("WRONG_TX_COMMITMENT" in e for e in r.errors)
        and not r.anchor_included
        and not (r.identity_anchored and r.inclusion_proof_valid and not r.errors)
    )
    result = {
        "attack": "F-J2",
        "expected": "WRONG_TX_COMMITMENT",
        "actual_errors": r.errors,
        "anchor_included": r.anchor_included,
        "identity_anchored": r.identity_anchored,
        "pass": blocked,
    }
    OUT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())

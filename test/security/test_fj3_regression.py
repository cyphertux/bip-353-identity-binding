#!/usr/bin/env python3
"""M6 regression: F-J3 — raw_tx for another tx vs claimed proof.txid → REJECT.

Expected: TXID_MISMATCH (SHA256d(raw_tx) ≠ proof.txid).
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

OUT = Path(__file__).resolve().parent / "fj3_regression_result.json"


def main() -> int:
    m4 = ROOT / "vectors" / "m4"
    proof = BitcoinAnchorProofV1.from_dict(
        json.loads((m4 / "bitcoin-anchor-proof.json").read_text())
    )
    expected = json.loads((m4 / "expected.json").read_text())
    commitment = bytes.fromhex(expected["identity_commitment"])

    # Keep original raw_tx (contains expected commitment) but claim a different txid
    # with a Merkle proof consistent for that *other* txid alone.
    p = copy.deepcopy(proof)
    other_txid = bytes(32)
    p.txid = other_txid
    p.tx_index = 0
    p.merkle_branch = []
    hdr = bytearray(p.block_header)
    hdr[36:68] = other_txid  # merkle root = other_txid (single-tx tree)
    p.block_header = bytes(hdr)
    # proof.commitment still equals expected (auxiliary)

    r = verify_bitcoin_anchor_proof(
        p,
        expected_commitment=commitment,
        header_context=HeaderContext.TRUSTED,
    )
    blocked = any("TXID_MISMATCH" in e for e in r.errors) and not r.anchor_included
    result = {
        "attack": "F-J3",
        "expected": "TXID_MISMATCH",
        "actual_errors": r.errors,
        "anchor_included": r.anchor_included,
        "transaction_valid": r.transaction_valid,
        "pass": blocked,
    }
    OUT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if blocked else 1


if __name__ == "__main__":
    raise SystemExit(main())

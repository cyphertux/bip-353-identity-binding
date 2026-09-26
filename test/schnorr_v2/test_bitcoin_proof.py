"""Tests for experimental V2 Bitcoin dual-binding (F-S1)."""

from __future__ import annotations

import json
from pathlib import Path

from reference.schnorr_v2.bitcoin_proof import (
    BitcoinProofError,
    proof_from_jsonable,
    verify_bitcoin_anchor_proof_v2,
)
from reference.schnorr_v2.key import keypair_from_secret
from reference.schnorr_v2.anchor import anchor_commitment, build_anchor_message

ROOT = Path(__file__).resolve().parents[2]
VEC = ROOT / "vectors" / "schnorr"
ROOT_SK = bytes.fromhex("01" * 32)


def _load(name: str) -> dict:
    return json.loads((VEC / name).read_text(encoding="utf-8"))


def _expect(name: str, code: str | None) -> None:
    vec = _load(name)
    proof = proof_from_jsonable(vec["bitcoin_proof"])
    expected = bytes.fromhex(vec["anchor_commitment"])
    if code is None:
        verify_bitcoin_anchor_proof_v2(proof, expected_commitment=expected)
        # continuity: root in vector matches commitment reconstruction
        root = keypair_from_secret(ROOT_SK)
        assert vec["root_pubkey"] == root.pubkey.hex()
        am = build_anchor_message(
            domain=vec["domain"],
            identifier=vec["identifier"],
            root_pubkey=root.pubkey,
        )
        assert anchor_commitment(am) == expected
        print(f"{name}: PASS")
        return
    try:
        verify_bitcoin_anchor_proof_v2(proof, expected_commitment=expected)
        raise AssertionError(f"{name}: expected {code}")
    except BitcoinProofError as exc:
        assert exc.code == code, f"{name}: got {exc.code} want {code}"
        print(f"{name}: PASS ({code})")


def main() -> None:
    _expect("V2-BTC-VALID-001.json", None)
    _expect("V2-BTC-INVALID-001.json", "TXID_MISMATCH")
    _expect("V2-BTC-INVALID-002.json", "WRONG_MERKLE_PROOF")
    _expect("V2-BTC-INVALID-003.json", "WRONG_MERKLE_PROOF")
    _expect("V2-BTC-INVALID-004.json", "WRONG_MERKLE_PROOF")
    _expect("V2-BTC-INVALID-005.json", "WRONG_TX_COMMITMENT")
    _expect("V2-BTC-INVALID-006.json", "NO_B353S2_OUTPUT")
    _expect("V2-BTC-INVALID-007.json", "AMBIGUOUS_B353S2_OUTPUTS")
    print("BITCOIN DUAL-BINDING TESTS: PASS")


if __name__ == "__main__":
    main()

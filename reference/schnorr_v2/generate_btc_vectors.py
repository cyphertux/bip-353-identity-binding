#!/usr/bin/env python3
"""Generate experimental V2 Bitcoin dual-binding fixtures (manual --write only)."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from reference.schnorr_v2.anchor import (
    anchor_commitment,
    build_anchor_message,
    build_opreturn_script,
)
from reference.schnorr_v2.bitcoin_proof import (
    build_header_for_txid,
    build_minimal_legacy_tx,
    proof_from_parts,
    proof_to_jsonable,
    verify_bitcoin_anchor_proof_v2,
)
from reference.schnorr_v2.key import keypair_from_secret
from reference.bitcoin_tx import parse_transaction

OUT = Path(__file__).resolve().parents[2] / "vectors" / "schnorr"
ROOT_SK = bytes.fromhex("01" * 32)
DOMAIN = "example.test"
IDENTIFIER = "alice@example.test"


def hx(b: bytes) -> str:
    return b.hex()


def expected_commitment() -> tuple[bytes, bytes]:
    root = keypair_from_secret(ROOT_SK)
    am = build_anchor_message(
        domain=DOMAIN, identifier=IDENTIFIER, root_pubkey=root.pubkey
    )
    return anchor_commitment(am), root.pubkey


def write(name: str, obj: dict) -> None:
    path = OUT / name
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    print("wrote", path)


def gen_valid() -> dict:
    commitment, root_pubkey = expected_commitment()
    script = build_opreturn_script(commitment)
    raw = build_minimal_legacy_tx(opreturn_script=script)
    proof = proof_from_parts(raw_tx=raw, expected_commitment=commitment)
    verify_bitcoin_anchor_proof_v2(proof, expected_commitment=commitment)
    return {
        "id": "V2-BTC-VALID-001",
        "version": 2,
        "description": "Complete dual-binding Bitcoin proof for experimental B353S2.",
        "warning": "TEST VECTOR ONLY — synthetic regtest fixture — NOT FOR PRODUCTION",
        "encoding": "hex-lowercase",
        "domain": DOMAIN,
        "identifier": IDENTIFIER,
        "root_pubkey": hx(root_pubkey),
        "anchor_commitment": hx(commitment),
        "bitcoin_proof": proof_to_jsonable(proof),
        "expected": {"result": "valid", "error_code": None},
    }


def gen_invalids(valid: dict) -> list[dict]:
    commitment = bytes.fromhex(valid["anchor_commitment"])
    base = proof_from_parts(
        raw_tx=bytes.fromhex(valid["bitcoin_proof"]["raw_tx"]),
        expected_commitment=commitment,
    )
    out = []

    # B wrong txid
    p = proof_to_jsonable(base)
    p["txid_internal"] = bytes(32).hex()
    out.append(
        {
            "id": "V2-BTC-INVALID-001",
            "description": "Auxiliary txid_internal does not match SHA256d(raw_tx).",
            "root_pubkey": valid["root_pubkey"],
            "domain": DOMAIN,
            "identifier": IDENTIFIER,
            "anchor_commitment": valid["anchor_commitment"],
            "bitcoin_proof": p,
            "expected": {"result": "invalid", "error_code": "TXID_MISMATCH"},
        }
    )

    # C wrong merkle sibling
    sib = bytes.fromhex("aa" * 32)
    header, branch = build_header_for_txid(base.txid, sibling=sib, tx_index=0)
    p = proof_to_jsonable(base)
    # keep correct header from base but wrong branch sibling
    p["merkle_branch"] = [bytes.fromhex("bb" * 32).hex()]
    # need header that expects a branch — use single-tx header with fake branch → WRONG_MERKLE
    out.append(
        {
            "id": "V2-BTC-INVALID-002",
            "description": "Merkle sibling corrupted.",
            "root_pubkey": valid["root_pubkey"],
            "domain": DOMAIN,
            "identifier": IDENTIFIER,
            "anchor_commitment": valid["anchor_commitment"],
            "bitcoin_proof": {
                **proof_to_jsonable(base),
                "merkle_branch": [hx(bytes.fromhex("cc" * 32))],
                # single-tx merkle root == txid; non-empty wrong branch fails
            },
            "expected": {"result": "invalid", "error_code": "WRONG_MERKLE_PROOF"},
        }
    )

    # For single-tx tree empty branch is correct. Wrong branch with empty expected:
    # verify_merkle_branch with non-empty branch won't equal root.
    # Good.

    # D wrong tx_index on 2-tx tree
    sibling = bytes.fromhex("11" * 32)
    header, branch = build_header_for_txid(base.txid, sibling=sibling, tx_index=0)
    proof2 = proof_from_parts(
        raw_tx=base.raw_tx, expected_commitment=commitment, sibling=sibling, tx_index=0
    )
    bad = proof_to_jsonable(proof2)
    bad["tx_index"] = 1  # wrong index with same branch
    out.append(
        {
            "id": "V2-BTC-INVALID-003",
            "description": "tx_index flipped for Merkle path.",
            "root_pubkey": valid["root_pubkey"],
            "domain": DOMAIN,
            "identifier": IDENTIFIER,
            "anchor_commitment": valid["anchor_commitment"],
            "bitcoin_proof": bad,
            "expected": {"result": "invalid", "error_code": "WRONG_MERKLE_PROOF"},
        }
    )

    # E wrong header merkle root
    bad_h = bytearray(base.block_header)
    bad_h[36] ^= 1
    p = proof_to_jsonable(base)
    p["block_header"] = bytes(bad_h).hex()
    out.append(
        {
            "id": "V2-BTC-INVALID-004",
            "description": "block_header.merkle_root mutated.",
            "root_pubkey": valid["root_pubkey"],
            "domain": DOMAIN,
            "identifier": IDENTIFIER,
            "anchor_commitment": valid["anchor_commitment"],
            "bitcoin_proof": p,
            "expected": {"result": "invalid", "error_code": "WRONG_MERKLE_PROOF"},
        }
    )

    # F wrong commitment in OP_RETURN
    wrong_commit = bytes([commitment[0] ^ 1]) + commitment[1:]
    raw_f = build_minimal_legacy_tx(opreturn_script=build_opreturn_script(wrong_commit))
    # Build proof that matches wrong tx's merkle but expected is correct commitment
    proof_f = proof_from_parts(raw_tx=raw_f, expected_commitment=wrong_commit)
    pj = proof_to_jsonable(proof_f)
    out.append(
        {
            "id": "V2-BTC-INVALID-005",
            "description": "raw_tx B353S2 commitment != expected AnchorMessage commitment.",
            "root_pubkey": valid["root_pubkey"],
            "domain": DOMAIN,
            "identifier": IDENTIFIER,
            "anchor_commitment": valid["anchor_commitment"],  # expected correct
            "bitcoin_proof": pj,  # tx commits to wrong
            "expected": {"result": "invalid", "error_code": "WRONG_TX_COMMITMENT"},
        }
    )

    # G no B353S2
    bare = bytes([0x6A, 0x01, 0x00])  # OP_RETURN push empty-ish not B353S2
    # use a simple OP_RETURN "x"
    script = bytes([0x6A, 0x01, 0x78])
    raw_g = build_minimal_legacy_tx(opreturn_script=script)
    # still need a structurally valid proof object for txid/merkle
    parsed = parse_transaction(raw_g)
    header, branch = build_header_for_txid(parsed.txid_internal)
    out.append(
        {
            "id": "V2-BTC-INVALID-006",
            "description": "Transaction has OP_RETURN but not B353S2.",
            "root_pubkey": valid["root_pubkey"],
            "domain": DOMAIN,
            "identifier": IDENTIFIER,
            "anchor_commitment": valid["anchor_commitment"],
            "bitcoin_proof": {
                "chain": "regtest",
                "raw_tx": hx(raw_g),
                "txid": parsed.txid_internal[::-1].hex(),
                "txid_internal": hx(parsed.txid_internal),
                "block_header": hx(header),
                "tx_index": 0,
                "merkle_branch": [],
                "commitment": valid["anchor_commitment"],
                "header_context": "trusted",
            },
            "expected": {"result": "invalid", "error_code": "NO_B353S2_OUTPUT"},
        }
    )

    # H duplicate B353S2
    script = build_opreturn_script(commitment)
    raw_h = build_minimal_legacy_tx(
        opreturn_script=script, extra_scripts=[script]
    )
    proof_h = proof_from_parts(raw_tx=raw_h, expected_commitment=commitment)
    # proof_from_parts doesn't verify extraction; verify will fail
    out.append(
        {
            "id": "V2-BTC-INVALID-007",
            "description": "Two matching B353S2 outputs in one transaction.",
            "root_pubkey": valid["root_pubkey"],
            "domain": DOMAIN,
            "identifier": IDENTIFIER,
            "anchor_commitment": valid["anchor_commitment"],
            "bitcoin_proof": proof_to_jsonable(proof_h),
            "expected": {"result": "invalid", "error_code": "AMBIGUOUS_B353S2_OUTPUTS"},
        }
    )
    return out


def update_checksums() -> None:
    # Append/update only BTC vector lines; keep Phase 4 lines intact by rewriting full file from all json
    lines = [
        "# Experimental Schnorr V2 vector checksums",
        "# EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1",
        "# Format: <sha256_hex>  <path-relative-to-repo-root>",
        "# Do not modify vectors/M7_CHECKSUMS.txt",
        "",
    ]
    for path in sorted(OUT.glob("V2-*.json")):
        rel = path.relative_to(OUT.parents[1])
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {rel.as_posix()}")
    (OUT / "SCHNORR_V2_CHECKSUMS.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    valid = gen_valid()
    invalids = gen_invalids(valid)
    if not args.write:
        print("dry-run OK", valid["id"], [v["id"] for v in invalids])
        return
    write("V2-BTC-VALID-001.json", valid)
    for v in invalids:
        write(f"{v['id']}.json", v)
    update_checksums()
    print("updated SCHNORR_V2_CHECKSUMS.txt")


if __name__ == "__main__":
    main()

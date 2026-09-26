#!/usr/bin/env python3
"""M6 verification hardening suite: binding, OP_RETURN, mutations, claims."""

from __future__ import annotations

import copy
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reference.bitcoin_anchor import (  # noqa: E402
    CommitmentExtractError,
    build_op_return_script,
    extract_identity_commitment,
    parse_op_return_commitment,
)
from reference.bitcoin_proof import (  # noqa: E402
    BitcoinAnchorProofV1,
    HeaderContext,
    verify_bitcoin_anchor_proof,
)
from reference.bitcoin_tx import txid_from_raw  # noqa: E402
from reference.limits import LIMITS  # noqa: E402
from reference.verifier import verify_proof_bundle  # noqa: E402
import tempfile

PASS = FAIL = 0
RESULTS: list[dict] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {name}")
        RESULTS.append({"id": name, "pass": True, "detail": detail})
    else:
        FAIL += 1
        print(f"[FAIL] {name}: {detail}")
        RESULTS.append({"id": name, "pass": False, "detail": detail})


def load_m4():
    m4 = ROOT / "vectors" / "m4"
    proof = BitcoinAnchorProofV1.from_dict(
        json.loads((m4 / "bitcoin-anchor-proof.json").read_text())
    )
    expected = json.loads((m4 / "expected.json").read_text())
    return proof, bytes.fromhex(expected["identity_commitment"]), expected


def test_txid_binding():
    proof, commitment, _ = load_m4()
    computed = txid_from_raw(proof.raw_tx)
    check("raw_tx_to_txid", computed == proof.txid, computed[::-1].hex())
    r = verify_bitcoin_anchor_proof(
        proof, expected_commitment=commitment, header_context=HeaderContext.TRUSTED
    )
    check("full_chain_ok", r.transaction_valid and r.inclusion_proof_valid and r.anchor_included)


def test_extract_opreturn():
    proof, commitment, _ = load_m4()
    extracted = extract_identity_commitment(proof.raw_tx)
    check("extract_valid", extracted == commitment)

    # wrong tag
    bad = build_op_return_script(commitment, tag=b"XXXXXX")
    check("wrong_tag", parse_op_return_commitment(bad) is None)

    # wrong version
    bad = build_op_return_script(commitment, version=0x02)
    check("wrong_version", parse_op_return_commitment(bad) is None)

    # wrong length / truncated
    script = build_op_return_script(commitment)
    check("truncated", parse_op_return_commitment(script[:-1]) is None)

    # extra bytes after commitment in payload
    tag = b"B353ID"
    payload = tag + b"\x01" + commitment + b"\x00"
    extra = b"\x6a" + bytes([len(payload)]) + payload
    check("extra_bytes", parse_op_return_commitment(extra) is None)

    # multiple B353ID outputs → ambiguous
    # Build a minimal 1-in 2-out tx by mutating M4 raw: duplicate OP_RETURN output.
    # Simpler: call extract on crafted dual-output via concatenating scripts into a
    # synthetic tx is hard; use parse on two scripts and policy unit-test:
    try:
        # Craft raw with two identical OP_RETURN by replacing change output script
        # with another B353ID (may invalidate amounts — parser doesn't care).
        raw = bytearray(proof.raw_tx)
        # Find second scriptPubKey (change) — fragile; instead build minimal tx.
        from reference.bitcoin_tx import parse_transaction

        # Minimal legacy tx: version=2, 1 input (null), 2 OP_RETURN outs, locktime=0
        def varint(n: int) -> bytes:
            return bytes([n]) if n < 0xFD else b"\xfd" + n.to_bytes(2, "little")

        opreturn = build_op_return_script(commitment)
        opreturn_b = build_op_return_script(bytes([0xFF]) + commitment[1:])
        vin = b"\x00" * 32 + b"\xff\xff\xff\xff" + varint(0) + b"\xff\xff\xff\xff"
        def out(script: bytes) -> bytes:
            return struct.pack("<Q", 0) + varint(len(script)) + script

        raw_multi = (
            struct.pack("<I", 2)
            + varint(1)
            + vin
            + varint(2)
            + out(opreturn)
            + out(opreturn_b)
            + struct.pack("<I", 0)
        )
        try:
            extract_identity_commitment(raw_multi)
            ok = False
            code = "accepted"
        except CommitmentExtractError as e:
            ok = e.code == "AMBIGUOUS_B353ID_OUTPUTS"
            code = e.code
        check("multiple_b353id_rejected", ok, code)
    except Exception as exc:
        check("multiple_b353id_rejected", False, str(exc))


def test_mutations():
    proof, commitment, _ = load_m4()
    cases = []

    def run(name, mutate, want_substr):
        p = copy.deepcopy(proof)
        mutate(p)
        r = verify_bitcoin_anchor_proof(
            p, expected_commitment=commitment, header_context=HeaderContext.TRUSTED
        )
        ok = (not r.anchor_included) and any(want_substr in e for e in r.errors)
        check(
            f"mut_{name}",
            ok,
            f"expected~{want_substr} actual={r.errors} included={r.anchor_included}",
        )
        cases.append(
            {
                "mutation": name,
                "expected": want_substr,
                "actual": r.errors,
                "anchor_included": r.anchor_included,
                "reason": "must not report included if binding broken",
                "pass": ok,
            }
        )

    def flip_opreturn(p):
        raw = bytearray(p.raw_tx)
        i = bytes(raw).find(b"B353ID") + 7
        raw[i] ^= 0x01
        p.raw_tx = bytes(raw)
        p.txid = txid_from_raw(p.raw_tx)

    run("op_return", flip_opreturn, "WRONG_TX_COMMITMENT")

    def mut_txid(p):
        p.txid = bytes(32)

    run("txid", mut_txid, "TXID_MISMATCH")

    def mut_commitment_field(p):
        p.commitment = bytes(32)

    run("commitment_field", mut_commitment_field, "WRONG_TX_COMMITMENT")

    def mut_raw(p):
        p.raw_tx = p.raw_tx + b"\x00"

    run("raw_tx_trailing", mut_raw, "TX_PARSE_ERROR")

    def mut_branch(p):
        if p.merkle_branch:
            p.merkle_branch = [bytes(32)] + list(p.merkle_branch[1:])
        else:
            p.merkle_branch = [bytes(32)]

    run("merkle_branch", mut_branch, "WRONG_MERKLE_PROOF")

    def mut_merkle_root(p):
        hdr = bytearray(p.block_header)
        hdr[36] ^= 0xFF
        p.block_header = bytes(hdr)

    run("merkle_root", mut_merkle_root, "WRONG_MERKLE_PROOF")

    def mut_header_version(p):
        # Changing non-merkle fields keeps merkle valid; still inclusion_proof_valid
        # under TRUSTED — height/hash not bound. Ensure human_verified false.
        hdr = bytearray(p.block_header)
        hdr[0] ^= 0x01
        p.block_header = bytes(hdr)

    p = copy.deepcopy(proof)
    mut_header_version(p)
    r = verify_bitcoin_anchor_proof(
        p, expected_commitment=commitment, header_context=HeaderContext.TRUSTED
    )
    # Merkle still verifies; block *hash* changed — Mode A honesty requires wallet
    # to have trusted this exact header. We still require human_verified false.
    check(
        "mut_header_non_merkle_no_human",
        r.human_verified is False and r.freshness_status == "unknown",
        str(r.to_dict()),
    )
    cases.append(
        {
            "mutation": "header_non_merkle",
            "expected": "human_verified=false; wallet must re-bind header hash",
            "actual": {
                "inclusion_proof_valid": r.inclusion_proof_valid,
                "human_verified": r.human_verified,
            },
            "anchor_included": r.anchor_included,
            "reason": "PoW/tip binding is wallet header_context responsibility",
            "pass": True,
        }
    )

    (ROOT / "test" / "m6" / "mutation_results.json").write_text(
        json.dumps(cases, indent=2) + "\n"
    )


def test_header_modes():
    proof, commitment, _ = load_m4()
    u = verify_bitcoin_anchor_proof(
        proof, expected_commitment=commitment, header_context=HeaderContext.UNTRUSTED
    )
    check(
        "mode_b_untrusted",
        u.inclusion_proof_valid
        and u.header_context == "untrusted"
        and not u.anchor_included,
        str(u.bitcoin),
    )
    t = verify_bitcoin_anchor_proof(
        proof, expected_commitment=commitment, header_context=HeaderContext.TRUSTED
    )
    check(
        "mode_a_trusted",
        t.inclusion_proof_valid and t.anchor_included and t.header_context == "trusted",
    )


def test_freshness_rollback():
    proof, commitment, _ = load_m4()
    r = verify_bitcoin_anchor_proof(
        proof, expected_commitment=commitment, header_context=HeaderContext.TRUSTED
    )
    check("freshness_unknown", r.freshness_status == "unknown" and r.freshness == "unknown")
    check("rollback_not_provided", r.rollback_resistance == "not_provided")
    check(
        "never_current",
        r.freshness_detail.get("status") == "unknown",
    )

    vdir = ROOT / "vectors" / "valid"
    with tempfile.TemporaryDirectory(prefix="m6-gpg-") as td:
        vr = verify_proof_bundle(
            identity_document_cbor=(vdir / "identity-document.cbor").read_bytes(),
            payment_binding_cbor=(vdir / "payment-binding.cbor").read_bytes(),
            anchor_message_cbor=(vdir / "anchor-message.cbor").read_bytes(),
            root_certificate_path=vdir / "root.asc",
            gnupghome=Path(td),
            requested_identifier=json.loads((vdir / "expected.json").read_text())[
                "identifier"
            ],
            expected_commitment=bytes.fromhex(
                json.loads((vdir / "expected.json").read_text())["identity_commitment"]
            ),
            now=json.loads((vdir / "expected.json").read_text()).get("verification_time"),
        )
        check("id_freshness_unknown", vr.freshness_status == "unknown")
        check("id_rollback_not_provided", vr.rollback_resistance == "not_provided")
        check("id_revocation_unknown", vr.revocation_status == "unknown")
        check("id_human_false", vr.human_verified is False)
        check("id_no_current_claim", vr.freshness_detail.get("status") == "unknown")


def test_limits_documented():
    check("limits_present", "raw_transaction" in LIMITS and LIMITS["domain"]["status"] == "PROVISIONAL")


def main() -> int:
    (ROOT / "test" / "m6").mkdir(exist_ok=True)
    test_txid_binding()
    test_extract_opreturn()
    test_mutations()
    test_header_modes()
    test_freshness_rollback()
    test_limits_documented()

    out = {
        "pass": PASS,
        "fail": FAIL,
        "results": RESULTS,
    }
    (ROOT / "test" / "m6" / "m6_results.json").write_text(json.dumps(out, indent=2) + "\n")
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

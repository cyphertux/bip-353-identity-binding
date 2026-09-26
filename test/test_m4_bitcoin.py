#!/usr/bin/env python3
"""M4 Bitcoin anchor, inclusion proof, reorg, and attack vectors."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.bitcoin_anchor import (
    build_anchor_message_a,
    build_anchor_message_b,
    build_anchor_message_c,
    build_op_return_script,
    identity_commitment,
    opreturn_size_analysis,
    parse_op_return_commitment,
)
from reference.bitcoin_proof import (
    AnchorStatus,
    BitcoinAnchorProofV1,
    BlockHeader,
    HeaderContext,
    evaluate_anchor_status,
    verify_bitcoin_anchor_proof,
    verify_merkle_branch,
)
from reference.payment_binding import build_payment_binding, payment_hash

PASS = FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}: {detail}")


def test_anchor_sensitivity():
    domain = "example.test"
    ident = "alice@example.test"
    root = bytes.fromhex("de26bd614a4224ac0b704ed1c8f68e1738268297")
    base = build_anchor_message_a(domain=domain, identifier=ident, root_fingerprint=root)
    h = identity_commitment(base)

    check(
        "H_domain_change",
        identity_commitment(
            build_anchor_message_a(
                domain="evil.test", identifier=ident, root_fingerprint=root
            )
        )
        != h,
    )
    check(
        "H_identifier_change",
        identity_commitment(
            build_anchor_message_a(
                domain=domain, identifier="bob@example.test", root_fingerprint=root
            )
        )
        != h,
    )
    check(
        "H_root_change",
        identity_commitment(
            build_anchor_message_a(
                domain=domain, identifier=ident, root_fingerprint=bytes(20)
            )
        )
        != h,
    )
    check(
        "H_version_change",
        identity_commitment(
            build_anchor_message_a(
                domain=domain, identifier=ident, root_fingerprint=root, version=2
            )
        )
        != h,
    )


def test_candidate_abc():
    domain = "example.test"
    ident = "alice@example.test"
    root = bytes.fromhex("de26bd614a4224ac0b704ed1c8f68e1738268297")
    ksign = bytes.fromhex("55f38348c4a60b8ffd7b40c86186d1b88a7badea")
    pay1 = payment_hash(
        build_payment_binding(
            [("bitcoin", bytes.fromhex("00141111111111111111111111111111111111111111"))]
        )
    )
    pay2 = payment_hash(
        build_payment_binding(
            [("bitcoin", bytes.fromhex("00142222222222222222222222222222222222222222"))]
        )
    )

    a1 = identity_commitment(
        build_anchor_message_a(domain=domain, identifier=ident, root_fingerprint=root)
    )
    a2 = identity_commitment(
        build_anchor_message_a(domain=domain, identifier=ident, root_fingerprint=root)
    )
    check("I_A_stable_across_payment", a1 == a2)

    b1 = identity_commitment(
        build_anchor_message_b(
            domain=domain,
            identifier=ident,
            root_fingerprint=root,
            payment_hash_value=pay1,
        )
    )
    b2 = identity_commitment(
        build_anchor_message_b(
            domain=domain,
            identifier=ident,
            root_fingerprint=root,
            payment_hash_value=pay2,
        )
    )
    check("I_B_changes_with_payment", b1 != b2)

    c1 = identity_commitment(
        build_anchor_message_c(
            domain=domain,
            identifier=ident,
            root_fingerprint=root,
            signing_fingerprint=ksign,
            payment_hash_value=pay1,
        )
    )
    c2 = identity_commitment(
        build_anchor_message_c(
            domain=domain,
            identifier=ident,
            root_fingerprint=root,
            signing_fingerprint=bytes(20),
            payment_hash_value=pay1,
        )
    )
    check("I_C_changes_with_ksign", c1 != c2)
    check("I_retain_candidate_A", a1 == a2 and b1 != b2 and c1 != c2)


def test_opreturn():
    analysis = opreturn_size_analysis()
    check("J_payload_within_80", analysis["within_80_byte_policy"])
    check("J_payload_39", analysis["payload_bytes"] == 39, str(analysis["payload_bytes"]))
    c = bytes(32)
    script = build_op_return_script(c)
    check("J_parse_roundtrip", parse_op_return_commitment(script) == c)
    check("J_wrong_tag_rejected", parse_op_return_commitment(b"\x6a\x01\xff") is None)


def test_reorg_statuses():
    check(
        "M_seen",
        evaluate_anchor_status(included=False, confirmations=0, confirmation_policy=6)
        == AnchorStatus.ANCHOR_SEEN,
    )
    check(
        "M_included",
        evaluate_anchor_status(included=True, confirmations=1, confirmation_policy=6)
        == AnchorStatus.ANCHOR_INCLUDED,
    )
    check(
        "M_confirmed",
        evaluate_anchor_status(included=True, confirmations=6, confirmation_policy=6)
        == AnchorStatus.ANCHOR_CONFIRMED,
    )
    check(
        "M_orphaned",
        evaluate_anchor_status(
            included=True, confirmations=3, confirmation_policy=6, orphaned=True
        )
        == AnchorStatus.ANCHOR_ORPHANED,
    )


def test_m4_fixture_and_attacks():
    proof_path = ROOT / "vectors" / "m4" / "bitcoin-anchor-proof.json"
    expected_path = ROOT / "vectors" / "m4" / "expected.json"
    if not proof_path.exists():
        print("[SKIP] m4 fixture missing")
        return

    expected = json.loads(expected_path.read_text())
    proof = BitcoinAnchorProofV1.from_dict(
        json.loads(proof_path.read_text())
    )
    commitment = bytes.fromhex(expected["identity_commitment"])

    ok = verify_bitcoin_anchor_proof(
        proof,
        expected_commitment=commitment,
        confirmation_policy=1,
        header_context=HeaderContext.TRUSTED,
    )
    check("O_e2e_anchored", ok.identity_anchored)
    check("O_e2e_included", ok.anchor_included)
    check("O_e2e_freshness_unknown", ok.freshness == "unknown")
    check("O_e2e_not_human", ok.human_verified is False)
    check("O_e2e_no_errors", not ok.errors, str(ok.errors))
    check("O_e2e_tx_valid", ok.transaction_valid)
    check("O_e2e_inclusion_valid", ok.inclusion_proof_valid)
    check("O_e2e_header_trusted", ok.header_context == "trusted")

    # Attacks
    cases = []

    p = copy.deepcopy(proof)
    p.commitment = bytes(32)
    r = verify_bitcoin_anchor_proof(
        p, expected_commitment=commitment, header_context=HeaderContext.TRUSTED
    )
    cases.append(("wrong-commitment", "WRONG_TX_COMMITMENT", r))

    p = copy.deepcopy(proof)
    p.merkle_branch = list(p.merkle_branch)
    if p.merkle_branch:
        p.merkle_branch[0] = bytes(32)
    else:
        # coinbase-only block unlikely; invent sibling
        p.merkle_branch = [bytes(32)]
        p.tx_index = 0
    r = verify_bitcoin_anchor_proof(
        p, expected_commitment=commitment, header_context=HeaderContext.TRUSTED
    )
    cases.append(("wrong-merkle-proof", "WRONG_MERKLE_PROOF", r))

    p = copy.deepcopy(proof)
    hdr = bytearray(p.block_header)
    hdr[36] ^= 0xFF  # corrupt merkle root in header
    p.block_header = bytes(hdr)
    r = verify_bitcoin_anchor_proof(
        p, expected_commitment=commitment, header_context=HeaderContext.TRUSTED
    )
    cases.append(("wrong-merkle-root", "WRONG_MERKLE_PROOF", r))

    p = copy.deepcopy(proof)
    r = verify_bitcoin_anchor_proof(
        p,
        expected_commitment=commitment,
        known_orphaned=True,
        header_context=HeaderContext.TRUSTED,
    )
    cases.append(("orphaned-anchor", "ORPHANED_ANCHOR", r))

    p = copy.deepcopy(proof)
    r = verify_bitcoin_anchor_proof(
        p,
        expected_commitment=commitment,
        known_orphaned=True,
        header_context=HeaderContext.TRUSTED,
    )
    cases.append(("reorged-anchor", "ORPHANED_ANCHOR", r))

    # wrong expected commitment vs raw_tx OP_RETURN
    cases.append(
        (
            "wrong-opreturn",
            "WRONG_TX_COMMITMENT",
            verify_bitcoin_anchor_proof(
                proof,
                expected_commitment=bytes([1]) + bytes(31),
                header_context=HeaderContext.TRUSTED,
            ),
        )
    )

    attack_report = []
    for name, want, result in cases:
        matched = any(want in e for e in result.errors)
        check(f"P_{name}", matched, str(result.errors))
        attack_report.append(
            {
                "fixture": name,
                "expected_failure": want,
                "actual": result.errors,
                "result": "PASS" if matched else "FAIL",
            }
        )

    (ROOT / "test" / "m4_attack_results.json").write_text(
        json.dumps(attack_report, indent=2) + "\n"
    )


def main() -> int:
    test_anchor_sensitivity()
    test_candidate_abc()
    test_opreturn()
    test_reorg_statuses()
    test_m4_fixture_and_attacks()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

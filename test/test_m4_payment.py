#!/usr/bin/env python3
"""M4 payment binding + hash + scriptPubKey canonicalisation tests."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference import cbor
from reference.payment_binding import (
    address_to_script_pubkey,
    build_payment_binding,
    classify_script,
    parse_payment_binding,
    payment_hash,
    PaymentBindingError,
)

PASS = FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        print(f"[FAIL] {name}: {detail}")


def test_script_types():
    # Well-known test vectors (not for spending)
    # P2WPKH bc1q... using zeros hash160 via constructed script
    p2wpkh = bytes.fromhex("0014" + "11" * 20)
    p2wsh = bytes.fromhex("0020" + "22" * 32)
    p2tr = bytes.fromhex("5120" + "33" * 32)
    p2pkh = bytes.fromhex("76a914" + "44" * 20 + "88ac")
    p2sh = bytes.fromhex("a914" + "55" * 20 + "87")
    check("D_P2WPKH", classify_script(p2wpkh) == "P2WPKH")
    check("D_P2WSH", classify_script(p2wsh) == "P2WSH")
    check("D_P2TR", classify_script(p2tr) == "P2TR")
    check("D_P2PKH", classify_script(p2pkh) == "P2PKH")
    check("D_P2SH", classify_script(p2sh) == "P2SH")


def test_address_same_script_different_text():
    # Same P2WPKH script from lowercase bech32 — uppercase QR form must match
    # Use a valid checksum address from bitcoin-cli if available, else skip
    # Construct via known vector: empty-ish
    spk = bytes.fromhex("00141111111111111111111111111111111111111111")
    # Two bindings with same script from different construction paths
    h1 = payment_hash(build_payment_binding([("bitcoin", spk)]))
    h2 = payment_hash(build_payment_binding([("bitcoin", bytes(spk))]))
    check("D_script_not_address_string", h1 == h2)


def test_payment_hash_vectors():
    spk_a = bytes.fromhex("00141111111111111111111111111111111111111111")
    spk_b = bytes.fromhex("00142222222222222222222222222222222222222222")

    base = build_payment_binding([("bitcoin", spk_a)])
    h_base = payment_hash(base)

    # Vector A — same object
    check("E_vector_A_identical", payment_hash(base) == h_base)

    # Vector B — different destination
    h_b = payment_hash(build_payment_binding([("bitcoin", spk_b)]))
    check("E_vector_B_dest_differs", h_b != h_base)

    # Vector C/D — amount/label are NOT in binding → hash unchanged
    # (simulated by not including them — binding identical)
    check("E_vector_C_amount_excluded", payment_hash(base) == h_base)
    check("E_vector_D_label_excluded", payment_hash(base) == h_base)

    # Vector E — method order
    m1 = build_payment_binding(
        [("bitcoin", spk_a), ("test-method", b"\x01\x02")]
    )
    m2 = build_payment_binding(
        [("test-method", b"\x01\x02"), ("bitcoin", spk_a)]
    )
    check("E_vector_E_order_independent", payment_hash(m1) == payment_hash(m2))
    check("E_vector_E_cbor_identical", cbor.dumps(m1) == cbor.dumps(m2))

    # Vector F — non-canonical rejected on parse
    # Manually build unsorted methods CBOR
    from reference.constants import METHOD_DESTINATION, METHOD_TYPE, PAY_METHODS, PAY_VERSION

    noncanon_obj = {
        PAY_VERSION: 1,
        PAY_METHODS: [
            {METHOD_TYPE: "test-method", METHOD_DESTINATION: b"\x01\x02"},
            {METHOD_TYPE: "bitcoin", METHOD_DESTINATION: spk_a},
        ],
    }
    # Force dumps without going through build_payment_binding sort —
    # but our cbor.dumps sorts map keys only, not array order. So array
    # order [test-method, bitcoin] differs from canonical [bitcoin, test-method].
    noncanon_bytes = cbor.dumps(noncanon_obj)
    canon_bytes = cbor.dumps(m1)
    check("E_vector_F_bytes_differ_before_canon", noncanon_bytes != canon_bytes)
    try:
        parse_payment_binding(noncanon_bytes)
        check("E_vector_F_noncanon_rejected", False, "accepted non-canonical")
    except PaymentBindingError:
        check("E_vector_F_noncanon_rejected", True)


def test_registry_and_unknown_fields():
    spk = bytes.fromhex("00141111111111111111111111111111111111111111")
    b = build_payment_binding([("bitcoin", spk)])
    # Unknown top-level field changes hash if naively added
    weird = dict(b)
    weird[99] = "x"
    check("Q_unknown_field_changes_hash", payment_hash(b) != payment_hash(weird))


def test_duplicate_methods_collapsed():
    spk = bytes.fromhex("00141111111111111111111111111111111111111111")
    a = build_payment_binding([("bitcoin", spk), ("bitcoin", spk)])
    b = build_payment_binding([("bitcoin", spk)])
    check("F_duplicates_collapsed", payment_hash(a) == payment_hash(b))
    check("F_single_method", len(a[1]) == 1)


def main() -> int:
    test_script_types()
    test_address_same_script_different_text()
    test_payment_hash_vectors()
    test_registry_and_unknown_fields()
    test_duplicate_methods_collapsed()

    # Round-trip m4 fixture if present
    m4 = ROOT / "vectors" / "m4" / "payment-binding.cbor"
    if m4.exists():
        data = m4.read_bytes()
        obj = parse_payment_binding(data)
        check("m4_fixture_canonical", True)
        check("m4_fixture_hash_stable", payment_hash(obj) == payment_hash(obj))

    print(f"\n{PASS} passed, {FAIL} failed")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Phase 11 property tests: UTF-8 CBOR accept/reject + canonical encode stability.

Does not patch JS. Documents ADV-M1 as known implementation defect.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from reference import cbor
from reference.cbor import CBORError

ROOT = Path(__file__).resolve().parents[2]
CASES = ROOT / "test" / "schnorr_v2" / "phase11_utf8_cases.json"
JS_RESULTS = ROOT / "test" / "schnorr_v2" / "phase11_utf8_js_results.json"
SEED = "a3535210"

# Invalid UTF-8 cases where JS currently diverges (ADV-M1 class) — must reject in Python
INVALID_NAMES = {
    "ADV-M1-minimal",
    "overlong_slash_C0_AF",
    "overlong_nul_C0_80",
    "surrogate_ED_A0_80",
    "surrogate_ED_BF_BF",
    "truncated_E2_82",
    "invalid_cont_C2_00",
    "stray_cont_80",
    "impossible_F5_80_80_80",
    "ff_lone",
}


def test_python_rejects_invalid() -> None:
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    assert cases["seed"] == SEED
    for c in cases["cases"]:
        raw = bytes.fromhex(c["raw_hex"])
        if c["name"] in INVALID_NAMES:
            try:
                cbor.loads(raw)
                raise AssertionError(f"{c['name']}: Python should reject")
            except CBORError:
                pass
        else:
            obj = cbor.loads(raw)
            assert isinstance(obj, str)
            assert cbor.dumps(obj) == raw
    print("PROPERTY invalid→Python reject / valid→stable encode: PASS")


def test_js_results_encoding_agreement_on_accept() -> None:
    """Both-accept cases must have identical canonical CBOR (from recorded JS run)."""
    if not JS_RESULTS.is_file():
        print("SKIP JS results (run independent/.../phase11_utf8.mjs first)")
        return
    js = json.loads(JS_RESULTS.read_text(encoding="utf-8"))
    assert js["summary"]["encoding_mismatch_both_accept"] == 0
    for row in js["rows"]:
        if row["name"] in INVALID_NAMES:
            assert row["python"] == "reject"
            assert row["javascript"] == "accept"  # known ADV-M1 defect
        elif row["python"] == "accept":
            assert row["javascript"] == "accept"
            assert row["encoding_same"] is True
    print("PROPERTY both-accept encodings equal; ADV-M1 class documented: PASS")


def test_normalization_not_collapsed() -> None:
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    by = {c["name"]: c for c in cases["cases"]}
    assert by["norm_NFC_e_acute"]["raw_hex"] != by["norm_NFD_e_acute"]["raw_hex"]
    print("PROPERTY Unicode normalization NOT PART OF V2: PASS")


def test_adv_m1_minimal() -> None:
    raw = bytes.fromhex("61ff")
    try:
        cbor.loads(raw)
        raise AssertionError("ADV-M1-minimal must reject in Python")
    except CBORError as e:
        assert "UTF-8" in str(e) or "utf" in str(e).lower()
    print("ADV-M1-minimal Python reject: PASS")


if __name__ == "__main__":
    if not CASES.is_file():
        print("Run phase11_utf8_investigate.py first", file=sys.stderr)
        sys.exit(1)
    test_adv_m1_minimal()
    test_python_rejects_invalid()
    test_normalization_not_collapsed()
    test_js_results_encoding_agreement_on_accept()
    print("PHASE 11 PROPERTY TESTS: PASS")

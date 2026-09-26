"""Phase 11 — ADV-M1 CBOR UTF-8 divergence investigation.

Deterministic. Does NOT patch protocol or frozen vectors.
Seed: a3535210 (same as Phase 10 ADV-M1).

EXPERIMENTAL — NON-NORMATIVE
"""

from __future__ import annotations

import json
import struct
import sys
import unicodedata
from pathlib import Path
from typing import Any

from reference import cbor
from reference.cbor import CBORError
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.tags import TAG_ANCHOR, TAG_IDENTITY, TAG_PAYMENT

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "test" / "schnorr_v2"
SEED = "a3535210"
MINIMAL_HEX = "61ff"  # CBOR tstr(1) + 0xFF


def py_decode(hex_blob: str) -> dict[str, Any]:
    raw = bytes.fromhex(hex_blob)
    try:
        obj = cbor.loads(raw)
        if isinstance(obj, str):
            enc = cbor.dumps(obj)
            return {
                "status": "accept",
                "decoded": obj,
                "decoded_codepoints": [f"U+{ord(c):04X}" for c in obj],
                "reencode_hex": enc.hex(),
                "roundtrip_same": enc == raw,
                "error": None,
            }
        return {
            "status": "accept",
            "decoded_type": type(obj).__name__,
            "reencode_hex": cbor.dumps(obj).hex(),
            "error": None,
        }
    except CBORError as e:
        return {"status": "reject", "error": str(e), "exception": "CBORError"}
    except Exception as e:  # noqa: BLE001
        return {"status": "reject", "error": str(e), "exception": type(e).__name__}


def wrap_text_cbor(payload: bytes) -> bytes:
    """Encode major-type-3 with definite length (shortest form for small lens)."""
    n = len(payload)
    if n < 24:
        return bytes([0x60 | n]) + payload
    if n < 256:
        return bytes([0x78, n]) + payload
    raise ValueError("payload too long for this harness")


def case_row(name: str, payload: bytes | None = None, *, raw_hex: str | None = None) -> dict[str, Any]:
    if raw_hex is not None:
        blob = bytes.fromhex(raw_hex)
        payload_hex = None
    else:
        assert payload is not None
        blob = wrap_text_cbor(payload)
        payload_hex = payload.hex()
    py = py_decode(blob.hex())
    return {
        "name": name,
        "raw_hex": blob.hex(),
        "payload_hex": payload_hex,
        "python": py,
    }


def build_matrix() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    # ADV-M1 minimal
    rows.append(case_row("ADV-M1-minimal", raw_hex=MINIMAL_HEX))

    # ASCII / NUL / control
    rows.append(case_row("ascii_hello", b"hello"))
    rows.append(case_row("nul_U+0000", b"\x00"))
    rows.append(case_row("control_U+000A", b"\n"))
    rows.append(case_row("ascii_DEL_U+007F", b"\x7f"))

    # Valid multi-byte
    rows.append(case_row("utf8_2byte_U+00A9", "©".encode("utf-8")))  # C2 A9
    rows.append(case_row("utf8_3byte_U+20AC", "€".encode("utf-8")))  # E2 82 AC
    rows.append(case_row("utf8_4byte_U+1F600", "😀".encode("utf-8")))  # F0 9F 98 80

    # Boundaries
    boundaries = [
        ("U+0000", "\u0000"),
        ("U+007F", "\u007f"),
        ("U+0080", "\u0080"),
        ("U+07FF", "\u07ff"),
        ("U+0800", "\u0800"),
        ("U+D7FF", "\ud7ff"),
        ("U+E000", "\ue000"),
        ("U+FFFF", "\uffff"),
        ("U+10000", "\U00010000"),
        ("U+10FFFF", "\U0010ffff"),
    ]
    for label, ch in boundaries:
        rows.append(case_row(f"boundary_{label}", ch.encode("utf-8")))

    # Invalid UTF-8 classes
    rows.append(case_row("overlong_slash_C0_AF", bytes([0xC0, 0xAF])))
    rows.append(case_row("overlong_nul_C0_80", bytes([0xC0, 0x80])))
    rows.append(case_row("surrogate_ED_A0_80", bytes([0xED, 0xA0, 0x80])))  # U+D800
    rows.append(case_row("surrogate_ED_BF_BF", bytes([0xED, 0xBF, 0xBF])))  # U+DFFF
    rows.append(case_row("truncated_E2_82", bytes([0xE2, 0x82])))
    rows.append(case_row("invalid_cont_C2_00", bytes([0xC2, 0x00])))
    rows.append(case_row("stray_cont_80", bytes([0x80])))
    rows.append(case_row("impossible_F5_80_80_80", bytes([0xF5, 0x80, 0x80, 0x80])))
    rows.append(case_row("ff_lone", bytes([0xFF])))  # same payload as ADV-M1

    # Normalization pairs (same abstract char, different bytes) — must remain distinct
    nfc = unicodedata.normalize("NFC", "é")  # U+00E9
    nfd = unicodedata.normalize("NFD", "é")  # e + combining acute
    rows.append(case_row("norm_NFC_e_acute", nfc.encode("utf-8")))
    rows.append(case_row("norm_NFD_e_acute", nfd.encode("utf-8")))
    rows.append(case_row("norm_NFKC_fi_ligature", unicodedata.normalize("NFKC", "ﬁ").encode("utf-8")))
    rows.append(case_row("norm_NFKD_fi_ligature", unicodedata.normalize("NFKD", "ﬁ").encode("utf-8")))

    return rows


def hash_impact_analysis() -> dict[str, Any]:
    """Can invalid UTF-8 become a signed digest via Python path?"""
    raw = bytes.fromhex(MINIMAL_HEX)
    try:
        cbor.loads(raw)
        decode_ok = True
    except CBORError as e:
        decode_ok = False
        decode_err = str(e)

    # Digests always over caller-supplied bytes in verify path
    # Invalid tstr cannot be produced by cbor.dumps(str) in Python
    try:
        cbor.dumps("\ufffd")  # replacement char is valid Unicode
        replacement_encodable = True
        replacement_hex = cbor.dumps("\ufffd").hex()
    except CBORError:
        replacement_encodable = False
        replacement_hex = None

    # Impact statement
    return {
        "invalid_utf8_python_decode": "reject" if not decode_ok else "ACCEPT",
        "decode_error": None if decode_ok else decode_err,
        "python_dumps_cannot_emit_0xff_text_payload": True,
        "replacement_char_U+FFFD_is_valid_unicode": replacement_encodable,
        "replacement_cbor_hex": replacement_hex,
        "identity_digest_over_raw_bytes": (
            "TaggedHash(TAG_IDENTITY, raw_cbor). "
            "If implementations hash the wire bytes, invalid UTF-8 never verifies "
            "as a Python-accepted document. If JS decodes→re-encodes before hash, "
            "digest differs from wire (61ff → 63efbfbd)."
        ),
        "wire_to_reencode_divergence_hex": {
            "input": MINIMAL_HEX,
            "js_reencode_after_replacement": "63efbfbd",  # from Phase 10 observation
        },
        "same_identity_different_signed_bytes_via_valid_utf8": False,
        "protocol_impact": "MEDIUM",
        "rationale": (
            "Interop accept/reject diverge on invalid UTF-8 CBOR text. "
            "Not a dual-accept of one valid identity with two different digests "
            "for well-formed UTF-8. Risk is JS-only acceptance of malformed wire "
            "or decode→re-encode hash skew."
        ),
    }


def rfc8949_notes() -> dict[str, Any]:
    return {
        "references": [
            "RFC 8949 §3.1 major type 3 — text string: UTF-8 encoded text",
            "RFC 8949 §4.2.1 Core Deterministic Encoding — shortest lengths, sorted keys",
            "RFC 8949 does not require Unicode NFC/NFD normalization for CBOR text",
        ],
        "valid_utf8": "Byte sequence that is well-formed UTF-8 per Unicode / RFC 3629",
        "invalid_utf8": "Overlong, surrogates, truncated, bad continuations, >U+10FFFF",
        "normalization_required": False,
        "normalization_forbidden": False,
        "normalization_part_of_v2": False,
        "noncharacters_accepted": "Yes as UTF-8 code points if well-formed (e.g. U+FFFF)",
        "control_characters_accepted": "Yes at CBOR layer if well-formed UTF-8",
        "v2_mini_spec": (
            "Reuses V1 deterministic CBOR subset; text fields are UTF-8 domain/identifier. "
            "Does not define NFC/NFD. Canonical CBOR ≠ Unicode normalization."
        ),
        "application_level": (
            "Domain/identifier have additional rules (no '@' in domain, identifier "
            "endswith @domain) — separate from UTF-8 well-formedness."
        ),
    }


def main() -> int:
    matrix = build_matrix()
    report = {
        "phase": 11,
        "seed": SEED,
        "finding": "ADV-M1",
        "minimal_case": {
            "id": "ADV-M1-minimal",
            "input_bytes_hex": MINIMAL_HEX,
            "description": "CBOR text string length 1 whose single byte is 0xFF (not valid UTF-8)",
            "python": py_decode(MINIMAL_HEX),
            "javascript_expected_without_fix": {
                "status": "ACCEPT",
                "decoded": "\ufffd",
                "reencode_hex": "63efbfbd",
                "library": "TextDecoder() default non-fatal",
            },
            "expected_per_rfc8949_and_v2_subset": "reject",
        },
        "layer_analysis": {
            "cbor_framing": "OK — both parse major type 3 length 1",
            "utf8_validation": "DIVERGES — Python strict; JS TextDecoder replaces",
            "application_string_validation": "Not reached for ADV-M1-minimal (fails at CBOR text decode in Python)",
            "unicode_normalization": "Not involved in ADV-M1-minimal",
            "library_specific": "JS TextDecoder without {fatal:true}",
        },
        "rfc8949": rfc8949_notes(),
        "hash_impact": hash_impact_analysis(),
        "unicode_normalization": "NOT PART OF V2",
        "matrix_python": matrix,
        "decision": {
            "class": "C",
            "label": "implementation defect",
            "defective_component": "independent/schnorr_v2/src/lib.mjs cborDecode text path",
            "spec_clear": True,
            "patch_in_phase_11": False,
            "reason": "Silent patch forbidden; dedicated fix phase required",
        },
    }

    # NFC vs NFD must differ if both accepted
    nfc_row = next(r for r in matrix if r["name"] == "norm_NFC_e_acute")
    nfd_row = next(r for r in matrix if r["name"] == "norm_NFD_e_acute")
    report["normalization_pair"] = {
        "nfc_hex": nfc_row["raw_hex"],
        "nfd_hex": nfd_row["raw_hex"],
        "encodings_equal": nfc_row["raw_hex"] == nfd_row["raw_hex"],
        "expected": "different encodings (no Unicode normalization in V2)",
        "ok": nfc_row["raw_hex"] != nfd_row["raw_hex"],
    }

    out = OUT_DIR / "phase11_utf8_report.json"
    out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    # Cases for JS differential
    cases_out = OUT_DIR / "phase11_utf8_cases.json"
    cases_out.write_text(
        json.dumps(
            {
                "seed": SEED,
                "minimal_hex": MINIMAL_HEX,
                "cases": [
                    {
                        "name": r["name"],
                        "raw_hex": r["raw_hex"],
                        "python_status": r["python"]["status"],
                        "python_reencode_hex": r["python"].get("reencode_hex"),
                    }
                    for r in matrix
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "wrote": str(out),
        "minimal_python": report["minimal_case"]["python"],
        "decision": report["decision"]["label"],
        "norm_pair_ok": report["normalization_pair"]["ok"],
        "case_count": len(matrix),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

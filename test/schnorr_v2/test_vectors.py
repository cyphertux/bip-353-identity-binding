"""Independent verification of frozen experimental Schnorr V2 vectors.

Does NOT import or call generate_vectors.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from reference import cbor
from reference.schnorr_v2 import binding as binding_mod
from reference.schnorr_v2 import identity as identity_mod
from reference.schnorr_v2 import payment as payment_mod
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.key import verify_msg32
from reference.schnorr_v2.tags import TAG_IDENTITY, TAG_PAYMENT, TAG_SUBKEY_BINDING
from reference.schnorr_v2.verify import VerifyError, verify

ROOT = Path(__file__).resolve().parents[2]
VEC_DIR = ROOT / "vectors" / "schnorr"
CHECKSUMS = VEC_DIR / "SCHNORR_V2_CHECKSUMS.txt"
RECONCILED_CHECKSUMS = VEC_DIR / "SCHNORR_V2_RECONCILED_CHECKSUMS.txt"
# Byte-identical to schnorr-v2-experimental-1
LEGACY_VALID_001_SHA256 = (
    "f1b9617824d29b58ecc4f9eea3df5a440accac87ee24ea0552f9b5d56402e014"
)


def _load(name: str) -> dict:
    path = VEC_DIR / name
    return json.loads(path.read_text(encoding="utf-8"))


def _unhex(s: str) -> bytes:
    return bytes.fromhex(s)


def _verify_from_vector(
    vec: dict,
    *,
    opreturn: bytes | None,
    bitcoin_proof: dict | None = None,
) -> dict:
    body = cbor.loads(_unhex(vec["subkey_binding_cbor"]))
    document = cbor.loads(_unhex(vec["identity_document_cbor"]))
    payment = cbor.loads(_unhex(vec["payment_binding_cbor"]))
    return verify(
        root_pubkey=_unhex(vec["root_pubkey"]),
        signing_pubkey=_unhex(vec["signing_pubkey"]),
        binding_body=body,
        binding_signature=_unhex(vec["subkey_binding_signature"]),
        identity_document=document,
        payment_binding=payment,
        now=int(vec["now"]),
        opreturn_script=opreturn,
        bitcoin_proof=bitcoin_proof,
    )


def _check_checksum_file(path: Path, *, min_files: int) -> int:
    lines = path.read_text(encoding="utf-8").splitlines()
    checked = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, rel = line.split()
        data = (ROOT / rel).read_bytes()
        got = hashlib.sha256(data).hexdigest()
        assert got == digest, f"checksum mismatch for {rel}"
        checked += 1
    assert checked >= min_files
    return checked


def test_checksums() -> None:
    n = _check_checksum_file(CHECKSUMS, min_files=6)
    print(f"CHECKSUMS (freeze historical): PASS ({n} files)")


def test_reconciled_checksums() -> None:
    n = _check_checksum_file(RECONCILED_CHECKSUMS, min_files=8)
    print(f"RECONCILED CHECKSUMS: PASS ({n} files)")


def test_valid_001() -> None:
    """LEGACY FROZEN VECTOR from schnorr-v2-experimental-1.

    expected.identity_anchored=true is historical (pre-F-S1). Hardened verify
    requires dual-binding; without bitcoin_proof → identity_anchored=false.
    Phase 8 independent reproduction discovered this; Phase 9 preserves the file.
    """
    raw = (VEC_DIR / "V2-VALID-001.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == LEGACY_VALID_001_SHA256
    vec = _load("V2-VALID-001.json")
    # Independent recomputation of hashes from CBOR fixtures
    body_cbor = _unhex(vec["subkey_binding_cbor"])
    assert tagged_hash_msg(TAG_SUBKEY_BINDING, body_cbor) == _unhex(vec["subkey_binding_hash"])
    pay_cbor = _unhex(vec["payment_binding_cbor"])
    assert tagged_hash_msg(TAG_PAYMENT, pay_cbor) == _unhex(vec["payment_hash"])
    signed_cbor = _unhex(vec["identity_signed_cbor"])
    assert tagged_hash_msg(TAG_IDENTITY, signed_cbor) == _unhex(vec["identity_message_hash"])
    assert verify_msg32(
        _unhex(vec["root_pubkey"]),
        _unhex(vec["subkey_binding_hash"]),
        _unhex(vec["subkey_binding_signature"]),
    )
    assert verify_msg32(
        _unhex(vec["signing_pubkey"]),
        _unhex(vec["identity_message_hash"]),
        _unhex(vec["identity_signature"]),
    )
    result = _verify_from_vector(vec, opreturn=_unhex(vec["op_return"]))
    assert result["identity_verified"] is True
    assert result["payment_verified"] is True
    # Hardened dual-binding: logical OP_RETURN alone does not anchor
    assert result["identity_anchored"] is False
    assert result["continuity_verified"] is False
    # Historical expected field (do not rewrite the frozen JSON)
    assert vec["expected"]["identity_anchored"] is True
    from reference.schnorr_v2.anchor import verify_anchor_logical
    from reference.schnorr_v2.key import keypair_from_secret

    root = keypair_from_secret(bytes.fromhex(vec["root_private_key"]))
    verify_anchor_logical(
        domain=vec["domain"],
        identifier=vec["identifier"],
        root_pubkey=root.pubkey,
        opreturn_script=_unhex(vec["op_return"]),
    )
    print(
        "V2-VALID-001: PASS (LEGACY FROZEN; crypto OK; "
        "expected.identity_anchored historical ≠ hardened verify)"
    )


def test_valid_002_anchored() -> None:
    vec = _load("V2-VALID-002.json")
    assert vec["expected"]["identity_anchored"] is True
    result = _verify_from_vector(
        vec,
        opreturn=_unhex(vec["op_return"]),
        bitcoin_proof=vec["bitcoin_proof"],
    )
    assert result["identity_verified"] is True
    assert result["payment_verified"] is True
    assert result["identity_anchored"] is True
    assert result["continuity_verified"] is True
    print("V2-VALID-002: PASS (dual-binding identity_anchored=true)")


def test_valid_003_non_anchored() -> None:
    vec = _load("V2-VALID-003.json")
    assert "bitcoin_proof" not in vec
    assert vec["expected"]["identity_anchored"] is False
    result = _verify_from_vector(vec, opreturn=_unhex(vec["op_return"]))
    assert result["identity_verified"] is True
    assert result["payment_verified"] is True
    assert result["identity_anchored"] is False
    assert result["continuity_verified"] is False
    print("V2-VALID-003: PASS (identity_verified ≠ identity_anchored)")


def _expect_error(name: str, code: str, *, opreturn_field: str | None = "op_return") -> None:
    vec = _load(name)
    opreturn = None
    if opreturn_field and opreturn_field in vec:
        opreturn = _unhex(vec[opreturn_field])
    try:
        _verify_from_vector(vec, opreturn=opreturn)
        raise AssertionError(f"{name}: expected {code}")
    except VerifyError as exc:
        assert exc.code == code, f"{name}: got {exc.code} want {code}"
    print(f"{name.replace('.json','')}: PASS ({code})")


def test_invalids() -> None:
    _expect_error("V2-INVALID-001.json", "INVALID_SUBKEY_BINDING", opreturn_field=None)
    _expect_error("V2-INVALID-002.json", "INVALID_IDENTITY_SIGNATURE", opreturn_field=None)
    _expect_error("V2-INVALID-003.json", "ANCHOR_MISMATCH")
    _expect_error("V2-INVALID-004.json", "PAYMENT_BINDING_MISMATCH", opreturn_field=None)
    _expect_error("V2-INVALID-005.json", "INVALID_IDENTITY_SIGNATURE", opreturn_field=None)


def test_determinism_roundtrip_bytes() -> None:
    """Same frozen CBOR → same TaggedHash (no generator)."""
    vec = _load("V2-VALID-001.json")
    h1 = tagged_hash_msg(TAG_SUBKEY_BINDING, _unhex(vec["subkey_binding_cbor"]))
    h2 = tagged_hash_msg(TAG_SUBKEY_BINDING, _unhex(vec["subkey_binding_cbor"]))
    assert h1 == h2 == _unhex(vec["subkey_binding_hash"])
    print("VECTOR DETERMINISM: PASS")


def main() -> None:
    # Guard: this module must not import the generator
    import sys

    assert "reference.schnorr_v2.generate_vectors" not in sys.modules
    test_checksums()
    test_reconciled_checksums()
    test_valid_001()
    test_valid_002_anchored()
    test_valid_003_non_anchored()
    test_invalids()
    test_determinism_roundtrip_bytes()
    assert "reference.schnorr_v2.generate_vectors" not in sys.modules
    print("INDEPENDENT VERIFICATION: PASS")


if __name__ == "__main__":
    main()

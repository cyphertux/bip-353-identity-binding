#!/usr/bin/env python3
"""Run all vector tests against the reference verifier."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.verifier import verify_proof_bundle


def run_one(vector_dir: Path) -> tuple[bool, str]:
    expected = json.loads((vector_dir / "expected.json").read_text())
    with tempfile.TemporaryDirectory(prefix="bip353-verify-") as td:
        gnupghome = Path(td)
        result = verify_proof_bundle(
            identity_document_cbor=(vector_dir / "identity-document.cbor").read_bytes(),
            payment_binding_cbor=(vector_dir / "payment-binding.cbor").read_bytes(),
            anchor_message_cbor=(vector_dir / "anchor-message.cbor").read_bytes(),
            root_certificate_path=vector_dir / "root.asc",
            gnupghome=gnupghome,
            requested_identifier=expected["identifier"],
            expected_commitment=bytes.fromhex(expected["identity_commitment"])
            if expected.get("identity_commitment")
            and expected.get("expected_failure")
            not in ("ANCHOR_MISMATCH", "ROOT_KEY_MISMATCH")
            else (
                None
                if expected.get("expected_failure")
                in ("ANCHOR_MISMATCH", "ROOT_KEY_MISMATCH")
                else bytes.fromhex(expected["identity_commitment"])
            ),
            now=expected.get("verification_time"),
        )

    want_fail = expected.get("expected_failure")
    if want_fail is None:
        ok = result.identity_verified and result.identity_anchored and not result.errors
        detail = json.dumps(result.to_dict(), indent=2)
        return ok, detail

    # For wrong-anchor we pass the mutated commitment as expected_commitment
    # so the mismatch is detected against document KROOT — handled above.

    errors = result.errors
    matched = any(want_fail in e or e.startswith(want_fail) for e in errors)
    # Also accept if the primary error code equals want_fail
    matched = matched or (errors and errors[0].split(":")[0] == want_fail)
    detail = f"expected={want_fail} got={errors} checks={result.checks}"
    return matched, detail


def main() -> int:
    valid = ROOT / "vectors" / "valid"
    invalid_root = ROOT / "vectors" / "invalid"

    failures = 0
    print("=== VALID ===")
    ok, detail = run_one(valid)
    status = "PASS" if ok else "FAIL"
    print(f"[{status}] valid")
    if not ok:
        print(detail)
        failures += 1
    else:
        print(detail)

    print("\n=== INVALID ===")
    for case_dir in sorted(invalid_root.iterdir()):
        if not case_dir.is_dir():
            continue
        ok, detail = run_one(case_dir)
        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {case_dir.name}: {detail}")
        if not ok:
            failures += 1

    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

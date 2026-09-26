#!/usr/bin/env python3
"""Milestone 2: run existing vectors through GnuPG verifier + Sequoia OpenPGP checks.

Does NOT regenerate or modify vectors.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.constants import (
    DOMAIN_SEPARATOR_IDENTITY,
    KEY_SIGNATURE,
)
from reference import cbor
from reference.identity import identity_signing_message, strip_signature
from reference.verifier import verify_proof_bundle

SQ = Path(
    os.environ.get(
        "SQ",
        str(ROOT / ".tools" / "sq-root" / "usr" / "bin" / "sq"),
    )
)

EXPECTED_ROOT = "de26bd614a4224ac0b704ed1c8f68e1738268297"
EXPECTED_SIGN = "55f38348c4a60b8ffd7b40c86186d1b88a7badea"
EXPECTED_COMMITMENT = "82282ed2aebfcbe223a040db5689e569925503f321e643163eeab0ceb47968ae"
EXPECTED_PAYMENT = "35bc7db73b5091938aa3e3c4a3da97e360b6b086fb95f9b084126d665e938629"


def run_sq(args: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = [str(SQ), "--cert-store=none", *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def sequoia_inspect_fingerprints(asc: Path) -> tuple[str, str, bool, bool]:
    """Return (root_fpr, sign_fpr, has_0x18, has_0x19) lowercase hex."""
    inspect = run_sq(["inspect", str(asc)])
    dump = run_sq(["packet", "dump", str(asc)])
    text = inspect.stdout + inspect.stderr
    dump_text = dump.stdout + dump.stderr
    root = ""
    sign = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Fingerprint:"):
            root = line.split(":", 1)[1].strip().lower().replace(" ", "")
        if line.startswith("Subkey:"):
            sign = line.split(":", 1)[1].strip().lower().replace(" ", "")
    has_18 = "Type: SubkeyBinding" in dump_text
    has_19 = "Type: PrimaryKeyBinding" in dump_text
    return root, sign, has_18, has_19


def build_signed_message_from_payload(payload: bytes) -> bytes:
    return DOMAIN_SEPARATOR_IDENTITY + payload


def sequoia_verify_detached(message: bytes, signature: bytes, cert: Path) -> bool:
    with tempfile.TemporaryDirectory(prefix="sq-verify-") as td:
        td_path = Path(td)
        msg_path = td_path / "msg.bin"
        sig_path = td_path / "sig.bin"
        msg_path.write_bytes(message)
        sig_path.write_bytes(signature)
        proc = run_sq(
            [
                "verify",
                "--signer-file",
                str(cert),
                "--signature-file",
                str(sig_path),
                str(msg_path),
            ]
        )
        return proc.returncode == 0


def verify_vector_with_gnupg(vector_dir: Path) -> dict:
    expected = json.loads((vector_dir / "expected.json").read_text())
    with tempfile.TemporaryDirectory(prefix="bip353-m2-") as td:
        result = verify_proof_bundle(
            identity_document_cbor=(vector_dir / "identity-document.cbor").read_bytes(),
            payment_binding_cbor=(vector_dir / "payment-binding.cbor").read_bytes(),
            anchor_message_cbor=(vector_dir / "anchor-message.cbor").read_bytes(),
            root_certificate_path=vector_dir / "root.asc",
            gnupghome=Path(td),
            requested_identifier=expected["identifier"],
            expected_commitment=(
                None
                if expected.get("expected_failure")
                in ("ANCHOR_MISMATCH", "ROOT_KEY_MISMATCH")
                else bytes.fromhex(expected["identity_commitment"])
            ),
            now=expected.get("verification_time"),
        )
    return {
        "expected_failure": expected.get("expected_failure"),
        "errors": result.errors,
        "identity_verified": result.identity_verified,
        "freshness": result.freshness,
        "result": result,
    }


def classify_vector(info: dict) -> tuple[str, bool]:
    """Return (actual_label, pass?)."""
    want = info["expected_failure"]
    if want is None:
        ok = info["identity_verified"] and not info["errors"]
        return ("VALID CRYPTOGRAPHICALLY", ok)
    matched = any(want in e or e.startswith(want) for e in info["errors"])
    matched = matched or (
        info["errors"] and info["errors"][0].split(":")[0] == want
    )
    actual = info["errors"][0] if info["errors"] else "NO_ERROR"
    return (actual, matched)


def main() -> int:
    if not SQ.exists():
        print(f"ERROR: sq not found at {SQ}", file=sys.stderr)
        return 2

    report: dict = {"sq_version": "", "cases": [], "checks": {}}

    ver = run_sq(["version"])
    report["sq_version"] = (ver.stdout + ver.stderr).strip()
    print("=== Sequoia ===")
    print(report["sq_version"])

    # A/B fingerprints + binding
    root_fpr, sign_fpr, has_18, has_19 = sequoia_inspect_fingerprints(
        ROOT / "vectors" / "valid" / "root.asc"
    )
    print("\n=== Fingerprints (Sequoia) ===")
    print(f"KROOT={root_fpr} expected={EXPECTED_ROOT} match={root_fpr == EXPECTED_ROOT}")
    print(f"KSIGN={sign_fpr} expected={EXPECTED_SIGN} match={sign_fpr == EXPECTED_SIGN}")
    print(f"0x18 SubkeyBinding={has_18}")
    print(f"0x19 PrimaryKeyBinding={has_19}")
    report["checks"]["kroot"] = root_fpr == EXPECTED_ROOT
    report["checks"]["ksign"] = sign_fpr == EXPECTED_SIGN
    report["checks"]["binding_0x18"] = has_18
    report["checks"]["binding_0x19"] = has_19

    # C: identity signature via Sequoia on exact existing bytes
    payload = (ROOT / "vectors" / "valid" / "identity-payload.cbor").read_bytes()
    # Prefer payload file; also cross-check against document field 9 strip
    doc = cbor.loads((ROOT / "vectors" / "valid" / "identity-document.cbor").read_bytes())
    sig = (ROOT / "vectors" / "valid" / "identity-signature.bin").read_bytes()
    assert doc[KEY_SIGNATURE] == sig, "signature bytes diverge between document and .bin"
    message = build_signed_message_from_payload(payload)
    # Ensure payload matches strip_signature re-encode of document fields 0..8
    rebuilt = cbor.dumps(strip_signature(doc))
    assert rebuilt == payload, (
        "CONFLICT: identity-payload.cbor != CanonicalCBOR(strip_signature(document))\n"
        f"payload={payload.hex()}\nrebuilt={rebuilt.hex()}"
    )
    assert message == identity_signing_message(strip_signature(doc))

    sq_ok = sequoia_verify_detached(
        message, sig, ROOT / "vectors" / "valid" / "root.asc"
    )
    print("\n=== Identity signature (GnuPG→Sequoia) ===")
    print(f"signature_valid={sq_ok}")
    report["checks"]["gnupg_to_sequoia"] = sq_ok

    # Invalid signature must fail under Sequoia
    bad_dir = ROOT / "vectors" / "invalid" / "invalid-signature"
    bad_payload = (bad_dir / "identity-payload.cbor").read_bytes()
    bad_sig = (bad_dir / "identity-signature.bin").read_bytes()
    bad_ok = sequoia_verify_detached(
        build_signed_message_from_payload(bad_payload),
        bad_sig,
        bad_dir / "root.asc",
    )
    print(f"invalid-signature rejected_by_sequoia={not bad_ok}")
    report["checks"]["sequoia_rejects_invalid_sig"] = not bad_ok

    # All vectors through existing verifier (GnuPG path) — semantic protocol checks
    print("\n=== Vector table ===")
    print(f"{'Fixture':<22} {'Expected':<32} {'Actual':<40} {'Result'}")
    failures = 0

    cases = [("valid", ROOT / "vectors" / "valid")]
    for d in sorted((ROOT / "vectors" / "invalid").iterdir()):
        if d.is_dir():
            cases.append((d.name, d))

    for name, path in cases:
        info = verify_vector_with_gnupg(path)
        actual, ok = classify_vector(info)
        want = info["expected_failure"] or "VALID / freshness UNKNOWN"
        if name == "rollback":
            # Special: must remain cryptographically valid
            ok = info["identity_verified"] and not info["errors"]
            actual = f"VALID / freshness={info['freshness']}"
            want = "VALID / freshness UNKNOWN"
        status = "PASS" if ok else "FAIL"
        if not ok:
            failures += 1
        print(f"{name:<22} {want:<32} {actual:<40} {status}")
        report["cases"].append(
            {
                "fixture": name,
                "expected": want,
                "actual": actual,
                "result": status,
                "errors": info["errors"],
            }
        )

    report["checks"]["all_vectors"] = failures == 0

    # Write machine-readable summary for the markdown report
    out = ROOT / "test" / "m2_results.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\nWrote {out}")
    print(f"{failures} failure(s)")
    return 1 if failures or not all(
        [
            report["checks"]["kroot"],
            report["checks"]["ksign"],
            report["checks"]["binding_0x18"],
            report["checks"]["binding_0x19"],
            report["checks"]["gnupg_to_sequoia"],
            report["checks"]["sequoia_rejects_invalid_sig"],
        ]
    ) else 0


if __name__ == "__main__":
    raise SystemExit(main())

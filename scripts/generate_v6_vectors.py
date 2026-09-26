#!/usr/bin/env python3
"""Generate independent OpenPGP v6 vectors (does NOT modify M1 vectors)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference import cbor
from reference.constants import (
    DOMAIN_SEPARATOR_IDENTITY,
    KEY_SIGNATURE,
)
from reference.identity import (
    build_anchor_message,
    build_identity_document,
    build_payment_binding,
    build_signed_identity_document,
    identity_commitment,
    identity_signing_message,
    payment_hash,
    provisional_op_return_payload,
)

SQ = Path(os.environ.get("SQ", str(ROOT / ".tools/sq-root/usr/bin/sq")))
SECRET = Path(os.environ.get("V6_SECRET", str(ROOT / ".tools/v6/secret-v6.pgp")))
OUT = ROOT / "vectors" / "v6"

DOMAIN = "example.test"
IDENTIFIER = "alice-v6@example.test"
SCRIPT = bytes.fromhex("00141111111111111111111111111111111111111111")
# Use key creation-aligned times from Sequoia inspect: 2026-09-26 13:18:49 UTC
CREATED = 1790428729
EXPIRES = CREATED + 365 * 24 * 3600
SEQUENCE = 1

KROOT_HEX = "06951ac6b194ead55cb3b139a7a3e9d81f78a8c0521b2d65cf9df81ee36427bc"
KSIGN_HEX = "e855280752edb2622febf1da2b633bed3d0d83f01269a320881d1dd9aad32bc9"


def run_sq(args: list[str], input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    cmd = [str(SQ), "--cert-store=none", "--key-store=none", *args]
    return subprocess.run(cmd, input=input_data, capture_output=True)


def main() -> int:
    if not SQ.exists():
        print(f"sq not found at {SQ}", file=sys.stderr)
        return 2
    if not SECRET.exists():
        print(f"v6 secret not found at {SECRET}", file=sys.stderr)
        return 2

    OUT.mkdir(parents=True, exist_ok=True)

    # Public cert already exported to root-v6.asc — refresh from secret
    pub = run_sq(
        [
            "--overwrite",
            "key",
            "delete",
            f"--cert-file={SECRET}",
            f"--output={OUT / 'root-v6.asc'}",
        ]
    )
    if pub.returncode != 0:
        print(pub.stderr.decode(), file=sys.stderr)
        # If delete fails because already public-only path, keep existing
        if not (OUT / "root-v6.asc").exists():
            return 1
    (OUT / "signing-v6.asc").write_bytes((OUT / "root-v6.asc").read_bytes())

    root_fpr = bytes.fromhex(KROOT_HEX)
    sign_fpr = bytes.fromhex(KSIGN_HEX)
    assert len(root_fpr) == 32 and len(sign_fpr) == 32

    payment = build_payment_binding([("bitcoin", SCRIPT)])
    pay_cbor = cbor.dumps(payment)
    pay_hash = payment_hash(payment)

    signed = build_signed_identity_document(
        domain=DOMAIN,
        identifier=IDENTIFIER,
        root_fingerprint=root_fpr,
        signing_fingerprint=sign_fpr,
        created_at=CREATED,
        expires_at=EXPIRES,
        payment_hash_value=pay_hash,
        sequence=SEQUENCE,
    )
    payload_cbor = cbor.dumps(signed)
    message = identity_signing_message(signed)

    msg_path = OUT / "signed-message.bin"
    msg_path.write_bytes(message)
    sig_path = OUT / "identity-v6.sig"

    # Sign with Sequoia (--signer-file alone; signing-capable subkey is selected).
    # Note: --signer=<fpr> requires a certificate store in sq 1.3.1.
    sig = run_sq(
        [
            "sign",
            f"--signer-file={SECRET}",
            f"--signature-file={sig_path}",
            "--binary",
            str(msg_path),
        ]
    )
    if sig.returncode != 0:
        print("sign failed:", sig.stderr.decode(), file=sys.stderr)
        return 1

    # Verify immediately with Sequoia
    ver = run_sq(
        [
            "verify",
            f"--signer-file={OUT / 'root-v6.asc'}",
            f"--signature-file={sig_path}",
            str(msg_path),
        ]
    )
    if ver.returncode != 0:
        print("verify failed:", ver.stderr.decode(), file=sys.stderr)
        return 1

    signature = sig_path.read_bytes()
    identity_doc = build_identity_document(signed, signature)
    identity_cbor = cbor.dumps(identity_doc)

    anchor = build_anchor_message(
        domain=DOMAIN, identifier=IDENTIFIER, root_fingerprint=root_fpr
    )
    anchor_cbor = cbor.dumps(anchor)
    commitment = identity_commitment(anchor)

    (OUT / "payment-binding.cbor").write_bytes(pay_cbor)
    (OUT / "identity-payload.cbor").write_bytes(payload_cbor)
    (OUT / "identity-v6.cbor").write_bytes(identity_cbor)
    (OUT / "anchor-message.cbor").write_bytes(anchor_cbor)
    (OUT / "anchor-opreturn-provisional.bin").write_bytes(
        provisional_op_return_payload(commitment)
    )

    expected = {
        "openpgp_version": 6,
        "domain": DOMAIN,
        "identifier": IDENTIFIER,
        "kroot_fingerprint": KROOT_HEX,
        "ksign_fingerprint": KSIGN_HEX,
        "kroot_fingerprint_len": 32,
        "ksign_fingerprint_len": 32,
        "payment_hash": pay_hash.hex(),
        "identity_commitment": commitment.hex(),
        "signature_valid_sequoia": True,
        "created_at": CREATED,
        "expires_at": EXPIRES,
        "sequence": SEQUENCE,
        "domain_separator_hex": DOMAIN_SEPARATOR_IDENTITY.hex(),
        "message_len": len(message),
        "note": (
            "Independent v6 fixture generated with Sequoia --profile rfc9580. "
            "Does not replace M1 v4 vectors. Secret key is NOT stored in vectors/."
        ),
        "verification_time": CREATED + 3600,
    }
    (OUT / "expected-v6.json").write_text(json.dumps(expected, indent=2) + "\n")

    print("Generated vectors/v6/")
    print(f"  KROOT v6 = {KROOT_HEX}")
    print(f"  KSIGN v6 = {KSIGN_HEX}")
    print(f"  payment_hash = {pay_hash.hex()}")
    print(f"  identity_commitment = {commitment.hex()}")
    print(f"  Sequoia verify: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

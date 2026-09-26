"""Shared helpers for M5 adversarial security tests.

Does NOT modify vectors/valid, vectors/invalid, vectors/m4, or vectors/v6.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]

from reference import cbor
from reference.bitcoin_proof import BitcoinAnchorProofV1, verify_bitcoin_anchor_proof
from reference.constants import (
    DOMAIN_SEPARATOR_ANCHOR,
    DOMAIN_SEPARATOR_IDENTITY,
    DOMAIN_SEPARATOR_PAYMENT,
    KEY_DOMAIN,
    KEY_IDENTIFIER,
    KEY_PAYMENT_HASH,
    KEY_PROTOCOL_VERSION,
    KEY_ROOT_FINGERPRINT,
    KEY_SEQUENCE,
    KEY_SIGNATURE,
    KEY_SIGNING_FINGERPRINT,
)
from reference.identity import (
    build_anchor_message,
    identity_commitment,
    identity_signing_message,
    payment_hash,
    strip_signature,
)
from reference.payment_binding import build_payment_binding, parse_payment_binding
from reference.verifier import VerificationResult, verify_proof_bundle


class Outcome(str, Enum):
    BLOCKED = "BLOCKED"  # rejected before useful deception
    DETECTED = "DETECTED"  # accepted as invalid / mismatch flagged
    ACCEPTED = "ACCEPTED"  # verifier considers input valid
    AMBIGUOUS = "AMBIGUOUS"  # protocol undefined / depends on policy


@dataclass
class Finding:
    id: str
    severity: str  # CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|N/A
    attack: str
    precondition: str
    steps: list[str]
    expected: str
    actual: str
    outcome: str
    impact: str
    mitigation: str
    classification: str  # vulnerability|known_limitation|out_of_threat_model|needs_change


@dataclass
class AttackResult:
    id: str
    part: str
    name: str
    expected_outcome: str
    actual_outcome: str
    expected_detail: str
    actual_detail: str
    pass_: bool
    notes: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["pass"] = d.pop("pass_")
        return d


RESULTS: list[AttackResult] = []
FINDINGS: list[Finding] = []


def record(ar: AttackResult) -> AttackResult:
    RESULTS.append(ar)
    status = "PASS" if ar.pass_ else "FAIL"
    print(f"[{status}] {ar.id} {ar.name}: {ar.actual_outcome} ({ar.actual_detail[:80]})")
    return ar


def add_finding(f: Finding) -> None:
    FINDINGS.append(f)


def load_valid() -> dict[str, Any]:
    base = ROOT / "vectors" / "valid"
    return {
        "dir": base,
        "expected": json.loads((base / "expected.json").read_text()),
        "identity": (base / "identity-document.cbor").read_bytes(),
        "payload": (base / "identity-payload.cbor").read_bytes(),
        "payment": (base / "payment-binding.cbor").read_bytes(),
        "anchor": (base / "anchor-message.cbor").read_bytes(),
        "sig": (base / "identity-signature.bin").read_bytes(),
        "root_asc": base / "root.asc",
    }


def load_m4() -> dict[str, Any] | None:
    base = ROOT / "vectors" / "m4"
    if not (base / "bitcoin-anchor-proof.json").exists():
        return None
    return {
        "dir": base,
        "expected": json.loads((base / "expected.json").read_text()),
        "proof": BitcoinAnchorProofV1.from_dict(
            json.loads((base / "bitcoin-anchor-proof.json").read_text())
        ),
        "payment": (base / "payment-binding.cbor").read_bytes(),
        "anchor": (base / "anchor-message.cbor").read_bytes(),
    }


def mutate_doc_field(identity_cbor: bytes, key: int, value: Any) -> bytes:
    doc = cbor.loads(identity_cbor)
    doc[key] = value
    return cbor.dumps(doc)


def verify_identity(
    *,
    identity: bytes,
    payment: bytes,
    anchor: bytes,
    root_asc: Path,
    requested_identifier: str,
    expected_commitment: bytes | None = None,
    now: int | None = None,
) -> VerificationResult:
    with tempfile.TemporaryDirectory(prefix="m5-") as td:
        return verify_proof_bundle(
            identity_document_cbor=identity,
            payment_binding_cbor=payment,
            anchor_message_cbor=anchor,
            root_certificate_path=root_asc,
            gnupghome=Path(td),
            requested_identifier=requested_identifier,
            expected_commitment=expected_commitment,
            now=now,
        )


def expect_error(result: VerificationResult, code: str) -> bool:
    return any(code in e or e.startswith(code) for e in result.errors)


def write_results() -> Path:
    out = ROOT / "test" / "security" / "m5_results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "results": [r.to_dict() for r in RESULTS],
        "findings": [asdict(f) for f in FINDINGS],
        "summary": {
            "total": len(RESULTS),
            "pass": sum(1 for r in RESULTS if r.pass_),
            "fail": sum(1 for r in RESULTS if not r.pass_),
            "by_outcome": {},
        },
    }
    for o in Outcome:
        payload["summary"]["by_outcome"][o.value] = sum(
            1 for r in RESULTS if r.actual_outcome == o.value
        )
    out.write_text(json.dumps(payload, indent=2) + "\n")
    return out

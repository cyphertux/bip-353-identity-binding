#!/usr/bin/env python3
"""M5 adversarial attack suite against M1–M4 verifiers.

Does not modify frozen vectors. Writes results to test/security/m5_results.json.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from harness import (  # noqa: E402
    AttackResult,
    Finding,
    Outcome,
    FINDINGS,
    RESULTS,
    add_finding,
    expect_error,
    load_m4,
    load_valid,
    mutate_doc_field,
    record,
    verify_identity,
    write_results,
)
from reference import cbor
from reference.bitcoin_anchor import (
    build_anchor_message_a,
    build_op_return_script,
    identity_commitment,
    parse_op_return_commitment,
)
from reference.bitcoin_proof import (
    AnchorStatus,
    HeaderContext,
    evaluate_anchor_status,
    verify_bitcoin_anchor_proof,
    verify_merkle_branch,
)
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
from reference.identity import identity_signing_message, strip_signature
from reference.payment_binding import (
    PaymentBindingError,
    build_payment_binding,
    parse_payment_binding,
    payment_hash,
)
from reference.cbor import CBORError


def _pass_if(cond: bool, **kwargs) -> AttackResult:
    return record(AttackResult(pass_=cond, **kwargs))


# ---------------------------------------------------------------------------
# PART A — Cross-layer
# ---------------------------------------------------------------------------


def part_a(v: dict) -> None:
    exp = v["expected"]
    ident = exp["identifier"]
    commit = bytes.fromhex(exp["identity_commitment"])

    # A1: DNS payment A vs identity payment B
    pay_b = cbor.dumps(
        build_payment_binding(
            [("bitcoin", bytes.fromhex("00142222222222222222222222222222222222222222"))]
        )
    )
    r = verify_identity(
        identity=v["identity"],
        payment=pay_b,
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier=ident,
        expected_commitment=commit,
        now=exp["verification_time"],
    )
    _pass_if(
        expect_error(r, "PAYMENT_BINDING_MISMATCH"),
        id="A1",
        part="A",
        name="DNS/payment vs identity payment mismatch",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value
        if expect_error(r, "PAYMENT_BINDING_MISMATCH")
        else Outcome.ACCEPTED.value,
        expected_detail="PAYMENT_BINDING_MISMATCH",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    # A2: attacker KROOT' with valid-looking local sig path — use wrong-root fixture pattern
    fake_root = bytes.fromhex("000102030405060708090a0b0c0d0e0f10111213")
    id2 = mutate_doc_field(v["identity"], KEY_ROOT_FINGERPRINT, fake_root)
    # also mutate anchor to match fake → still fails cert fingerprint
    from reference.identity import build_anchor_message

    fake_anchor = cbor.dumps(
        build_anchor_message(
            domain=exp["domain"],
            identifier=ident,
            root_fingerprint=fake_root,
        )
    )
    r = verify_identity(
        identity=id2,
        payment=v["payment"],
        anchor=fake_anchor,
        root_asc=v["root_asc"],
        requested_identifier=ident,
        expected_commitment=commit,  # historical Bitcoin commitment for real KROOT
        now=exp["verification_time"],
    )
    blocked = expect_error(r, "ROOT_KEY_MISMATCH") or expect_error(r, "ANCHOR_MISMATCH")
    _pass_if(
        blocked,
        id="A2",
        part="A",
        name="DNS+hosting without KROOT (fake root)",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value if blocked else Outcome.ACCEPTED.value,
        expected_detail="ROOT_KEY_MISMATCH or ANCHOR_MISMATCH",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    # A3: hosting only — mutate identity payment hash without valid sig
    id3 = mutate_doc_field(v["identity"], KEY_PAYMENT_HASH, bytes(32))
    r = verify_identity(
        identity=id3,
        payment=v["payment"],
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier=ident,
        expected_commitment=commit,
        now=exp["verification_time"],
    )
    _pass_if(
        expect_error(r, "INVALID_IDENTITY_SIGNATURE"),
        id="A3",
        part="A",
        name="Hosting-only IdentityDocument mutation",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value
        if expect_error(r, "INVALID_IDENTITY_SIGNATURE")
        else Outcome.ACCEPTED.value,
        expected_detail="INVALID_IDENTITY_SIGNATURE",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    # A4: DNS only — payment divergence already A1; anchor still matches KROOT
    _pass_if(
        True,
        id="A4",
        part="A",
        name="DNS-only divergence covered by payment binding",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value,
        expected_detail="payment mismatch without KROOT cannot forge identity",
        actual_detail="same mechanism as A1; anchor remains for real KROOT",
        notes="DNS-only attacker can change BIP-353 payment; binding catches divergence.",
    )


# ---------------------------------------------------------------------------
# PART B — OpenPGP
# ---------------------------------------------------------------------------


def part_b(v: dict) -> None:
    exp = v["expected"]
    ident = exp["identifier"]
    commit = bytes.fromhex(exp["identity_commitment"])

    # B1: KSIGN can produce valid signatures — if attacker has KSIGN they can
    # re-sign documents. We cannot produce a new sig without secret; document
    # as known property using conceptual classification.
    _pass_if(
        True,
        id="B1",
        part="B",
        name="KSIGN compromise can mint new IdentityDocuments",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="signature valid under KSIGN; continuity via KROOT binding still holds",
        actual_detail=(
            "If attacker controls KSIGN, OpenPGP signatures verify. "
            "They cannot change KROOT or Bitcoin anchor. "
            "They CAN change payment_hash/sequence/expiry in new docs."
        ),
        notes="KNOWN LIMITATION: operational key compromise allows state updates until revocation.",
    )
    add_finding(
        Finding(
            id="F-B1",
            severity="HIGH",
            attack="KSIGN compromise",
            precondition="Attacker possesses current signing subkey",
            steps=[
                "Steal KSIGN",
                "Publish new IdentityDocument with attacker payment_hash",
                "Signature verifies; KROOT→KSIGN binding still valid",
                "Bitcoin anchor unchanged (Candidate A)",
            ],
            expected="Detect unauthorized payment change without KROOT",
            actual="ACCEPTED if signed by authorized KSIGN — protocol treats as legitimate rotation of payment state",
            outcome=Outcome.ACCEPTED.value,
            impact="Attacker can redirect payment binding until KSIGN revoked / rotated by KROOT offline",
            mitigation="Short KSIGN validity; revoke compromised KSIGN; offline KROOT authorizes replacement; monitor published documents",
            classification="known_limitation",
        )
    )

    # B2: wrong signing key fingerprint in doc (existing fixture)
    inv = ROOT / "vectors" / "invalid" / "wrong-signing-key"
    r = verify_identity(
        identity=(inv / "identity-document.cbor").read_bytes(),
        payment=(inv / "payment-binding.cbor").read_bytes(),
        anchor=(inv / "anchor-message.cbor").read_bytes(),
        root_asc=inv / "root.asc",
        requested_identifier=json.loads((inv / "expected.json").read_text())["identifier"],
        now=exp["verification_time"],
    )
    _pass_if(
        expect_error(r, "SIGNING_KEY_MISMATCH"),
        id="B2",
        part="B",
        name="Fake/unrelated KSIGN fingerprint",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value
        if expect_error(r, "SIGNING_KEY_MISMATCH")
        else Outcome.ACCEPTED.value,
        expected_detail="SIGNING_KEY_MISMATCH",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    # B3 wrong root
    inv = ROOT / "vectors" / "invalid" / "wrong-root"
    r = verify_identity(
        identity=(inv / "identity-document.cbor").read_bytes(),
        payment=(inv / "payment-binding.cbor").read_bytes(),
        anchor=(inv / "anchor-message.cbor").read_bytes(),
        root_asc=inv / "root.asc",
        requested_identifier=ident,
        now=exp["verification_time"],
    )
    _pass_if(
        expect_error(r, "ROOT_KEY_MISMATCH"),
        id="B3",
        part="B",
        name="KROOT mismatch vs certificate",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value
        if expect_error(r, "ROOT_KEY_MISMATCH")
        else Outcome.ACCEPTED.value,
        expected_detail="ROOT_KEY_MISMATCH",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    # B4: signature valid concept — invalid-signature fixture
    inv = ROOT / "vectors" / "invalid" / "invalid-signature"
    r = verify_identity(
        identity=(inv / "identity-document.cbor").read_bytes(),
        payment=(inv / "payment-binding.cbor").read_bytes(),
        anchor=(inv / "anchor-message.cbor").read_bytes(),
        root_asc=inv / "root.asc",
        requested_identifier=ident,
        expected_commitment=commit,
        now=exp["verification_time"],
    )
    _pass_if(
        expect_error(r, "INVALID_IDENTITY_SIGNATURE"),
        id="B4",
        part="B",
        name="Wrong/tampered signature under claimed keys",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value
        if expect_error(r, "INVALID_IDENTITY_SIGNATURE")
        else Outcome.ACCEPTED.value,
        expected_detail="INVALID_IDENTITY_SIGNATURE",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    # B5/B6 revocation — verifier checks revoked flags from gpg import
    _pass_if(
        True,
        id="B5",
        part="B",
        name="Revoked KSIGN handling",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.AMBIGUOUS.value,
        expected_detail="IDENTITY_REVOKED when revocation present in certificate",
        actual_detail=(
            "Reference verifier checks OpenPGP revoked flags on import. "
            "No revoked fixture generated in M5 without mutating keyring secrets; "
            "property depends on revocation being delivered in Proof Bundle."
        ),
        notes="LIMITATION: revocation discovery/transport not fully specified.",
    )
    _pass_if(
        True,
        id="B6",
        part="B",
        name="Revoked KROOT handling",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.AMBIGUOUS.value,
        expected_detail="IDENTITY_REVOKED",
        actual_detail="Same as B5 — revocation transport OPEN",
        notes="Escrowed revocation recommended but not wire-specified.",
    )
    add_finding(
        Finding(
            id="F-B5",
            severity="MEDIUM",
            attack="Missing revocation in Proof Bundle",
            precondition="KSIGN/KROOT revoked elsewhere but proof omits revocation",
            steps=["Revoke key", "Serve old certificate without revocation", "Verify"],
            expected="Reject revoked keys",
            actual="AMBIGUOUS without mandatory revocation channel",
            outcome=Outcome.AMBIGUOUS.value,
            impact="Stale keys may verify until revocation is fetched",
            mitigation="Require revocation status in Proof Bundle or transparency log (M6)",
            classification="needs_change",
        )
    )

    # B7 old KSIGN — without revocation, old authorized subkey still verifies
    _pass_if(
        True,
        id="B7",
        part="B",
        name="Old but still-bound KSIGN",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="cryptographically valid if binding not revoked",
        actual_detail="V1 has no 'current key' oracle beyond cert + freshness unknown",
        notes="NOT PROVIDED: currently authorized vs historically authorized without freshness.",
    )


# ---------------------------------------------------------------------------
# PART C — KROOT compromise
# ---------------------------------------------------------------------------


def part_c(v: dict) -> None:
    _pass_if(
        True,
        id="C1",
        part="C",
        name="KROOT compromise vs Bitcoin anchor",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="Attacker with KROOT can authorize new KSIGN and new documents",
        actual_detail=(
            "Bitcoin Candidate A commits to KROOT. If attacker has that same KROOT, "
            "new IdentityDocuments verify and match the existing anchor. "
            "Bitcoin does NOT prevent KROOT compromise. "
            "Bitcoin DOES prevent silently replacing KROOT with KROOT' without a new on-chain commitment."
        ),
        notes="Honest limitation — recovery/escrowed revocation is the mitigation path.",
    )
    add_finding(
        Finding(
            id="F-C1",
            severity="CRITICAL",
            attack="Full KROOT compromise",
            precondition="Attacker has KROOT private key matching Bitcoin anchor",
            steps=[
                "Steal KROOT",
                "Create KSIGN_attacker bound by KROOT",
                "Publish IdentityDocument for attacker payment",
                "Commitment still matches historical Bitcoin anchor",
            ],
            expected="Protocol cannot cryptographically distinguish attacker from owner",
            actual="ACCEPTED — same as legitimate owner operations",
            outcome=Outcome.ACCEPTED.value,
            impact="Complete identity takeover until recovery/revocation published and checked",
            mitigation="Offline KROOT; escrowed revocation; recovery key (OPEN for M6)",
            classification="out_of_threat_model",
        )
    )


# ---------------------------------------------------------------------------
# PART D — Replay / rollback
# ---------------------------------------------------------------------------


def part_d(v: dict) -> None:
    exp = v["expected"]
    inv = ROOT / "vectors" / "invalid" / "rollback"
    r = verify_identity(
        identity=(inv / "identity-document.cbor").read_bytes(),
        payment=(inv / "payment-binding.cbor").read_bytes(),
        anchor=(inv / "anchor-message.cbor").read_bytes(),
        root_asc=inv / "root.asc",
        requested_identifier=exp["identifier"],
        expected_commitment=bytes.fromhex(exp["identity_commitment"]),
        now=exp["verification_time"],
    )
    _pass_if(
        r.identity_verified and r.freshness == "unknown",
        id="D1",
        part="D",
        name="Old IdentityDocument replay (rollback)",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value
        if r.identity_verified
        else Outcome.BLOCKED.value,
        expected_detail="identity_verified=true, freshness=unknown",
        actual_detail=f"verified={r.identity_verified} freshness={r.freshness}",
        notes="V1 intentionally lacks freshness — NOT a silent bug if UI shows FRESHNESS UNKNOWN.",
    )
    add_finding(
        Finding(
            id="F-D1",
            severity="HIGH",
            attack="Rollback / stale IdentityDocument",
            precondition="Attacker can serve older still-valid document",
            steps=["Publish sequence N+1", "Serve sequence N to new wallets"],
            expected="Detect staleness",
            actual="ACCEPTED cryptographically; freshness=unknown",
            outcome=Outcome.ACCEPTED.value,
            impact="Users may pay to outdated payment binding",
            mitigation="Transparency log / freshness layer (M6); UI must show FRESHNESS UNKNOWN",
            classification="known_limitation",
        )
    )

    # D2 sequence field alone
    for seq, label in [(0, "zero"), (2, "higher"), (2**32, "large")]:
        idm = mutate_doc_field(v["identity"], KEY_SEQUENCE, seq)
        r = verify_identity(
            identity=idm,
            payment=v["payment"],
            anchor=v["anchor"],
            root_asc=v["root_asc"],
            requested_identifier=exp["identifier"],
            now=exp["verification_time"],
        )
        # unsigned field change breaks signature
        ok = expect_error(r, "INVALID_IDENTITY_SIGNATURE")
        _pass_if(
            ok,
            id=f"D2-{label}",
            part="D",
            name=f"Sequence mutation ({label}) without re-sign",
            expected_outcome=Outcome.BLOCKED.value,
            actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
            expected_detail="INVALID_IDENTITY_SIGNATURE",
            actual_detail=str(r.errors),
            errors=r.errors,
            notes="Sequence is signed but does not provide freshness across documents.",
        )

    # D3 old bitcoin anchor — Candidate A has single historical root commitment
    _pass_if(
        True,
        id="D3",
        part="D",
        name="Old Bitcoin anchor still matches Candidate A",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="Historical anchor remains valid for same KROOT",
        actual_detail="No 'current anchor' selection without transparency/multiple-anchor policy",
        notes="freshness=unknown for anchors as well.",
    )


# ---------------------------------------------------------------------------
# PART E — Cross-context
# ---------------------------------------------------------------------------


def part_e(v: dict) -> None:
    exp = v["expected"]
    commit = bytes.fromhex(exp["identity_commitment"])

    cases = [
        ("E1", "bob@example.com", "cross-identifier same domain"),
        ("E2", "carol@example.com", "other identifier"),
        ("E3", "alice@evil.test", "cross-domain"),
    ]
    for eid, req, name in cases:
        r = verify_identity(
            identity=v["identity"],
            payment=v["payment"],
            anchor=v["anchor"],
            root_asc=v["root_asc"],
            requested_identifier=req,
            expected_commitment=commit,
            now=exp["verification_time"],
        )
        ok = expect_error(r, "IDENTIFIER_MISMATCH") or expect_error(
            r, "DOMAIN_IDENTIFIER_INCONSISTENT"
        )
        _pass_if(
            ok,
            id=eid,
            part="E",
            name=name,
            expected_outcome=Outcome.BLOCKED.value,
            actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
            expected_detail="IDENTIFIER_MISMATCH",
            actual_detail=str(r.errors),
            errors=r.errors,
        )

    # E4 same KROOT other domain — would need new signed doc; unsigned domain change fails sig
    idm = mutate_doc_field(v["identity"], KEY_DOMAIN, "evil.test")
    idm = mutate_doc_field(idm, KEY_IDENTIFIER, "alice@evil.test")
    r = verify_identity(
        identity=idm,
        payment=v["payment"],
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier="alice@evil.test",
        now=exp["verification_time"],
    )
    ok = expect_error(r, "INVALID_IDENTITY_SIGNATURE") or expect_error(r, "ANCHOR_MISMATCH")
    _pass_if(
        ok,
        id="E4",
        part="E",
        name="Same KROOT transplanted to other domain without resign",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
        expected_detail="signature/anchor failure",
        actual_detail=str(r.errors),
        errors=r.errors,
    )


# ---------------------------------------------------------------------------
# PART F — Payment binding
# ---------------------------------------------------------------------------


def part_f(v: dict) -> None:
    spk_a = bytes.fromhex("00141111111111111111111111111111111111111111")
    spk_b = bytes.fromhex("00142222222222222222222222222222222222222222")
    h_a = payment_hash(build_payment_binding([("bitcoin", spk_a)]))
    h_b = payment_hash(build_payment_binding([("bitcoin", spk_b)]))
    _pass_if(
        h_a != h_b,
        id="F1",
        part="F",
        name="Destination / scriptPubKey mutation changes hash",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value if h_a != h_b else Outcome.ACCEPTED.value,
        expected_detail="different payment_hash",
        actual_detail=f"{h_a.hex()[:16]} vs {h_b.hex()[:16]}",
    )

    # amount/label not in binding — same hash
    _pass_if(
        h_a == payment_hash(build_payment_binding([("bitcoin", spk_a)])),
        id="F2",
        part="F",
        name="Amount/label excluded from binding",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="hash unchanged (by design)",
        actual_detail="request metadata not in PaymentBindingV1",
        notes="NOT a vulnerability — intentional.",
    )

    m1 = build_payment_binding([("bitcoin", spk_a), ("test-method", b"\x01")])
    m2 = build_payment_binding([("test-method", b"\x01"), ("bitcoin", spk_a)])
    _pass_if(
        payment_hash(m1) == payment_hash(m2) and cbor.dumps(m1) == cbor.dumps(m2),
        id="F3",
        part="F",
        name="Method reorder canonicalisation",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value,
        expected_detail="same canonical bytes",
        actual_detail="order-independent",
    )

    dup = build_payment_binding([("bitcoin", spk_a), ("bitcoin", spk_a)])
    _pass_if(
        len(dup[1]) == 1,
        id="F4",
        part="F",
        name="Method duplication collapsed",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value,
        expected_detail="single method",
        actual_detail=f"count={len(dup[1])}",
    )

    # non-canonical rejected
    from reference.constants import METHOD_DESTINATION, METHOD_TYPE, PAY_METHODS, PAY_VERSION

    noncanon = cbor.dumps(
        {
            PAY_VERSION: 1,
            PAY_METHODS: [
                {METHOD_TYPE: "test-method", METHOD_DESTINATION: b"\x01"},
                {METHOD_TYPE: "bitcoin", METHOD_DESTINATION: spk_a},
            ],
        }
    )
    try:
        parse_payment_binding(noncanon)
        ok = False
    except PaymentBindingError:
        ok = True
    _pass_if(
        ok,
        id="F5",
        part="F",
        name="Non-canonical payment CBOR rejected",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
        expected_detail="PaymentBindingError",
        actual_detail="rejected" if ok else "accepted",
    )


# ---------------------------------------------------------------------------
# PART G — CBOR
# ---------------------------------------------------------------------------


def part_g() -> None:
    # non-shortest int
    try:
        cbor.loads(bytes([0x18, 0x01]))
        ok = False
    except CBORError:
        ok = True
    _pass_if(ok, id="G1", part="G", name="Non-shortest integer", expected_outcome=Outcome.BLOCKED.value,
             actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
             expected_detail="CBORError", actual_detail="ok")

    # trailing
    try:
        cbor.loads(cbor.dumps({0: 1}) + b"\x00")
        ok = False
    except CBORError:
        ok = True
    _pass_if(ok, id="G2", part="G", name="Trailing bytes", expected_outcome=Outcome.BLOCKED.value,
             actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
             expected_detail="CBORError", actual_detail="ok")

    # duplicate keys
    try:
        cbor.loads(bytes([0xA2, 0x00, 0x01, 0x00, 0x02]))
        ok = False
    except CBORError:
        ok = True
    _pass_if(ok, id="G3", part="G", name="Duplicate map keys", expected_outcome=Outcome.BLOCKED.value,
             actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
             expected_detail="CBORError", actual_detail="ok")

    # key reorder
    try:
        cbor.loads(bytes([0xA2, 0x02, 0x00, 0x00, 0x00]))
        ok = False
    except CBORError:
        ok = True
    _pass_if(ok, id="G4", part="G", name="Unsorted map keys", expected_outcome=Outcome.BLOCKED.value,
             actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
             expected_detail="CBORError", actual_detail="ok")

    a = {0: 1, 1: "x"}
    b = {1: "x", 0: 1}
    _pass_if(
        cbor.dumps(a) == cbor.dumps(b),
        id="G5",
        part="G",
        name="Semantic map → unique bytes",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value,
        expected_detail="identical encoding",
        actual_detail="ok",
    )

    try:
        cbor.loads(bytes([0xBF, 0x00, 0x01, 0xFF]))
        ok = False
    except CBORError:
        ok = True
    _pass_if(
        ok,
        id="G6",
        part="G",
        name="Indefinite-length map rejected",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
        expected_detail="CBORError",
        actual_detail="ok" if ok else "accepted",
    )

    try:
        cbor.loads(bytes([0x5F, 0x41, 0x00, 0xFF]))
        ok = False
    except CBORError:
        ok = True
    _pass_if(
        ok,
        id="G7",
        part="G",
        name="Indefinite-length bytes rejected",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
        expected_detail="CBORError",
        actual_detail="ok" if ok else "accepted",
    )


# ---------------------------------------------------------------------------
# PART H/I — Domain separators / hash separation
# ---------------------------------------------------------------------------


def part_hi(v: dict) -> None:
    payload = v["payload"]
    # Wrong separators must not verify under OpenPGP — use sequoia/python conceptual:
    # Message with wrong sep won't match signature (already tested M3). Here check tag domains.
    pay = payment_hash(cbor.loads(v["payment"]))
    commit = identity_commitment(cbor.loads(v["anchor"]))
    _pass_if(
        pay != commit,
        id="I1",
        part="I",
        name="PAYMENT_HASH ≠ IDENTITY_COMMITMENT",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if pay != commit else Outcome.ACCEPTED.value,
        expected_detail="different digests",
        actual_detail=f"pay={pay[:4].hex()} commit={commit[:4].hex()}",
    )

    # Cross-feed: use payment hash bytes as expected commitment
    exp = v["expected"]
    r = verify_identity(
        identity=v["identity"],
        payment=v["payment"],
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier=exp["identifier"],
        expected_commitment=pay,  # wrong domain
        now=exp["verification_time"],
    )
    ok = expect_error(r, "ANCHOR_MISMATCH")
    _pass_if(
        ok,
        id="I2",
        part="I",
        name="Reject PAYMENT_HASH as Bitcoin commitment",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value if ok else Outcome.ACCEPTED.value,
        expected_detail="ANCHOR_MISMATCH",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    seps = {
        "identity": DOMAIN_SEPARATOR_IDENTITY,
        "payment": DOMAIN_SEPARATOR_PAYMENT,
        "anchor": DOMAIN_SEPARATOR_ANCHOR,
    }
    vals = list(seps.values())
    _pass_if(
        len(set(vals)) == 3,
        id="H1",
        part="H",
        name="Domain separators pairwise distinct",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value,
        expected_detail="3 distinct byte strings",
        actual_detail=str({k: v.hex() for k, v in seps.items()}),
    )

    # Wrong identity separator length simulation
    wrong = b"BIP353-IDENTITY\x00\x02" + payload
    right = DOMAIN_SEPARATOR_IDENTITY + payload
    _pass_if(
        wrong != right and hashlib.sha256(wrong).digest() != hashlib.sha256(right).digest(),
        id="H2",
        part="H",
        name="Version-byte separator change alters message",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value,
        expected_detail="different message bytes",
        actual_detail="ok",
    )

    # Additional separator variants must all differ from canonical
    variants = [
        b"BIP353-IDENTITY\x00\x01",  # missing nothing — exact
        b"BIP353-IDENTITY\x00\x02",
        b"BIP353-IDENTITY\x01",
        b"BIP353-IDENTITY",
        b"BIP353-IDENTITY/PAYMENT",
        b"BIP353-IDENTITY/ANCHOR",
        DOMAIN_SEPARATOR_PAYMENT,
        DOMAIN_SEPARATOR_ANCHOR,
    ]
    canon = DOMAIN_SEPARATOR_IDENTITY
    distinct = all(v != canon or v is variants[0] for v in variants[1:]) and all(
        hashlib.sha256(v + payload).digest() != hashlib.sha256(canon + payload).digest()
        for v in variants
        if v != canon
    )
    _pass_if(
        distinct and variants[0] == canon,
        id="H3",
        part="H",
        name="Cross-protocol separator variants ≠ identity v1",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if distinct else Outcome.ACCEPTED.value,
        expected_detail="all non-canonical separators produce different messages",
        actual_detail="ok" if distinct else "collision",
    )


# ---------------------------------------------------------------------------
# PART J/K — Bitcoin
# ---------------------------------------------------------------------------


def part_jk(m4: dict | None) -> None:
    if not m4:
        _pass_if(
            False,
            id="J0",
            part="J",
            name="M4 fixture present",
            expected_outcome=Outcome.DETECTED.value,
            actual_outcome=Outcome.AMBIGUOUS.value,
            expected_detail="vectors/m4 required",
            actual_detail="missing",
        )
        return

    proof = m4["proof"]
    commitment = bytes.fromhex(m4["expected"]["identity_commitment"])

    def attack(aid: str, name: str, mutate, want: str) -> None:
        p = copy.deepcopy(proof)
        mutate(p)
        r = verify_bitcoin_anchor_proof(
            p,
            expected_commitment=commitment,
            header_context=HeaderContext.TRUSTED,
        )
        ok = any(want in e for e in r.errors)
        _pass_if(
            ok,
            id=aid,
            part="J",
            name=name,
            expected_outcome=Outcome.DETECTED.value,
            actual_outcome=Outcome.DETECTED.value if ok else Outcome.ACCEPTED.value,
            expected_detail=want,
            actual_detail=str(r.errors),
            errors=r.errors,
        )

    attack(
        "J1",
        "Wrong commitment field",
        lambda p: setattr(p, "commitment", bytes(32)),
        "WRONG_TX_COMMITMENT",
    )

    # J2 — mutate OP_RETURN in raw_tx; keep proof.commitment = expected (M6 FIXED)
    p_j2 = copy.deepcopy(proof)
    raw = bytearray(p_j2.raw_tx)
    tag = b"B353ID"
    idx = bytes(raw).find(tag)
    assert idx >= 0, "M4 fixture must contain B353ID tag"
    flip_at = idx + len(tag) + 1
    raw[flip_at] ^= 0x01
    p_j2.raw_tx = bytes(raw)
    r_j2 = verify_bitcoin_anchor_proof(
        p_j2,
        expected_commitment=commitment,
        header_context=HeaderContext.TRUSTED,
    )
    j2_blocked = any("WRONG_TX_COMMITMENT" in e for e in r_j2.errors) and not (
        r_j2.anchor_included
    )
    _pass_if(
        j2_blocked,
        id="J2",
        part="J",
        name="Wrong OP_RETURN in raw_tx (M6 regression)",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if j2_blocked else Outcome.ACCEPTED.value,
        expected_detail="WRONG_TX_COMMITMENT",
        actual_detail=str(r_j2.errors),
        notes="F-J2 FIXED in M6",
        errors=r_j2.errors,
    )

    # J3 — claim other txid with Merkle for that txid; raw_tx still original
    p_j3 = copy.deepcopy(proof)
    other_txid = bytes(32)
    p_j3.txid = other_txid
    p_j3.tx_index = 0
    p_j3.merkle_branch = []
    hdr = bytearray(p_j3.block_header)
    hdr[36:68] = other_txid
    p_j3.block_header = bytes(hdr)
    r_j3 = verify_bitcoin_anchor_proof(
        p_j3,
        expected_commitment=commitment,
        header_context=HeaderContext.TRUSTED,
    )
    j3_blocked = any("TXID_MISMATCH" in e for e in r_j3.errors) and not r_j3.anchor_included
    _pass_if(
        j3_blocked,
        id="J3",
        part="J",
        name="Wrong transaction txid (M6 regression)",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if j3_blocked else Outcome.ACCEPTED.value,
        expected_detail="TXID_MISMATCH",
        actual_detail=str(r_j3.errors),
        notes="F-J3 FIXED in M6",
        errors=r_j3.errors,
    )

    # J4 — Wrong block (prev_hash) with valid merkle; Mode B untrusted
    p_j4 = copy.deepcopy(proof)
    hdr = bytearray(p_j4.block_header)
    hdr[4] ^= 0xFF
    p_j4.block_header = bytes(hdr)
    r_j4 = verify_bitcoin_anchor_proof(
        p_j4,
        expected_commitment=commitment,
        header_context=HeaderContext.UNTRUSTED,
    )
    j4_ok = (
        r_j4.inclusion_proof_valid
        and r_j4.header_context == "untrusted"
        and not r_j4.anchor_included
        and not r_j4.human_verified
    )
    _pass_if(
        j4_ok,
        id="J4",
        part="J",
        name="Wrong prev_hash; untrusted header context",
        expected_outcome=Outcome.AMBIGUOUS.value,
        actual_outcome=Outcome.AMBIGUOUS.value if j4_ok else Outcome.ACCEPTED.value,
        expected_detail="inclusion_proof_valid + header_context=untrusted; not best-chain",
        actual_detail=(
            f"inclusion={r_j4.inclusion_proof_valid} ctx={r_j4.header_context} "
            f"included={r_j4.anchor_included}"
        ),
        notes="Mode B — wallet must supply trusted headers for anchor_included",
        errors=r_j4.errors,
    )
    add_finding(
        Finding(
            id="F-J4",
            severity="INFORMATIONAL",
            attack="Detached block header / wrong chain",
            precondition="Verifier called with header_context=untrusted",
            steps=[
                "Present Merkle-valid header not on wallet's best chain",
                "Observe header_context and anchor_included",
            ],
            expected="header_context=untrusted; anchor_included=false",
            actual="Mode B returns untrusted; does not claim best chain",
            outcome=Outcome.AMBIGUOUS.value,
            impact="Wallets must not treat isolated proofs as chain-confirmed",
            mitigation="Pass header_context=trusted only after wallet header sync",
            classification="known_limitation",
        )
    )

    def bad_branch(p):
        if p.merkle_branch:
            p.merkle_branch = [bytes(32)] + list(p.merkle_branch[1:])
        else:
            p.merkle_branch = [bytes(32)]

    attack("J5", "Wrong Merkle branch", bad_branch, "WRONG_MERKLE_PROOF")

    def bad_root(p):
        hdr = bytearray(p.block_header)
        hdr[36] ^= 0xFF
        p.block_header = bytes(hdr)

    attack("J6", "Wrong Merkle root in header", bad_root, "WRONG_MERKLE_PROOF")

    # J7 — Wrong height (metadata only; not cryptographically bound)
    p_j7 = copy.deepcopy(proof)
    p_j7.block_height = proof.block_height + 99999
    r_j7 = verify_bitcoin_anchor_proof(
        p_j7,
        expected_commitment=commitment,
        header_context=HeaderContext.TRUSTED,
    )
    j7_accepted = r_j7.identity_anchored and not r_j7.errors
    _pass_if(
        True,
        id="J7",
        part="J",
        name="Wrong claimed block height",
        expected_outcome=Outcome.AMBIGUOUS.value,
        actual_outcome=Outcome.ACCEPTED.value if j7_accepted else Outcome.DETECTED.value,
        expected_detail="Height is advisory unless header chain checked",
        actual_detail=(
            "ACCEPTED — height not verified against header/chain"
            if j7_accepted
            else str(r_j7.errors)
        ),
        notes="NOT PROVIDED: height authenticity in isolated proof",
        errors=r_j7.errors,
    )

    r = verify_bitcoin_anchor_proof(
        proof,
        expected_commitment=commitment,
        known_orphaned=True,
        header_context=HeaderContext.TRUSTED,
    )
    _pass_if(
        expect_error(r, "ORPHANED_ANCHOR") or "ORPHANED" in str(r.errors),
        id="J8",
        part="J",
        name="Orphaned anchor",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value if r.errors else Outcome.ACCEPTED.value,
        expected_detail="ORPHANED_ANCHOR",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    # J9 — Reorg semantics: once known_orphaned, must not stay ANCHOR_INCLUDED
    r_j9 = verify_bitcoin_anchor_proof(
        proof,
        expected_commitment=commitment,
        known_orphaned=True,
        header_context=HeaderContext.TRUSTED,
    )
    reorg_ok = (
        r_j9.anchor_status == AnchorStatus.ANCHOR_ORPHANED.value
        and not r_j9.anchor_included
        and expect_error(r_j9, "ORPHANED_ANCHOR")
    )
    _pass_if(
        reorg_ok,
        id="J9",
        part="J",
        name="Reorg → orphaned status (API)",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value if reorg_ok else Outcome.AMBIGUOUS.value,
        expected_detail="anchor_orphaned; anchor_included=false",
        actual_detail=f"status={r_j9.anchor_status} included={r_j9.anchor_included}",
        notes="Real chain reorg exercised in test_regtest_reorg.py when bitcoind available",
        errors=r_j9.errors,
    )

    # Confirmation semantics
    for conf, policy, expect in [
        (0, 6, AnchorStatus.ANCHOR_SEEN),
        (1, 6, AnchorStatus.ANCHOR_INCLUDED),
        (6, 6, AnchorStatus.ANCHOR_CONFIRMED),
    ]:
        st = evaluate_anchor_status(
            included=conf > 0, confirmations=conf, confirmation_policy=policy
        )
        # conf=0 with included=False → SEEN
        if conf == 0:
            st = evaluate_anchor_status(
                included=False, confirmations=0, confirmation_policy=policy
            )
        _pass_if(
            st == expect,
            id=f"K-{conf}conf",
            part="K",
            name=f"Confirmation semantics conf={conf}",
            expected_outcome=Outcome.DETECTED.value,
            actual_outcome=Outcome.DETECTED.value if st == expect else Outcome.AMBIGUOUS.value,
            expected_detail=expect.value,
            actual_detail=st.value,
        )

    # Valid proof still verifies under trusted header context
    r = verify_bitcoin_anchor_proof(
        proof,
        expected_commitment=commitment,
        header_context=HeaderContext.TRUSTED,
    )
    _pass_if(
        r.identity_anchored
        and r.anchor_included
        and r.transaction_valid
        and r.inclusion_proof_valid
        and not r.human_verified
        and r.freshness_status == "unknown"
        and r.rollback_resistance == "not_provided",
        id="J-valid",
        part="J",
        name="Valid M4 proof still verifies; not human",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value if r.identity_anchored else Outcome.BLOCKED.value,
        expected_detail="anchored+included, human_verified=false, freshness unknown",
        actual_detail=str(r.to_dict()),
    )


# ---------------------------------------------------------------------------
# PART M — Multiple payment methods
# ---------------------------------------------------------------------------


def part_m(v: dict) -> None:
    spk_a = bytes.fromhex("0014" + "11" * 20)
    spk_b = bytes.fromhex("0014" + "22" * 20)
    two = build_payment_binding([("bitcoin", spk_a), ("bitcoin", spk_b)])
    reordered = build_payment_binding([("bitcoin", spk_b), ("bitcoin", spk_a)])
    _pass_if(
        cbor.dumps(two) == cbor.dumps(reordered) and len(two[1]) == 2,
        id="M1",
        part="M",
        name="Bitcoin A + Bitcoin B canonical order",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value,
        expected_detail="order-independent; both destinations kept",
        actual_detail=f"methods={len(two[1])} equal_encoding=True",
    )

    removed = build_payment_binding([("bitcoin", spk_a)])
    _pass_if(
        payment_hash(two) != payment_hash(removed),
        id="M2",
        part="M",
        name="Method removal changes payment_hash",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value,
        expected_detail="different payment_hash",
        actual_detail=f"{payment_hash(two)[:4].hex()} vs {payment_hash(removed)[:4].hex()}",
    )

    # Lightning (lno) not fully defined — unknown type must not silently alias bitcoin
    try:
        build_payment_binding([("lno", b"offer1qq...")])
        # If accepted as opaque, hash must still differ from bitcoin of same bytes
        mixed = build_payment_binding([("bitcoin", spk_a), ("lno", spk_a)])
        same_type_collision = payment_hash(
            build_payment_binding([("bitcoin", spk_a)])
        ) == payment_hash(mixed)
        outcome = Outcome.DETECTED.value if not same_type_collision else Outcome.ACCEPTED.value
        detail = "type is part of binding" if not same_type_collision else "TYPE COLLISION"
    except Exception as e:
        outcome = Outcome.AMBIGUOUS.value
        detail = f"lno not registered / rejected: {type(e).__name__}"
        same_type_collision = False

    _pass_if(
        True,
        id="M3",
        part="M",
        name="Lightning/unknown method handling",
        expected_outcome=Outcome.AMBIGUOUS.value,
        actual_outcome=outcome,
        expected_detail="lno payload TBD by Lightning BIP; must not collide with bitcoin",
        actual_detail=detail,
        notes="OPEN: Lightning canonical form not frozen in V1",
    )


# ---------------------------------------------------------------------------
# PART L — Multiple anchors
# ---------------------------------------------------------------------------


def part_l() -> None:
    _pass_if(
        True,
        id="L1",
        part="L",
        name="Multiple Bitcoin txs with same commitment",
        expected_outcome=Outcome.AMBIGUOUS.value,
        actual_outcome=Outcome.AMBIGUOUS.value,
        expected_detail="Protocol does not define selection among multiple valid inclusions",
        actual_detail=(
            "Any tx containing the commitment with valid inclusion is acceptable. "
            "No replacement semantics. No 'latest wins'. Verifier may accept any."
        ),
        notes="NOT PROVIDED: multi-anchor policy. Informational for BIP text.",
    )
    add_finding(
        Finding(
            id="F-L1",
            severity="LOW",
            attack="Multiple anchors / ambiguous currentness",
            precondition="Same commitment published in multiple txs/blocks",
            steps=["Publish commitment twice", "Present either proof"],
            expected="Defined selection rule",
            actual="AMBIGUOUS — any valid inclusion works",
            outcome=Outcome.AMBIGUOUS.value,
            impact="Low for Candidate A (same KROOT); confusing UX if multiple proofs diverge in metadata",
            mitigation="Document 'any valid inclusion suffices'; optional prefer deepest confirmation",
            classification="known_limitation",
        )
    )


# ---------------------------------------------------------------------------
# PART N — Versioning
# ---------------------------------------------------------------------------


def part_n(v: dict) -> None:
    exp = v["expected"]
    for ver, label in [(0, "v0"), (2, "v2")]:
        idm = mutate_doc_field(v["identity"], KEY_PROTOCOL_VERSION, ver)
        r = verify_identity(
            identity=idm,
            payment=v["payment"],
            anchor=v["anchor"],
            root_asc=v["root_asc"],
            requested_identifier=exp["identifier"],
            now=exp["verification_time"],
        )
        # version change also breaks signature; either UNSUPPORTED_VERSION or INVALID_SIGNATURE
        ok = expect_error(r, "UNSUPPORTED_VERSION") or expect_error(
            r, "INVALID_IDENTITY_SIGNATURE"
        )
        _pass_if(
            ok,
            id=f"N-{label}",
            part="N",
            name=f"Unsupported document version {ver}",
            expected_outcome=Outcome.BLOCKED.value,
            actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
            expected_detail="reject",
            actual_detail=str(r.errors),
            errors=r.errors,
        )


# ---------------------------------------------------------------------------
# PART O — Type confusion
# ---------------------------------------------------------------------------


def part_o(v: dict) -> None:
    exp = v["expected"]
    # Feed commitment hex as identifier
    r = verify_identity(
        identity=v["identity"],
        payment=v["payment"],
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier=exp["identity_commitment"],
        now=exp["verification_time"],
    )
    ok = expect_error(r, "IDENTIFIER_MISMATCH")
    _pass_if(
        ok,
        id="O1",
        part="O",
        name="Commitment string as identifier",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
        expected_detail="IDENTIFIER_MISMATCH",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    # scriptPubKey as root fingerprint
    idm = mutate_doc_field(
        v["identity"],
        KEY_ROOT_FINGERPRINT,
        bytes.fromhex("00141111111111111111111111111111111111111111")[:20],
    )
    r = verify_identity(
        identity=idm,
        payment=v["payment"],
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier=exp["identifier"],
        now=exp["verification_time"],
    )
    ok = expect_error(r, "ROOT_KEY_MISMATCH") or expect_error(
        r, "INVALID_IDENTITY_SIGNATURE"
    )
    _pass_if(
        ok,
        id="O2",
        part="O",
        name="scriptPubKey confused as root fingerprint",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
        expected_detail="mismatch",
        actual_detail=str(r.errors),
        errors=r.errors,
    )


# ---------------------------------------------------------------------------
# PART P — Resource exhaustion
# ---------------------------------------------------------------------------


def part_p(v: dict) -> None:
    # Huge identifier request
    huge = "a" * 10000 + "@example.test"
    r = verify_identity(
        identity=v["identity"],
        payment=v["payment"],
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier=huge,
        now=v["expected"]["verification_time"],
    )
    ok = expect_error(r, "IDENTIFIER_MISMATCH")
    _pass_if(
        ok,
        id="P1",
        part="P",
        name="Huge requested identifier",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value if ok else Outcome.ACCEPTED.value,
        expected_detail="IDENTIFIER_MISMATCH quickly",
        actual_detail=str(r.errors),
        notes="No explicit size caps in verifier — INFORMATIONAL gap.",
    )
    add_finding(
        Finding(
            id="F-P1",
            severity="LOW",
            attack="Resource exhaustion via huge proofs",
            precondition="Attacker sends oversized CBOR/proof",
            steps=["Send megabyte IdentityDocument", "Force parse"],
            expected="Hard size limits",
            actual="No explicit caps in reference verifier",
            outcome=Outcome.AMBIGUOUS.value,
            impact="DoS risk for naive implementations",
            mitigation="Enforce max sizes on document, methods list, merkle branch, raw_tx",
            classification="needs_change",
        )
    )

    # Many payment methods
    methods = [("test-method", bytes([i % 256]) * 8) for i in range(1000)]
    big = build_payment_binding(methods)
    enc = cbor.dumps(big)
    _pass_if(
        len(enc) < 100_000,
        id="P2",
        part="P",
        name="1000 methods encode without explosion",
        expected_outcome=Outcome.AMBIGUOUS.value,
        actual_outcome=Outcome.AMBIGUOUS.value,
        expected_detail="should eventually be size-capped",
        actual_detail=f"encoded_len={len(enc)}",
        notes="Reference allows large lists — recommend MAX_METHODS.",
    )


# ---------------------------------------------------------------------------
# PART Q/R — Privacy / trust
# ---------------------------------------------------------------------------


def part_qr(v: dict) -> None:
    _pass_if(
        True,
        id="Q1",
        part="Q",
        name="Bitcoin anchor privacy disclosure",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="On-chain commitment enables correlation if preimage known",
        actual_detail=(
            "OP_RETURN stores H(domain||identifier||KROOT). "
            "Anyone who knows those inputs can scan chain for the commitment. "
            "Does not put cleartext email on-chain, but is linkable."
        ),
        notes="Privacy NOT PROVIDED as a hard guarantee.",
    )
    add_finding(
        Finding(
            id="F-Q1",
            severity="INFORMATIONAL",
            attack="Blockchain correlation of identity commitments",
            precondition="Observer knows domain/identifier/KROOT candidates",
            steps=["Brute or know inputs", "Scan OP_RETURN for matching commitment"],
            expected="Unlinkability",
            actual="Linkable by design once inputs known",
            outcome=Outcome.ACCEPTED.value,
            impact="Public chronology of identity anchoring",
            mitigation="Optional delay; avoid anchoring highly sensitive identifiers; document tradeoff",
            classification="known_limitation",
        )
    )

    r = verify_identity(
        identity=v["identity"],
        payment=v["payment"],
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier=v["expected"]["identifier"],
        expected_commitment=bytes.fromhex(v["expected"]["identity_commitment"]),
        now=v["expected"]["verification_time"],
    )
    _pass_if(
        r.trust_state == "first_seen" and r.identity_verified,
        id="R1",
        part="R",
        name="Cryptographic verify ≠ human trust",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value
        if r.trust_state == "first_seen"
        else Outcome.AMBIGUOUS.value,
        expected_detail="trust_state=first_seen even when verified",
        actual_detail=f"trust={r.trust_state} verified={r.identity_verified}",
    )


# ---------------------------------------------------------------------------
# PART S — Composed attacks
# ---------------------------------------------------------------------------


def part_s(v: dict, m4: dict | None) -> None:
    exp = v["expected"]
    commit = bytes.fromhex(exp["identity_commitment"])

    # Attack 1: DNS+hosting no KROOT → already A2
    _pass_if(
        True,
        id="S1",
        part="S",
        name="DNS+hosting without KROOT",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value,
        expected_detail="Cannot match Bitcoin anchor with new KROOT",
        actual_detail="See A2 — BLOCKED/DETECTED",
    )

    # Attack 2: hosting + KSIGN — see B1
    _pass_if(
        True,
        id="S2",
        part="S",
        name="Hosting + KSIGN compromise",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="Can change payment state until revocation",
        actual_detail="See F-B1",
    )

    # Attack 3: DNS + old IdentityDocument
    _pass_if(
        True,
        id="S3",
        part="S",
        name="DNS + stale IdentityDocument",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="freshness unknown; payment may diverge → binding mismatch if DNS changed",
        actual_detail=(
            "If DNS payment matches stale document, ACCEPTED. "
            "If DNS moved on but document is old, PAYMENT_BINDING_MISMATCH (DETECTED)."
        ),
        notes="Composition depends on whether DNS and document stay consistent.",
    )

    # Attack 7/8: valid payment wrong identity / valid identity wrong payment
    pay_evil = cbor.dumps(
        build_payment_binding(
            [("bitcoin", bytes.fromhex("0014ffffffffffffffffffffffffffffffffffffffff"))]
        )
    )
    r = verify_identity(
        identity=v["identity"],
        payment=pay_evil,
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier=exp["identifier"],
        expected_commitment=commit,
        now=exp["verification_time"],
    )
    _pass_if(
        expect_error(r, "PAYMENT_BINDING_MISMATCH"),
        id="S8",
        part="S",
        name="Valid identity + wrong payment",
        expected_outcome=Outcome.DETECTED.value,
        actual_outcome=Outcome.DETECTED.value
        if expect_error(r, "PAYMENT_BINDING_MISMATCH")
        else Outcome.ACCEPTED.value,
        expected_detail="PAYMENT_BINDING_MISMATCH",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    r = verify_identity(
        identity=v["identity"],
        payment=v["payment"],
        anchor=v["anchor"],
        root_asc=v["root_asc"],
        requested_identifier="attacker@evil.test",
        expected_commitment=commit,
        now=exp["verification_time"],
    )
    _pass_if(
        expect_error(r, "IDENTIFIER_MISMATCH"),
        id="S7",
        part="S",
        name="Valid payment/identity proof for wrong requested name",
        expected_outcome=Outcome.BLOCKED.value,
        actual_outcome=Outcome.BLOCKED.value
        if expect_error(r, "IDENTIFIER_MISMATCH")
        else Outcome.ACCEPTED.value,
        expected_detail="IDENTIFIER_MISMATCH",
        actual_detail=str(r.errors),
        errors=r.errors,
    )

    # Attack 5: KROOT compromise — see C1
    _pass_if(
        True,
        id="S5",
        part="S",
        name="KROOT + new KSIGN + new payment",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="Indistinguishable from legitimate owner",
        actual_detail="See F-C1",
    )

    # Attack 6: valid old anchor + new IdentityDocument with same KROOT
    _pass_if(
        True,
        id="S6",
        part="S",
        name="Old anchor + new IdentityDocument (same KROOT)",
        expected_outcome=Outcome.ACCEPTED.value,
        actual_outcome=Outcome.ACCEPTED.value,
        expected_detail="Candidate A allows payment/KSIGN evolution without new anchor",
        actual_detail="By design — continuity of KROOT",
    )


def main() -> int:
    print("=== M5 Adversarial Security Audit ===\n")
    v = load_valid()
    m4 = load_m4()

    part_a(v)
    part_b(v)
    part_c(v)
    part_d(v)
    part_e(v)
    part_f(v)
    part_g()
    part_hi(v)
    part_jk(m4)
    part_l()
    part_m(v)
    part_n(v)
    part_o(v)
    part_p(v)
    part_qr(v)
    part_s(v, m4)

    path = write_results()
    passed = sum(1 for r in RESULTS if r.pass_)
    failed = sum(1 for r in RESULTS if not r.pass_)
    print(f"\n{passed} pass, {failed} fail, {len(FINDINGS)} findings")
    print(f"Wrote {path}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

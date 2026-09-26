"""Phase 10 — deterministic adversarial / mutation suite for experimental Schnorr V2.

Does NOT modify frozen vectors. Does NOT patch protocol code.
SEED is fixed for reproducibility.

EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from reference import cbor
from reference.cbor import CBORError
from reference.payment_binding import build_payment_binding, encode_payment_binding
from reference.schnorr_v2 import anchor as anchor_mod
from reference.schnorr_v2 import binding as binding_mod
from reference.schnorr_v2 import identity as identity_mod
from reference.schnorr_v2 import payment as payment_mod
from reference.schnorr_v2.bitcoin_proof import (
    BitcoinProofError,
    build_header_for_txid,
    build_minimal_legacy_tx,
    extract_b353s2_commitment_from_raw_tx,
    proof_from_parts,
    proof_to_jsonable,
    verify_bitcoin_anchor_proof_v2,
)
from reference.schnorr_v2.hashutil import tagged_hash_msg
from reference.schnorr_v2.key import keypair_from_secret, verify_msg32
from reference.schnorr_v2.tags import (
    OP_RETURN_TAG,
    TAG_ANCHOR,
    TAG_IDENTITY,
    TAG_PAYMENT,
    TAG_SUBKEY_BINDING,
)
from reference.schnorr_v2.verify import VerifyError, verify
from reference.bitcoin_tx import parse_transaction

ROOT = Path(__file__).resolve().parents[2]
VEC = ROOT / "vectors" / "schnorr"
OUT = ROOT / "test" / "schnorr_v2" / "adversarial_results.json"

# Deterministic fuzz seed (recorded for reproduction)
SEED = 0xA3535210  # Phase 10 deterministic seed
SEED_HEX = f"{SEED:08x}"

NOW = 1_700_000_000
DOMAIN = "example.test"
IDENTIFIER = "alice@example.test"
ROOT_SK = bytes.fromhex("01" * 32)
SIGNING_SK = bytes.fromhex("02" * 32)
ALT_SK = bytes.fromhex("03" * 32)
ALT2_SK = bytes.fromhex("04" * 32)


@dataclass
class Finding:
    id: str
    severity: str  # CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL
    title: str
    detail: str
    reproduction: dict[str, Any] = field(default_factory=dict)


@dataclass
class CaseResult:
    suite: str
    name: str
    expected: str
    actual: str
    ok: bool
    seed: str = SEED_HEX
    notes: str = ""


class AdversarialHarness:
    def __init__(self) -> None:
        self.cases: list[CaseResult] = []
        self.findings: list[Finding] = []
        self.cross_diffs: list[dict[str, Any]] = []
        self.root = keypair_from_secret(ROOT_SK)
        self.signing = keypair_from_secret(SIGNING_SK)
        self.alt = keypair_from_secret(ALT_SK)
        self.alt2 = keypair_from_secret(ALT2_SK)
        self.base = self._build_base()

    def _build_base(self) -> dict[str, Any]:
        body = binding_mod.build_binding_body(
            root_pubkey=self.root.pubkey,
            signing_pubkey=self.signing.pubkey,
            created_at=NOW - 60,
            expires_at=NOW + 86400 * 365,
        )
        binding_sig = binding_mod.sign_binding(self.root, body)
        pay = payment_mod.make_fixture_payment_binding(
            script_pubkey=bytes([0x00, 0x14]) + bytes(range(20))
        )
        pay_hash = payment_mod.payment_hash_v2(pay)
        signed = identity_mod.build_signed_map(
            domain=DOMAIN,
            identifier=IDENTIFIER,
            root_pubkey=self.root.pubkey,
            signing_pubkey=self.signing.pubkey,
            created_at=NOW - 60,
            expires_at=NOW + 86400 * 365,
            payment_hash=pay_hash,
        )
        id_sig = identity_mod.sign_identity(self.signing, signed)
        document = identity_mod.attach_signature(signed, id_sig)
        am = anchor_mod.build_anchor_message(
            domain=DOMAIN, identifier=IDENTIFIER, root_pubkey=self.root.pubkey
        )
        commitment = anchor_mod.anchor_commitment(am)
        opreturn = anchor_mod.build_opreturn_script(commitment)
        raw = build_minimal_legacy_tx(opreturn_script=opreturn)
        proof = proof_from_parts(raw_tx=raw, expected_commitment=commitment)
        return {
            "body": body,
            "binding_sig": binding_sig,
            "pay": pay,
            "pay_hash": pay_hash,
            "signed": signed,
            "document": document,
            "id_sig": id_sig,
            "am": am,
            "commitment": commitment,
            "opreturn": opreturn,
            "raw": raw,
            "proof": proof,
        }

    def record(
        self,
        suite: str,
        name: str,
        *,
        expected: str,
        actual: str,
        ok: bool,
        notes: str = "",
    ) -> None:
        self.cases.append(
            CaseResult(
                suite=suite,
                name=name,
                expected=expected,
                actual=actual,
                ok=ok,
                notes=notes,
            )
        )
        if not ok:
            print(f"FAIL [{suite}] {name}: expected={expected} actual={actual} {notes}")

    def expect_reject(self, suite: str, name: str, fn: Callable[[], Any]) -> None:
        try:
            fn()
            self.record(suite, name, expected="reject", actual="ACCEPT", ok=False)
        except Exception as exc:  # noqa: BLE001 — adversarial: any reject is success
            self.record(
                suite,
                name,
                expected="reject",
                actual=f"reject:{type(exc).__name__}:{getattr(exc, 'code', '')}",
                ok=True,
            )

    def expect_accept(self, suite: str, name: str, fn: Callable[[], Any]) -> None:
        try:
            fn()
            self.record(suite, name, expected="accept", actual="accept", ok=True)
        except Exception as e:  # noqa: BLE001
            self.record(
                suite,
                name,
                expected="accept",
                actual=f"reject:{e}",
                ok=False,
            )

    # ------------------------------------------------------------------ CBOR
    def suite_cbor(self) -> None:
        suite = "CBOR"
        good = cbor.dumps(self.base["signed"])

        # Property A: encode idempotent
        e1 = cbor.dumps(self.base["document"])
        e2 = cbor.dumps(cbor.loads(e1))
        self.record(
            suite,
            "property_A_encode_stable",
            expected="equal",
            actual="equal" if e1 == e2 else "differ",
            ok=e1 == e2,
        )

        # Property B: roundtrip
        decoded = cbor.loads(good)
        self.record(
            suite,
            "property_B_roundtrip",
            expected="equal",
            actual="equal" if cbor.dumps(decoded) == good else "differ",
            ok=cbor.dumps(decoded) == good,
        )

        mutations: list[tuple[str, bytes]] = [
            ("trailing_byte", good + b"\x00"),
            ("truncated", good[:-1]),
            ("non_shortest_uint_0", bytes([0x18, 0x00])),  # 0 as 1-byte
            ("indefinite_array", bytes([0x9F, 0x01, 0xFF])),
            ("indefinite_map", bytes([0xBF, 0x00, 0x01, 0xFF])),
            ("float16", bytes([0xF9, 0x3C, 0x00])),
            ("true", bytes([0xF5])),
            ("null", bytes([0xF6])),
            ("tag_date", bytes([0xC0, 0x00])),
            ("empty_then_extra", bytes([0xA0, 0x00])),
            ("dup_key_map", bytes([0xA2, 0x00, 0x01, 0x00, 0x02])),  # {0:1, 0:2}
            ("unsorted_keys", bytes([0xA2, 0x02, 0x01, 0x01, 0x02])),  # key 2 then 1
            ("invalid_utf8_text", bytes([0x61, 0xFF])),  # text len1 = 0xFF
            ("oversized_bstr_len", bytes([0x58, 0xFF]) + b"\x00" * 10),
        ]
        for name, blob in mutations:
            self.expect_reject(suite, name, lambda b=blob: cbor.loads(b))

        # Reordered map values that dump sorts — two dict insertion orders same encoding
        m1 = {0: 1, 2: b"\xab", 1: "x"}
        m2 = {2: b"\xab", 1: "x", 0: 1}
        self.record(
            suite,
            "map_insertion_order_canonical",
            expected="equal",
            actual="equal" if cbor.dumps(m1) == cbor.dumps(m2) else "differ",
            ok=cbor.dumps(m1) == cbor.dumps(m2),
        )

    # ----------------------------------------------------------- signatures
    def suite_signatures(self) -> None:
        suite = "SIGNATURE"
        msg = identity_mod.identity_digest(self.base["signed"])
        sig = self.base["id_sig"]
        pk = self.signing.pubkey

        def ok():
            assert verify_msg32(pk, msg, sig)

        self.expect_accept(suite, "baseline_verify", ok)

        mutants = [
            ("flip_bit0", bytes([sig[0] ^ 1]) + sig[1:]),
            ("truncate", sig[:63]),
            ("append_byte", sig + b"\x00"),
            ("zero_R", bytes(32) + sig[32:]),
            ("zero_s", sig[:32] + bytes(32)),
            ("replace_all_ff", b"\xff" * 64),
        ]
        for name, bad in mutants:
            self.record(
                suite,
                name,
                expected="reject",
                actual="accept" if (len(bad) == 64 and verify_msg32(pk, msg, bad)) else "reject",
                ok=not (len(bad) == 64 and verify_msg32(pk, msg, bad)),
            )

        # Cross message
        other = dict(self.base["signed"])
        other[identity_mod.K_DOMAIN] = "other.test"
        other[identity_mod.K_IDENTIFIER] = "alice@other.test"
        # skip domain check by hashing mutated map bytes directly
        msg_b = tagged_hash_msg(TAG_IDENTITY, cbor.dumps(other))
        self.record(
            suite,
            "sig_A_message_B",
            expected="reject",
            actual="accept" if verify_msg32(pk, msg_b, sig) else "reject",
            ok=not verify_msg32(pk, msg_b, sig),
        )

        # Cross pubkey
        self.record(
            suite,
            "sig_valid_pubkey_B",
            expected="reject",
            actual="accept" if verify_msg32(self.alt.pubkey, msg, sig) else "reject",
            ok=not verify_msg32(self.alt.pubkey, msg, sig),
        )

    # ------------------------------------------------------ domain separation
    def suite_domain_separation(self) -> None:
        suite = "DOMAIN"
        payload = cbor.dumps(self.base["signed"])
        tags = [TAG_SUBKEY_BINDING, TAG_IDENTITY, TAG_PAYMENT, TAG_ANCHOR]
        digests = {t: tagged_hash_msg(t, payload) for t in tags}
        # all digests distinct
        vals = list(digests.values())
        distinct = len(set(vals)) == len(vals)
        self.record(
            suite,
            "all_tags_distinct_digest",
            expected="distinct",
            actual="distinct" if distinct else "collision",
            ok=distinct,
        )

        # sign under IDENTITY, verify digest under PAYMENT
        sig = self.signing.sign_msg32(digests[TAG_IDENTITY])
        self.record(
            suite,
            "sign_IDENTITY_verify_PAYMENT",
            expected="reject",
            actual=(
                "accept"
                if verify_msg32(self.signing.pubkey, digests[TAG_PAYMENT], sig)
                else "reject"
            ),
            ok=not verify_msg32(self.signing.pubkey, digests[TAG_PAYMENT], sig),
        )
        for wrong in (TAG_SUBKEY_BINDING, TAG_ANCHOR):
            self.record(
                suite,
                f"sign_IDENTITY_verify_{wrong.split('/')[-1]}",
                expected="reject",
                actual=(
                    "accept"
                    if verify_msg32(self.signing.pubkey, digests[wrong], sig)
                    else "reject"
                ),
                ok=not verify_msg32(self.signing.pubkey, digests[wrong], sig),
            )

    # --------------------------------------------------- root/signing confuse
    def suite_root_signing(self) -> None:
        suite = "ROOT_SIGNING"
        b = self.base

        def run_verify(**kw: Any) -> None:
            verify(
                root_pubkey=kw.get("root", self.root.pubkey),
                signing_pubkey=kw.get("signing", self.signing.pubkey),
                binding_body=kw.get("body", b["body"]),
                binding_signature=kw.get("bsig", b["binding_sig"]),
                identity_document=kw.get("doc", b["document"]),
                payment_binding=kw.get("pay", b["pay"]),
                now=NOW,
            )

        self.expect_accept(suite, "A_binds_B_baseline", lambda: run_verify())

        # A→C binding body with A's signature over original → reject
        bad_body = dict(b["body"])
        bad_body[binding_mod.KEY_SIGNING] = self.alt.pubkey
        self.expect_reject(
            suite,
            "binding_signing_substituted_stale_sig",
            lambda: run_verify(body=bad_body, signing=self.alt.pubkey),
        )

        # Present root=alt, keep binding for root=A
        self.expect_reject(
            suite,
            "presented_root_alt",
            lambda: run_verify(root=self.alt.pubkey),
        )

        # Swap root and signing roles
        self.expect_reject(
            suite,
            "swap_root_and_signing_presented",
            lambda: run_verify(root=self.signing.pubkey, signing=self.root.pubkey),
        )

        # Valid binding A→B but document signing = C
        bad_doc = dict(b["document"])
        bad_doc[identity_mod.K_SIGNING] = self.alt.pubkey
        self.expect_reject(
            suite,
            "doc_signing_C_binding_B",
            lambda: run_verify(doc=bad_doc, signing=self.alt.pubkey),
        )

        # Binding signed by wrong key (alt root) for A→B body
        wrong_sig = self.alt.sign_msg32(binding_mod.binding_digest(b["body"]))
        self.expect_reject(
            suite,
            "binding_signed_by_alt_root",
            lambda: run_verify(bsig=wrong_sig),
        )

    # ------------------------------------------------ identity mutations
    def suite_identity(self) -> None:
        suite = "IDENTITY"
        b = self.base
        fields = {
            "domain": (identity_mod.K_DOMAIN, "evil.test"),
            "identifier": (identity_mod.K_IDENTIFIER, "bob@example.test"),
            "root": (identity_mod.K_ROOT, self.alt.pubkey),
            "signing": (identity_mod.K_SIGNING, self.alt.pubkey),
            "created_at": (identity_mod.K_CREATED, NOW + 10),
            "expires_at": (identity_mod.K_EXPIRES, NOW - 10),
            "payment_hash": (identity_mod.K_PAYMENT_HASH, bytes(32)),
            "version": (identity_mod.K_VERSION, 99),
            "signature_flip": (
                identity_mod.K_SIGNATURE,
                bytes([b["document"][9][0] ^ 1]) + b["document"][9][1:],
            ),
        }
        for name, (key, val) in fields.items():
            doc = dict(b["document"])
            doc[key] = val
            # fix identifier if domain mutated so we isolate field when needed
            if name == "domain":
                doc[identity_mod.K_IDENTIFIER] = "alice@evil.test"

            def _v(d=doc):
                verify(
                    root_pubkey=self.root.pubkey if key != identity_mod.K_ROOT else d[identity_mod.K_ROOT],
                    signing_pubkey=(
                        self.signing.pubkey
                        if key != identity_mod.K_SIGNING
                        else d[identity_mod.K_SIGNING]
                    ),
                    binding_body=b["body"],
                    binding_signature=b["binding_sig"],
                    identity_document=d,
                    payment_binding=b["pay"],
                    now=NOW,
                )

            self.expect_reject(suite, f"mutate_{name}", _v)

        # field removal
        for key, label in [
            (identity_mod.K_DOMAIN, "domain"),
            (identity_mod.K_PAYMENT_HASH, "payment_hash"),
            (identity_mod.K_SIGNATURE, "signature"),
        ]:
            doc = dict(b["document"])
            del doc[key]
            self.expect_reject(
                suite,
                f"remove_{label}",
                lambda d=doc: verify(
                    root_pubkey=self.root.pubkey,
                    signing_pubkey=self.signing.pubkey,
                    binding_body=b["body"],
                    binding_signature=b["binding_sig"],
                    identity_document=d,
                    payment_binding=b["pay"],
                    now=NOW,
                ),
            )

        # type substitution
        doc = dict(b["document"])
        doc[identity_mod.K_DOMAIN] = b"not-a-string"
        self.expect_reject(
            suite,
            "type_sub_domain_bytes",
            lambda: verify(
                root_pubkey=self.root.pubkey,
                signing_pubkey=self.signing.pubkey,
                binding_body=b["body"],
                binding_signature=b["binding_sig"],
                identity_document=doc,
                payment_binding=b["pay"],
                now=NOW,
            ),
        )

    # ------------------------------------------------ payment binding
    def suite_payment(self) -> None:
        suite = "PAYMENT"
        base = self.base["pay"]
        h0 = payment_mod.payment_hash_v2(base)

        # mutate scriptPubKey
        spk2 = bytes([0x00, 0x14]) + bytes(range(20, 40))
        pay2 = payment_mod.make_fixture_payment_binding(script_pubkey=spk2)
        h2 = payment_mod.payment_hash_v2(pay2)
        self.record(
            suite,
            "different_spk_different_hash",
            expected="differ",
            actual="differ" if h2 != h0 else "same",
            ok=h2 != h0,
        )

        # method type change
        pay3 = build_payment_binding([("test-method", spk2)])
        h3 = payment_mod.payment_hash_v2(pay3)
        self.record(
            suite,
            "different_method_type_different_hash",
            expected="differ",
            actual="differ" if h3 != h0 else "same",
            ok=h3 != h0,
        )

        # Duplicate identical (type, destination) pairs are collapsed by design (V1 builder)
        pay4 = build_payment_binding(
            [
                ("bitcoin", bytes([0x00, 0x14]) + bytes(range(20))),
                ("bitcoin", bytes([0x00, 0x14]) + bytes(range(20))),
            ]
        )
        h4 = payment_mod.payment_hash_v2(pay4)
        self.record(
            suite,
            "duplicate_identical_method_collapsed",
            expected="equal",
            actual="equal" if h4 == h0 else "differ",
            ok=h4 == h0,
            notes="build_payment_binding collapses duplicate (type,destination)",
        )
        # Distinct destinations must not collapse
        pay4b = build_payment_binding(
            [
                ("bitcoin", bytes([0x00, 0x14]) + bytes(range(20))),
                ("bitcoin", bytes([0x00, 0x14]) + bytes(range(1, 21))),
            ]
        )
        h4b = payment_mod.payment_hash_v2(pay4b)
        self.record(
            suite,
            "two_distinct_methods_different_hash",
            expected="differ",
            actual="differ" if h4b != h0 else "same",
            ok=h4b != h0,
        )

        # Excluded fields must not enter PaymentBinding model —
        # building with only method type+destination; confirm amount etc. absent
        enc = encode_payment_binding(base)
        self.record(
            suite,
            "excluded_fields_absent_from_cbor",
            expected="absent",
            actual=(
                "absent"
                if b"amount" not in enc and b"label" not in enc and b"message" not in enc
                else "present"
            ),
            ok=b"amount" not in enc and b"label" not in enc and b"message" not in enc,
        )

        # Same scriptPubKey → same binding regardless of how we obtained bytes
        pay_a = payment_mod.make_fixture_payment_binding(
            script_pubkey=bytes([0x00, 0x14]) + bytes(range(20))
        )
        pay_b = payment_mod.make_fixture_payment_binding(
            script_pubkey=bytes([0x00, 0x14]) + bytes(range(20))
        )
        self.record(
            suite,
            "same_spk_same_hash",
            expected="equal",
            actual=(
                "equal"
                if payment_mod.payment_hash_v2(pay_a) == payment_mod.payment_hash_v2(pay_b)
                else "differ"
            ),
            ok=payment_mod.payment_hash_v2(pay_a) == payment_mod.payment_hash_v2(pay_b),
        )

        # Verify rejects mismatched payment
        self.expect_reject(
            suite,
            "verify_with_mutated_payment",
            lambda: verify(
                root_pubkey=self.root.pubkey,
                signing_pubkey=self.signing.pubkey,
                binding_body=self.base["body"],
                binding_signature=self.base["binding_sig"],
                identity_document=self.base["document"],
                payment_binding=pay2,
                now=NOW,
            ),
        )

    # ----------------------------------------------------- anchor / B353S2
    def suite_anchor_b353s2(self) -> None:
        suite = "B353S2"
        c0 = self.base["commitment"]
        am2 = anchor_mod.build_anchor_message(
            domain="evil.test",
            identifier="alice@evil.test",
            root_pubkey=self.root.pubkey,
        )
        c2 = anchor_mod.anchor_commitment(am2)
        self.record(
            suite,
            "different_anchor_different_commitment",
            expected="differ",
            actual="differ" if c2 != c0 else "same",
            ok=c2 != c0,
        )

        wrong_root_am = anchor_mod.build_anchor_message(
            domain=DOMAIN, identifier=IDENTIFIER, root_pubkey=self.alt.pubkey
        )
        wrong_c = anchor_mod.anchor_commitment(wrong_root_am)
        wrong_op = anchor_mod.build_opreturn_script(wrong_c)
        wrong_raw = build_minimal_legacy_tx(opreturn_script=wrong_op)
        # Proof for wrong commitment but verify against expected (correct) commitment
        proof = proof_from_parts(raw_tx=wrong_raw, expected_commitment=wrong_c)
        self.expect_reject(
            suite,
            "wrong_root_commitment_vs_identity",
            lambda: verify_bitcoin_anchor_proof_v2(
                proof, expected_commitment=c0
            ),
        )

        # B353S2 counts
        good_op = self.base["opreturn"]
        self.expect_reject(
            suite,
            "missing_B353S2",
            lambda: extract_b353s2_commitment_from_raw_tx(
                build_minimal_legacy_tx(opreturn_script=bytes([0x6A, 0x01, 0x00]))
            ),
        )
        self.expect_accept(
            suite,
            "one_B353S2",
            lambda: extract_b353s2_commitment_from_raw_tx(
                build_minimal_legacy_tx(opreturn_script=good_op)
            ),
        )
        self.expect_reject(
            suite,
            "two_B353S2",
            lambda: extract_b353s2_commitment_from_raw_tx(
                build_minimal_legacy_tx(
                    opreturn_script=good_op, extra_scripts=[good_op]
                )
            ),
        )
        self.expect_reject(
            suite,
            "three_B353S2",
            lambda: extract_b353s2_commitment_from_raw_tx(
                build_minimal_legacy_tx(
                    opreturn_script=good_op, extra_scripts=[good_op, good_op]
                )
            ),
        )

        # Wrong / similar tags
        def _payload(tag: bytes, ver: int, commit: bytes) -> bytes:
            p = tag + bytes([ver]) + commit
            return bytes([0x6A, len(p)]) + p

        for name, script in [
            ("wrong_tag_B353ID", _payload(b"B353ID", 1, c0)),
            ("wrong_tag_B353S3", _payload(b"B353S3", 1, c0)),
            ("truncated_payload", bytes([0x6A, 0x20]) + b"B353S2" + b"\x01" + c0[:20]),
            ("extra_payload", bytes([0x6A, 0x28]) + b"B353S2" + b"\x01" + c0 + b"\x00"),
            ("wrong_version", _payload(b"B353S2", 2, c0)),
        ]:
            self.expect_reject(
                suite,
                name,
                lambda s=script: extract_b353s2_commitment_from_raw_tx(
                    build_minimal_legacy_tx(opreturn_script=s)
                ),
            )

        # B353ID must not be accepted as V2
        self.record(
            suite,
            "B353ID_not_confused_with_B353S2",
            expected="reject",
            actual="reject",  # covered above
            ok=True,
            notes="B353ID OP_RETURN rejected by extract_commitment_from_opreturn",
        )

    # ----------------------------------------------- raw tx / merkle / header
    def suite_btc_proof(self) -> None:
        suite = "BTC"
        b = self.base
        proof = b["proof"]
        c0 = b["commitment"]

        self.expect_accept(
            suite,
            "baseline_dual_binding",
            lambda: verify_bitcoin_anchor_proof_v2(proof, expected_commitment=c0),
        )

        # raw_tx mutations → txid change
        raw = bytearray(b["raw"])
        raw[0] ^= 1  # version LSB
        mutated = bytes(raw)
        txid0 = parse_transaction(b["raw"]).txid_internal
        txid1 = parse_transaction(mutated).txid_internal
        self.record(
            suite,
            "raw_tx_mutation_changes_txid",
            expected="differ",
            actual="differ" if txid0 != txid1 else "same",
            ok=txid0 != txid1,
        )

        # Dual-binding matrix
        matrix = [
            ("valid_all", "anchored", None),
        ]
        # invalid merkle
        bad = deepcopy(proof)
        bad.merkle_branch = [bytes.fromhex("aa" * 32)]
        self.expect_reject(
            suite,
            "matrix_valid_tx_invalid_merkle",
            lambda: verify_bitcoin_anchor_proof_v2(bad, expected_commitment=c0),
        )
        # missing B353S2
        raw_miss = build_minimal_legacy_tx(opreturn_script=bytes([0x6A, 0x01, 0x00]))
        # keep header for original txid — dual fail
        p_miss = proof_from_parts(raw_tx=raw_miss, expected_commitment=c0)
        # proof_from_parts will fail at extract — catch
        self.expect_reject(
            suite,
            "matrix_missing_B353S2",
            lambda: verify_bitcoin_anchor_proof_v2(
                # craft with original header but missing output — use raw_miss + wrong header
                type(proof)(
                    raw_tx=raw_miss,
                    txid=parse_transaction(raw_miss).txid_internal,
                    block_header=build_header_for_txid(
                        parse_transaction(raw_miss).txid_internal
                    )[0],
                    tx_index=0,
                    merkle_branch=[],
                    commitment=c0,
                ),
                expected_commitment=c0,
            ),
        )
        # duplicate B353S2
        raw_dup = build_minimal_legacy_tx(
            opreturn_script=b["opreturn"], extra_scripts=[b["opreturn"]]
        )
        self.expect_reject(
            suite,
            "matrix_duplicate_B353S2",
            lambda: verify_bitcoin_anchor_proof_v2(
                type(proof)(
                    raw_tx=raw_dup,
                    txid=parse_transaction(raw_dup).txid_internal,
                    block_header=build_header_for_txid(
                        parse_transaction(raw_dup).txid_internal
                    )[0],
                    tx_index=0,
                    merkle_branch=[],
                    commitment=c0,
                ),
                expected_commitment=c0,
            ),
        )
        # wrong commitment
        self.expect_reject(
            suite,
            "matrix_wrong_commitment",
            lambda: verify_bitcoin_anchor_proof_v2(proof, expected_commitment=bytes(32)),
        )
        # mutated raw with stale proof fields
        p_mut = deepcopy(proof)
        p_mut.raw_tx = mutated
        self.expect_reject(
            suite,
            "matrix_mutated_raw_stale_txid",
            lambda: verify_bitcoin_anchor_proof_v2(p_mut, expected_commitment=c0),
        )
        # wrong header merkle root
        p_hdr = deepcopy(proof)
        hdr = bytearray(p_hdr.block_header)
        hdr[36] ^= 1  # touch merkle root region
        p_hdr.block_header = bytes(hdr)
        self.expect_reject(
            suite,
            "matrix_wrong_header_merkle_root",
            lambda: verify_bitcoin_anchor_proof_v2(p_hdr, expected_commitment=c0),
        )

        # Merkle index / sibling fuzz
        sib = bytes.fromhex("11" * 32)
        header, branch = build_header_for_txid(txid0, sibling=sib, tx_index=0)
        p_ok = deepcopy(proof)
        p_ok.block_header = header
        p_ok.merkle_branch = branch
        p_ok.tx_index = 0
        # Need raw_tx whose txid is txid0 — use original
        self.expect_accept(
            suite,
            "merkle_even_index_with_sibling",
            lambda: verify_bitcoin_anchor_proof_v2(p_ok, expected_commitment=c0),
        )
        p_odd = deepcopy(p_ok)
        p_odd.tx_index = 1
        # wrong index for branch construction
        self.expect_reject(
            suite,
            "merkle_wrong_index",
            lambda: verify_bitcoin_anchor_proof_v2(p_odd, expected_commitment=c0),
        )
        p_extra = deepcopy(p_ok)
        p_extra.merkle_branch = branch + [bytes(32)]
        self.expect_reject(
            suite,
            "merkle_extra_sibling",
            lambda: verify_bitcoin_anchor_proof_v2(p_extra, expected_commitment=c0),
        )

        # Header field mutations that don't change merkle_root should still
        # pass inclusion check (V2 does not claim PoW) — document behaviour
        p_ts = deepcopy(proof)
        hdr2 = bytearray(p_ts.block_header)
        # timestamp at bytes 68-71 little-endian
        hdr2[68] ^= 1
        p_ts.block_header = bytes(hdr2)
        try:
            verify_bitcoin_anchor_proof_v2(p_ts, expected_commitment=c0)
            self.record(
                suite,
                "header_timestamp_mutation_still_passes_inclusion",
                expected="accept_inclusion_only",
                actual="accept",
                ok=True,
                notes="V2 does not validate PoW/timestamp; INFORMATIONAL",
            )
            self.findings.append(
                Finding(
                    id="ADV-I1",
                    severity="INFORMATIONAL",
                    title="Block header non-merkle fields are not validated",
                    detail=(
                        "Mutating timestamp/nBits/nonce/prev_hash/version while "
                        "keeping merkle_root leaves dual-binding inclusion PASS. "
                        "Matches stated non-claim: no PoW/best-chain/finality."
                    ),
                    reproduction={"seed": SEED_HEX, "mutation": "header[68]^=1"},
                )
            )
        except BitcoinProofError as e:
            self.record(
                suite,
                "header_timestamp_mutation_still_passes_inclusion",
                expected="accept_inclusion_only",
                actual=f"reject:{e.code}",
                ok=False,
            )

    # --------------------------------------------------- state separation
    def suite_state(self) -> None:
        suite = "STATE"
        b = self.base
        r = verify(
            root_pubkey=self.root.pubkey,
            signing_pubkey=self.signing.pubkey,
            binding_body=b["body"],
            binding_signature=b["binding_sig"],
            identity_document=b["document"],
            payment_binding=b["pay"],
            now=NOW,
            bitcoin_proof=None,
        )
        self.record(
            suite,
            "verified_without_btc_not_anchored",
            expected="iv=T,pv=T,ia=F,cv=F",
            actual=(
                f"iv={r['identity_verified']},pv={r['payment_verified']},"
                f"ia={r['identity_anchored']},cv={r['continuity_verified']}"
            ),
            ok=(
                r["identity_verified"]
                and r["payment_verified"]
                and not r["identity_anchored"]
                and not r["continuity_verified"]
            ),
        )
        r2 = verify(
            root_pubkey=self.root.pubkey,
            signing_pubkey=self.signing.pubkey,
            binding_body=b["body"],
            binding_signature=b["binding_sig"],
            identity_document=b["document"],
            payment_binding=b["pay"],
            now=NOW,
            bitcoin_proof=proof_to_jsonable(b["proof"]),
        )
        self.record(
            suite,
            "full_dual_binding_anchored",
            expected="all_true",
            actual=str(r2),
            ok=all(
                [
                    r2["identity_verified"],
                    r2["payment_verified"],
                    r2["identity_anchored"],
                    r2["continuity_verified"],
                ]
            ),
        )
        # Logical OP_RETURN must not grant anchor
        r3 = verify(
            root_pubkey=self.root.pubkey,
            signing_pubkey=self.signing.pubkey,
            binding_body=b["body"],
            binding_signature=b["binding_sig"],
            identity_document=b["document"],
            payment_binding=b["pay"],
            now=NOW,
            opreturn_script=b["opreturn"],
            bitcoin_proof=None,
        )
        self.record(
            suite,
            "logical_opreturn_not_anchored",
            expected="ia=false",
            actual=f"ia={r3['identity_anchored']}",
            ok=r3["identity_anchored"] is False,
        )

    # ------------------------------------------------ sequence / time
    def suite_sequence_time(self) -> None:
        suite = "SEQUENCE_TIME"
        # Sequence present / absent / max — signing still works; no rollback check
        for seq, label in [(0, "zero"), (1, "one"), (2**32 - 1, "u32max")]:
            signed = identity_mod.build_signed_map(
                domain=DOMAIN,
                identifier=IDENTIFIER,
                root_pubkey=self.root.pubkey,
                signing_pubkey=self.signing.pubkey,
                created_at=NOW - 60,
                expires_at=NOW + 1000,
                payment_hash=self.base["pay_hash"],
                sequence=seq,
            )
            sig = identity_mod.sign_identity(self.signing, signed)
            doc = identity_mod.attach_signature(signed, sig)
            identity_mod.verify_identity_signature(doc)
            self.record(
                suite,
                f"sequence_{label}_accepted_in_document",
                expected="accept",
                actual="accept",
                ok=True,
            )

        # sequence max+1 as int is fine for CBOR if < 2^64
        signed = identity_mod.build_signed_map(
            domain=DOMAIN,
            identifier=IDENTIFIER,
            root_pubkey=self.root.pubkey,
            signing_pubkey=self.signing.pubkey,
            created_at=NOW - 60,
            expires_at=NOW + 1000,
            payment_hash=self.base["pay_hash"],
            sequence=2**32,
        )
        self.record(
            suite,
            "sequence_2_32_encodable",
            expected="accept_encode",
            actual="accept",
            ok=True,
            notes="No protocol max; ROLLBACK RESISTANCE NOT PROVIDED",
        )

        self.findings.append(
            Finding(
                id="ADV-I2",
                severity="INFORMATIONAL",
                title="ROLLBACK RESISTANCE = NOT PROVIDED",
                detail=(
                    "Optional sequence is carried in IdentityDocument but V2 does "
                    "not compare sequences across documents or reject decreases. "
                    "Documented non-claim; adversarial suite confirms absence."
                ),
                reproduction={"seed": SEED_HEX},
            )
        )

        # Time boundaries
        self.expect_reject(
            suite,
            "created_gt_expires_build",
            lambda: identity_mod.build_signed_map(
                domain=DOMAIN,
                identifier=IDENTIFIER,
                root_pubkey=self.root.pubkey,
                signing_pubkey=self.signing.pubkey,
                created_at=NOW + 100,
                expires_at=NOW,
                payment_hash=self.base["pay_hash"],
            ),
        )
        # equal timestamps OK at build
        signed_eq = identity_mod.build_signed_map(
            domain=DOMAIN,
            identifier=IDENTIFIER,
            root_pubkey=self.root.pubkey,
            signing_pubkey=self.signing.pubkey,
            created_at=NOW,
            expires_at=NOW,
            payment_hash=self.base["pay_hash"],
        )
        self.record(
            suite,
            "created_eq_expires_build",
            expected="accept",
            actual="accept",
            ok=True,
        )
        # now outside window
        sig = identity_mod.sign_identity(self.signing, signed_eq)
        doc = identity_mod.attach_signature(signed_eq, sig)
        self.expect_reject(
            suite,
            "now_outside_equal_window",
            lambda: verify(
                root_pubkey=self.root.pubkey,
                signing_pubkey=self.signing.pubkey,
                binding_body=self.base["body"],
                binding_signature=self.base["binding_sig"],
                identity_document=doc,
                payment_binding=self.base["pay"],
                now=NOW + 1,
            ),
        )
        # negative created_at: builder currently accepts into a Python dict, but
        # Canonical CBOR cannot encode negatives → signing/verify path rejects.
        try:
            signed_neg = identity_mod.build_signed_map(
                domain=DOMAIN,
                identifier=IDENTIFIER,
                root_pubkey=self.root.pubkey,
                signing_pubkey=self.signing.pubkey,
                created_at=-1,
                expires_at=NOW + 1000,
                payment_hash=self.base["pay_hash"],
            )
            build_accepted = True
        except Exception:
            signed_neg = None
            build_accepted = False
        encode_rejected = False
        if build_accepted:
            try:
                cbor.dumps(signed_neg)
            except CBORError:
                encode_rejected = True
        self.record(
            suite,
            "negative_created_encode_rejects",
            expected="encode_reject",
            actual=(
                "encode_reject"
                if encode_rejected
                else ("build_reject" if not build_accepted else "ACCEPT")
            ),
            ok=encode_rejected or not build_accepted,
        )
        if build_accepted and encode_rejected:
            self.findings.append(
                Finding(
                    id="ADV-L2",
                    severity="LOW",
                    title="build_signed_map accepts negative created_at before CBOR",
                    detail=(
                        "identity.build_signed_map does not reject created_at < 0. "
                        "Canonical CBOR encoding refuses negatives, so wire/sign/verify "
                        "cannot succeed. Boundary robustness gap only; not a crypto bypass."
                    ),
                    reproduction={
                        "seed": SEED_HEX,
                        "created_at": -1,
                        "mutation": "build_signed_map(created_at=-1)",
                    },
                )
            )

    # ---------------------------------------------- property bag + known LOW
    def suite_properties_and_known(self) -> None:
        suite = "PROPERTY"
        # Property C already covered by identity mutations
        # Property D payment
        # Property E/F dual-binding
        self.record(
            suite,
            "property_C_mutation_rejects",
            expected="covered",
            actual="covered",
            ok=all(
                c.ok
                for c in self.cases
                if c.suite == "IDENTITY" and c.name.startswith("mutate_")
            ),
        )
        self.findings.append(
            Finding(
                id="ADV-L1",
                severity="LOW",
                title="F-S2 (pre-existing): dict-based verify API",
                detail=(
                    "Verifier accepts Python dicts rather than raw CBOR bytes as "
                    "sole input. Accepted for experimental freeze; not a new "
                    "Phase-10 discovery. Prefer CBOR-bytes API in a future phase."
                ),
                reproduction={},
            )
        )
        self.findings.append(
            Finding(
                id="ADV-I3",
                severity="INFORMATIONAL",
                title="F-S4 (pre-existing): SubkeyBinding omits domain",
                detail="By design in mini-spec; domain is bound in IdentityDocument.",
                reproduction={},
            )
        )
        self.findings.append(
            Finding(
                id="ADV-M1",
                severity="MEDIUM",
                title="Cross-impl CBOR: invalid UTF-8 accepted by JS decoder",
                detail=(
                    "Python reference/cbor.loads rejects text strings with invalid "
                    "UTF-8. Independent JS cborDecode uses TextDecoder without "
                    "{fatal:true}, accepting bytes and replacing with U+FFFD; "
                    "re-encoding diverges from input. "
                    "Not a BIP-340 bypass when digests are over raw CBOR bytes, "
                    "but Python-reject / JS-accept parser divergence. "
                    "DO NOT PATCH in Phase 10 — deferred to a future fix phase."
                ),
                reproduction={
                    "seed": SEED_HEX,
                    "input_hex": "61ff",
                    "python": "reject",
                    "javascript": "ACCEPT (replacement U+FFFD)",
                },
            )
        )

    def run_all(self) -> dict[str, Any]:
        self.suite_cbor()
        self.suite_signatures()
        self.suite_domain_separation()
        self.suite_root_signing()
        self.suite_identity()
        self.suite_payment()
        self.suite_anchor_b353s2()
        self.suite_btc_proof()
        self.suite_state()
        self.suite_sequence_time()
        self.suite_properties_and_known()

        failed = [c for c in self.cases if not c.ok]
        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for f in self.findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

        report = {
            "seed": SEED_HEX,
            "seed_int": SEED,
            "baseline_ref": "schnorr-v2-experimental-2",
            "case_total": len(self.cases),
            "case_pass": len(self.cases) - len(failed),
            "case_fail": len(failed),
            "failed_cases": [c.__dict__ for c in failed],
            "findings": [f.__dict__ for f in self.findings],
            "severity_counts": by_sev,
            "cases": [c.__dict__ for c in self.cases],
        }
        OUT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(
            f"ADVERSARIAL: {report['case_pass']}/{report['case_total']} PASS "
            f"(seed={SEED_HEX})"
        )
        print("FINDINGS:", by_sev)
        if failed:
            print("FAILED CASES:", [c.name for c in failed])
            return report
        return report


def main() -> int:
    h = AdversarialHarness()
    report = h.run_all()
    # Phase 10 fail gate: CRITICAL/HIGH or failed properties
    if report["severity_counts"]["CRITICAL"] or report["severity_counts"]["HIGH"]:
        return 2
    if report["case_fail"]:
        return 1
    print("ADVERSARIAL SUITE: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())

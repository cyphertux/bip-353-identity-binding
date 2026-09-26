# Experimental Schnorr V2 — Independent Security Review (Phase 6)

**EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1 — NOT FROZEN**

| Field | Value |
|-------|--------|
| Branch | `experiment/schnorr-identity-v2` |
| Date | 2026-09-26 |
| Scope | Red-team of mini-spec + `reference/schnorr_v2/` + `vectors/schnorr/` |
| Harness | `test/schnorr_v2/test_security_review.py` |
| Protocol changes applied | **None** (findings only) |

V1 remains FROZEN and was not modified.

---

## 1. Reconstructed authentication model

| Step | Authenticated | Not authenticated | Bytes hashed / signed | Context bound |
|------|---------------|-------------------|------------------------|---------------|
| Root key | Possession of `root_sk` for later binding sigs | Human identity; longevity | — | secp256k1 x-only 32 B |
| Root→Signing binding | `signing_pubkey` authorized by `root_pubkey` for validity window | Domain, identifier, payments | `TaggedHash(TAG_SUBKEY_BINDING, CanonicalCBOR(body{0..4}))` then BIP-340 Sign | Tag + body fields only |
| Signing key | Can create IdentityDocuments while binding valid | Cannot mint binding without root | — | — |
| IdentityDocument | Fields 0..7 (and 8 if present) under `signing_pubkey` | Freshness; that signer is human | `TaggedHash(TAG_IDENTITY, CanonicalCBOR(signed map))` + BIP-340 | Tag + document fields |
| PaymentBinding | Consistency of destinations ↔ `payment_hash` | Payment occurred / settled | `TaggedHash(TAG_PAYMENT, CanonicalCBOR(PaymentBinding))` | Tag + binding |
| Anchor (lab) | Commitment to `{version,domain,identifier,root_pubkey}` in OP_RETURN `B353S2` | Chain inclusion / reorg immunity / dual-binding | `TaggedHash(TAG_ANCHOR, CanonicalCBOR(AnchorMessage))` | Tag + message |

---

## 2. BIP-340 review

| Check | Result |
|-------|--------|
| Library | `embit==0.8.0` `schnorr_sign` / `schnorr_verify` / `xonly` / `from_xonly` |
| Official BIP-340 verify vector 0 | **PASS** (pubkey + signature) |
| Off-curve x-only reject | **PASS** |
| Application message | Always 32-byte `TaggedHash` then Sign/Verify | **PASS** (by construction) |
| Independent `TaggedHash` (hashlib vs embit) | **PASS** |
| Second independent Schnorr implementation | **NOT TESTED** |

**BIP-340 REVIEW: PASS** (wrt embit + official verify vectors + tagged-hash cross-check).

---

## 3–15. Attack results (summary)

Harness: all listed attack cases **PASS** (reject when required). Evidence: `test/schnorr_v2/test_security_review.py`.

| Area | Result |
|------|--------|
| Signing / root substitution | REJECT |
| Domain change without resign | REJECT (`INVALID_IDENTITY_SIGNATURE`) |
| Cross-root binding reuse | REJECT |
| Cross-tag signature reuse | REJECT |
| V1 tag strings ≠ V2 tags | PASS |
| Canonical CBOR (non-minimal, trailing, indefinite) | REJECT |
| Identity field mutations | REJECT |
| Payment destination substitution | REJECT (`PAYMENT_BINDING_MISMATCH`) |
| Anchor root/domain/identifier/commitment mutation | REJECT |
| `B353ID` presented to V2 OP_RETURN parser | REJECT |
| Light fuzz (300 random blobs) | No crash |
| Happy path | PASS |

### Replay / rollback

| Question | Conclusion |
|----------|------------|
| Can `sequence` provide anti-rollback? | **No** — optional; not anti-rollback |
| Present older valid document after newer one | **Accepted** if still within expiry and keys valid |
| **ROLLBACK RESISTANCE** | **NOT PROVIDED** (design) |
| **FRESHNESS** | **NOT PROVIDED** (design) |

Binding contains **no** domain/identifier (same structural idea as OpenPGP subkey binding in V1). Domain binding lives in the IdentityDocument. That is **by design**, not a binding forge.

### Key compromise

| Key | Attacker capability |
|-----|---------------------|
| Signing key only | Forge IdentityDocuments for any domain/identifier/payment while a valid root→signing binding exists and is unexpired; cannot create a new binding for a different signing key |
| Root key | Create arbitrary bindings; fully usurp cryptographic identity root; same ceiling as V1 KROOT compromise — **NOT PROVIDED** resistance |

### Bitcoin dual-binding / Merkle

`reference/schnorr_v2/` implements **logical** OP_RETURN commitment checks only. It does **not** implement:

* `raw_tx` authority,
* txid = SHA256d(non-witness serialization),
* Merkle inclusion under a header,
* multi-output `B353S2` ambiguity policy at transaction level.

Therefore **full Bitcoin inclusion proof is not demonstrated** by this lab, despite OP_RETURN tag wiring.

---

## 16. Independent implementation

| Check | Status |
|-------|--------|
| Independent TaggedHash (hashlib) | PASS |
| BIP-340 verify via official vectors (embit) | PASS |
| Second Schnorr library / pure reimplementation | **NOT TESTED** |

---

## 17. Security claim matrix (post-review)

| Property | Result | Evidence |
|----------|--------|----------|
| Root → signing binding | **PASS** | harness A/B/D + vectors |
| Identity authenticity | **PASS** | mutations + vectors |
| Payment binding | **PASS** | dest substitution + vectors |
| Anchor commitment (logical OP_RETURN) | **PASS** | anchor attacks + vectors |
| Continuity (root byte equality given logical anchor) | **PASS** | wrong-root OP_RETURN |
| Domain separation | **PASS** | cross-tag tests |
| Canonical CBOR | **PASS** | non-canonical rejects |
| Bitcoin dual-binding inclusion | **FAIL (not implemented)** | code inventory |
| Replay resistance (cross-domain without resign) | **PASS** | requires new identity sig |
| Rollback resistance | **NOT PROVIDED** | design |
| Freshness | **NOT PROVIDED** | design |
| Human identity | **NOT PROVIDED** | design |
| Revocation freshness | **NOT PROVIDED** | design |
| Privacy | **NOT PROVIDED** | design |
| Root/signing compromise resistance | **NOT PROVIDED** | design |

---

## 18. Findings

### F-S1 — Missing Bitcoin dual-binding in experimental reference

| Field | Value |
|-------|--------|
| **ID** | F-S1 |
| **Severity** | **HIGH** |
| **Component** | `reference/schnorr_v2/` anchor / verifier vs mini-spec claim wording |
| **Description** | Lab verifies OP_RETURN payload ↔ recomputed commitment only. No `raw_tx`↔txid↔Merkle↔header dual-binding as in V1 M6. |
| **Reproduction** | `rg raw_tx reference/schnorr_v2` empty; harness `gap-no-raw-tx-merkle` |
| **Impact** | Readers may over-read “Bitcoin anchor” as full inclusion proof. Inclusion under a wallet header is **not** demonstrated. |
| **Current behavior** | `identity_anchored` set after logical OP_RETURN match |
| **Expected behavior** | Either implement dual-binding for experimental parity with V1, **or** document explicitly that Phase 3–5 only claim logical commitment checks |
| **Potential fix** | Port V1 `verify_bitcoin_anchor_proof` patterns with tag `B353S2`; keep V1 code untouched |
| **Protocol impact** | **PROTOCOL DECISION REQUIRED** only if mini-spec claim matrix is read as asserting dual-binding *today*; wording already hedges with “once … exists”. README should not imply more than logical checks until implemented. |

### F-S2 — Verifier API accepts in-memory dicts without CBOR round-trip

| Field | Value |
|-------|--------|
| **ID** | F-S2 |
| **Severity** | **LOW** |
| **Component** | `verify.py` API |
| **Description** | `verify()` takes Python dicts; canonicity is enforced when CBOR is parsed via `reference.cbor.loads`, not when callers pass dicts directly. |
| **Reproduction** | Call `verify(...)` with hand-built dicts |
| **Impact** | Wire parsers that skip strict CBOR could diverge; lab vectors use strict loads |
| **Potential fix** | Prefer verify-from-CBOR-bytes entry point for production-shaped APIs |
| **Protocol impact** | None (implementation hygiene) |

### F-S3 — No multi-`B353S2` transaction policy in lab

| Field | Value |
|-------|--------|
| **ID** | F-S3 |
| **Severity** | **INFORMATIONAL** |
| **Component** | Anchor / future tx scanner |
| **Description** | V1 rejects ambiguous multiple matching identity outputs. V2 lab never scans a full transaction. |
| **Impact** | Deferred until dual-binding exists |
| **Protocol impact** | When implementing tx-level verify, reuse V1 ambiguity rule with `B353S2` |

### F-S4 — SubkeyBinding omits domain/identifier

| Field | Value |
|-------|--------|
| **ID** | F-S4 |
| **Severity** | **INFORMATIONAL** |
| **Component** | Binding design |
| **Description** | Same root→signing binding can authorize documents for any domain; domain is bound only by IdentityDocument signature. |
| **Impact** | Expected; matches “KROOT authorizes KSIGN, document binds name” model. Stolen signing key is the residual risk. |
| **Protocol impact** | None unless a future design wants per-domain bindings |

### Counts

| Severity | Count |
|----------|-------|
| CRITICAL | **0** |
| HIGH | **1** (F-S1) |
| MEDIUM | **0** |
| LOW | **1** (F-S2) |
| INFORMATIONAL | **2** (F-S3, F-S4) |

---

## 19. No silent fixes

No tagged-hash, CBOR, wire, anchor, signature, or key-binding changes were applied in Phase 6.

F-S1 requires an **implementation** follow-up and/or **documentation clarification**, not a silent mini-spec rewrite.

---

## 20. V1 integrity

`BIP-XXX.md`, V1 vectors, `M7_CHECKSUMS.txt`, and V1 tests were not modified for this review.

---

## 21. Phase 6 gate assessment

| Gate | Result |
|------|--------|
| BIP-340 REVIEW | PASS |
| KEY BINDING REVIEW | PASS |
| DOMAIN SEPARATION | PASS |
| CANONICAL CBOR | PASS |
| IDENTITY SIGNATURE | PASS |
| PAYMENT BINDING | PASS |
| ANCHOR (logical) | PASS |
| BITCOIN PROOF (dual-binding) | **FAIL** — not implemented (F-S1 HIGH) |
| REPLAY ANALYSIS | PASS |
| KEY COMPROMISE ANALYSIS | PASS |
| PARSING REVIEW | PASS |
| FUZZING | PASS (light) |
| INDEPENDENT IMPLEMENTATION | NOT TESTED (second Schnorr lib) / PARTIAL (official vectors + hashlib) |
| V1 INTEGRITY | PASS |

**PHASE 6 overall: FAIL** because of finding **F-S1 (HIGH)** — Bitcoin dual-binding inclusion is not implemented/demonstrated, so full bitcoin-proof claims must not be treated as PASS.

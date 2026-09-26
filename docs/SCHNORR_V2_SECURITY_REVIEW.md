# Experimental Schnorr V2 — Independent Security Review (Phase 6 / 6.1)

**EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1 — NOT FROZEN**

| Field | Value |
|-------|--------|
| Branch | `experiment/schnorr-identity-v2` |
| Phase 6 | FAIL (F-S1 HIGH open) |
| Phase 6.1 | Dual-binding hardening for F-S1 |
| Harness | `test/schnorr_v2/test_security_review.py`, `test_bitcoin_proof.py` |
| Protocol crypto changes (tags/docs/bindings) | **None** beyond Bitcoin proof path |

V1 remains FROZEN.

---

## F-S1 — Status: **RESOLVED** (Phase 6.1)

| Field | Value |
|-------|--------|
| **ID** | F-S1 |
| **Severity** | HIGH → **RESOLVED** |
| **Component** | `reference/schnorr_v2/bitcoin_proof.py` + verifier wiring |
| **Fix summary** | Dual-binding Bitcoin proof for experimental tag `B353S2` |

### Implemented authority paths

```text
raw_tx
  ├─► SHA256d(non-witness serialization) = txid  (aux field cross-checked)
  │         └─► Merkle branch + tx_index ─► block_header.merkle_root
  └─► parse outputs ─► unique B353S2 ─► commitment
            └─► must equal TaggedHash(TAG_ANCHOR, AnchorMessage)
```

`identity_anchored` / `continuity_verified` require this full proof.  
Logical OP_RETURN-only checks no longer set `identity_anchored` (Phase 4 fixtures remain valid for crypto/payment; they do not claim dual-binding anymore at verify time).

### Tests / vectors

| ID | Result |
|----|--------|
| V2-BTC-VALID-001 | PASS |
| V2-BTC-INVALID-001 TXID_MISMATCH | PASS |
| V2-BTC-INVALID-002 WRONG_MERKLE_PROOF | PASS |
| V2-BTC-INVALID-003 WRONG_MERKLE_PROOF | PASS |
| V2-BTC-INVALID-004 WRONG_MERKLE_PROOF | PASS |
| V2-BTC-INVALID-005 WRONG_TX_COMMITMENT | PASS |
| V2-BTC-INVALID-006 NO_B353S2_OUTPUT | PASS |
| V2-BTC-INVALID-007 AMBIGUOUS_B353S2_OUTPUTS | PASS |

Phase 4 JSON fixtures were **not** modified (byte-identical).

---

## Remaining findings

| ID | Severity | Status |
|----|----------|--------|
| F-S2 | LOW | OPEN — verify() dict API without CBOR round-trip |
| F-S3 | INFORMATIONAL | **RESOLVED** for tx-level extract — `AMBIGUOUS_B353S2_OUTPUTS` |
| F-S4 | INFORMATIONAL | OPEN — binding omits domain (by design) |

| Severity | Count (open) |
|----------|----------------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 1 |
| INFORMATIONAL | 1 |

---

## Claim matrix (post 6.1)

| Property | Result |
|----------|--------|
| Root → signing binding | PASS |
| Identity authenticity | PASS |
| Payment binding | PASS |
| Anchor commitment + dual-binding inclusion | **PASS** (synthetic regtest fixtures) |
| Domain separation | PASS |
| Canonical CBOR | PASS |
| Rollback / freshness / human identity | NOT PROVIDED |
| Absolute best-chain validation | NOT PROVIDED (header_context trusted/untrusted; no PoW/chain walk) |

---

## V1 integrity

No modifications to `BIP-XXX.md`, V1 vectors, `M7_CHECKSUMS.txt`, or V1 tests.

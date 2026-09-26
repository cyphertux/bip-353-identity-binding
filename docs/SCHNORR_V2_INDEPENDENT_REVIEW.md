# Experimental Schnorr V2 — Independent Reproduction (Phase 8)

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

| Field | Value |
|-------|--------|
| Historical freeze tag | `schnorr-v2-experimental-1` (unchanged) |
| Reconciled snapshot | `schnorr-v2-experimental-2` (Phase 9) |
| Independent tree | `independent/schnorr_v2/` |
| Reference tree | `reference/schnorr_v2/` (not imported) |

## Independent stack

| Item | Value |
|------|--------|
| Language | JavaScript |
| Runtime | Node.js v22.22.1 |
| Libraries | `@noble/curves@1.8.1`, `@noble/hashes@1.7.1` |
| CBOR | hand-written deterministic subset |
| Bitcoin | hand-written txid / Merkle / header / B353S2 extract |

## Comparison matrix

| Component | Independent | Reference | Match |
|-----------|-------------|-----------|-------|
| BIP-340 | noble schnorr + official vector 0 | embit | **YES** |
| TaggedHash | noble sha256 | embit hashes | **YES** (vector digests) |
| Root→Signing | verify vs frozen sigs | embit | **YES** |
| Canonical CBOR | hand encoder/decoder | `reference.cbor` | **YES** (round-trip / hashes) |
| IdentityDocument | noble verify | embit | **YES** |
| PaymentBinding | TAG_PAYMENT hash | embit path | **YES** |
| Anchor commitment | TAG_ANCHOR hash | embit path | **YES** |
| B353S2 | hand extract | Python extract | **YES** |
| TXID | hand SHA256d non-witness | V1 parser reused by ref | **YES** |
| Merkle proof | hand | V1 helper via ref | **YES** |
| Block header | hand (merkle_root field) | V1 BlockHeader | **YES** |
| Dual-binding | hand full path | `bitcoin_proof.py` | **YES** |
| Negative tests | all INVALID / BTC-INVALID | harness | **YES** |
| Full vectors | all current `V2-*.json` | fixtures | **YES** (see legacy note) |

## Phase 8 finding (preserved)

`V2-VALID-001.expected.identity_anchored=true` is a **LEGACY FROZEN** field from
`schnorr-v2-experimental-1` (pre–F-S1). Independent verification correctly yields
`identity_anchored=false` without `bitcoin_proof`. Phase 8 remains **PASS**.

Phase 9 adds:

* `V2-VALID-002` — dual-binding → `identity_anchored=true`
* `V2-VALID-003` — non-anchored → `identity_anchored=false`

See [`SCHNORR_V2_VECTOR_RECONCILIATION.md`](SCHNORR_V2_VECTOR_RECONCILIATION.md).

## Divergences

**none** (cryptographic digests, signatures, BTC dual-binding error codes).

## Security interpretation

Independent reproduction: **PASS**.

Still explicitly:

* No formal proof  
* No production security audit  
* No human identity guarantee  
* No freshness guarantee  
* No rollback resistance  
* No split-view resistance  

## Conclusion

V2 has been independently reproduced against the frozen experimental snapshot.
The reconciled vector set explicitly separates `identity_verified` from `identity_anchored`.

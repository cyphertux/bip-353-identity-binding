# Milestone 6 — Verification Hardening

**Status:** PASS  
**Date:** 2026-09-26  
**Scope:** Fix F-J2/F-J3; freeze honest V1 guarantees. No transparency log, freshness protocol, recovery, PSBT, Lightning freeze, UI, or BIP text.

Frozen vectors `vectors/valid/*` and `vectors/m4/*` **unchanged** (checksums verified).

---

## Executive Summary

M6 closes the HIGH inclusion gap from M5:

| Attack | M5 | M6 |
|--------|----|----|
| F-J2 mutate OP_RETURN in `raw_tx` | ACCEPTED | **BLOCKED** `WRONG_TX_COMMITMENT` |
| F-J3 wrong txid / foreign Merkle | ACCEPTED | **BLOCKED** `TXID_MISMATCH` |

The verifier now treats **`raw_tx` as the only authority** for both txid and commitment. Bundle fields `proof.txid` and `proof.commitment` are auxiliary cross-checks only.

V1 claims are frozen honestly:

- `freshness = unknown`
- `rollback_resistance = not_provided`
- `revocation_status = unknown` (**UNKNOWN BY DESIGN**) unless revocation material is present in the offered certificate
- `human_verified = false` always from this protocol
- Header validity is **CONTEXT-DEPENDENT** (`trusted` vs `untrusted`)

---

## F-J2 / F-J3 Fix

### Binding graph (mandatory)

```
                    ┌── SHA256d(non-witness) = txid ── Merkle ── header.merkle_root
raw_tx ─────────────┤
                    └── OP_RETURN B353ID||0x01||32 ── commitment
```

Both branches must agree with `expected_commitment` and with each other.  
`anchor_included = true` additionally requires `header_context = trusted`.

### Authority rules

| Field | Role |
|-------|------|
| `raw_tx` | **Authority** for txid and OP_RETURN commitment |
| `proof.txid` | Must equal `SHA256d(raw_tx)`; else `TXID_MISMATCH` |
| `proof.commitment` | Must equal extracted; else `WRONG_TX_COMMITMENT` |
| `expected_commitment` | Must equal extracted; else `WRONG_TX_COMMITMENT` |
| `merkle_branch` + `block_header` | Prove computed txid under header root |
| `block_height` | Advisory only |

---

## Transaction Binding

Implemented in `reference/bitcoin_tx.py`:

- Parse legacy and BIP-141 (segwit) transactions
- `txid = SHA256d(non-witness serialization)`
- Reject trailing bytes, oversized scripts, excessive in/out counts (`MAX_RAW_TX_BYTES=100000`)

Regression: `test/security/test_fj2_regression.py`, `test/security/test_fj3_regression.py`.

---

## OP_RETURN Parsing

`extract_identity_commitment(raw_tx)` in `reference/bitcoin_anchor.py`:

1. Parse transaction  
2. Scan outputs  
3. Match provisional layout: `B353ID || 0x01 || 32-byte commitment`  
4. Return the unique match  

Tests: valid / wrong tag / wrong version / truncated / extra bytes / multiple B353ID.

### Multiple B353ID policy (V1) — **Option 1: Reject ambiguous**

| Situation | Result |
|-----------|--------|
| Zero matching B353ID v1 outputs | `NO_B353ID_OUTPUT` |
| Exactly one match | Return commitment |
| Two or more matches (even if identical) | `AMBIGUOUS_B353ID_OUTPUTS` |
| Non-matching OP_RETURNs | Ignored |

**Rationale:** Order-independent; prevents wallets from disagreeing on which output is authoritative; avoids silent multi-identity packing. Republishing the same commitment in *separate transactions* remains allowed (multi-anchor policy still AMBIGUOUS — any valid inclusion of Candidate A may verify).

---

## Merkle Verification

Distinguishes:

| Concept | Field / meaning |
|---------|-----------------|
| Transaction structurally valid | `transaction_valid` |
| Txid included under claimed header | `inclusion_proof_valid` |
| Claimed header accepted by wallet chain view | `header_context == trusted` → may set `anchor_included` |

A valid Merkle proof **does not** prove best-chain membership.

---

## Header Trust Model

### Mode A — `header_context = trusted`

Wallet has validated PoW / linkage / tip (its own model).  
Then `anchor_included` / `anchor_confirmed` may be set from confirmation depth.

### Mode B — `header_context = untrusted` (default)

Isolated proof only:

```json
{
  "transaction_valid": true,
  "inclusion_proof_valid": true,
  "header_context": "untrusted",
  "anchor_included": false
}
```

J4 (mutated `prev_hash` with intact merkle): Mode B keeps `inclusion_proof_valid` relative to that header but **never** claims best chain.

---

## Reorg Semantics

Unchanged ladder:

- `anchor_seen`
- `anchor_included`
- `anchor_confirmed`
- `anchor_orphaned`

No absolute finality. Static ProofBundle cannot observe future reorgs; wallet tip state drives `known_orphaned`.  
Real regtest exercise: `test/security/test_regtest_reorg.py`.

---

## Freshness V1

**Normative:** without an external freshness mechanism:

```text
freshness = unknown
freshness_status = unknown
```

Never derived from:

- highest `sequence` seen locally  
- existence of a Bitcoin anchor  
- confirmation depth  

Result objects expose `freshness_detail.status = "unknown"` and never `current = true`.

---

## Rollback V1

**Normative claim for BIP text:**

> V1 provides no cryptographic guarantee that the presented IdentityDocument is the most recent valid document.

```text
rollback_resistance = not_provided
```

Visible in Bitcoin and identity verification results.

---

## Revocation V1 — **UNKNOWN BY DESIGN**

### Options considered

| Option | Summary | Decision |
|--------|---------|----------|
| A — Mandatory channel in ProofBundle | Forces transport; needs freshness of revocation itself | Rejected for V1 (scope / new mechanism) |
| B — External channel only | Wallet fetches elsewhere | Compatible as *wallet policy*, not protocol guarantee |
| C — Unknown by design | Honest default | **Chosen** |

### Chosen policy

1. If the **offered** OpenPGP certificate contains RFC 9580 revocation flags for KROOT/KSIGN → reject (`IDENTITY_REVOKED`), `revocation.status = revoked`.  
2. Otherwise → `revocation.status = unknown` (`policy = unknown_by_design`).  
3. Absence of revocation material is **not** proof that keys are live.  
4. No new OpenPGP revocation invention; no escrowed-revocation protocol in V1.  
5. Offline KROOT / network-absent wallets: still `unknown`.

---

## Resource Limits

Documented in `reference/limits.py` — all **PROVISIONAL**:

| Limit | Max | Reason |
|-------|-----|--------|
| domain | 253 B | DNS practical |
| identifier | 320 B | BIP-353 margin |
| IdentityDocument | 16 KiB | Parse DoS |
| PaymentBinding | 8 KiB | Parse DoS |
| method count | 32 | UI/CPU |
| raw_tx | 100_000 B | Enforced in parser |
| merkle branch depth | 32 | Enforced in verifier |
| proof bundle | 256 KiB | Fetch DoS |

Large enough for BIP-353 + OpenPGP fingerprints/signatures; not a hard interoperability freeze yet.

---

## Result Structure

Bitcoin path (conceptual):

```json
{
  "payment_verified": null,
  "identity_verified": null,
  "identity_anchored": true,
  "bitcoin": {
    "transaction_valid": true,
    "inclusion_proof_valid": true,
    "header_context": "trusted",
    "status": "anchor_confirmed",
    "extracted_commitment": "...",
    "computed_txid": "..."
  },
  "freshness": { "status": "unknown" },
  "revocation": { "status": "unknown", "policy": "unknown_by_design" },
  "trust": { "status": "first_seen" },
  "rollback_resistance": "not_provided",
  "human_verified": false
}
```

Principle: **never** collapse to a single “verified human” boolean.

---

## Security Claim Matrix (post-M6)

| Property | V1 |
|----------|----|
| Identity signature authenticity | **PROVEN** |
| KROOT → KSIGN binding | **PROVEN** |
| Payment destination binding | **PROVEN** |
| Identity commitment (Candidate A) | **PROVEN** |
| Transaction → txid | **PROVEN** |
| txid → Merkle inclusion (claimed header) | **PROVEN** |
| OP_RETURN → commitment | **PROVEN** |
| Header chain / best-chain validity | **CONTEXT-DEPENDENT** |
| Reorg resistance | **NOT PROVIDED** |
| Freshness | **NOT PROVIDED** |
| Rollback resistance | **NOT PROVIDED** |
| Split-view resistance | **NOT PROVIDED** |
| Human identity | **NOT PROVIDED** |
| KROOT compromise resistance | **NOT PROVIDED** |
| KSIGN compromise resistance | **NOT PROVIDED** |
| Revocation | **UNKNOWN BY DESIGN** (honor if present) |
| DoS resistance | **NOT PROVIDED** / **bounded (provisional)** |
| Privacy guarantee | **NOT PROVIDED** |

---

## Regression

| Suite | Result |
|-------|--------|
| M1 `test/test_vectors.py` | PASS |
| M4 bitcoin / payment / e2e | PASS |
| M5 adversarial (70) | PASS (J2/J3 now BLOCKED) |
| F-J2 / F-J3 regression | PASS |
| M6 `test/m6/test_verification_hardening.py` | PASS (26) |
| Regtest reorg | PASS |
| Frozen vector checksums | Unchanged |

---

## FROZEN

- M1–M4 test vectors  
- Candidate A semantics  
- PaymentBindingV1 exclusions (amount/label/message)  
- `human_verified = false` from protocol alone  
- Dual-binding verification rule (`raw_tx` authority)  
- Multi-B353ID = reject ambiguous  
- Freshness unknown / rollback not provided  
- Revocation UNKNOWN BY DESIGN  

## PROVISIONAL

- OP_RETURN tag `B353ID` + version `0x01`  
- Resource limit numbers  
- Confirmation policy thresholds (wallet-local)  

## OPEN

- Transparency / freshness protocol  
- KROOT recovery / social recovery  
- Mandatory revocation transport  
- Multi-anchor selection policy  
- Lightning canonical method  
- Privacy hardening  
- Final BIP text  
- PSBT / full UI  

---

## M6 STATUS

# **PASS**

### FROZEN
See above.

### PROVISIONAL
OP_RETURN wire; numeric DoS caps.

### OPEN
Transparency/freshness; recovery; privacy; BIP draft.

### REQUIRED CHANGES BEFORE BIP

1. Keep F-J2/F-J3 binding in all implementations (not optional).  
2. Publish the claim matrix as normative non-goals (freshness, rollback, human identity, KROOT theft).  
3. Require wallets to set `header_context` honestly.  
4. Decide whether provisional OP_RETURN tag becomes normative or is reassigned.

---

## SINGLE NEXT STEP

**M7 = final protocol freeze** (wire + claims + limits), **not** transparency/freshness and **not** another open-ended audit.

Rationale: the only CRITICAL implementation hole from M5 is closed; remaining gaps are explicitly NOT PROVIDED. Freezing V1 text/vectors now prevents claim drift. Transparency/freshness should be a **separate** optional layer (post-V1 or BIP companion), not a gate that reopens V1 scope.

Do **not** auto-draft the BIP until that freeze milestone explicitly authorizes it.

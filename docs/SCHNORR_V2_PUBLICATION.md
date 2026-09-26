# Experimental Schnorr V2 — Publication & Reproducibility (Phase 15)

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

Companion to the repository [`README.md`](../README.md).  
Aimed at an **external researcher** with no project chat history.

---

## External researcher path

```text
README.md
  → SCHNORR_V2_MINI_SPEC.md
  → vectors/schnorr/ (+ README)
  → reference/schnorr_v2/
  → independent/schnorr_v2/
  → SCHNORR_V2_THREAT_MODEL.md
  → SCHNORR_V2_SECURITY_CLAIMS.md
  → SCHNORR_V2_ADVERSARIAL_REVIEW.md
  → SCHNORR_V2_INDEPENDENT_REVIEW.md
  → SCHNORR_V2_SPEC_AUDIT.md
  → SCHNORR_V2_VECTOR_RECONCILIATION.md
```

Internal “Phase 0…14” labels are **historical lab milestones**, not conceptual
prerequisites for reading the experiment.

---

## Snapshot traceability

| Tag | Commit role | Notes |
|-----|-------------|-------|
| `schnorr-v2-experimental-1` | First experimental freeze | Immutable; includes legacy `V2-VALID-001` |
| `schnorr-v2-experimental-2` | Reconciled experimental snapshot | Hardened dual-binding; `V2-VALID-002` / `003`; independent reproduction landed *after* tag as follow-on commits on the branch |

Tags are **annotated**, **not GPG-signed**.

---

## Vector traceability (selected)

| Vector | Snapshot relevance | Purpose | Expected (hardened) |
|--------|--------------------|---------|---------------------|
| `V2-VALID-001` | **LEGACY** `experimental-1` | Crypto + logical OP_RETURN | Crypto PASS; `identity_anchored=false` without `bitcoin_proof` |
| `V2-VALID-002` | `experimental-2` reconciled | Full dual-binding | `identity_anchored=true` |
| `V2-VALID-003` | reconciled | Non-anchored valid crypto | `identity_anchored=false` |
| `V2-INVALID-*` | both eras | Negative cases | reject with error codes |
| `V2-BTC-*` | post F-S1 | Dual-binding BTC matrix | accept/reject per fixture |

Checksums:

* Historical freeze set: `vectors/schnorr/SCHNORR_V2_CHECKSUMS.txt`  
* Reconciled set: `vectors/schnorr/SCHNORR_V2_RECONCILED_CHECKSUMS.txt`  

Checksums prove **artifact integrity**, not protocol security.

---

## Environment pinning

| Dependency | Version | Role |
|------------|---------|------|
| Python | 3.14.x lab / 3.11+ OK | Reference & tests |
| Node.js | v22.x | Independent reproduction |
| embit | 0.8.0 | BIP-340 in Python reference |
| @noble/curves | 1.8.1 | BIP-340 in JS |
| @noble/hashes | 1.7.1 | SHA-256 / utils in JS |
| reference.cbor | in-tree | Canonical CBOR subset |

Libraries are **not** claimed “audited” merely by use.

---

## Reproducibility matrix

Verified in Phase 15 from a fresh clone + fresh dependency install:

| Artifact | Command | Expected | Reproduced |
|----------|---------|----------|------------|
| V1 CBOR smoke | `PYTHONPATH=. python3 test/test_cbor.py` | PASS | PASS |
| V1 vectors smoke | `PYTHONPATH=. python3 test/test_vectors.py` | PASS | PASS |
| V2 vectors | `test/schnorr_v2/test_vectors.py` | PASS | PASS |
| V2 BTC proofs | `test/schnorr_v2/test_bitcoin_proof.py` | PASS | PASS |
| V2 checksums | `sha256sum -c vectors/schnorr/SCHNORR_V2_*.txt` | PASS | PASS |
| V1 checksums | `sha256sum -c vectors/M7_CHECKSUMS.txt` | PASS | PASS |
| Independent JS | `npm ci && npm run bip340 && npm run verify` | PASS | PASS |
| Adversarial | `test_adversarial.py` + `npm run adversarial` | PASS | PASS |
| Spec-only harness | `audit/schnorr_v2_spec_only/verify_from_spec.py` | PASS | PASS |

---

## Artifact completeness

| Artifact | Present |
|----------|---------|
| Mini-spec / design notes | yes |
| Vectors + checksums | yes |
| Reference implementation | yes |
| Independent implementation | yes |
| Security claims / threat model / adversarial / spec audit | yes |
| Reproduction instructions | README + this file |
| LICENSE | BSD-2-Clause |
| SECURITY.md / CONTRIBUTING.md | **absent** (experimental; documented in README) |

---

## Terminology

| Term | Means in this repo |
|------|-------------------|
| identity / identity root | Cryptographic key identity (pubkey), not human identity |
| continuity | Same root bytes historically anchored for domain+identifier |
| identity_anchored | Dual-binding under **supplied** header — not Bitcoin finality |
| PASS (tests) | Property held for tested cases — not a security proof |

---

## Document consistency notes (Phase 15)

| Item | Class | Note |
|------|-------|------|
| Mini-spec banner “NOT A FROZEN PROTOCOL” vs experimental snapshot tags | DOCUMENTATION | Means **not normatively frozen**; experimental tags are reproducible lab snapshots |
| Older roadmap text “Phase 7 CURRENT” | DOCUMENTATION | Superseded by README researcher path (fixed in Phase 15 README rewrite) |
| `identity_anchored` definition | Consistent | Dual-binding in mini-spec, claims, threat model, vectors README |

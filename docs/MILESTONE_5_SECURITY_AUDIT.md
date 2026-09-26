# Milestone 5 — Full Adversarial Security Audit

**Status:** PASS WITH LIMITATIONS  
**Date:** 2026-09-26  
**Scope:** Attack M1–M4 only. No BIP text. No silent vector mutation.  
**Harness:** `test/security/test_adversarial.py` → `test/security/m5_results.json`  
**Reorg:** `test/security/test_regtest_reorg.py` → `test/security/m5_reorg_result.json`  
**Frozen vectors:** `vectors/valid/*`, `vectors/m4/*` unchanged (checksums verified).

---

## Executive Summary

M5 ran a reproducible adversarial suite across cross-layer, OpenPGP, payment binding, CBOR, domain separation, Bitcoin inclusion, reorg, privacy, and trust-model attacks.

**Result of suite:** 70/70 attack cases recorded; 0 harness failures.  
**Outcomes observed:** BLOCKED / DETECTED / ACCEPTED / AMBIGUOUS — all classified.

The protocol **does** bind payment destinations to a signed IdentityDocument under KROOT→KSIGN, bind Candidate A to Bitcoin via `H(domain||identifier||KROOT)`, and reject cross-context replay of identifiers. It **does not** provide freshness, absolute finality, human identity, or resistance to full KROOT compromise. The reference Bitcoin inclusion verifier has a **HIGH** completeness gap: it trusts `proof.commitment` without binding `raw_tx → txid → OP_RETURN`.

M5 passes because guarantees and non-guarantees are now precise. Claims that overstate protection must be marked **NOT PROVIDED** (or fixed before any BIP).

---

## Threat Model

| Actor | Controls | Does not control |
|-------|----------|------------------|
| DNS attacker | BIP-353 TXT / DNSSEC path | KROOT, Bitcoin history |
| Hosting attacker | `.well-known` / CDN | KROOT, DNS (alone) |
| KSIGN thief | Current signing subkey | KROOT offline; prior Bitcoin preimage without KROOT |
| KROOT thief | Certification key matching anchor | Recovery/revocation out-of-band (OPEN) |
| Proof forger | Malicious Proof Bundle bytes | Valid OpenPGP sig under real keys; honest wallet header sync |
| Chain observer | Public OP_RETURN scan | Cleartext email (commitment is hash) |

**Out of scope for V1:** transparency log, social recovery, PSBT UX, mainnet finality myths, KYC/human attestation.

---

## Attack Matrix

| Part | Attack | Outcome | Class |
|------|--------|---------|-------|
| A1 | DNS payment ≠ identity payment | DETECTED | — |
| A2 | DNS+hosting, fake KROOT | DETECTED | — |
| A3 | Hosting-only mutation | BLOCKED | — |
| A4 | DNS-only divergence | DETECTED | — |
| B1 | KSIGN compromise | ACCEPTED | known limitation |
| B2 | Fake KSIGN | DETECTED | — |
| B3 | KROOT mismatch | DETECTED | — |
| B4 | Wrong signature | BLOCKED | — |
| B5/B6 | Revoked keys | AMBIGUOUS | needs change |
| B7 | Old valid KSIGN | ACCEPTED | known limitation |
| C1 | KROOT compromise | ACCEPTED | out of threat model |
| D1 | Stale IdentityDocument | ACCEPTED | known limitation |
| D2 | Sequence without resign | BLOCKED | — |
| D3 | Old Bitcoin anchor | ACCEPTED | known limitation |
| E1–E4 | Cross-context replay | BLOCKED | — |
| F* | Payment binding mutations | BLOCKED/DETECTED/ACCEPTED† | †amount/label excluded by design |
| G* | Non-canonical CBOR | BLOCKED | — |
| H/I | Domain / hash separation | BLOCKED/DETECTED | — |
| J1 | Wrong commitment field | DETECTED | — |
| J2 | Wrong OP_RETURN in raw_tx | **ACCEPTED** | **vulnerability** |
| J3 | Wrong tx Merkle | **ACCEPTED** | **vulnerability** |
| J4 | Wrong header (prev) | ACCEPTED | known limitation (wallet headers) |
| J5/J6 | Bad Merkle | DETECTED | — |
| J7 | Wrong height | ACCEPTED | known limitation |
| J8/J9 | Orphan / reorg API | DETECTED | — |
| K | Confirmation ladder | DETECTED | — |
| L | Multiple anchors | AMBIGUOUS | known limitation |
| M | Multi-method payment | BLOCKED/DETECTED | Lightning OPEN |
| N | Unknown versions | BLOCKED | — |
| O | Type confusion | BLOCKED | — |
| P | Resource exhaustion | AMBIGUOUS | needs change |
| Q | Privacy / correlation | ACCEPTED | known limitation |
| R | Trust ≠ crypto | ACCEPTED | by design |
| S* | Composed attacks | matches parts above | — |

---

## Cross-Layer Attacks

### A1 — DNS + Identity mismatch — DETECTED
Malicious DNS payment vs signed `payment_hash` → `PAYMENT_BINDING_MISMATCH`.

### A2 — DNS + Hosting, no KROOT — DETECTED
Forged IdentityDocument under unrelated KROOT fails `ROOT_KEY_MISMATCH` (and cannot match Candidate A anchor for the real KROOT).

### A3 — Hosting only — BLOCKED
Unsigned / mutated IdentityDocument → `INVALID_IDENTITY_SIGNATURE`.

### A4 — DNS only — DETECTED
Same binding check as A1. DNS alone cannot forge continuity; it can only diverge payment until binding fails.

---

## OpenPGP Attacks

| ID | Result | Note |
|----|--------|------|
| B1 | ACCEPTED | Compromised KSIGN can publish new payment/sequence; continuity of KROOT still holds |
| B2 | DETECTED | `SIGNING_KEY_MISMATCH` |
| B3 | DETECTED | `ROOT_KEY_MISMATCH` |
| B4 | BLOCKED | Valid OpenPGP shape alone is insufficient |
| B5/B6 | AMBIGUOUS | Verifier can honor revoked flags if present; no mandatory revocation channel |
| B7 | ACCEPTED | No “currently authorized” oracle beyond cert contents + freshness unknown |

**Distinction enforced:** OpenPGP signature validity ≠ identity continuity authority ≠ human trust.

---

## KROOT Compromise

### C1 — ACCEPTED (fundamental)

If the attacker owns the **same** KROOT whose fingerprint is in Candidate A:

| Bitcoin anchor prevents | Bitcoin anchor does **not** prevent |
|-------------------------|-------------------------------------|
| Substituting a *different* KROOT while reusing the historical commitment | Creating new KSIGN′ + IdentityDocument′ under the stolen KROOT |
| Pretending a foreign root matches the on-chain commitment | Redirecting payment bindings signed by attacker-controlled KSIGN′ |
| | Looking like the legitimate owner cryptographically |

**Do not claim Bitcoin protects against full KROOT compromise.** It freezes the root fingerprint for that (domain, identifier) pair; whoever holds that root is the protocol identity.

---

## Replay / Rollback

### D1 — Old IdentityDocument — ACCEPTED
`identity_verified=true` possible; `freshness=unknown`. V1 has no log of “latest sequence”.

### D2 — Sequence field
Unsigned mutation of `sequence` → signature fails (BLOCKED).  
**What sequence guarantees:** monotonic intent *inside* a signed document; ordering aid for *consumers that already have history*.  
**What sequence does not guarantee:** freshness, global latest, anti-rollback against a withholding attacker.

### D3 — Old Bitcoin anchor — ACCEPTED
Candidate A still matches forever for that KROOT. Without transparency / multi-anchor policy, “current” is undefined → `freshness=unknown`.

---

## Payment Binding

| Mutation | Effect |
|----------|--------|
| Destination / scriptPubKey | Changes `payment_hash` |
| Amount / label / message | **Not in** PaymentBindingV1 (by design) |
| Method reorder / duplicate | Canonicalised / collapsed |
| Non-canonical CBOR | Rejected |
| Same semantic ↔ one encoding | Enforced |
| Different semantic ↔ same encoding | Rejected via type+destination keying |

Lightning (`lno`) payload not frozen — type string participates in the hash (no silent alias to `bitcoin`).

---

## CBOR

Deterministic CBOR rejects: non-shortest ints, trailing bytes, duplicate keys, unsorted keys, indefinite-length maps/bytes. Semantic maps encode uniquely.

---

## Domain Separation

Separators are pairwise distinct:

- Identity: `BIP353-IDENTITY\x00\x01`
- Payment: `BIP353-IDENTITY/PAYMENT/v1`
- Anchor: `BIP353-IDENTITY/ANCHOR/v1`

Variants (`\x00\x02`, bare string, `/PAYMENT`, `/ANCHOR`) produce different messages. `PAYMENT_HASH` is rejected as Bitcoin `IDENTITY_COMMITMENT` (`ANCHOR_MISMATCH`).

---

## Bitcoin Anchor

| Attack | Outcome |
|--------|---------|
| J1 Wrong commitment field | DETECTED `WRONG_COMMITMENT` |
| **J2 Wrong OP_RETURN in raw_tx** | **ACCEPTED** (gap) |
| **J3 Merkle for other txid** | **ACCEPTED** (same gap) |
| J4 Wrong prev_hash, valid merkle | ACCEPTED by *isolated* verifier — wallet must supply trusted headers |
| J5/J6 Bad merkle | DETECTED |
| J7 Wrong height | ACCEPTED (metadata unbound) |
| J8 Orphaned flag | DETECTED `ORPHANED_ANCHOR` |
| J9 Reorg API + real regtest | DETECTED (see below) |

**Provisional OP_RETURN:** `B353ID || 0x01 || 32-byte commitment` — still PROVISIONAL.

**Inclusion claim honesty:** cryptographic inclusion is only as strong as verifying that the Merkle-proven transaction *contains* the commitment. Reference `verify_bitcoin_anchor_proof` currently does **not** check `sha256d(raw_tx)==txid` nor parse OP_RETURN from `raw_tx` → **F-J2 / F-J3**.

---

## Bitcoin Reorg

Real Knots/Core regtest (`test_regtest_reorg.py`):

1. Broadcast OP_RETURN anchor → mine block A → proof `anchor_included` / confirmed under policy.  
2. `invalidateblock` A → tip rewinds.  
3. With `known_orphaned=True` → `anchor_orphaned`, `anchor_included=false`.  
4. Mine longer competing branch B.

**Semantics:** wallet tip knowledge drives orphan detection. Isolated proof bytes cannot observe reorgs. **No absolute finality.**

Confirmation ladder (Part K): `anchor_seen` (0 conf) / `anchor_included` (≥1) / `anchor_confirmed` (≥ policy) / `anchor_orphaned`.

---

## Multiple Anchors

Same commitment in multiple txs: **AMBIGUOUS**.

1. Allowed? Yes (nothing forbids republishing).  
2. Second replaces first? **No rule.**  
3. All valid? Any with valid inclusion may verify.  
4. Newer meaningful? Not without policy/log.  
5. Multiple chains? Possible under reorg; wallet chooses tip.  
6. Verifier choose? **Not specified** — document “any valid inclusion of Candidate A suffices”.

---

## Versioning

| Input | Behavior |
|-------|----------|
| Identity `version` 0 or 2 | `UNSUPPORTED_VERSION` reject |
| Unknown payment method type | Accepted as opaque bytes in binding (type|dest hashed); Lightning form OPEN |
| Unknown OP_RETURN version | Parse fails / no commitment |
| Unknown Identity fields | Not forward-compatible in V1 reference (strict signed CBOR object) |

---

## Resource Exhaustion

No hard caps in reference verifier for document size, method count, merkle depth, `raw_tx` size. Large lists encode (P2 ≈ 6KB for 1000 methods). **DoS resistance NOT PROVIDED** for naive implementations → recommend caps in M6.

---

## Privacy

On-chain: `H(domain || identifier || KROOT_fingerprint)` (Candidate A).

| Question | Answer |
|----------|--------|
| Correlation | Yes, if observer knows or guesses inputs |
| Rotation of payment/KSIGN | Does not change commitment (privacy-friendly for rotation; linkable forever to that triple) |
| Chain surveillance | Chronology of first/republished anchors |
| Enumeration | Bruteforce of known directories/identifiers |
| Linking payments | Via published IdentityDocuments off-chain, not via commitment alone |
| Cleartext email on-chain | No |

Privacy optimization deferred — **do not change protocol in M5**.

---

## Trust Model

| State | Source |
|-------|--------|
| FIRST_SEEN | Default after crypto verify |
| USER_TRUSTED | Explicit user action |
| EXTERNAL_ATTESTATION | Out-of-band |
| UNTRUSTED | User/policy |

`human_verified` remains **false** from protocol alone even when payment+identity+anchor all true (R1, M4 e2e).

---

## Composed Attacks

| Attack | Result |
|--------|--------|
| S1 DNS+hosting, no KROOT | DETECTED (A2) |
| S2 Hosting + KSIGN | ACCEPTED until revoke (B1) |
| S3 DNS + stale document | ACCEPTED if payment still matches; else binding DETECTED |
| S4 KSIGN + payment change | ACCEPTED (B1) |
| S5 KROOT + new KSIGN + payment | ACCEPTED (C1) |
| S6 Old anchor + new document same KROOT | ACCEPTED (Candidate A design) |
| S7 Valid proof, wrong name | BLOCKED |
| S8 Valid identity, wrong payment | DETECTED |

---

## Security Claims

| # | Property | Verdict |
|---|----------|---------|
| 1 | Authenticity (signed IdentityDocument under bound KSIGN) | **PROVEN** |
| 2 | Key continuity (KROOT binding + Candidate A) | **PARTIALLY PROVEN** (not vs KROOT theft) |
| 3 | Payment binding | **PROVEN** (destinations; not amount/label) |
| 4 | Bitcoin anchoring (commitment construction) | **PROVEN** |
| 5 | Bitcoin inclusion (honest SPV end-to-end) | **PARTIALLY PROVEN** — **reference verifier incomplete (F-J2)** |
| 6 | Replay resistance (cross-context) | **PROVEN** |
| 7 | Rollback resistance (stale documents) | **NOT PROVIDED** |
| 8 | Freshness | **NOT PROVIDED** |
| 9 | Split-view resistance | **NOT PROVIDED** (needs transparency / multi-path) |
| 10 | Human identity | **NOT PROVIDED** |
| 11 | DNS compromise resistance | **PARTIALLY PROVEN** (binding catches payment divergence; not stale-but-consistent pairs) |
| 12 | Hosting compromise resistance | **PROVEN** without keys |
| 13 | KSIGN compromise resistance | **NOT PROVIDED** (until revoke) |
| 14 | KROOT compromise resistance | **NOT PROVIDED** |
| 15 | Privacy | **NOT PROVIDED** as hard guarantee |
| 16 | DoS resistance | **NOT PROVIDED** (no caps) |

---

## Findings

### F-J2 / F-J3 — HIGH — vulnerability
- **Attack:** Mutate OP_RETURN in `raw_tx` or present Merkle-valid *other* txid while `proof.commitment` matches expected.  
- **Precondition:** Malicious Proof Bundle; wallet uses reference verifier as-is.  
- **Expected:** Reject (`TXID_MISMATCH` / `WRONG_TX_COMMITMENT`).  
- **Actual:** ACCEPTED.  
- **Impact:** Overstated “anchor included” if wallet does not separately bind tx body.  
- **Mitigation:** Require `sha256d(raw_tx)==txid` and OP_RETURN parse == commitment.  
- **Classification:** vulnerability (verifier completeness) — **required before BIP**.

### F-B1 — HIGH — known limitation
KSIGN compromise redirects payment until revocation/rotation by KROOT.

### F-D1 — HIGH — known limitation
Stale IdentityDocument verifies; `freshness=unknown`.

### F-C1 — CRITICAL severity label, out_of_threat_model
Full KROOT compromise = full protocol identity takeover. Bitcoin does not save you.

### F-B5 — MEDIUM — needs_change
Revocation transport not mandatory in Proof Bundle.

### F-J4 — MEDIUM — known limitation
Isolated proof does not validate header chain / PoW / tip.

### F-L1 — LOW — known limitation
Multi-anchor selection undefined.

### F-P1 — LOW — needs_change
Missing size caps.

### F-Q1 — INFORMATIONAL — known limitation
Commitment linkability if preimage known.

---

## Critical Findings

1. **F-J2 / F-J3:** Inclusion verification gap in reference code — must fix for honest “Bitcoin inclusion” claim.  
2. **Freshness / rollback NOT PROVIDED** — UI must never imply “current”.  
3. **KROOT compromise NOT PROVIDED** — recovery/revocation is OPEN, not magic from OP_RETURN.

---

## Recommendations (for M6 triage; not implemented here)

1. Bind `raw_tx ↔ txid ↔ OP_RETURN commitment` in `verify_bitcoin_anchor_proof`.  
2. Specify Proof Bundle revocation / freshness channel (or explicitly forever-`unknown`).  
3. Document size limits for wallet parsers.  
4. Keep `human_verified=false` invariant in all UI specs.  
5. Leave OP_RETURN tag PROVISIONAL until inclusion binding + claim text are honest.

---

## Part U — Critical UI Question

**Biggest wallet lie:** Showing a single green “Verified identity / safe to pay” (or “Human verified”) because crypto checks passed — collapsing payment binding, key continuity, inclusion depth, freshness, and human trust into one badge.

### Required UI states (separable)

| State | Meaning |
|-------|---------|
| PAYMENT VERIFIED | DNS semantic payment matches signed `payment_hash` |
| IDENTITY VERIFIED | OpenPGP + KROOT→KSIGN + document checks |
| IDENTITY ANCHORED | Commitment matches Candidate A construction |
| ANCHOR INCLUDED | Tx with commitment in a wallet-trusted block |
| KEY REVOKED | Revocation observed (when channel exists) |
| FRESHNESS UNKNOWN | Always unless a freshness layer exists |
| FIRST SEEN | No prior user trust |
| USER TRUSTED | Explicit local trust |

**Never** display **HUMAN VERIFIED** from BIP-XXX alone.

---

## SECURITY STATUS

# **PASS WITH LIMITATIONS**

### PROVEN
Authenticity under bound keys; payment destination binding; Candidate A commitment; cross-context separation; deterministic CBOR; domain separators; orphan API when wallet knows tip.

### NOT PROVIDED
Freshness; rollback resistance; split-view resistance; human identity; KSIGN/KROOT compromise resistance; privacy-as-guarantee; DoS caps; multi-anchor currentness; absolute finality.

### VULNERABILITIES
**F-J2 / F-J3** — reference inclusion verifier does not bind transaction body to commitment (HIGH).

### REQUIRED CHANGES (before BIP)
1. Fix inclusion proof verification binding.  
2. Align all public claims with the matrix above (especially freshness and KROOT).  
3. Decide revocation transport (mandatory field vs explicit AMBIGUOUS).

### FROZEN
M1–M4 test vectors (`vectors/valid`, `vectors/m4`, interop matrices). Candidate A semantics. PaymentBindingV1 exclusions (amount/label). `human_verified=false` from protocol.

### PROVISIONAL
OP_RETURN wire: `B353ID || 0x01 || commitment`. Confirmation policy thresholds (wallet-local).

### OPEN
Transparency / freshness layer; recovery after KROOT loss; privacy hardening; Lightning canonical method; multi-anchor policy; size limits; revoked-key distribution.

---

## Single recommendation for M6

**M6 must close the Bitcoin inclusion verification gap (`raw_tx → txid → OP_RETURN == commitment`) and freeze an explicit V1 stance on freshness/revocation (channel or forever-`unknown`) so the BIP cannot claim properties M5 proved are NOT PROVIDED or only PARTIALLY PROVEN.**

Do not draft the final BIP until those claim boundaries are honest in code and text.

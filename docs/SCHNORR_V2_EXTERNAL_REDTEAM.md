# Experimental Schnorr V2 — External Red-Team / Reviewer Simulation (Phase 16)

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

| Field | Value |
|-------|--------|
| Snapshot under review | `schnorr-v2-experimental-2` (**not modified**) |
| Mode | Hostile external reviewer simulation |
| Protocol changes | **NONE** (review only) |

This document does **not** trust prior phase conclusions a priori. It challenges
public claims against stated evidence and assumptions.

---

## Blind first pass (public docs only)

Sources for initial critique: README, mini-spec, security claims, threat model,
`vectors/schnorr/`, reproduction instructions.

**First impressions (hostile):**

* Status labeling (experimental / non-normative / not official BIP) is **hard to miss**.  
* `identity_anchored` is easy to **over-read** as “Bitcoin-finalized identity” unless the
  reader follows links to dual-binding + header_context.  
* Mini-spec still uses **PROVEN** in §12 while claims use **TESTED** — a careful
  reviewer will flag terminology inflation.  
* V2 is not self-contained: CBOR/PaymentBinding/Merkle “reuse V1” forces reading
  `PROTOCOL_FREEZE_V1.md`.  
* Independent JS + vectors are strong for **reproduction**, weak if marketed as
  **audit** (README currently avoids that mistake).

---

## Claim challenge

| Claim (as commonly read) | Evidence | Assumptions | Counterexample / bound | Verdict |
|--------------------------|----------|-------------|------------------------|---------|
| Root→signing authenticity | TaggedHash(SUBKEY)+BIP-340; vectors | Honest BIP-340; canonical CBOR | Compromised root forges new bindings | **SUPPORTED WITH ASSUMPTIONS** |
| Identity document authenticity | TaggedHash(IDENTITY)+BIP-340 | Valid binding; time window checked | Compromised signing forges docs in window | **SUPPORTED WITH ASSUMPTIONS** |
| Payment binding integrity | TaggedHash(PAYMENT) vs doc | PB is the object hashed | DNS alone can diverge from signed PB | **SUPPORTED WITH ASSUMPTIONS** (doc↔PB only) |
| Anchor commitment integrity | TaggedHash(ANCHOR) | Correct fields | Wrong domain/id/root → different digest | **SUPPORTED** |
| Bitcoin inclusion (`identity_anchored`) | Dual-binding AND; V2-BTC-* | **Supplied** header; non-witness txid | Fake/untrusted header; reorg; no PoW in V2 | **SUPPORTED WITH ASSUMPTIONS** (bounded) |
| Continuity | Anchored ∧ root equality | `identity_anchored` true | Not freshness / non-compromise | **SUPPORTED** (narrow) |
| Cross-tag / B353S2≠B353ID separation | Distinct tags/tags; tests | Implementer uses exact ASCII | Confused implementer mixing V1/V2 | **SUPPORTED WITH ASSUMPTIONS** |
| Freshness / rollback / split-view / human ID / finality / revocation / privacy / non-compromise | Explicit NOT PROVIDED | — | — | **NOT SUPPORTED** (correctly) |

Stronger reformulations (“anchored ⇒ final”, “continuity ⇒ current control”) are
**false**. Original bounded claims remain coherent.

---

## Strongest credible criticisms (by property)

### Root→signing
**Criticism:** Authenticity is only as strong as root-key custody; binding does not
include domain, so a root could authorize a signing key used across contexts unless
IdentityDocument binds domain.  
**Response in docs:** Domain is in IdentityDocument; F-S4 accepted.  
**Verdict:** Design trade-off, not a silent overclaim.

### Identity document
**Criticism:** Valid signature ≠ current organizational approval; expiry is optional
discipline (`now` check).  
**Verdict:** Bounded correctly; replay within window remains possible.

### Payment binding
**Criticism:** “Payment verified” sounds like payment happened.  
**Verdict:** Claims explicitly deny settlement; wording risk is UX/doc, not crypto.

### Anchor / Bitcoin inclusion
**Criticism:** Verifier-supplied headers make “anchored” a **local proof check**, not
consensus finality. Synthetic regtest fixtures do not demonstrate mainnet economics.  
**Verdict:** Claims say TESTED + no PoW/finality — **correctly bounded** if readers
obey that text.

### Continuity
**Criticism:** Name suggests ongoing identity; definition is only root byte equality
after anchoring.  
**Verdict:** Terminology hazard; definition is precise when read.

### Cross-tag separation
**Criticism:** Depends on implementers not “helpfully” accepting B353ID as B353S2.  
**Verdict:** Spec forbids; tests cover confusion cases.

---

## Topic reviews (hostile Q&A)

### KROOT
Historical dual-binding remains checkable; **future** authenticity under compromised
root is lost; current control and human identity are **not** shown by an old anchor.

### KSIGN
Attacker forges IdentityDocuments (and new payment hashes) in the binding validity
window; cannot authorize new signing keys or rewrite past Bitcoin anchors; root can
bind a replacement signing key.

### Bitcoin
`identity_anchored` = dual-binding under **supplied** header. Trusted vs untrusted
`header_context` is wallet policy. PoW, confirmations, reorg, finality = **outside** V2.

### DNS / BIP-353
V2 proves **document↔PaymentBinding hash consistency**, not DNSSEC and not settlement.
Ambiguous casual speech (“proves the payment”) would be rejected by a careful reviewer;
written claims avoid it.

### Continuity / replay / split-view / revocation
Match threat model: no rollback compare; replay valid until expiry; no split-view
detection; cryptographic validity ≠ revocation-fresh current validity.

### Payment substitution
Different destinations → different PB → different `payment_hash` → breaks identity
signature match. Anchor does **not** freeze payment destinations — a reviewer should
insist that continuity ≠ frozen payments (threat model already separates these).

### Cross-protocol
B353ID / B353S2 and TaggedHash tags separate contexts; accepting cross-context objects
would be an implementation bug, not a V2 feature.

### Canonical CBOR
With V1 subset + RFC 8949 + UTF-8 fatal decode, reasonable “equivalent” encodings that
differ in bytes are **not** treated as equal (by design). Residual risk: implementers
using permissive CBOR libraries.

### Implementation residual risk
Despite tests: unmodeled witness/segwit tx variants, exotic script forms, integer edge
cases in non-protocol fields, dependency bugs in embit/@noble, dict-API footguns (F-S2),
and packaging/transport formats for a “proof bundle” not fully specified as a single
wire object in the mini-spec.

### Independent implementation
Reproduction evidence only — README/claims correctly avoid “formal verification” /
“security audit” language.

### Spec-only / third-party implementability
A third party can implement from mini-spec + V1 CBOR/Payment/Merkle incorporation +
BIP-340/RFC 8949 + vectors. Remaining friction: dual-document reading, Merkle/header
not fully restated, legacy VALID-001 semantics.  
**THIRD-PARTY IMPLEMENTABILITY = PASS** (with assumptions).

---

## Review findings

| ID | Sev | Claim / area | Criticism | Evidence | Impact | Mitigation now | Recommendation |
|----|-----|--------------|-----------|----------|--------|----------------|----------------|
| RT-L1 | LOW | Mini-spec §12 “PROVEN” vs claims “TESTED” | Terminology inflation | Mini-spec vs SECURITY_CLAIMS | Reader overconfidence | Claims/threat model clearer | Align wording in a future doc-only edit |
| RT-L2 | LOW | F-S2 dict verify API | Wire bytes not sole API surface | Open finding F-S2/ADV-L1 | Malleability via non-canonical dict paths if misused | Tests use fixtures | Prefer CBOR-bytes verify API (FUTURE DESIGN / hardening) |
| RT-I1 | INFO | `identity_anchored` casual reading | Sounds like finality | Dual-binding text + threat model | Mis-marketing risk | Explicit NOT PROVIDED finality | Keep README bounds prominent |
| RT-I2 | INFO | Continuity naming | Sounds like freshness | Narrow definition | Misuse in product copy | Documented | Prefer “root continuity (bytes)” in UIs |
| RT-I3 | INFO | V2-VALID-001 legacy expected | Stale `identity_anchored` field | Reconciliation docs | Naive fixture misuse | LEGACY labeling | Keep; never rewrite freeze |
| RT-I4 | INFO | Spec incorporation by reference | CBOR/PB/Merkle in V1 freeze | Mini-spec + PROTOCOL_FREEZE | Incomplete solo mini-spec | Spec audit notes | Add explicit “required reading” box (doc-only) |
| RT-I5 | INFO | Tags not GPG-signed | Supply-chain of git tags | `git tag --verify` | Integrity of *which* commit | Annotated tags + checksums | Optional signed tags later |
| RT-I6 | INFO | ADV-L2 negative `created_at` builder | Builder accepts before CBOR | Adversarial review | Not a wire bypass | CBOR rejects | Harden builders later |
| RT-I7 | INFO | F-S4 binding omits domain | Cross-context signing key | By design | Domain bound in IdentityDocument | Accepted | Keep explicit |
| — | — | Prior CRITICAL/HIGH/MEDIUM | None found that falsify bounded claims | — | — | — | — |

**New CRITICAL/HIGH/MEDIUM that falsify stated claims: 0**

Open severity after review (including prior open items, not double-counting RT-L2 with F-S2):

| Severity | Open count |
|----------|------------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 2 (F-S2/ADV-L1, ADV-L2) |
| INFORMATIONAL | 3+ (F-S4/ADV-I*, plus RT-I* as additional notes) |

RT-I* are reviewer notes; they do not raise protocol severity beyond documentation.

---

## Future design only (not implemented)

* Freshness / challenge-response  
* Rollback / sequence enforcement  
* Revocation channel  
* Split-view / transparency  
* New anchor or rotation protocols  
* CBOR-bytes-only verify API  

---

## Reviewer conclusions

| Question | Answer |
|----------|--------|
| Would I implement a third copy from the public repo? | **Yes** (with V1 CBOR/Payment/Merkle docs + BIP-340) |
| Would I trust claims as written? | Crypto binding claims: **SUPPORTED WITH ASSUMPTIONS**; NOT PROVIDED list: **accurate**; unbounded marketing readings: **reject** |
| Coherence vs correction needed? | **A — internally coherent experimental protocol** |
| Specification ready (experimental)? | **YES** |
| Reproduction ready? | **YES** |
| Security claims bounded? | **YES** |
| Experimental status clear? | **YES** |

No protocol correction required to resolve a false **stated** claim. Remaining issues are
documentation terminology, residual implementation hygiene, and inherent threat-model
non-goals.

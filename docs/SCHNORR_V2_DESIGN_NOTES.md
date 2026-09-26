# Experimental Schnorr Identity Root — Design Notes

**EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1**

| Field | Value |
|-------|--------|
| Working title | Experimental Schnorr Identity Root |
| Branch | `experiment/schnorr-identity-v2` |
| Phase | 7 — Experimental freeze gate |
| Status | Experimental snapshot freeze (non-normative) |
| Normative authority | **None.** V1 remains `BIP-XXX.md` / `PROTOCOL_FREEZE_V1.md` |
| Decisions document | [`docs/SCHNORR_V2_MINI_SPEC.md`](SCHNORR_V2_MINI_SPEC.md) (**EXPERIMENTAL**, not frozen) |

This document does **not** define a normative protocol version 2.  
Phase 1 captured inventory and open questions.  
Phase 2 **experimental decisions** live in `SCHNORR_V2_MINI_SPEC.md` — still **non-normative** and **not frozen**.

Schnorr is **not** asserted to be automatically “better” than OpenPGP.  
Trade-offs (ecosystem interop vs wallet-native primitives) remain open.

---

## 1. Scope

**In scope for this experiment (eventually):**

* Replace the OpenPGP trust root (`KROOT` / `KSIGN` / certificates / detached sigs) with BIP-340 Schnorr keys and signatures.
* Keep the payment-binding and Bitcoin-anchor *ideas* aligned with V1’s security goals where possible.
* Document what can be reused vs what must be redesigned.

**Out of scope for Phase 1:**

* Any implementation code.
* Any frozen V2 wire format.
* Any change to V1 files, vectors, checksums, or tests.
* HD derivation paths (`m/353'/…`).
* Full revocation / freshness / transparency designs.

---

## 2. Relationship with V1

| Topic | Statement |
|-------|-----------|
| V1 status | **FROZEN** — do not modify |
| Compatibility | This experiment is **not** claimed compatible with V1 Proof Bundles |
| Versioning | If a Schnorr design is ever specified, it REQUIRES a **new** protocol version and **new** domain separators / tags — never reuse V1 identity separators |
| Shared goals | Authenticate BIP-353 payment destinations under a durable crypto root; optional historical Bitcoin commitment; honest claim matrix |
| Non-goals shared with V1 | Human/legal identity; freshness; rollback resistance; KROOT-compromise resistance; absolute finality |

V1 OpenPGP artifacts (`vectors/`, `reference/`, `test/`, `BIP-XXX.md`) remain the publication baseline on `main`.

---

## 3. Reusable Components

Inventory of V1 pieces relative to a hypothetical Schnorr-based experiment.  
Labels: **REUSE** | **REUSE WITH CHANGES** | **REDESIGN**

| Component | Label | Short justification |
|-----------|--------|---------------------|
| Canonical CBOR subset (RFC 8949 core deterministic rules) | **REUSE** | Independent of signature algorithm; malleability rules still apply. |
| Domain / identifier UTF-8 equality rules | **REUSE** | Same BIP-353 identifier model; no OpenPGP dependency. |
| PaymentBindingV1 structure & construction from BIP-321 semantics | **REUSE** | Payment object is not an identity mechanism; keep separation. |
| Payment hash formula *shape* (`SHA256(sep \|\| CanonicalCBOR(PaymentBinding))`) | **REUSE WITH CHANGES** | Semantic reuse yes; **separator bytes must be new** if/when specified (never V1 `…/PAYMENT/v1`). |
| BIP-353 / BIP-321 resolution pipeline | **REUSE** | Upstream of this experiment; unchanged. |
| Payment verification model (`payment_verified`) | **REUSE** | Compare resolved semantics → binding → hash → identity document field. |
| Bitcoin OP_RETURN *idea* (tag \|\| version \|\| 32-byte commitment) | **REUSE WITH CHANGES** | Same dual-binding goals; **tag/version must not collide with V1 `B353ID\|\|0x01`** if ever specified. |
| BitcoinAnchorProof dual binding (`raw_tx`→txid + `raw_tx`→commitment) | **REUSE** | Algorithmic; independent of identity crypto. |
| Merkle proof under claimed header | **REUSE** | Same inclusion math. |
| Header context (`trusted` / `untrusted`) | **REUSE** | Wallet-local policy, not identity-layer. |
| Confirmation / reorg model | **REUSE** | Still policy + `known_orphaned`; not absolute finality. |
| `payment_verified` claim semantics | **REUSE** | Same meaning and non-claims. |
| `identity_anchored` claim semantics | **REUSE WITH CHANGES** | Same *meaning*; commitment input changes if root representation changes. |
| `continuity_verified` claim semantics | **REUSE WITH CHANGES** | Same *meaning* (same root historically for domain+identifier); root object type changes. |
| `identity_verified` claim semantics | **REDESIGN** | Must be redefined around Schnorr verify + binding object, not OpenPGP cert checks. |
| Security claim matrix structure | **REUSE** | Keep PROVEN / NOT PROVIDED / CONTEXT-DEPENDENT honesty. |
| Limitations / threat-model structure | **REUSE** | Same ceiling: no freshness, no human ID, no root-compromise resistance. |
| IdentityDocument map *layout idea* (version, domain, identifier, times, payment_hash, sequence, signature) | **REUSE WITH CHANGES** | Keys that hold OpenPGP fingerprints / OpenPGP sig blob must be redesigned. |
| Identity domain separator V1 (17-byte `BIP353-IDENTITY\x00\x01`) | **REDESIGN** | Must **not** reuse. New separator / tagged-hash scheme required for any future spec. |
| OpenPGP stack | **REDESIGN** | Entirely replaced in this experiment’s hypothesis. |

---

## 4. Components to Replace

| V1 OpenPGP-dependent piece | Likely experimental replacement concept |
|----------------------------|----------------------------------------|
| **KROOT** (OpenPGP primary / certification key) | Long-term **root public key** (hypothesis: 32-byte BIP-340 x-only pubkey) — *not frozen* |
| **KSIGN** (OpenPGP signing subkey) | Operational **signing public key** (hypothesis: 32-byte BIP-340 x-only pubkey) — *not frozen* |
| **RFC 9580 certificates** | Explicit key material in the Proof Bundle (raw pubkeys + binding object); no certificate packet stream |
| **OpenPGP subkey binding (`0x18` / `0x19`)** | Conceptual **`SubkeyBinding`** object: canonical CBOR statement that `signing_pubkey` is authorized by `root_pubkey`, authenticated by a BIP-340 signature under the root |
| **OpenPGP detached binary signature** (IdentityDocument key 9) | Conceptual **BIP-340 signature** (hypothesis: 64 bytes) over a V2-only signature input |
| **OpenPGP revocation** (type 0x20 etc.) | **FUTURE DESIGN** — no mechanism in Phase 1; problem recorded in §7 Q7 |
| **OpenPGP fingerprints** (20- or 32-byte fpr as continuity/id fields) | Direct pubkey bytes and/or a hash of the pubkey in documents/anchors — **open** (see Q4–Q5) |

---

## 5. Proposed Architecture

**Research hypothesis only — not a specification.**

```
                    BIP-353
                       │
                    DNSSEC
                       │
                       ▼
                Payment Resolution
                       │
                       ▼
                PaymentBinding
                       │
                       ▼
              IdentityDocument (experimental)
                       │
              ┌────────┴────────┐
              │                 │
        Root Pubkey         Signing Pubkey
          BIP-340              BIP-340
              │                 │
              └───────┬─────────┘
                      │
                Schnorr Binding
                      │
                      ▼
                Bitcoin Anchor
```

Intended separation (same as V1 intent):

* PaymentBinding authenticates **destinations**, not identity.
* Identity layer authenticates **who authorizes those destinations**.
* Bitcoin anchor records a **historical commitment** to (domain, identifier, root), not every payment rotation.

---

## 6. Open Design Questions

### Q1 — Root key

**Question:** What exact object is the identity root?

**Working hypothesis (not frozen):**

```text
root_pubkey = 32-byte BIP-340 x-only public key
```

**Still open:**

* Store raw x-only bytes in documents, or a typed envelope?
* Is the root allowed to sign IdentityDocuments directly (no separate signing key)?
* How is the root compared for continuity (byte equality vs hash)?

No decision in Phase 1.

---

### Q2 — Signing key / SubkeyBinding

**Conceptual flow (hypothesis only):**

```text
root_pubkey
    ↓
SubkeyBinding  (canonical CBOR + BIP-340 sig by root)
    ↓
signing_pubkey
```

**Fields to decide later (not designed here):**

| Topic | Notes |
|-------|--------|
| Signed message | Likely `sep \|\| CanonicalCBOR(SubkeyBindingBody)` with a **new** separator / BIP-340 tagged hash — never V1 separators |
| Domain separation | Prefer exploring BIP-340 tagged hashes *or* a new ASCII/byte prefix family — undecided |
| Canonical CBOR | Reuse V1 CBOR rules for the binding body |
| Key representation | Likely 32-byte x-only for root and signing pubkeys |
| Signature representation | Likely 64-byte BIP-340 `(R,s)` |
| Time validity | Optional `valid_from` / `valid_until` — undecided whether mandatory |
| Sequence | Optional monotonic field — same anti-pattern warning as V1: **not** anti-rollback by itself |

**Do not implement in Phase 1.**

---

### Q3 — IdentityDocument signature

**V1:** OpenPGP detached binary over  
`IdentityDomainSeparator_V1 || CanonicalCBOR(SignedIdentityDocumentV1)`.

**Experimental direction:** BIP-340 Schnorr over a **new** input, conceptually:

```text
message =
  DOMAIN_SEPARATOR_EXPERIMENTAL
  ||
  CanonicalCBOR(SignedIdentityDocumentExperimental)
```

or a BIP-340 tagged-hash equivalent of that statement.

**Hard rule:** never reuse V1 identity domain separator bytes  
`BIP353-IDENTITY || 0x00 || 0x01`.

Exact tag strings, CBOR key map, and whether signature is key `9` or external — **undecided**.

---

### Q4 — Key representation

| Object | BIP-340 usual size | Implications (analysis only) |
|--------|--------------------|------------------------------|
| x-only public key | 32 bytes | Fits CBOR `bstr`; no OpenPGP version branching (20 vs 32 fpr) |
| Signature | 64 bytes | Fixed length; no “semantic packet verify” across libraries |
| Secret key | 32 bytes | Implementation concern only; never in Proof Bundle |

**Open:** whether documents store pubkeys raw, or `HASH(pubkey)` for anchors only, or both.

Wire format **not frozen**.

---

### Q5 — Bitcoin Anchor

V1 AnchorMessage Candidate A commits to:

```text
version || domain || identifier || kroot_fingerprint
```

**Experimental options to compare (none selected):**

| Option | Sketch | Pros | Cons |
|--------|--------|------|------|
| **A** | `domain + identifier + root_pubkey` (32 B) | Direct continuity on the key itself | Larger CBOR; pubkey reuse in multiple layers |
| **B** | `domain + identifier + HASH(root_pubkey)` | Stable 32-byte field; hides nothing cryptographically strong but uniform size | Extra hash step; must define hash/tag |
| **C** | Typed construction (versioned map with explicit `key_alg` / `root_id`) | Extensible | More design surface; easier to bikeshed |

**Also open:** whether experimental anchors may share V1 OP_RETURN tag space (almost certainly **no** — collision risk) or need a distinct tag/version.

No selection without later justification.

---

### Q6 — PaymentBinding

**Question:** Can PaymentBinding V1 be reused *semantically*?

**Phase 1 answer:** **Yes, semantically** — the experiment should preserve:

```text
BIP-353 resolution
        ↓
semantic payment object
        ↓
payment hash
        ↓
identity document
```

PaymentBinding must **not** become an identity mechanism.

If an experimental protocol is ever specified:

* Prefer keeping the same payment method model (`bitcoin` + `scriptPubKey` bytes, sort/collapse rules).
* Use a **new** payment domain separator string/bytes (do not reuse V1 `BIP353-IDENTITY/PAYMENT/v1`) so experimental hashes cannot be confused with V1.

---

### Q7 — Revocation

**Problem (documented only):**

Without OpenPGP certificates, how does a verifier learn that a `root_pubkey` or `signing_pubkey` is compromised/revoked?

V1 already treats revocation as **unknown by design** unless offered OpenPGP revocation material proves revoked.

**Mark:** **FUTURE DESIGN**  
No revocation protocol in this phase. Do not invent transparency logs or mandatory revocation channels here.

---

### Q8 — HD keys

Paths such as `m/353'/…` and BIP-43 purpose registration:

**OUT OF SCOPE** for this experiment phase (and not to be designed or implemented now).

---

## 7. Security Questions

Questions any Schnorr-root design must still answer (same honesty bar as V1):

1. **DNS-only compromise:** If the verifier already requires a known `root_pubkey`, does payment hash mismatch still reject attacker destinations? (Expected: yes, if identity layer holds.)
2. **First contact:** Without prior trust/anchor, can an attacker present DNS + a self-consistent Schnorr Proof Bundle? (Expected: yes — same as V1 first-seen limitation.)
3. **Root compromise:** Does Schnorr change the ceiling? (**No** — still NOT PROVIDED.)
4. **Binding forgery:** Can `signing_pubkey` authorize documents without a valid root signature over the binding object? (Must be impossible under the eventual verify rules.)
5. **Cross-protocol confusion:** Can V1 OpenPGP material or V1 domain separators be mixed into experimental verify paths? (Must be rejected by version/separator discipline.)
6. **Anchor ambiguity:** Multi-commitment outputs — keep V1’s reject-ambiguous rule?
7. **Batch verification:** Possible future *implementation* benefit of Schnorr; **not** a Phase 1 security claim and not a reason to oversell the experiment.

---

## 8. Explicit Non-Goals

This phase / experiment does **not** aim to:

* Modify or “prepare” V1 for Schnorr.
* Claim V1/V2 compatibility.
* Ship wallet HD integration (`m/353'`).
* Provide freshness, rollback resistance, or transparency.
* Provide human/legal identity.
* Provide a complete revocation system.
* Assert Schnorr superiority over OpenPGP on security guarantees alone.
* Freeze any experimental wire format in Phase 1.

---

## 9. Phase 2 decision pointer

Phase 2 decisions (root key, Option B binding, tags, IdentityDocument fields, payment hash tagging, anchor Option A, continuity, failures, claim matrix, MVP scenario, future vector IDs) are recorded in:

**[`docs/SCHNORR_V2_MINI_SPEC.md`](SCHNORR_V2_MINI_SPEC.md)**

That file is **EXPERIMENTAL / NON-NORMATIVE / NOT FROZEN / NOT PART OF V1**.

### Next Phase

**No further protocol development** unless a new experimental phase is explicitly opened.

Snapshot tag (local): `schnorr-v2-experimental-1`  
Meaning: reproducible experimental state — **not** a standard, **not** production-ready.


---

## Appendix — Invariant checklist (Phase 1)

| Check | Required |
|-------|----------|
| V1 files modified | NO |
| V1 vectors modified | NO |
| V1 checksums modified | NO |
| V1 tests modified | NO |
| V1 protocol modified | NO |
| Protocol V2 implemented | NO |
| Wire format V2 frozen | NO |
| Cryptography V2 frozen | NO |

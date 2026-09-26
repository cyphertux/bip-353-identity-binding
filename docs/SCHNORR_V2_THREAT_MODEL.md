# Experimental Schnorr V2 — Threat Model & Security Boundary (Phase 14)

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP — NOT PRODUCTION-READY**

| Field | Value |
|-------|--------|
| Snapshot | `schnorr-v2-experimental-2` (**unchanged**) |
| Mini-spec | [`SCHNORR_V2_MINI_SPEC.md`](SCHNORR_V2_MINI_SPEC.md) |
| Claims | [`SCHNORR_V2_SECURITY_CLAIMS.md`](SCHNORR_V2_SECURITY_CLAIMS.md) |
| Adversarial | [`SCHNORR_V2_ADVERSARIAL_REVIEW.md`](SCHNORR_V2_ADVERSARIAL_REVIEW.md) |
| Spec audit | [`SCHNORR_V2_SPEC_AUDIT.md`](SCHNORR_V2_SPEC_AUDIT.md) |

Terminology mapping (V1 names used in attack narratives → V2 objects):

| Narrative name | V2 object |
|----------------|-----------|
| KROOT | `root_pubkey` / root secret |
| KSIGN | `signing_pubkey` / signing secret |

This document does **not** add mechanisms. It checks that claims match boundaries.

---

## 1. Assets

| Asset | What it is |
|-------|------------|
| Root identity | 32-byte BIP-340 x-only `root_pubkey` (cryptographic identity root) |
| Signing identity | 32-byte `signing_pubkey` authorized by SubkeyBinding under root |
| Payment binding | Canonical PaymentBindingV1 → `payment_hash` in IdentityDocument |
| Anchor commitment | `TaggedHash(TAG_ANCHOR, CanonicalCBOR(AnchorMessage))` |
| Identity continuity | Byte equality of presented root vs historically anchored root |
| Bitcoin inclusion evidence | Dual-binding proof: raw_tx ↔ txid↔Merkle↔header **and** unique B353S2 |

---

## 2. Adversaries

| ID | Adversary | Capabilities (assumed) | Not assumed |
|----|-----------|------------------------|-------------|
| A1 | Network attacker | Observe/modify transit; MITM | Break BIP-340; forge DNSSEC |
| A2 | Malicious DNS operator | Forge/alter DNS answers (no/weak DNSSEC) | Break Schnorr; rewrite Bitcoin history |
| A3 | Malicious BIP-353 publisher | Publish chosen BIP-353 records under controlled names | Control victim’s root secret |
| A4 | Compromised KSIGN | Knows signing secret | Knows root secret (unless also A5) |
| A5 | Compromised KROOT | Knows root secret | Rewrite past Bitcoin blocks |
| A6 | Malicious Bitcoin data provider | Supply fake `raw_tx` / headers / Merkle to a verifier | Force wallet’s best-chain view if header is `trusted` by wallet |
| A7 | Chain reorg adversary | Cause/benefit from reorg orphaning an anchor block | Break dual-binding math on a still-valid header |
| A8 | Replay attacker | Replay old valid bundles | Mint new signatures without keys |
| A9 | Split-view attacker | Show different proofs/headers to different verifiers | Global transparency log (none in V2) |
| A10 | Malicious verifier | Lie about verification results to users | Change what honest verification of bytes yields |
| A11 | Malicious identity publisher | Publishes coherent forged “identity” they fully control | Prove human/legal legitimacy via V2 alone |

---

## 3. Security property matrix

| Property | Attacker | Protected? | Condition | Limitation |
|----------|----------|------------|-----------|------------|
| Root authenticity (binding under root) | A1–A3, A4, A6–A11 | **Yes** (crypto) | BIP-340 Verify(root, TaggedHash(SUBKEY,…), sig) | Lost if A5 |
| Signing-key authenticity (doc under signing) | A1–A3, A5*, A6–A11 | **Yes** (crypto) | Binding + Verify(signing, TaggedHash(IDENTITY,…), sig) | *A5 can authorize new signing; A4 forges docs |
| Payment binding integrity | A1, A2†, A6–A11 | **Yes** (crypto vs document) | `payment_hash` = TaggedHash(PAYMENT, PB) | †DNS can change *resolved* destinations without a matching signed doc |
| Anchor integrity (commitment bytes) | A1–A4, A8–A11 | **Yes** (crypto) | Commitment binds domain+identifier+root | A5 can create *new* anchors; history not erased |
| Continuity | — | **Narrow yes** | `identity_anchored` ∧ root bytes equal | Not freshness / non-compromise |
| Freshness | A8 | **No** | — | **NOT PROVIDED** |
| Replay resistance | A8 | **Partial** | `expires_at` / binding expiry if checked | No nonce/challenge; old docs valid until expiry |
| Rollback resistance | A8 | **No** | sequence optional, not compared | **NOT PROVIDED** |
| Split-view resistance | A9 | **No** | — | **NOT PROVIDED** |
| Human identity | A11 | **No** | — | **NOT PROVIDED** |
| Current key control | A4, A5 | **No** | — | **NOT PROVIDED** |
| Revocation freshness | A4, A5 | **No** | No revocation channel | **NOT PROVIDED** |
| Bitcoin finality | A6, A7 | **No** | Dual-binding ≠ best-chain/PoW | **NOT PROVIDED** |
| DNS integrity | A2, A3 | **No** (in V2) | Depends on DNSSEC/BIP-353 outside V2 | V2 binds payments *when* PB matches doc |
| Privacy | A1 | **No** | Keys/domains in clear documents | **NOT PROVIDED** |

---

## 4. KROOT compromise (A5)

Assume attacker knows root secret.

| Question | Answer |
|----------|--------|
| Create new KSIGN / SubkeyBinding? | **Yes** |
| Create new IdentityDocument? | **Yes** (authorize signing key, then sign or authorize a signing key they hold) |
| Create new Bitcoin anchor? | **Yes** (new commitment for chosen domain/id/root; publish tx if they can) |
| Impersonate *future* identity under that root? | **Yes** |
| Alter *historical* Bitcoin anchors already confirmed? | **No** (cannot rewrite past chain data; can only create competing *new* history) |
| Historical authenticity of old dual-binding proofs? | **Still cryptographically checkable** as past evidence |
| Future authenticity under same root? | **Lost** to the attacker |

V2 **must not** claim a historical anchor protects against **future** root compromise.

---

## 5. KSIGN compromise (A4)

Assume attacker knows signing secret; root secret intact.

| Question | Answer |
|----------|--------|
| Forge IdentityDocuments under that signing key? | **Yes** (until binding expires / root rotates binding) |
| Change payment binding in a new doc? | **Yes** (new `payment_hash` + new signature) |
| Create future identities under *new* root? | **No** |
| Authorize a *new* signing key? | **No** (needs root) |
| Modify historical Bitcoin anchors? | **No** |
| Protected by KROOT | Historical SubkeyBinding still proves root once authorized that signing key; root can bind a replacement signing key |
| Lost | Authenticity of documents signed by the compromised signing key for the binding’s validity window |

---

## 6. DNS / BIP-353 compromise (A2 / A3)

| Question | Answer |
|----------|--------|
| Redirect *resolved* payment (DNS only)? | **Yes** if DNSSEC/BIP-353 resolution is broken or unused |
| Produce new valid IdentityDocument? | **No** without signing/root secrets |
| Change historical anchor? | **No** |
| Conflicting payment binding vs signed doc? | Verifier with both: `payment_verified` fails if PB ≠ document hash |

Separate: **DNSSEC-protected resolution** (external) vs **untrusted DNS**.  
V2 does **not** supply DNS security; it binds destinations **inside** a signed document when presented.

---

## 7. Payment redirection

```text
same root + signing
different scriptPubKey in PaymentBinding
→ different CanonicalCBOR → different payment_hash
→ old IdentityDocument signature no longer matches (or hash mismatch)
```

| Layer | Effect of destination change |
|-------|------------------------------|
| Unsigned DNS resolution | May change what wallets *resolve today* |
| Signed IdentityDocument | Invalid unless re-signed with new `payment_hash` |
| Historical anchor | Commits to root/domain/id — **not** to payment destinations |

Historically anchored **identity root** ≠ historically frozen **payment destination**.

---

## 8. Bitcoin reorg (A7)

Anchor included in block H; later H orphaned.

| V2 knows | V2 does not know / claim |
|----------|---------------------------|
| Dual-binding under *supplied* header still math-checks | That header is on the best chain |
| `identity_anchored` relative to that proof object | Absolute finality |

`identity_anchored` ≠ final. Confirmation / orphan handling is **wallet-local** (`header_context`), **NOT PROVIDED** as protocol finality.

---

## 9. Malicious block header (A6)

| Context | Meaning |
|---------|---------|
| `trusted` | Wallet asserts header is on its accepted chain (PoW/linkage per **wallet policy**) |
| `untrusted` | Only checks txid→Merkle→**this** header; must not treat as best-chain inclusion |

Fake header with matching Merkle for a fake/conflicting tx can fool an **untrusted** or overly trusting verifier. V2’s claim is inclusion under the **supplied** header, not global consensus truth.

---

## 10. Split-view (A9)

Verifier A sees anchor proof X; verifier B sees Y.

V2 has **no** transparency log, gossip, or cross-verifier consistency check.

**SPLIT-VIEW RESISTANCE = NOT PROVIDED**

---

## 11. Replay (A8)

Old valid IdentityDocument + optional old anchor reused “today”.

| Mechanism | Protects? |
|-----------|-----------|
| BIP-340 signatures | Authenticity of *those bytes*, not “fresh now” |
| `created_at` / `expires_at` | Time window **if verifier checks `now`** |
| `sequence` | **No** protocol comparison |
| Bitcoin anchor | Historical inclusion evidence, not liveness |

Valid signature ≠ freshness. **Freshness = NOT PROVIDED.**

---

## 12. Rollback

Document sequence 5 later replaced by presentation of sequence 3.

V2 does **not** require monotonic sequence checks across documents.

**ROLLBACK RESISTANCE = NOT PROVIDED**

---

## 13. Revocation

| Question | Answer |
|----------|--------|
| Carry revocation state? | **No** |
| Fresh revocation info for verifier? | **No** |
| Old document remain cryptographically valid? | **Yes**, until expiry / policy outside V2 |

Cryptographic validity ≠ current organizational validity.  
**Revocation freshness = NOT PROVIDED.**

---

## 14. Human identity (A11)

“Who controls this key?”

V2 proves **key possession / signature authenticity**, not human, legal, or organizational identity.

**HUMAN IDENTITY = NOT PROVIDED**

---

## 15. Key rotation

`root` → `signing_A` then `signing_B` (new SubkeyBinding).

| Concept | Meaning in V2 |
|---------|----------------|
| Continuity | Same **root** bytes historically anchored for domain+identifier |
| Identity root | Still the root pubkey |
| Documents under signing_A | Remain verifiable as past statements if binding/doc time window allows |
| Compromised signing_A | Forges new docs as A until expiry; B is separately authorized by root |

No additional rotation protocol beyond new bindings/docs.

---

## 16. Malicious verifier (A10)

Protocol guarantees apply to **honest evaluation of bytes**.  
A malicious UI can display “verified” falsely.

**protocol correctness ≠ correct verifier implementation**

---

## 17. Malicious identity publisher (A11)

Fully coherent attacker-controlled identity.

| Can V2 prove… | Result |
|---------------|--------|
| Ownership of published keys | Possession via signatures only |
| Human / reputation / legitimacy | **No** |

Key possession ≠ real-world identity.

---

## 18. Payment / identity decoupling

| Scenario | Bound? |
|----------|--------|
| Same root, different payment binding | Different docs/`payment_hash`; root continuity unchanged |
| Same payment destination, different root | Unrelated identities; PB alone is not identity |

---

## 19. Anchor reuse / substitution

Commitment = TaggedHash(ANCHOR, {version, domain, identifier, root_pubkey}).

Copying an anchor from domain A / id A / root A into context B fails commitment match when fields differ (and B353S2 payload must match expected commitment).

Cross-domain substitution of the commitment bytes is **detected** by dual-binding check 4.

---

## 20. Cross-protocol attacks

| Separation | Role |
|------------|------|
| `B353ID` vs `B353S2` | V1 vs experimental V2 OP_RETURN |
| `TAG_SUBKEY` / `TAG_PAYMENT` / `TAG_IDENTITY` / `TAG_ANCHOR` | Distinct TaggedHash domains |
| V1 ASCII separators | Must not be reused |

A valid object in one tag/context is not a proof under another.

---

## 21. Claim rewriting (precise)

| Casual phrase | Precise meaning |
|---------------|-----------------|
| “Identity is verified” | Binding under root + IdentityDocument BIP-340 under signing + field rules succeed for presented bytes and `now` |
| “Payment is verified” | Recomputed `TaggedHash(TAG_PAYMENT, CanonicalCBOR(PB))` equals document `payment_hash` (and resolved semantics match PB when that pipeline is used) |
| “Identity is anchored” | Supplied `raw_tx` has SHA256d non-witness txid matching proof; Merkle proves that txid under **supplied** header; **exactly one** B353S2 output yields commitment equal to `TaggedHash(TAG_ANCHOR, CanonicalCBOR(AnchorMessage))` for presented domain/id/root — **not** Bitcoin finality |
| “Continuity verified” | `identity_anchored` and presented root equals root in that AnchorMessage |

---

## 22. Attack matrix

| Attack | Possible? | Detection | Protected property | Limitation |
|--------|-----------|-----------|--------------------|------------|
| KROOT compromise | Yes (future) | Out of band | Past dual-binding math still checks | Future authenticity lost |
| KSIGN compromise | Yes (docs) | Out of band / expiry | Root binding / new bindings | Forged docs in window |
| DNS compromise | Yes (resolution) | DNSSEC external; hash mismatch vs signed PB | Signed payment_hash | V2 ≠ DNSSEC |
| Payment redirect (unsigned) | Yes | Compare to signed PB | Document-bound destinations | DNS alone unprotected by V2 |
| Replay | Yes (within expiry) | Expiry if checked | — | No freshness |
| Rollback | Yes | None in protocol | — | NOT PROVIDED |
| Reorg | Yes | Wallet chain view | Dual-binding under header | No finality |
| Fake header | Yes if trusted blindly | Wallet PoW/policy | Inclusion under supplied header only | Context-dependent |
| Split view | Yes | None | — | NOT PROVIDED |
| Revocation | N/A (absent) | None | — | NOT PROVIDED |
| Human impersonation | Crypto “identity” only | None for humans | Key authenticity | NOT PROVIDED |
| Key rotation | Supported via new binding | Verify new binding | Root continuity | Old signing risk until expiry |
| Cross-protocol reuse | Blocked by tags/tags | Verify fails | Domain separation | — |
| Anchor reuse (wrong context) | Blocked by commitment | Commitment mismatch | Anchor binding | — |

---

## 23. Security boundary

### V2 PROVES (under stated assumptions)

* Root → signing SubkeyBinding authenticity (BIP-340 + TaggedHash SUBKEY)  
* IdentityDocument authenticity under `signing_pubkey` (BIP-340 + TaggedHash IDENTITY)  
* PaymentBinding integrity vs document `payment_hash` (TaggedHash PAYMENT)  
* Anchor commitment binding of domain + identifier + root (TaggedHash ANCHOR)  
* Dual-binding inclusion under a **supplied** header + unique B353S2 match  
* Continuity as root byte equality **given** `identity_anchored`  
* Cross-tag / B353ID≠B353S2 domain separation for the above constructions  

### V2 DEPENDS ON

* BIP-340 correctness  
* Canonical CBOR + UTF-8 rules (RFC 8949 core subset / V1 reuse)  
* Correct TaggedHash tag strings  
* Bitcoin tx / Merkle / header serialization conventions used in proofs  
* Verifier `now` / expiry checks when freshness-of-window is desired  
* Wallet `header_context` policy for any chain-trust interpretation  
* DNSSEC / BIP-353 when claiming secure *resolution* (outside V2)  
* Honest verifier software for user-visible results  

### V2 DOES NOT PROVIDE

* Human / legal / organizational identity  
* Freshness / liveness of control  
* Rollback resistance  
* Split-view resistance  
* Absolute Bitcoin finality / reorg resistance  
* Revocation freshness  
* Root- or signing-key non-compromise  
* Privacy guarantees  
* DNS integrity by itself  
* Payment received / settled  

---

## 24. Consistency with other documents

| Source | Freshness / rollback / split-view / human / finality / compromise |
|--------|------------------------------------------------------------------|
| Mini-spec §12 | NOT PROVIDED — match |
| Security claims | NOT PROVIDED — match |
| Adversarial review | ADV-I2 rollback NOT PROVIDED — match |
| This threat model | Same — **no contradictions** |

---

## 25. Open findings (re-check)

| ID | Open? | Security relevance | Threat-model conflict? |
|----|-------|--------------------|------------------------|
| F-S2 / ADV-L1 (dict verify API) | Yes LOW | Impl robustness | No |
| ADV-L2 (negative created_at builder) | Yes LOW | Builder hygiene; wire rejects | No |
| ADV-I1 (non-merkle header fields) | Yes INFO | Matches no-PoW claim | No |
| ADV-I2 (rollback) | Yes INFO | Matches NOT PROVIDED | No |
| ADV-I3 / F-S4 (binding omits domain) | Yes INFO | Domain in IdentityDocument | No |

Not closed artificially.

---

## 26. Protocol changes

**None.** Documentary threat model only. Future protocol work (revocation, freshness, transparency) would need an explicit later phase.

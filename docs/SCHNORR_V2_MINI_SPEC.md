# Experimental Schnorr Identity Root — Mini-Spec (Phase 2)

**EXPERIMENTAL**  
**NON-NORMATIVE**  
**NOT PART OF V1**  
**NOT A FROZEN PROTOCOL**

| Field | Value |
|-------|--------|
| Branch | `experiment/schnorr-identity-v2` |
| Phase | 2 — Mini-spec decisions |
| Companion | `docs/SCHNORR_V2_DESIGN_NOTES.md` |
| Implementation | **None yet** (Phase 3) |
| Compatibility with V1 | **None claimed** |

This document records **experimental design decisions** for a future MVP.  
It is not a BIP, not authoritative over V1, and may change before any freeze.

Decisions below are marked **DECIDED (experimental)** or **OPEN**.

---

## 0. Design summary

| Topic | Status | Choice (short) |
|-------|--------|----------------|
| Root key | **DECIDED** | 32-byte BIP-340 x-only `root_pubkey`; identity = pubkey bytes |
| Root → signing | **DECIDED** | Option B: TaggedHash then BIP-340 Sign |
| Identity document | **DECIDED** | Minimal CBOR map; `sequence` optional |
| Identity signature | **DECIDED** | BIP-340 under `signing_pubkey` over TaggedHash(IDENTITY, …) |
| PaymentBinding | **DECIDED** | Reuse V1 **structure**; new V2 payment tagged hash |
| Bitcoin anchor | **DECIDED** | Option A: commit `root_pubkey` directly |
| Anchor commitment | **DECIDED** | BIP-340 TaggedHash with V2 ANCHOR tag (= 32-byte commitment) |
| Continuity | **DECIDED** | `presented root_pubkey == anchored root_pubkey` |
| Failure states | **DECIDED** | Minimal MVP set |
| HD / revocation / freshness | **OUT OF SCOPE** | — |

---

## 1. Root key

### DECIDED (experimental)

```text
root_pubkey = BIP-340 x-only public key = exactly 32 bytes
```

| Topic | Decision |
|-------|----------|
| Curve | secp256k1 |
| Representation | Raw 32-byte x-only public key (BIP-340), CBOR major type 2 (`bstr`) length 32 |
| Validation | Reject if length ≠ 32; reject if BIP-340 public-key lift / implied point is invalid (same rules as BIP-340 Verify key checks) |
| Relation to BIP-340 | Keys and signatures MUST conform to [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) |
| Cryptographic identity | **The identity root is `root_pubkey` itself** (byte-identical 32-byte value) |
| Key fingerprint / HASH(root) | **Not used** for MVP identity or continuity |

### Rationale

* Simplest separation: **key material = identity root object**; no parallel fingerprint namespace (V1 needed fingerprints because OpenPGP keys are large certificates).
* Continuity and document fields compare the same 32-byte value.
* `HASH(root_pubkey)` remains available later if privacy/size constraints appear; not needed for MVP.

### What constitutes “same identity root”

Byte equality of the 32-byte `root_pubkey` (after successful key validation).

---

## 2. Root → signing key binding

### Options compared

#### Option A — Prefix domain separator || CBOR, then Sign

```text
msg = DOMAIN_SEPARATOR || CanonicalCBOR(SubkeyBindingBody)
sig = SchnorrSign(root_sk, msg)
```

| Criterion | Assessment |
|-----------|------------|
| Domain separation | Depends on unique prefix bytes; easy to get wrong vs other ASCII protocols |
| Canonicalization | Yes, if CBOR rules reused |
| Replay / cross-context | OK **if** separator unique; weaker alignment with Bitcoin tagged-hash norms |
| Key substitution | Preventable if body includes both pubkeys |
| Cross-protocol | Higher confusion risk with ad hoc separators |
| Rotation | New binding object + new sig |
| Simplicity | High |
| BIP-340 | Valid (BIP-340 accepts arbitrary-length `msg`) but not idiomatic |
| Auditability | Fine, but two separator styles in one stack (ASCII prefix vs tagged) |

#### Option B — TaggedHash, then Sign

```text
binding_digest = TaggedHash(TAG_SUBKEY_BINDING, CanonicalCBOR(SubkeyBindingBody))
sig = SchnorrSign(root_sk, binding_digest)   # msg is 32 bytes
```

where BIP-340 `TaggedHash` is:

```text
TaggedHash(tag, msg) = SHA256( SHA256(tag) || SHA256(tag) || msg )
```

(`tag` = UTF-8/ASCII tag string bytes; `msg` = canonical CBOR bytes.)

| Criterion | Assessment |
|-----------|------------|
| Domain separation | Explicit BIP-340 tagged context |
| Canonicalization | Yes |
| Replay / cross-context | Distinct tags ⇒ distinct digests |
| Key substitution | Body must include `root_pubkey` and `signing_pubkey` |
| Cross-protocol | Matches Taproot/BIP-341 style; lower “proprietary separator” smell |
| Rotation | New binding + new signature under same root |
| Simplicity | One extra hash; still minimal |
| BIP-340 | Correct use of tagged hash + Sign/Verify |
| Auditability | High for Bitcoin reviewers |

#### Option C

Not introduced. No third construction was necessary for MVP.

### DECIDED (experimental): **Option B**

**Justification:** Domain separation should use the same primitive family wallets already trust for Taproot (BIP-340 tagged hashes), while BIP-340 Sign/Verify handles the Schnorr challenge hashing. Option A is cryptographically workable but invents a second separator style beside V1’s ASCII prefixes and beside BIP-340 tags — worse for audit and cross-protocol hygiene.

### SubkeyBinding body (experimental)

Canonical CBOR map, integer keys, **signed content only** (signature carried alongside):

| Key | Name | Type | MVP |
|-----|------|------|-----|
| 0 | `version` | uint | REQUIRED; experimental value **1** for this binding object |
| 1 | `root_pubkey` | bstr (32) | REQUIRED |
| 2 | `signing_pubkey` | bstr (32) | REQUIRED |
| 3 | `created_at` | uint (unix) | REQUIRED |
| 4 | `expires_at` | uint (unix) | REQUIRED; MUST be ≥ `created_at` |

Signature (not inside the signed map):

| Name | Type | MVP |
|------|------|-----|
| `binding_signature` | bstr (64) | REQUIRED — BIP-340 sig by `root_pubkey` |

```text
SubkeyBindingBody = CanonicalCBOR({0..4})
binding_digest    = TaggedHash(TAG_SUBKEY_BINDING, SubkeyBindingBody)
binding_signature = Sign(root_sk, binding_digest)     # 64 bytes
Verify(root_pubkey, binding_digest, binding_signature)
```

Verifier MUST check `root_pubkey` / `signing_pubkey` in the binding equal those claimed by the IdentityDocument (byte equality).

---

## 3. Tagged hash tags (experimental)

### DECIDED (experimental)

BIP-340 `TaggedHash(tag, msg)` with these **exact** ASCII tag strings (no trailing NUL):

| Constant | ASCII tag string | Len (bytes) | Context |
|----------|------------------|-------------|---------|
| `TAG_SUBKEY_BINDING` | `BIP353-IDENTITY/V2/SUBKEY-BINDING` | 34 | Root authorizes signing key |
| `TAG_IDENTITY` | `BIP353-IDENTITY/V2/IDENTITY` | 27 | Identity document authenticity |
| `TAG_PAYMENT` | `BIP353-IDENTITY/V2/PAYMENT` | 26 | Payment hash domain |
| `TAG_ANCHOR` | `BIP353-IDENTITY/V2/ANCHOR` | 25 | Anchor commitment |

**Never reuse V1 separators**, including:

* `BIP353-IDENTITY` \|\| `0x00` \|\| `0x01` (17-byte identity separator)
* `BIP353-IDENTITY/PAYMENT/v1`
* `BIP353-IDENTITY/ANCHOR/v1`

V2 tags intentionally include `/V2/` to reduce confusion with V1 strings.

---

## 4. BIP-340 message construction (precision)

BIP-340 `Sign(sk, msg)` / `Verify(pk, msg, sig)` take `msg` as an **octet string of arbitrary length**. Internally, BIP-340 absorbs `msg` into `hash_BIP0340/challenge(R \|\| P \|\| msg)`.

This experiment does **not** treat “BIP-340 signs a hash” as a vague slogan. For every application signature:

1. Build `payload = CanonicalCBOR(...)` (deterministic CBOR subset as in V1 rules).
2. Compute `msg32 = TaggedHash(TAG_*, payload)` → **exactly 32 bytes**.
3. Compute `sig = Sign(sk, msg32)` → **exactly 64 bytes**.
4. Verify with `Verify(pk, msg32, sig)`.

So application domain separation is **TaggedHash**; BIP-340’s own challenge tagged hash remains internal to the Schnorr scheme.

---

## 5. IdentityDocument (experimental)

### Field analysis

| Key | Name | Decision | Notes |
|-----|------|----------|-------|
| 0 | `protocol_version` | **REQUIRED** | MUST be `2` for this experiment |
| 1 | `domain` | **REQUIRED** | Same rules as V1 (non-empty; no `@`) |
| 2 | `identifier` | **REQUIRED** | MUST be consistent `…@domain` |
| 3 | `root_pubkey` | **REQUIRED** | Replace V1 `kroot_fingerprint` |
| 4 | `signing_pubkey` | **REQUIRED** | Replace V1 `ksign_fingerprint` |
| 5 | `created_at` | **REQUIRED** | Unix time |
| 6 | `expires_at` | **REQUIRED** | Unix ≥ `created_at` |
| 7 | `payment_hash` | **REQUIRED** | 32 bytes; see §6 |
| 8 | `sequence` | **OPTIONAL** | Not required for MVP; if present, uint; **not** anti-rollback |
| 9 | `signature` | **REQUIRED** on wire for a complete doc | **Not** part of signed CBOR |

V1 OpenPGP signature blob semantics → **REPLACE** with 64-byte BIP-340 signature.

### Signed map

```text
SignedIdentityDocument =
  CanonicalCBOR( map with keys {0,1,2,3,4,5,6,7} and key 8 if present )
  # key 9 excluded
```

Unknown keys outside the allowed set: **reject** (strict), same spirit as V1.

---

## 6. Identity document signature

### DECIDED (experimental)

| Item | Value |
|------|--------|
| Signing key | `signing_pubkey` / corresponding secret (not the root, unless root == signing — not the MVP default) |
| Signature length | Exactly **64** bytes (BIP-340) |
| Pubkey length | Exactly **32** bytes x-only |
| Message | `msg32 = TaggedHash(TAG_IDENTITY, SignedIdentityDocument)` |
| Signature | `Sign(signing_sk, msg32)` |
| Verify | `Verify(signing_pubkey, msg32, signature)` |

Order of operations for a verifier:

1. Parse document; reject non-canonical CBOR.
2. Validate pubkeys (32 bytes + BIP-340 lift rules).
3. Verify SubkeyBinding under `root_pubkey`; check pubkey fields match document.
4. Check `now` against `created_at`/`expires_at` per MVP policy (document expiry).
5. Recompute `payment_hash`; compare.
6. Compute `msg32`; verify identity signature under `signing_pubkey`.

---

## 7. PaymentBinding

### DECIDED (experimental)

* **Structure:** Reuse **PaymentBindingV1** semantics and CBOR shape (`version`, `methods[]` with `bitcoin` + `scriptPubKey` bytes, sort/collapse rules).
* **Do not** create PaymentBindingV2 unless a later normative difference appears.
* **Hash domain:** **New** — do **not** use V1 `BIP353-IDENTITY/PAYMENT/v1`.

```text
payment_hash = TaggedHash(
  TAG_PAYMENT,
  CanonicalCBOR(PaymentBindingV1)
)
```

Thus `payment_hash` is 32 bytes (TaggedHash output), same width as V1’s SHA256 payment hash, but **cryptographically separated** from V1.

PaymentBinding remains **not** an identity proof.

---

## 8. Bitcoin anchor

### Options compared

| | Option A: `root_pubkey` in anchor | Option B: `root_key_hash` in anchor |
|--|-----------------------------------|-------------------------------------|
| Size | +32 B pubkey in CBOR | +32 B hash |
| Continuity proof | Direct equality with document root | Equality of hashes; must define hash |
| Encoding mistakes | Wrong key fails openly | Hash mismatches can obscure which key was meant |
| Correlation | Same bytes as document | One-way; slight indirection |
| Simplicity | Higher | Extra constant to audit |
| Match V1 spirit | V1 used fingerprint of root; pubkey is the natural Schnorr analogue of “root id” | Closer to “always 32-byte opaque id” |

### DECIDED (experimental): **Option A**

```text
AnchorMessage = {
  0: version,          # uint, experimental 1 for this object
  1: domain,           # tstr
  2: identifier,       # tstr
  3: root_pubkey       # bstr 32
}
```

Rationale: continuity is literally “same root key”; no fingerprint layer; simplest audit path for MVP.

---

## 9. Anchor commitment

### DECIDED (experimental)

```text
identity_commitment = TaggedHash(
  TAG_ANCHOR,
  CanonicalCBOR(AnchorMessage)
)
```

* Output length: **32 bytes**.
* Not V1 `SHA256(ANCHOR_DOMAIN_SEPARATOR || …)`.
* Confusion with V1 commitments: prevented by different hash construction **and** different tag/content; experimental on-chain tag/version for OP_RETURN is **OPEN** for Phase 3 wiring (must not collide with V1 `B353ID||0x01` when implemented).

**OPEN (Phase 3):** exact OP_RETURN tag bytes for experimental anchors (must be distinct from V1).

---

## 10. Continuity model

### DECIDED (experimental)

```text
continuity_verified =
  identity_anchored
  AND (presented root_pubkey == root_pubkey in verified AnchorMessage)
```

Means **only**: the historically anchored root key bytes equal the presented root key bytes.

Does **not** mean: human control, non-compromise, latest key, or freshness.

Freshness: **NOT PROVIDED** (unchanged policy).

---

## 11. Failure states (MVP)

Minimal set (conceptual codes):

| Code | When |
|------|------|
| `UNSUPPORTED_VERSION` | `protocol_version ≠ 2` (or unknown binding/anchor version) |
| `INVALID_ROOT_PUBKEY` | Bad length / fails BIP-340 key checks |
| `INVALID_SIGNING_PUBKEY` | Bad length / fails BIP-340 key checks |
| `INVALID_SUBKEY_BINDING` | Binding CBOR/sig/field mismatch / expired binding |
| `INVALID_BIP340_SIGNATURE` | Low-level Schnorr verify failed (generic) |
| `INVALID_IDENTITY_SIGNATURE` | Identity `msg32` verify failed under signing key |
| `PAYMENT_BINDING_MISMATCH` | Recomputed payment hash ≠ document |
| `ANCHOR_MISMATCH` | Commitment / anchor fields disagree with presented root or proof |
| `IDENTIFIER_MISMATCH` / `INVALID_DOMAIN` | Same conceptual role as V1 |

`INVALID_BIP340_SIGNATURE` may be used internally; user-facing MVP may map binding vs identity failures to `INVALID_SUBKEY_BINDING` / `INVALID_IDENTITY_SIGNATURE`.

Do not expand taxonomy further in Phase 2.

---

## 12. Security claims (V2 MVP ceiling)

| Property | V2 MVP |
|----------|--------|
| Root signature authenticity (binding under root) | **PROVEN** if BIP-340 verify of binding succeeds |
| Root → signing key binding | **PROVEN** under Option B construction |
| Identity document authenticity | **PROVEN** if BIP-340 verify under `signing_pubkey` succeeds |
| Payment destination binding | **PROVEN** if `payment_hash` matches TaggedHash(PAYMENT, PaymentBinding) and BIP-353 semantics match binding |
| Bitcoin identity commitment | **PROVEN** if dual-binding inclusion proof validates for `TaggedHash(ANCHOR, AnchorMessage)` *(once OP_RETURN wiring exists)* |
| Historical continuity | **PROVEN** only as byte equality of rooted keys given `identity_anchored` |
| Freshness | **NOT PROVIDED** |
| Rollback resistance | **NOT PROVIDED** |
| Split-view resistance | **NOT PROVIDED** |
| Human identity | **NOT PROVIDED** |
| Root-key compromise resistance | **NOT PROVIDED** |
| Signing-key compromise resistance | **NOT PROVIDED** (binding allows rotation; theft of signing key still forges docs until expiry/rotation policy) |
| Revocation freshness | **NOT PROVIDED** |
| Privacy guarantee | **NOT PROVIDED** |

---

## 13. MVP demonstration scenario

```text
DNSSEC / BIP-353
      ↓
payment resolution
      ↓
PaymentBinding (V1 structure)
      ↓
payment_hash = TaggedHash(TAG_PAYMENT, CanonicalCBOR(PaymentBinding))
      ↓
root_pubkey / signing_pubkey (BIP-340)
      ↓
SubkeyBinding + binding_signature (Option B)
      ↓
IdentityDocument (protocol_version=2) + identity signature
      ↓
AnchorMessage with root_pubkey → identity_commitment
      ↓
Bitcoin anchor proof (experimental wiring in Phase 3)
      ↓
verification → payment_verified / identity_verified / identity_anchored / continuity_verified
```

**Target property (same class as V1):**  
An attacker who alters DNS-resolved destinations or IdentityDocument fields cannot produce a valid proof bundle without the corresponding Schnorr secret keys.

---

## 14. Minimum future test matrix

**Do not generate vectors in Phase 2.**

| ID | Intent |
|----|--------|
| `V2-VALID-001` | Valid doc + binding + payment + anchor |
| `V2-INVALID-001` | Signing key replaced without new binding |
| `V2-INVALID-002` | IdentityDocument mutated after signature |
| `V2-INVALID-003` | Anchor commitment for a different `root_pubkey` |

---

## 15. Explicit non-goals (still)

HD derivation (`m/353'/…`), revocation protocol, recovery, freshness, transparency log, batch verification, Lightning binding, PSBT, social recovery, multisig/threshold roots.

---

## 16. OPEN items deferred to Phase 3+

| Item | Why open |
|------|----------|
| Experimental OP_RETURN tag/version bytes | Need distinct on-chain tag from V1; no implementation yet |
| Whether `sequence` appears in first vectors | Optional field; MVP can omit |
| Binding object `version` numbering vs document `protocol_version` | Provisional (`binding version=1`, `protocol_version=2`) — revisit if confusing |
| Library choice for BIP-340 in reference code | Implementation detail |

If any DECIDED item above proves unjustifiable during implementation, revert it to OPEN in a follow-up note rather than silently changing V1 or shipping ambiguity.

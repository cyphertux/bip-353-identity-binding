# Experimental Schnorr V2 — Formal Specification / Protocol Audit (Phase 13)

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

| Field | Value |
|-------|--------|
| Audit mode | Specification-first |
| Current snapshot | `schnorr-v2-experimental-2` (**unchanged**) |
| Historical | `schnorr-v2-experimental-1` (**unchanged**) |
| Spec-only verifier | `audit/schnorr_v2_spec_only/` |

This audit does **not** claim formal verification or completeness.

---

## Method

1. Read `docs/SCHNORR_V2_MINI_SPEC.md`, design notes, security claims, adversarial review,
   and `docs/SCHNORR_V2_CBOR_UTF8.md`.  
2. Treat **explicitly referenced / reused** material as normative for reused pieces:
   BIP-340, RFC 8949 §4.2.1, and V1 `PROTOCOL_FREEZE_V1.md` §§2 / 7 / 11 where the
   mini-spec says “as in V1 rules” / “Reuse PaymentBindingV1” / “Merkle … REUSE”.  
3. Do **not** use `reference/schnorr_v2/` or `independent/schnorr_v2/` to resolve
   ambiguities before attempting a documentation-only answer.  
4. Classify leftover gaps; no silent protocol edits.

---

## Implementer checklist (from documentation)

| Step | Input | Output | Encoding / algorithm | Failure |
|------|-------|--------|----------------------|---------|
| Parse IdentityDocument | CBOR bytes | map int→value | Canonical CBOR decode | non-canonical / unknown keys / bad types |
| Validate domain/id | tstr fields | OK | V1 domain rules (no `@` in domain; id ends with `@domain`) | `INVALID_DOMAIN` / `IDENTIFIER_MISMATCH` |
| Validate keys | bstr | 32-byte x-only | BIP-340 key checks | `INVALID_*_PUBKEY` |
| Parse SubkeyBinding | body CBOR + 64-byte sig | OK | keys 0..4; TaggedHash(SUBKEY)+Verify(root) | `INVALID_SUBKEY_BINDING` |
| Match keys | binding vs document | OK | byte equality | `INVALID_SUBKEY_BINDING` |
| Time window | `now`, created, expires | OK | `created ≤ now ≤ expires` (MVP) | reject (mapped to identity/binding) |
| PaymentBinding | CBOR | map | PaymentBindingV1 shape + sort/collapse | non-canonical / bad methods |
| payment_hash | binding | 32 B | `TaggedHash(TAG_PAYMENT, CanonicalCBOR(PB))` | `PAYMENT_BINDING_MISMATCH` |
| Identity sig | signed map CBOR | OK | TaggedHash(IDENTITY)+Verify(signing) | `INVALID_IDENTITY_SIGNATURE` |
| AnchorMessage | domain, id, root | commitment | TaggedHash(ANCHOR, CanonicalCBOR(AM)) | — |
| B353S2 extract | raw_tx | 32 B | exactly one `OP_RETURN`+push(`B353S2\|\|0x01\|\|32`) | `NO_*` / `AMBIGUOUS_*` / mismatch |
| txid | raw_tx | 32 B internal | SHA256d(non-witness serialization) | `TX_PARSE_ERROR` / `TXID_MISMATCH` |
| Merkle | txid, index, branch, header | OK | Bitcoin Merkle under `header.merkle_root` | `WRONG_MERKLE_PROOF` |
| Dual-binding | all above | `identity_anchored` | **AND** of all four legs | any leg fails → not anchored |
| Continuity | anchored + roots | flag | byte equality of roots | false if not anchored |

---

## Section results

### Cryptographic primitives — PASS

| Primitive | Spec determination |
|-----------|-------------------|
| BIP-340 Sign/Verify | Referenced BIP; msg = 32-byte TaggedHash output; sig 64 B |
| TaggedHash | `SHA256(SHA256(tag)\|\|SHA256(tag)\|\|msg)`; tag = exact ASCII bytes |
| SHA-256 / SHA256d | Bitcoin / BIP-340 usage; txid = SHA256d(non-witness) |
| Byte order | Pubkeys/sigs/tags as raw bytes; Merkle siblings “internal order” via V1 reuse |

### Key representation — PASS

`root_pubkey` / `signing_pubkey` = exactly 32-byte BIP-340 x-only `bstr`.  
Not private keys, not compressed 33-byte keys, not fingerprints (explicitly unused).

### Root → signing — PASS

```text
body = CanonicalCBOR({0:1, 1:root, 2:signing, 3:created, 4:expires})
digest = TaggedHash("BIP353-IDENTITY/V2/SUBKEY-BINDING", body)
sig = Sign(root_sk, digest); Verify(root_pk, digest, sig)
```

Tag length 33 documented. Field constraints and cross-check with IdentityDocument documented.

### IdentityDocument — PASS (with incorporation of V1 domain rules)

| Field | Type | Required | Signed | Canonical | Validation |
|-------|------|----------|--------|-----------|------------|
| 0 protocol_version | uint | yes | yes | shortest uint | MUST be 2 |
| 1 domain | tstr | yes | yes | UTF-8 | V1: non-empty, no `@` |
| 2 identifier | tstr | yes | yes | UTF-8 | ends with `@`+domain |
| 3 root_pubkey | bstr32 | yes | yes | raw | BIP-340 key checks |
| 4 signing_pubkey | bstr32 | yes | yes | raw | BIP-340 key checks |
| 5 created_at | uint | yes | yes | shortest | ≤ expires |
| 6 expires_at | uint | yes | yes | shortest | ≥ created |
| 7 payment_hash | bstr32 | yes | yes | raw | match recomputed |
| 8 sequence | uint | no | yes if present | shortest | optional; **not** anti-rollback |
| 9 signature | bstr64 | on wire | **no** | — | BIP-340 under signing |

Signed bytes = CanonicalCBOR(keys {0..7} ∪ {8?}); key 9 excluded. Unknown keys: reject.

### Canonical CBOR — PASS (via V1 §2 + RFC 8949 + CBOR_UTF8)

Mini-spec alone is incomplete; **incorporation by reference** to V1 CBOR subset is explicit
(“deterministic CBOR subset as in V1 rules”). Accept/reject for integers, maps, indefinite,
trailing, floats/bools/null/tags, invalid UTF-8 is determinable from that package.

Unicode normalization: **NOT PART OF V2**.

### UTF-8 — PASS

Invalid UTF-8 → reject (RFC 8949 + `SCHNORR_V2_CBOR_UTF8.md`). ADV-M1 resolved in impl.

### PaymentBinding / payment_hash — PASS (via V1 §7 + mini-spec §7)

Included: version, methods[{type, destination=scriptPubKey}].  
Excluded: amount, label, message, pop, req-pop.  
Sort + collapse duplicates.  
`payment_hash = TaggedHash(TAG_PAYMENT, CanonicalCBOR(PB))` — **not** V1 SHA256(sep‖…).

### Anchor / B353S2 — PASS

AnchorMessage keys 0..3; commitment = TaggedHash(ANCHOR, …).  
Payload `B353S2 \|\| 0x01 \|\| 32` (39 B); scriptPubKey `OP_RETURN` + push.  
0 / 1 / >1 matching outputs → reject / accept / reject. B353ID must not match.

### Bitcoin serialization / Merkle / header — PASS with NON-BLOCKING gaps

Mini-spec states SHA256d(non-witness) and dual-binding AND.  
Exact Merkle even/odd fold and 80-byte header layout are **not restated**; design notes
say **REUSE** V1 / Bitcoin inclusion math. Determinable from Bitcoin + V1 §11, but not
self-contained in the mini-spec alone → **NON-BLOCKING / DOCUMENTATION**.

### Dual-binding — PASS

Formally AND of: txid from raw_tx; Merkle to supplied header; unique B353S2 commitment;
commitment equals expected. Logical OP_RETURN alone MUST NOT set `identity_anchored`.

### State model — PASS

| Condition | identity_verified | payment_verified | identity_anchored | continuity_verified |
|-----------|-------------------|------------------|-------------------|---------------------|
| Valid binding+identity+fields | true | (if pay match) | false | false |
| + payment hash match | true | true | false | false |
| + full dual-binding | true | true | true | true (root bytes match) |
| Historical root match alone | — | — | requires anchor | true only with anchor |

Does **not** imply human identity, payment received, freshness, finality.

### Failure semantics — PASS

MVP codes listed in mini-spec §11; BTC codes listed in § dual-binding. Sufficient for
interop; not a full formal error algebra.

### Security claims — PASS (honest)

| Claim | Audit |
|-------|-------|
| Root→signing / identity / payment / anchor integrity | **SUPPORTED** (TESTED under lab assumptions) |
| Dual-binding inclusion | **SUPPORTED** as TESTED on synthetic fixtures; PoW/best-chain **NOT PROVIDED** |
| Continuity | **SUPPORTED** as byte equality given anchored |
| Freshness, rollback, split-view, human/legal ID, current control, revocation freshness, absolute finality, privacy, compromise resistance | **NOT PROVIDED** — correctly stated |

---

## Ambiguities

| ID | Class | Topic | Notes |
|----|-------|-------|-------|
| SPEC-A1 | NON-BLOCKING | CBOR reject table not inlined in mini-spec | Resolved by “V1 rules” + RFC 8949; recommend explicit “MUST read PROTOCOL_FREEZE_V1 §2” |
| SPEC-A2 | NON-BLOCKING | Merkle fold / header bytes | Resolved by Bitcoin + V1 §11 REUSE; recommend short normative pointer + algorithm sketch |
| SPEC-A3 | NON-BLOCKING | PaymentBinding key integers | In V1 §7, not restated in mini-spec |
| SPEC-A4 | DOCUMENTATION | Mini-spec banner still says “NOT A FROZEN PROTOCOL” | Conflicts with experimental snapshot freeze wording; clarify “experimental freeze ≠ normative freeze” |
| SPEC-A5 | DOCUMENTATION | “MVP policy” for `now` | Intent is `created ≤ now ≤ expires`; spell out |
| SPEC-A6 | DOCUMENTATION | OP_RETURN push opcode for len 39 | Bitcoin push conventions; vectors fix `0x6a 0x27 ‖ payload` |

**BLOCKING ambiguities: 0**

---

## Prior LOW / INFORMATIONAL findings

| ID | Still open? | Spec-related? |
|----|-------------|----------------|
| F-S2 / ADV-L1 (dict verify API) | yes LOW | Implementation API, not wire ambiguity |
| ADV-L2 (negative created_at in builder) | yes LOW | Builder hygiene; wire CBOR rejects negatives |
| ADV-I1 header non-merkle fields | yes INFO | Matches NOT PROVIDED PoW |
| ADV-I2 rollback | yes INFO | Spec correctly says NOT PROVIDED |
| ADV-I3 / F-S4 binding omits domain | yes INFO | By design; domain in IdentityDocument |

Do not close artificially.

---

## Spec-only reproducibility

Directory `audit/schnorr_v2_spec_only/` implements a **minimal** verifier from:

* mini-spec constructions (TaggedHash tags, signed maps, B353S2, dual-binding AND)
* V1 CBOR module (`reference.cbor` — shared V1 subset, **not** `schnorr_v2`)
* BIP-340 via `embit` library (standard), not `reference.schnorr_v2.*`

It does **not** import `reference.schnorr_v2` or the JS tree.

Result: reproduces valid / invalid identity & payment vectors and BTC dual-binding
rejection cases against frozen fixtures → **SPEC REPRODUCIBILITY = PASS**
(with V1 CBOR/PaymentBinding incorporation by reference as documented above).

---

## Snapshot / git policy

| Check | Result |
|-------|--------|
| Protocol change | **NONE** |
| Recommended wording only | SPEC-A1–A6 |
| `schnorr-v2-experimental-2` | **UNCHANGED** |
| V1 / frozen vectors / checksums | **UNCHANGED** |

---

## Conclusion

V2 experimental documentation, together with explicitly reused V1 CBOR/Payment/Merkle
rules and BIP-340/RFC 8949, is sufficient for an independent implementer to match
frozen vectors. No blocking cryptographic ambiguities found. Remaining items are
non-blocking incorporation gaps and documentation clarity — not silent protocol fixes.

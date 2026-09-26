# PROTOCOL_FREEZE_V1 — BIP-353 Identity Binding and Continuity

**Protocol version:** 1  
**Freeze milestone:** M7  
**Status:** FROZEN  

This document is the normative V1 protocol freeze. The future BIP draft (M8) must be a **transcription** of this file — not a redesign.

Wire-format changes require a new protocol version.

---

## 0. Component freeze table

| Component | Version | Status |
|-----------|---------|--------|
| IdentityDocument | 1 | FROZEN |
| PaymentBinding | 1 | FROZEN |
| AnchorMessage (Candidate A) | 1 | FROZEN |
| BitcoinAnchorProof | 1 | FROZEN |
| OpenPGP signature (detached binary) | — | FROZEN |
| Deterministic CBOR subset | RFC 8949 Core | FROZEN |
| Identity domain separator | v1 (17 bytes) | FROZEN |
| Payment domain separator | v1 | FROZEN |
| Anchor domain separator | v1 | FROZEN |
| OP_RETURN format | v1 (`B353ID`) | FROZEN |
| Fingerprint encoding | raw `bstr` | FROZEN |
| Freshness | — | NOT PROVIDED |
| Rollback resistance | — | NOT PROVIDED |
| Revocation | — | UNKNOWN BY DESIGN |
| Human identity | — | NOT PROVIDED |
| Transparency log | — | V2 |
| Recovery | — | V2 |
| Privacy protocol | — | V2 |
| PSBT | — | FUTURE |
| Lightning method payload | — | FUTURE |

---

## 1. IdentityDocumentV1

### Structure (deterministic CBOR map, integer keys)

| Key | Name | CBOR type | Constraints | In signed payload? |
|-----|------|-----------|-------------|-------------------|
| 0 | `protocol_version` | unsigned int | MUST be `1` | Yes |
| 1 | `domain` | tstr (UTF-8) | Non-empty; MUST NOT contain `@`; recommended ≤253 bytes | Yes |
| 2 | `identifier` | tstr (UTF-8) | MUST equal `local@domain` consistent with key 1; recommended ≤320 bytes | Yes |
| 3 | `kroot_fingerprint` | bstr | Length 20 (OpenPGP v4) or 32 (OpenPGP v6); MUST match primary key fingerprint | Yes |
| 4 | `ksign_fingerprint` | bstr | Length 20 or 32; MUST match signing subkey fingerprint | Yes |
| 5 | `created_at` | unsigned int | Unix time (seconds) | Yes |
| 6 | `expires_at` | unsigned int | Unix time; MUST be ≥ `created_at` | Yes |
| 7 | `payment_hash` | bstr | Exactly 32 bytes | Yes |
| 8 | `sequence` | unsigned int | Non-negative; monotonic intent only | Yes |
| 9 | `signature` | bstr | OpenPGP detached binary signature packets | **No** |

### Rules

- All keys 0..9 are **mandatory** in a complete document presented for verification.
- **Unknown keys:** V1 receivers MUST reject documents containing keys outside 0..9 (strict).
- **Defaults:** none.
- **Signed object:** Canonical CBOR encoding of the map containing **only** keys 0..8.
- Key 9 is attached after signing; mutating 0..8 invalidates the signature.

---

## 2. Canonical CBOR (V1)

Encoding and decoding MUST follow RFC 8949 §4.2.1 Core Deterministic Encoding for the protocol subset:

| Topic | Rule |
|-------|------|
| Integers | Unsigned only; shortest form mandatory; reject non-shortest |
| Text | UTF-8; major type 3 |
| Byte strings | Major type 2; length-prefixed |
| Arrays | Definite length only |
| Maps | Integer keys only; sorted by **encoded key byte** order |
| Duplicate map keys | Reject |
| Indefinite-length | Reject |
| Trailing bytes | Reject after a complete top-level item |
| Booleans / null / floats / tags | Not used; reject if present in protocol objects |
| Unknown fields in IdentityDocument | Reject (strict V1) |

**Invariant:** one semantic protocol object → exactly one valid canonical byte string.

---

## 3. Domain separators (exact bytes)

### Identity (17 bytes)

```
42 49 50 33 35 33 2d 49 44 45 4e 54 49 54 59 00 01
```

ASCII `BIP353-IDENTITY` followed by `0x00` then `0x01`.  
Specified as **bytes**, never as a NUL-terminated C string.

### Payment

```
BIP353-IDENTITY/PAYMENT/v1
```
UTF-8 / ASCII bytes (no trailing NUL).

### Anchor

```
BIP353-IDENTITY/ANCHOR/v1
```

---

## 4. Identity signature

```
SignatureInput = IdentityDomainSeparator || CanonicalCBOR(SignedIdentityDocumentV1)
```

where `SignedIdentityDocumentV1` = fields 0..8.

- Signature: OpenPGP **detached binary** signature produced by **KSIGN**.
- Verification: **semantic** OpenPGP verification (GnuPG / Sequoia / openpgp.js).
- Implementations MUST NOT require identical signature packet serialization across libraries.

---

## 5. KROOT / KSIGN

| Role | Definition |
|------|------------|
| KROOT | OpenPGP primary (certification) key |
| KSIGN | OpenPGP signing-capable subkey bound to KROOT |

Binding: standard OpenPGP subkey binding (`0x18`) with primary key binding (`0x19`) as required by OpenPGP for the algorithm.

**OpenPGP versions:** V1 supports v4 and v6 keys. GnuPG 2.4.8 not parsing v6 is an **implementation limitation**, not a protocol prohibition.

---

## 6. Fingerprint representation — **raw `bstr`**

**Decision (M7):** Do **not** use a `KeyReference { version, fingerprint }` CBOR map.

| Rule | Value |
|------|-------|
| Encoding | Raw fingerprint bytes as CBOR `bstr` |
| OpenPGP v4 | Exactly **20** bytes |
| OpenPGP v6 | Exactly **32** bytes |
| Future versions | New protocol version required if fingerprint size/format changes |
| Validation | Byte-equality with fingerprint computed from the offered certificate for that key |

Rationale: matches all frozen vectors (v4: 20; v6 fixture: 32); avoids breaking M1 hashes.

---

## 7. PaymentBindingV1

```
PaymentBindingV1 = {
  0: version,          ; unsigned, MUST be 1
  1: methods: [ Method, ... ]
}

Method = {
  0: type,             ; tstr
  1: destination       ; bstr
}
```

### Bitcoin method

- `type` = `"bitcoin"`
- `destination` = Bitcoin `scriptPubKey` bytes (not address string)

### Explicitly EXCLUDED from the binding

`amount`, `label`, `message`, `pop` / `req-pop`, and other request-specific metadata.

**Normative meaning:** durable **payment destination set**, not a particular payment request.

### Ordering & duplicates

1. Normalize each method to `{0: type, 1: destination}`.
2. Sort by comparison key `(UTF-8 bytes of type, destination bytes)` lexicographically.
3. Collapse duplicate identical pairs.
4. Encode with Canonical CBOR.

Semantic equivalence ⇒ identical canonical bytes ⇒ identical `payment_hash`.

---

## 8. Payment hash

```
PAYMENT_HASH = SHA256(
  PAYMENT_DOMAIN_SEPARATOR || CanonicalCBOR(PaymentBindingV1)
)
```

`PAYMENT_DOMAIN_SEPARATOR = BIP353-IDENTITY/PAYMENT/v1` (exact bytes as above).

---

## 9. AnchorMessageV1 (Candidate A)

```
AnchorMessageV1 = {
  0: version,              ; 1
  1: domain,               ; tstr
  2: identifier,           ; tstr
  3: kroot_fingerprint     ; bstr (20 or 32)
}
```

```
IDENTITY_COMMITMENT = SHA256(
  ANCHOR_DOMAIN_SEPARATOR || CanonicalCBOR(AnchorMessageV1)
)
```

**MUST NOT** include KSIGN, `payment_hash`, amount, or label.

**Justification:** KSIGN and payment destinations may rotate without a new Bitcoin anchor; KROOT is the V1 continuity root.

---

## 10. Bitcoin OP_RETURN (V1 FROZEN)

| Field | Value |
|-------|-------|
| Tag | `B353ID` = `42 33 35 33 49 44` |
| Version | `0x01` |
| Commitment | 32-byte `IDENTITY_COMMITMENT` |
| Payload length | 39 bytes |
| scriptPubKey | `OP_RETURN` + push(payload) |

### Multiple matching outputs

If a transaction contains **more than one** output whose script parses as V1 `B353ID||0x01||32`:

→ **Reject** with `AMBIGUOUS_B353ID_OUTPUTS`.

Do not pick “first”, “last”, or “any matching expected”.

Non-matching OP_RETURN outputs are ignored.

---

## 11. BitcoinAnchorProofV1

Transport fields (may be present):

| Field | Role |
|-------|------|
| `protocol_version` | 1 |
| `chain` | `regtest` / `testnet` / `signet` / `main` |
| `raw_tx` | **Authority** |
| `txid` | Auxiliary — MUST equal SHA256d(raw_tx) |
| `commitment` | Auxiliary — MUST equal extracted OP_RETURN |
| `block_header` | 80-byte header |
| `tx_index` | Merkle leaf index |
| `merkle_branch` | Sibling hashes (internal byte order) |
| `block_height` | Advisory metadata |
| `tip_height_at_proof` | Advisory |
| `confirmations_at_proof` | Advisory / wallet policy input |

### Mandatory verification

```
raw_tx ──► parse ──► SHA256d(non-witness) = computed_txid
                  └► OP_RETURN B353ID ──► extracted_commitment

computed_txid + merkle_branch + tx_index ──► header.merkle_root
extracted_commitment ══ expected identity commitment
```

Both branches MUST succeed. Bundle-supplied txid/commitment are never independent authority.

---

## 12. Header context

| Mode | `header_context` | Meaning |
|------|------------------|---------|
| A | `trusted` | Wallet asserts header is on its accepted chain view (PoW/linkage/tip per wallet policy) |
| B | `untrusted` | Only verifies txid→merkle→this header; MUST NOT set `anchor_included` as best-chain inclusion |

---

## 13. Reorg / confirmation states

| Status | Condition (sketch) |
|--------|-------------------|
| `anchor_seen` | Tx known, not in an accepted block (e.g. mempool) |
| `anchor_included` | In a **trusted** header’s block; confirmations ≥ 1 and &lt; policy |
| `anchor_confirmed` | In trusted chain; confirmations ≥ wallet policy |
| `anchor_orphaned` | Previously included header no longer on wallet tip |

Confirmation count is **not** absolute finality. Depth policy is wallet-local.

---

## 14. Freshness & rollback

```
freshness.status = "unknown"     # unless an external V2 layer is used
rollback_resistance = "not_provided"
```

`sequence` orders signed documents for consumers that already share history; it does **not** prove global latest.

**BIP claim (mandatory wording):**  
V1 provides no cryptographic guarantee that the presented IdentityDocument is the most recent valid document.

---

## 15. Revocation — UNKNOWN BY DESIGN

1. If offered OpenPGP material shows KROOT/KSIGN revoked → reject (`IDENTITY_REVOKED`).
2. Otherwise → `revocation.status = "unknown"`.
3. Absence of revocation in the Proof Bundle does **not** mean keys are unrevoked.
4. No proprietary revocation channel in V1.

---

## 16. Human identity invariant

```
human_verified = false
```

Always, for this protocol alone. External trust is out of band.

---

## 17. Trust states

| State | Meaning |
|-------|---------|
| `first_seen` | Default after cryptographic verify |
| `user_trusted` | Explicit local user action |
| `external_attestation` | Out-of-band attestation |
| `untrusted` | Explicit distrust / policy |

`cryptographically valid` ≠ `user trusted` ≠ `human verified`.

---

## 18. Verifier result semantics (V1)

Minimum semantic fields (names may match implementation dataclasses):

| Field | Semantics |
|-------|-----------|
| `payment_verified` | DNS/semantic payment matches `payment_hash` |
| `identity_verified` | OpenPGP + document checks passed |
| `identity_anchored` | Commitment matches Candidate A for this identity |
| `bitcoin.transaction_valid` | raw_tx parsed; txid bound |
| `bitcoin.inclusion_proof_valid` | Merkle under claimed header |
| `bitcoin.header_context` | `trusted` \| `untrusted` |
| `bitcoin.status` | seen / included / confirmed / orphaned / … |
| `freshness.status` | `unknown` in V1 base |
| `revocation.status` | `unknown` \| `revoked` |
| `trust.status` | first_seen / … |
| `rollback_resistance` | `not_provided` |
| `human_verified` | always `false` |

---

## 19. Security claim matrix (normative ceiling)

| Property | V1 |
|----------|-----|
| Identity signature authenticity | PROVEN |
| KROOT → KSIGN binding | PROVEN |
| Payment destination binding | PROVEN |
| Identity commitment | PROVEN |
| raw_tx → txid | PROVEN |
| txid → Merkle inclusion (claimed header) | PROVEN |
| OP_RETURN → commitment | PROVEN |
| Header-chain validation | CONTEXT-DEPENDENT |
| Reorg resistance | NOT PROVIDED |
| Freshness | NOT PROVIDED |
| Rollback resistance | NOT PROVIDED |
| Split-view resistance | NOT PROVIDED |
| Human identity | NOT PROVIDED |
| KROOT compromise resistance | NOT PROVIDED |
| KSIGN compromise resistance | NOT PROVIDED |
| Revocation freshness | NOT PROVIDED |
| DoS resistance | LIMITED / CAP-DEPENDENT |
| Privacy guarantee | NOT PROVIDED |

No BIP text may claim more than this matrix.

---

## 20. Resource limits

Normative posture: implementations SHOULD enforce caps. Numbers in `reference/limits.py` are **PROVISIONAL recommendations**:

| Item | Recommended max | Enforced in reference? |
|------|-----------------|------------------------|
| domain | 253 UTF-8 bytes | Soft |
| identifier | 320 UTF-8 bytes | Soft |
| IdentityDocument | 16 KiB | Soft |
| PaymentBinding | 8 KiB | Soft |
| method count | 32 | Soft |
| raw_tx | 100_000 bytes | **Yes** |
| merkle branch depth | 32 | **Yes** |
| proof bundle | 256 KiB | Soft |

---

## 21. Error states (V1 set)

`IDENTIFIER_MISMATCH`, `ROOT_KEY_MISMATCH`, `SIGNING_KEY_MISMATCH`, `INVALID_ROOT_BINDING`, `INVALID_IDENTITY_SIGNATURE`, `IDENTITY_EXPIRED`, `IDENTITY_REVOKED`, `PAYMENT_BINDING_MISMATCH`, `ANCHOR_MISMATCH`, `UNSUPPORTED_VERSION`, `TXID_MISMATCH`, `WRONG_TX_COMMITMENT`, `WRONG_MERKLE_PROOF`, `BAD_BLOCK_HEADER`, `ORPHANED_ANCHOR`, `AMBIGUOUS_B353ID_OUTPUTS`, `NO_B353ID_OUTPUT`, `TX_PARSE_ERROR`.

---

## 22. Test vectors

Canonical checksums: `vectors/M7_CHECKSUMS.txt`.

Modification of any checksummed normative vector requires an **explicit versioned** change — never silent regeneration.

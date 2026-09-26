```
BIP: XXX
Title: BIP-353 Identity Binding and Continuity
Author: BIP-XXX Working Group <experimental>
Comments-Summary: No comments yet.
Status: Draft
Type: Standards Track
Created: 2026-09-26
License: BSD-2-Clause
Requires: BIP-353, BIP-321
Replaces:
```

# BIP-XXX: BIP-353 Identity Binding and Continuity

## Abstract

This document specifies a complementary protocol to [BIP-353](bip-0353.mediawiki) that cryptographically binds a BIP-353 payment identifier to:

1. an OpenPGP identity root key (`KROOT`) and authorized signing subkey (`KSIGN`);
2. a signed Identity Document encoding a payment destination binding;
3. a Bitcoin historical anchor committing to `(domain, identifier, KROOT)`;
4. optional inclusion evidence for that anchor transaction.

Given a Proof Bundle and (where applicable) BIP-353-resolved payment instructions, a verifier can determine whether the presented payment destinations are authenticated under the claimed OpenPGP identity and whether that identity root was historically committed on Bitcoin for the claimed identifier.

This protocol does **not** prove human or legal identity, does **not** prove continuous ownership of keys or accounts, does **not** prevent key compromise, and does **not** guarantee that a presented Identity Document is the most recent valid document (freshness is not provided in version 1).

## Motivation

BIP-353 maps human-readable identifiers (e.g. `alice@example.com`) to Bitcoin payment instructions via DNS and DNSSEC. DNSSEC protects the integrity of DNS-resolved payment data relative to the DNS hierarchy. It does not, by itself, provide a durable cryptographic identity root independent of DNS operators, hosting providers, or transient payment URI contents.

Operators and wallets benefit from an additional layer that:

* authenticates payment destination sets under an OpenPGP key hierarchy;
* allows payment destinations and signing subkeys to rotate without rewriting Bitcoin history;
* records a public, auditable commitment binding an identifier to a long-term OpenPGP root (`KROOT`);
* separates payment verification, identity verification, anchoring, inclusion, freshness, revocation, and user trust into distinct results.

Version 1 deliberately omits transparency logs, recovery protocols, privacy protocols, and absolute chain finality. Those are out of scope (see Non-Goals).

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

Protocol version **1** is frozen. Changing wire formats defined herein REQUIRES a new protocol version.

### 1. Terminology

| Term | Definition |
|------|------------|
| **BIP-353 identifier** | A payment name of the form `user@domain` as resolved by BIP-353. |
| **KROOT** | The OpenPGP primary (certification) key that is the root of continuity for an identity under this protocol. |
| **KSIGN** | An OpenPGP signing-capable subkey bound to KROOT and used to sign Identity Documents. |
| **IdentityDocument** | A deterministic-CBOR map (`IdentityDocumentV1`) describing identity metadata, payment hash, and an OpenPGP signature. |
| **PaymentBinding** | A deterministic-CBOR object (`PaymentBindingV1`) encoding durable payment destination methods (not a single payment request). |
| **Payment Hash** | `SHA256(payment_domain_separator \|\| CanonicalCBOR(PaymentBindingV1))`. |
| **AnchorMessage** | A deterministic-CBOR object (`AnchorMessageV1`, Candidate A) containing version, domain, identifier, and KROOT fingerprint. It is **reconstructed** by the verifier from those fields; it is **not** a mandatory verifier input and is **not** carried on-chain. |
| **Identity Commitment** | `SHA256(anchor_domain_separator \|\| CanonicalCBOR(AnchorMessageV1))`, computed locally from the reconstructed AnchorMessageV1. |
| **Bitcoin Anchor** | A Bitcoin transaction carrying the Identity Commitment in a V1 OP_RETURN output. |
| **BitcoinAnchorProof** | Evidence object (`BitcoinAnchorProofV1`) including `raw_tx`, Merkle path, and block header bytes used to verify inclusion relative to a header. |
| **Proof Bundle** | The collection of artifacts presented for verification: Identity Document, Payment Binding, OpenPGP certificate(s), and optionally a BitcoinAnchorProof. An AnchorMessage MAY be included for transport/debug only. |
| **Payment Verified** | BIP-353-resolved semantic payment instructions, encoded as PaymentBindingV1, produce a `PAYMENT_HASH` equal to IdentityDocument key `7`. This is **not** proof that a Bitcoin payment occurred, was received, or settled. |
| **Identity Verified** | OpenPGP certificate checks, KROOT→KSIGN binding, IdentityDocument signature, and document field validation succeeded. Independent of Bitcoin. This is **not** human identity, legal identity, proof of current control, freshness, or non-compromise. |
| **Identity Anchored** | A valid BitcoinAnchorProof demonstrates that the locally computed Identity Commitment was published in a Bitcoin transaction satisfying V1 verification rules. Local commitment computation alone is **not** sufficient. This is **not** freshness, rollback resistance, or proof of current control. |
| **Freshness** | Whether the presented Identity Document is known to be the latest valid document. **Not provided** by V1. |
| **Revocation** | OpenPGP key revocation status as observable from offered material. V1 distinguishes **revoked** (valid OpenPGP revocation observed) from **not known to be revoked** (`unknown`). Absence of revocation data is **not** “not revoked”. |
| **First Seen** | Default trust state after cryptographic verification with no prior local trust decision. |
| **User Trusted** | Explicit local user (or policy) trust decision, outside this protocol's cryptographic claims. |
| **Continuity Verified** | A verified historical Bitcoin anchor shows the same KROOT for the claimed domain and identifier (Candidate A). Requires `identity_anchored`. This does **not** mean latest key, current key, uncompromised key, human identity, continuous control, or freshness. |

### 2. Protocol Overview

```
USER@DOMAIN
     │
     ├──────── BIP-353 / DNSSEC ────────► Payment Instructions
     │                                      (BIP-321 semantics)
     │                                              │
     │                                              ▼
     │                                      PaymentBindingV1
     │                                              │
     │                                              ▼
     │                                         payment_hash
     │
     └──────── OpenPGP ─────────────────► Identity
                                            │
                                          KROOT
                                            │
                                          KSIGN
                                            │
                                      IdentityDocumentV1
                                            │
                                      (binds payment_hash)
                                            │
                                      (reconstruct AnchorMessageV1)
                                            │
                                      identity_commitment
                                            │
                                      Bitcoin OP_RETURN
                                            │
                                      BitcoinAnchorProofV1
                                         (→ identity_anchored)
```

Layer responsibilities:

| Layer | Responsibility |
|-------|----------------|
| BIP-353 / DNSSEC | Resolve payment instructions; this BIP does not modify DNSSEC |
| OpenPGP | Authenticate Identity Documents under KROOT→KSIGN |
| PaymentBinding | Canonicalize durable destinations; bind via payment_hash |
| Bitcoin Anchor | Publish historical commitment to (domain, identifier, KROOT) |
| Wallet header policy | Decide whether a proven header is on the wallet's accepted chain (`header_context`); this is wallet-local, not universal consensus |

#### Identifier and domain strings

For IdentityDocumentV1 and AnchorMessageV1:

* `domain` and `identifier` MUST be compared as exact UTF-8 byte sequences as stored in the CBOR text strings.
* This BIP does **not** define Unicode normalization, case-folding, or Punycode conversion.
* The BIP-353 identifier used as the verification request input MUST be the identifier as resolved under BIP-353. Where BIP-353 (and related DNS rules) already define how names are resolved, those rules apply **before** this protocol binds the resulting identifier string.
* Within this protocol, the string written in IdentityDocument key `2` MUST equal the requested identifier by exact CBOR text-string equality, and MUST end with `@` concatenated with key `1` (`domain`) by exact UTF-8 concatenation.

### 3. IdentityDocumentV1

IdentityDocumentV1 MUST be encoded as a deterministic CBOR map with non-negative integer keys:

| Key | Name | CBOR type | Constraints | In signed payload |
|-----|------|-----------|-------------|-------------------|
| 0 | `protocol_version` | unsigned integer | MUST be `1` | Yes |
| 1 | `domain` | text string (UTF-8) | Non-empty; MUST NOT contain `@` | Yes |
| 2 | `identifier` | text string (UTF-8) | MUST be consistent with key 1 as `…@domain` | Yes |
| 3 | `kroot_fingerprint` | byte string | Length 20 (OpenPGP v4) or 32 (OpenPGP v6); MUST match KROOT | Yes |
| 4 | `ksign_fingerprint` | byte string | Length 20 or 32; MUST match KSIGN | Yes |
| 5 | `created_at` | unsigned integer | Unix time in seconds; start of document validity window (not a freshness claim) | Yes |
| 6 | `expires_at` | unsigned integer | Unix time; MUST be ≥ `created_at`; end of document validity window (not a freshness claim) | Yes |
| 7 | `payment_hash` | byte string | Exactly 32 bytes | Yes |
| 8 | `sequence` | unsigned integer | Non-negative; ordering intent among signed documents only — **not** anti-rollback and **not** global currentness | Yes |
| 9 | `signature` | byte string | OpenPGP detached binary signature | **No** |

Rules:

1. Keys `0` through `9` are REQUIRED in a complete document presented for verification.
2. Receivers MUST reject documents containing map keys outside `0..9`.
3. There are no default values.
4. The signed object is the Canonical CBOR encoding of the map containing **only** keys `0..8`.
5. Key `9` is attached after signing. Any change to keys `0..8` invalidates the signature.
6. Implementations SHOULD reject documents exceeding the RECOMMENDED provisional size limits in Resource Limits (not a wire-format `MUST`).

### 4. Canonical CBOR

All signed and hashed protocol objects MUST use the deterministic CBOR subset defined here, following RFC 8949 §4.2.1 Core Deterministic Encoding Requirements for the types used.

| Topic | Rule |
|-------|------|
| Integers | Unsigned only; shortest form REQUIRED; non-shortest encodings MUST be rejected |
| Text strings | UTF-8; major type 3 |
| Byte strings | Major type 2; definite length |
| Arrays | Definite length only |
| Maps | Non-negative integer keys only; keys MUST be sorted by the byte encoding of the key |
| Duplicate map keys | MUST be rejected |
| Indefinite-length items | MUST be rejected |
| Trailing bytes | MUST be rejected after a complete top-level value |
| Boolean, null, floating point, tags | MUST NOT appear in protocol objects; MUST be rejected if present |

**Invariant:** One semantic protocol object MUST have exactly one valid canonical byte representation.

JSON MUST NOT be used as a signed or hashed representation of protocol objects.

### 5. OpenPGP Identity Binding

Identity authentication uses OpenPGP as specified in RFC 9580 (and compatible v4 profiles where applicable).

Verification of Identity Document signatures MUST be **semantic**: implementations MUST accept signatures that cryptographically verify under KSIGN according to OpenPGP rules. Implementations MUST NOT require byte-identical OpenPGP signature packet serialization across libraries.

Interop note for V1: verification has been exercised with GnuPG, Sequoia, and openpgp.js as independent OpenPGP implementations. Those implementations are interoperability evidence; they are **not** normative authorities. Packet encodings MAY differ across libraries.

### 6. KROOT and KSIGN

| Role | Definition |
|------|------------|
| KROOT | OpenPGP primary key |
| KSIGN | OpenPGP signing-capable subkey bound to KROOT |

The KROOT→KSIGN relationship MUST use standard OpenPGP mechanisms:

* Subkey Binding Signature type `0x18`;
* Primary Key Binding Signature type `0x19` where required by OpenPGP for the algorithm (e.g. for signing subkeys as specified by OpenPGP).

This BIP MUST NOT define a proprietary key-binding signature format.

**OpenPGP versions:** V1 supports OpenPGP v4 and v6 keys. Inability of a particular software release to parse v6 keys is an implementation limitation and MUST NOT be interpreted as a protocol prohibition of v6.

#### Fingerprints

Fingerprints MUST be encoded as raw CBOR byte strings (`bstr`).

| OpenPGP key version | Fingerprint length |
|---------------------|--------------------|
| v4 | Exactly 20 bytes |
| v6 | Exactly 32 bytes |

A future `KeyReference { version, fingerprint }` structure is **out of scope for V1**. Adopting it REQUIRES a new protocol version.

During verification, each fingerprint field MUST equal the fingerprint computed from the corresponding key in the offered OpenPGP certificate (byte equality).

### 7. PaymentBindingV1

```
PaymentBindingV1 = {
  0: version,     ; unsigned integer, MUST be 1
  1: methods      ; array of Method
}

Method = {
  0: type,        ; text string
  1: destination  ; byte string
}
```

#### Bitcoin method

For on-chain Bitcoin destinations:

* `type` MUST be the UTF-8 string `bitcoin`;
* `destination` MUST be the Bitcoin `scriptPubKey` bytes (not an address string, not a BIP-321 URI string).

#### Construction from BIP-353

Normative verification flow:

```
BIP-353 identifier
   → DNSSEC-validated BIP-353 resolution
   → BIP-321 semantic payment instructions
   → drop amount / label / message / pop (and other request metadata)
   → PaymentBindingV1 (scriptPubKey destinations for bitcoin methods)
   → CanonicalCBOR(PaymentBindingV1)
   → PAYMENT_HASH
   → MUST equal IdentityDocument.payment_hash
```

PaymentBindingV1 MUST be constructed from the **semantic** result of BIP-353 resolution (BIP-321 payment instructions after DNSSEC validation and URI reconstruction), NOT from raw DNS TXT octets and NOT from an unparsed `bitcoin:` URI string.

A PaymentBinding object carried in a Proof Bundle is **not** an independent authority. For `payment_verified = true`, a verifier MUST ensure:

```
BIP-353-resolved semantic destinations
        ==
canonical PaymentBindingV1
        ==
PAYMENT_HASH
        ==
IdentityDocument.payment_hash
```

If a Proof Bundle supplies PaymentBinding bytes, those bytes MUST be the Canonical CBOR encoding of the PaymentBindingV1 derived from the resolved semantics (or MUST hash-equal that encoding). A wallet MUST NOT accept a Proof Bundle PaymentBinding that disagrees with BIP-353-resolved semantics while still reporting `payment_verified = true`.

#### Explicit exclusions

The following MUST NOT be included in PaymentBindingV1:

* `amount`
* `label`
* `message`
* `pop` / `req-pop`
* other request-specific or ephemeral metadata

**Rationale:** The binding authenticates a durable **set of payment destinations**, not a particular payment request. Request metadata may change without representing a change of identity-bound destinations.

#### Ordering and duplicates

Implementations MUST canonicalize methods as follows:

1. Normalize each method to `{0: type, 1: destination}`.
2. Sort by comparison key `(UTF-8 encoding of type, destination bytes)` in lexicographic order.
3. Collapse duplicate identical `(type, destination)` pairs.
4. Encode with Canonical CBOR.

Semantically equivalent payment destination sets MUST produce identical canonical bytes and therefore identical payment hashes.

Method types other than `bitcoin` MAY appear as opaque `(type, destination)` pairs. Canonical forms for Lightning offers and other methods are **not** specified in V1.

### 8. Payment Hash

Let `PAYMENT_DOMAIN_SEPARATOR` be the ASCII bytes:

```
BIP353-IDENTITY/PAYMENT/v1
```

(no trailing NUL byte).

```
PAYMENT_HASH = SHA256(
    PAYMENT_DOMAIN_SEPARATOR || CanonicalCBOR(PaymentBindingV1)
)
```

`PAYMENT_HASH` is a 32-byte value stored in IdentityDocumentV1 key `7`.

### 9. Bitcoin Identity Anchor

V1 uses **Candidate A** only.

```
AnchorMessageV1 = {
  0: version,             ; unsigned integer, MUST be 1
  1: domain,              ; text string
  2: identifier,          ; text string
  3: kroot_fingerprint    ; byte string (20 or 32)
}
```

AnchorMessageV1 MUST NOT include KSIGN, `payment_hash`, amount, or label.

**Rationale:** KSIGN and payment destinations MAY rotate without publishing a new Bitcoin anchor. KROOT is the V1 root of continuity for the identifier.

**Critical:** AnchorMessageV1 is **not** written into the Bitcoin transaction. The chain carries only the 39-byte OP_RETURN payload (`B353ID || 0x01 || IDENTITY_COMMITMENT`).

The verifier MUST **reconstruct** AnchorMessageV1 locally from:

* `domain` (IdentityDocument key `1`)
* `identifier` (IdentityDocument key `2`)
* `kroot_fingerprint` (IdentityDocument key `3`, matching the certificate)

then recompute `IDENTITY_COMMITMENT`.

AnchorMessage bytes are **not** a mandatory verifier input. If a Proof Bundle optionally carries an AnchorMessage object, it is transport/debug only: it MUST NOT be treated as independent authority, MUST NOT replace or alter local reconstruction, and MUST be rejected (`ANCHOR_MISMATCH`) if it disagrees with the locally reconstructed AnchorMessageV1 / commitment.

### 10. Anchor Commitment

Let `ANCHOR_DOMAIN_SEPARATOR` be the ASCII bytes:

```
BIP353-IDENTITY/ANCHOR/v1
```

```
IDENTITY_COMMITMENT = SHA256(
    ANCHOR_DOMAIN_SEPARATOR || CanonicalCBOR(AnchorMessageV1)
)
```

`IDENTITY_COMMITMENT` is 32 bytes.

Relationship (MUST NOT be misread as “OP_RETURN contains AnchorMessage”):

```
AnchorMessageV1  (off-chain reconstruction)
        ↓
CanonicalCBOR(AnchorMessageV1)
        ↓
SHA256(ANCHOR_DOMAIN_SEPARATOR || …)
        ↓
IDENTITY_COMMITMENT
        ↓
placed on-chain as OP_RETURN payload bytes [7..38] after B353ID||0x01
```

### 11. OP_RETURN Encoding

A V1 Bitcoin identity anchor output MUST use a scriptPubKey of the form:

```
OP_RETURN <push payload>
```

where payload is exactly 39 bytes:

```
B353ID || 0x01 || IDENTITY_COMMITMENT
```

| Field | Bytes | Value |
|-------|-------|-------|
| Tag | 6 | ASCII `B353ID` = `42 33 35 33 49 44` |
| Version | 1 | `0x01` |
| Commitment | 32 | `IDENTITY_COMMITMENT` |

Parsing rules:

1. Only short push encodings with a single-byte length (`push_len < 76`) are REQUIRED to be accepted for V1.
2. Payload length MUST be exactly 39 bytes for a matching V1 output.
3. Wrong tag, wrong version, wrong length, truncation, or extra payload bytes → the output is **not** a matching V1 B353ID output.
4. Non-matching OP_RETURN outputs MUST be ignored for extraction purposes.

#### Multiple matching B353ID outputs

If a transaction contains **more than one** output that successfully parses as a V1 `B353ID || 0x01 || 32-byte commitment` (whether commitments are equal or not), verifiers MUST reject with `AMBIGUOUS_B353ID_OUTPUTS`.

Implementations MUST NOT select an output by position (“first”, “last”) or by matching an expected commitment among several matching outputs.

If zero matching outputs exist, verifiers MUST fail with `NO_B353ID_OUTPUT`.

Republishing the same commitment in **separate** transactions is allowed; selection among multiple valid inclusions is not specified beyond “any cryptographically valid inclusion of Candidate A MAY verify” (no replacement semantics).

### 12. BitcoinAnchorProofV1

BitcoinAnchorProofV1 MAY contain:

| Field | Description |
|-------|-------------|
| `protocol_version` | MUST be `1` |
| `chain` | One of `regtest`, `testnet`, `signet`, `main` |
| `raw_tx` | Serialized Bitcoin transaction (**authority**) |
| `txid` | Claimed txid (auxiliary) |
| `commitment` | Claimed commitment (auxiliary) |
| `block_header` | Serialized 80-byte block header |
| `tx_index` | Merkle leaf index |
| `merkle_branch` | Sibling hashes in internal (little-endian hash) byte order |
| `block_height` | Advisory |
| `tip_height_at_proof` | Advisory |
| `confirmations_at_proof` | Advisory input to wallet confirmation policy |

#### Dual binding (REQUIRED)

Verifiers MUST perform both bindings. Bundle-supplied `txid` and `commitment` MUST NEVER be treated as independent authority.

**Authority hierarchy**

| Cryptographic authority | Auxiliary / derived only (MUST match authority) |
|-------------------------|--------------------------------------------------|
| OpenPGP certificates | — |
| IdentityDocument signed payload (keys 0..8) + signature | IdentityDocument key 9 packets as transport |
| BIP-353 semantic resolution | Proof Bundle PaymentBinding bytes |
| `raw_tx` | provided `txid`, provided `commitment` |
| `block_header` (80 bytes) | `block_height`, confirmation counts |
| Merkle branch + `tx_index` | — |

**Binding 1 — transaction identity and inclusion**

```
raw_tx
  → Bitcoin transaction parse
  → txid = SHA256d(serialized transaction without witness data)
  → Merkle audit path (txid, tx_index, merkle_branch)
  → equals merkle_root field of block_header
```

`SHA256d(x)` means `SHA256(SHA256(x))`.

The provided `raw_tx` MAY include SegWit witness data. Witness data MUST NOT enter the txid preimage. For legacy (non-SegWit) transactions, the full serialization is the txid preimage.

##### Merkle audit path (byte order)

All 32-byte hash values in `txid`, `merkle_branch`, and `block_header.merkle_root` use Bitcoin **internal** byte order (the same order used in consensus Merkle computation — little-endian relative to the hex display hash commonly shown in explorers).

Let `h` start as `computed_txid` (internal order). Let `idx` start as `tx_index` (0-based index of the transaction in the block).

For each sibling `s` in `merkle_branch` in order:

* if `idx` is even: `h = SHA256d(h || s)`
* if `idx` is odd: `h = SHA256d(s || h)`
* then `idx = floor(idx / 2)`

After processing all siblings, `h` MUST equal `block_header.merkle_root` (bytes 36..67 of the 80-byte header, internal order). Otherwise fail with `WRONG_MERKLE_PROOF`.

If a provided `txid` field is present and differs from `computed_txid`, verifiers MUST fail with `TXID_MISMATCH`.

If the block header cannot be parsed as 80 bytes, verifiers MUST fail with `BAD_BLOCK_HEADER`.

**Binding 2 — OP_RETURN commitment**

```
raw_tx
  → parse outputs
  → extract unique V1 B353ID commitment
  → extracted_commitment
```

`extracted_commitment` MUST equal the expected Identity Commitment for the identity under verification. Otherwise verifiers MUST fail with `WRONG_TX_COMMITMENT`.

If a provided `commitment` field is present and differs from `extracted_commitment`, verifiers MUST fail with `WRONG_TX_COMMITMENT`.

Malformed transactions MUST fail with `TX_PARSE_ERROR` (or a more specific parse error subclass).

### 13. Verification Algorithm

The following algorithm is normative for V1 verification of a Proof Bundle. Steps that fail MUST stop verification for the corresponding claim and record the listed error where applicable. Implementations MAY structure code differently if the observable accept/reject conditions are identical.

**Inputs (mandatory):** IdentityDocument bytes; PaymentBinding bytes (or equivalent BIP-353-derived binding under verification); OpenPGP certificate(s) including KROOT/KSIGN; requested BIP-353 identifier; verification time `now`.

**Inputs (optional):** BitcoinAnchorProof; wallet header context (`trusted` or `untrusted`); orphaned flag; confirmation policy; optional transported AnchorMessage bytes (transport/debug only — never authoritative).

AnchorMessageV1 is always **reconstructed locally** from IdentityDocument `domain`, `identifier`, and `kroot_fingerprint`. It is **not** a required verifier input.

1. Parse IdentityDocument and PaymentBinding as Canonical CBOR. Reject non-canonical encodings. If optional AnchorMessage bytes are present, parse them as Canonical CBOR for consistency checking only.
2. If IdentityDocument key `0` ≠ `1`, fail with `UNSUPPORTED_VERSION`.
3. If IdentityDocument contains keys outside `0..9`, reject.
4. Validate field types per IdentityDocumentV1.
5. If key `2` (identifier) ≠ requested identifier, fail with `IDENTIFIER_MISMATCH`.
6. Validate domain (key `1`): non-empty and MUST NOT contain `@`. Validate that identifier (key `2`) ends with `@` + domain. On failure, verification MUST fail. (The reference vector suite records these failures as `INVALID_DOMAIN` or `DOMAIN_IDENTIFIER_INCONSISTENT`; both are document-validation failures under V1.)
7. Import OpenPGP certificate; identify primary key (KROOT) and signing subkey (KSIGN).
8. Compute KROOT fingerprint from the certificate; compare to key `3`. On mismatch, fail with `ROOT_KEY_MISMATCH`.
9. Compute KSIGN fingerprint; compare to key `4`. On mismatch, fail with `SIGNING_KEY_MISMATCH`.
10. If offered certificate material contains a cryptographically valid OpenPGP revocation applicable to KROOT or KSIGN under OpenPGP rules for that key type, fail with `IDENTITY_REVOKED` and set `revocation.status = revoked`. Otherwise set `revocation.status = unknown` (**not known to be revoked** — never treat missing revocation data as proof of non-revocation).
11. Verify standard OpenPGP KROOT→KSIGN binding (`0x18` / `0x19` as applicable). On failure, fail with `INVALID_ROOT_BINDING`.
12. Form SignedIdentityDocumentV1 = map keys `0..8` only. Encode with Canonical CBOR.
13. Form `SignatureInput = IdentityDomainSeparator || CanonicalCBOR(SignedIdentityDocumentV1)` where IdentityDomainSeparator is the 17 bytes `42 49 50 33 35 33 2d 49 44 45 4e 54 49 54 59 00 01`.
14. Semantically verify OpenPGP detached binary signature (key `9`) under KSIGN over `SignatureInput`. On failure, fail with `INVALID_IDENTITY_SIGNATURE`.
15. If `now` is outside `[created_at, expires_at]`, fail with `IDENTITY_EXPIRED`.
16. Obtain semantic BIP-353 payment instructions (caller responsibility: DNSSEC + BIP-321). Construct PaymentBindingV1 from those semantics per §7. Compute its hash. If the Proof Bundle also supplies PaymentBinding bytes, those bytes MUST Canonical-CBOR-decode to an object whose payment hash equals the hash of the BIP-353-derived binding (Proof Bundle PaymentBinding is never an authority that overrides BIP-353 resolution).
17. Compute `PAYMENT_HASH` per §8. Compare to IdentityDocument key `7`. On mismatch, fail with `PAYMENT_BINDING_MISMATCH` and set `payment_verified = false`. On success, set `payment_verified = true`.
18. Reconstruct AnchorMessageV1 locally from document domain, identifier, and KROOT fingerprint. Compute `expected_identity_commitment` per §10. If optional transported AnchorMessage bytes are present, they MUST encode the same map and commitment as the local reconstruction; otherwise fail with `ANCHOR_MISMATCH`. Transported AnchorMessage MUST NOT replace or alter local reconstruction.
19. Set `identity_verified = true` when steps 1–15 succeeded (OpenPGP certificate, KROOT→KSIGN binding, IdentityDocument validation and signature, and document field rules). Bitcoin evidence is **not** required for `identity_verified`. This does **not** mean human identity, legal identity, current control, freshness, or non-compromise.
20. Initialize `identity_anchored = false` and `continuity_verified = false`.
21. If no BitcoinAnchorProof is present, leave `identity_anchored = false` and `continuity_verified = false`. Computing `expected_identity_commitment` locally MUST NOT set `identity_anchored = true`.
22. If BitcoinAnchorProof is present:
    1. Parse `raw_tx`; on failure → `TX_PARSE_ERROR`.
    2. Extract commitment (Binding 2); enforce uniqueness; compare to `expected_identity_commitment` → `WRONG_TX_COMMITMENT` / `AMBIGUOUS_B353ID_OUTPUTS` / `NO_B353ID_OUTPUT` as applicable.
    3. Compute `computed_txid = SHA256d(non-witness serialization)`; compare to provided txid if present → `TXID_MISMATCH`.
    4. Verify Merkle inclusion of `computed_txid` under `block_header.merkle_root` → `WRONG_MERKLE_PROOF`.
    5. Record `transaction_valid` and `inclusion_proof_valid` accordingly.
    6. Evaluate `header_context`: if `untrusted`, MUST NOT treat the result as best-chain `anchor_included`. If `trusted`, evaluate confirmation/orphan status per §14.
    7. If wallet indicates the header is orphaned, set status `anchor_orphaned` and fail inclusion claims with `ORPHANED_ANCHOR`.
    8. Only if Bindings 1 and 2 succeed under V1 rules (valid BitcoinAnchorProof demonstrating publication of `expected_identity_commitment` in a Bitcoin transaction), set `identity_anchored = true`.
    9. If and only if `identity_anchored = true` and the verified on-chain commitment is Candidate A for the same domain, identifier, and KROOT, set `continuity_verified = true`. This does **not** imply latest key, current control, non-compromise, or freshness.
23. Set `freshness.status = unknown` (unless an external V2 freshness layer, out of scope, is used).
24. Set `rollback_resistance = not_provided`.
25. Set `trust.status` according to local policy defaulting to `first_seen`.
26. Set `human_verified = false`.
27. Return the structured verification result.

Property separation (normative):

```
OpenPGP + IdentityDocument     →  identity_verified
BIP-353 + PaymentBinding       →  payment_verified
valid BitcoinAnchorProof       →  identity_anchored
historical Candidate A match
  (same domain+identifier+KROOT,
   after identity_anchored)    →  continuity_verified
```

```
commitment computation  ≠  historical Bitcoin anchor
identity_verified       ≠  identity_anchored
identity_anchored       ≠  freshness / rollback resistance / current control
```

### 14. Reorganization Handling

When a wallet tracks heights, confirmation depth MUST be computed as:

```
depth = tip_height - block_height + 1
```

where `block_height` is the height of the block containing the anchor transaction on the wallet’s accepted chain view, and `tip_height` is the height of that chain tip. Depth is advisory metadata relative to wallet state; it is **not** absolute finality.

Let `confirmation_policy` be a positive integer chosen by the wallet (not a protocol constant).

Anchor status values (only meaningful for best-chain claims when `header_context = trusted`):

| Status | Meaning |
|--------|---------|
| `anchor_seen` | Transaction known but not in a wallet-accepted block (e.g. mempool), or depth = 0 under wallet policy |
| `anchor_included` | `header_context = trusted`, transaction included in the accepted chain, `depth >= 1`, and `depth < confirmation_policy` |
| `anchor_confirmed` | `header_context = trusted`, included in the accepted chain, and `depth >= confirmation_policy` |
| `anchor_orphaned` | Previously associated header is no longer on the wallet's accepted tip |

Rules:

1. Confirmation depth and `confirmation_policy` are **wallet policy**, not absolute finality and not a fixed protocol parameter.
2. This BIP MUST NOT claim absolute Bitcoin finality.
3. A static Proof Bundle alone cannot observe future reorganizations; the wallet MUST re-evaluate headers against its chain view.
4. Merkle proof validity relative to a header (`inclusion_proof_valid`) MUST NOT be equated with best-chain confirmation.
5. When `header_context = untrusted`, a verifier MAY report `inclusion_proof_valid = true` for the claimed header, but MUST NOT set `anchor_included` or `anchor_confirmed` as best-chain states.

### Header context

| Value | Meaning |
|-------|---------|
| `trusted` | The **wallet** asserts that the header belongs to **its** accepted Bitcoin chain view under **its** header/PoW/chain-selection policy. This is **not** a claim of universal network consensus or absolute finality. |
| `untrusted` | The verifier proves only `raw_tx → txid → Merkle proof → claimed block_header`. It MUST NOT conclude best-chain membership, `anchor_included`, or `anchor_confirmed`. |

### 15. Revocation Semantics

V1 revocation policy is **unknown by design**:

1. If a cryptographically valid OpenPGP revocation applicable to KROOT or KSIGN is present in the offered material (per OpenPGP rules for the relevant key type / version), verifiers MUST honor it, fail with `IDENTITY_REVOKED`, and set `revocation.status = revoked`.
2. Otherwise, verifiers MUST set `revocation.status = unknown` (meaning **not known to be revoked**).
3. Absence of revocation information in the Proof Bundle MUST NOT be interpreted as proof that keys are unrevoked (`unknown` ≠ `not revoked`).
4. This BIP MUST NOT define a proprietary revocation transport.

Revocation freshness is **NOT PROVIDED**.

### 16. Freshness Semantics

**V1 does not provide freshness.**

Absent an external freshness mechanism (out of scope / V2):

```
freshness.status = unknown
```

Field clarifications (MUST NOT be read as freshness guarantees):

* `sequence` — ordering intent among signed documents for parties that already share history. MUST NOT be treated as an anti-rollback mechanism or as proof of global latest document.
* `created_at` / `expires_at` — validity window for accepting a signature at time `now`. Expiry is not freshness; an unexpired document MAY still be stale relative to a newer signed document.

**Rollback resistance is NOT PROVIDED.**

Normative claim: V1 provides no cryptographic guarantee that the presented IdentityDocument is the most recent valid document.

Transparency logs are V2 and MUST NOT be required by V1 verifiers.

### 17. Error Conditions

Implementations MUST use the following error conditions where applicable (additional detail suffixes MAY be appended after `:` for diagnostics):

| Code | Condition |
|------|-----------|
| `IDENTIFIER_MISMATCH` | Requested identifier ≠ document identifier |
| `ROOT_KEY_MISMATCH` | Document KROOT fingerprint ≠ certificate |
| `SIGNING_KEY_MISMATCH` | Document KSIGN fingerprint ≠ certificate |
| `INVALID_ROOT_BINDING` | OpenPGP KROOT→KSIGN binding invalid |
| `INVALID_IDENTITY_SIGNATURE` | Detached signature verification failed |
| `IDENTITY_EXPIRED` | Verification time outside validity window |
| `IDENTITY_REVOKED` | Revocation observed in offered material |
| `PAYMENT_BINDING_MISMATCH` | Computed payment hash ≠ document |
| `ANCHOR_MISMATCH` | Optional transported AnchorMessage disagrees with local reconstruction / expected commitment |
| `UNSUPPORTED_VERSION` | protocol_version ≠ 1 |
| `TXID_MISMATCH` | Provided txid ≠ SHA256d(raw_tx) |
| `WRONG_TX_COMMITMENT` | Extracted OP_RETURN commitment mismatch |
| `WRONG_MERKLE_PROOF` | Merkle inclusion check failed |
| `BAD_BLOCK_HEADER` | Block header invalid / wrong size |
| `ORPHANED_ANCHOR` | Wallet marks header orphaned |
| `AMBIGUOUS_B353ID_OUTPUTS` | More than one matching V1 B353ID output |
| `NO_B353ID_OUTPUT` | No matching V1 B353ID output |
| `TX_PARSE_ERROR` | Transaction parse failure |

### 18. Resource Limits

Implementations SHOULD enforce size limits to mitigate denial-of-service from oversized proofs. The following maxima are **RECOMMENDED provisional numeric guidance only**. They are **not** wire-format constants and MUST NOT be treated as protocol `MUST` requirements unless an implementation chooses to hard-enforce them locally:

| Item | Recommended maximum (provisional) |
|------|-----------------------------------|
| Domain UTF-8 bytes | 253 |
| Identifier UTF-8 bytes | 320 |
| IdentityDocument CBOR size | 16384 |
| PaymentBinding CBOR size | 8192 |
| Payment method count | 32 |
| Raw transaction size | 100000 |
| Merkle branch depth | 32 |
| Aggregate Proof Bundle size | 256000 |

Reference implementations MAY hard-enforce raw transaction size and Merkle branch depth for DoS resistance; that choice is local policy, not a change to V1 encoding rules.

### Verifier Result

A verifier MUST produce a structured result. At minimum, the following semantics MUST be distinguishable:

| Field | Semantics |
|-------|-----------|
| `payment_verified` | BIP-353 semantics → PaymentBindingV1 → `PAYMENT_HASH` equals IdentityDocument key `7`. **Not** payment settled / received. |
| `identity_verified` | Certificate + KROOT→KSIGN + signature + document validation. Independent of Bitcoin. **Not** human/legal identity, current control, freshness, or non-compromise. |
| `identity_anchored` | Valid BitcoinAnchorProof demonstrates on-chain publication of `expected_identity_commitment` under V1 rules. Local commitment computation alone is **not** sufficient. **Not** freshness, rollback resistance, or current control. |
| `continuity_verified` | Requires `identity_anchored`; verified historical Candidate A matches same domain+identifier+KROOT. **Not** latest/uncompromised/human. |
| `bitcoin.transaction_valid` | `raw_tx` parsed; txid binding succeeded |
| `bitcoin.inclusion_proof_valid` | Merkle proof under the **claimed** header succeeded (does not imply best chain) |
| `bitcoin.header_context` | `trusted` (wallet-accepted chain view) or `untrusted` |
| `bitcoin.status` | `anchor_seen` / `anchor_included` / `anchor_confirmed` / `anchor_orphaned` (best-chain statuses require `trusted`) |
| `freshness.status` | `unknown` in base V1 |
| `revocation.status` | `unknown` (not known to be revoked) or `revoked` |
| `trust.status` | `first_seen`, `user_trusted`, `external_attestation`, or `untrusted` |
| `rollback_resistance` | `not_provided` |
| `human_verified` | MUST be `false` for claims established solely by this protocol |

`identity_verified` means OpenPGP/document cryptographic verification succeeded. It MUST NOT be presented as human identity verification and MUST NOT depend on Bitcoin anchoring.

## Security Considerations

### Claim matrix (normative ceiling)

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

Implementations and user interfaces MUST NOT claim properties beyond this matrix.

### Compromise notes

* Compromise of **KSIGN** allows issuance of new Identity Documents (including new payment hashes) until revocation is observed and honored.
* Compromise of **KROOT** matching a Bitcoin Candidate A commitment allows full cryptographic impersonation of that protocol identity; Bitcoin history does not distinguish the attacker from the legitimate holder of that KROOT.
* DNS-only attackers cannot forge Identity Documents without keys; payment divergence is detected via payment hash mismatch when documents remain honest.

### Domain separation

Identity, payment, and anchor hashes use distinct domain separators. Implementations MUST NOT accept a hash from one domain as a value in another.

## Privacy Considerations

* The on-chain value is the Identity Commitment (`SHA256` of domain-separated CanonicalCBOR of reconstructed AnchorMessageV1). It does not place the identifier in cleartext on-chain, but parties who know or can guess `(domain, identifier, KROOT fingerprint)` can correlate the commitment.
* Public anchoring creates an observable chronology of identity root commitments.
* A hash commitment is **not** a privacy guarantee. Per the claim matrix, **privacy guarantee = NOT PROVIDED**.
* This protocol does **not** provide anonymity or strong confidentiality.
* Payment destination rotation without re-anchoring avoids linking new destinations through a new on-chain commitment, but published Identity Documents off-chain may still link destinations.

## Trust Model

The following MUST remain distinct:

```
cryptographic validity
        ≠
historical anchoring
        ≠
freshness
        ≠
human identity
        ≠
user trust
```

Trust states:

| State | Meaning |
|-------|---------|
| `first_seen` | Default after cryptographic success |
| `user_trusted` | Explicit local trust |
| `external_attestation` | Out-of-band attestation |
| `untrusted` | Explicit distrust |

This protocol does not establish a global PKI or mandatory fingerprint directory. Verifiers MAY operate in a largely stateless manner on a presented Proof Bundle within the limits documented here (noting that best-chain and orphan detection require wallet header state).

## Non-Goals

V1 does **not** provide:

* human identity verification
* legal identity verification
* a certificate authority or global PKI
* a freshness oracle
* a transparency log
* automatic key recovery / social recovery
* absolute Bitcoin finality
* a privacy protocol
* a canonical Lightning payment-method binding
* a PSBT extension

These MAY be addressed in future versions without changing V1 wire formats.

## Compatibility

BIP-353 remains unchanged. This BIP is complementary: it does not modify BIP-353 DNS labels, DNSSEC validation, or BIP-321 URI resolution. Wallets MAY offer BIP-353 payment resolution without this identity layer, and MAY offer this identity layer only when a Proof Bundle is present.

## Reference Implementation

A reference implementation and frozen fixtures live in the accompanying repository (`reference/`, `test/`, `vectors/`). Semantic OpenPGP verification has been exercised with GnuPG, Sequoia, and openpgp.js as independent implementations (interop evidence, not normative authorities). Bitcoin inclusion fixtures include a real Bitcoin Knots regtest transaction under `vectors/m4/`.

## Test Vectors

Normative checksums of frozen vectors are recorded in `vectors/M7_CHECKSUMS.txt`. Categories:

| Set | Contents |
|-----|----------|
| `vectors/valid/` | Cryptographically valid Proof Bundle (OpenPGP v4) |
| `vectors/invalid/` | Targeted mutations with expected failure codes |
| `vectors/m4/` | Payment binding + Bitcoin regtest OP_RETURN + inclusion proof |
| `vectors/v6/` | OpenPGP v6 interop fixture (does not replace v4 vectors) |
| Security / M6 tests | Adversarial and regression tests under `test/security/`, `test/m6/` |

Independent implementations MUST be able to reproduce verification outcomes for these vectors. Silent regeneration or modification of checksummed vectors is forbidden without an explicit versioned protocol change.

## IANA Considerations

This document defines protocol-internal byte strings and an OP_RETURN application tag `B353ID` for use with this BIP. These are **not** claimed as registrations under any external IANA or BIP namespace allocation process beyond this specification. No DNS RR type changes are requested. No BIP-353 DNS label changes are requested.

## References

1. BIP-353: DNS Payment Instructions  
2. BIP-321: URI Scheme for Bitcoin Payment Instructions  
3. RFC 8949: Concise Binary Object Representation (CBOR)  
4. RFC 9580: OpenPGP  
5. RFC 2119: Key words for use in RFCs to Indicate Requirement Levels  
6. Bitcoin Merkle trees and transaction serialization (Bitcoin consensus rules)  

## Appendix A: Identity Domain Separator Bytes

```
Hex: 42 49 50 33 35 33 2d 49 44 45 4e 54 49 54 59 00 01
     B  I  P  3  5  3  -  I  D  E  N  T  I  T  Y  \0 \x01
Length: 17 bytes
```

## Appendix B: Identity Signature Input

```
SignatureInput =
    IdentityDomainSeparator
    ||
    CanonicalCBOR(SignedIdentityDocumentV1)
```

where `SignedIdentityDocumentV1` contains only keys `0..8`.

Signature: OpenPGP detached binary signature by KSIGN over `SignatureInput`.

# M7 Inventory — Decisions from M1–M6

**Purpose:** Complete inventory of protocol decisions before V1 freeze.  
**Rule:** Values below are those **actually implemented and tested** in this repository. No silent redesign.

---

## Legend

| Status | Meaning |
|--------|---------|
| FROZEN | Normative for V1; change requires new version |
| NOT PROVIDED | Explicit non-goal of V1 |
| CONTEXT-DEPENDENT | Depends on wallet Bitcoin header policy |
| V2 / FUTURE | Out of V1 scope |
| IMPLEMENTATION NOTE | Tooling limit, not a protocol limit |

---

## Cryptography & documents

| ID | Description | Current value | Source | Status | Normative? |
|----|-------------|---------------|--------|--------|------------|
| INV-01 | Protocol version integer | `1` | M1 | FROZEN | Yes |
| INV-02 | IdentityDocument CBOR keys 0..9 | See PROTOCOL_FREEZE_V1 | M1 | FROZEN | Yes |
| INV-03 | Signed payload | fields 0..8 only (key 9 excluded) | M1 | FROZEN | Yes |
| INV-04 | Canonical CBOR | RFC 8949 Core Deterministic; integer keys; reject non-shortest / indefinite / trailing / duplicates | M1 | FROZEN | Yes |
| INV-05 | Unknown IdentityDocument fields | Reject / not forward-compatible in V1 (strict map 0..9) | M1/M6 | FROZEN | Yes |
| INV-06 | Identity domain separator | `BIP353-IDENTITY\|\|0x00\|\|0x01` (17 bytes) hex `4249503335332d4944454e544954590001` | M1 | FROZEN | Yes |
| INV-07 | Signature input | `DOMAIN_SEPARATOR_IDENTITY \|\| CanonicalCBOR(fields 0..8)` | M1 | FROZEN | Yes |
| INV-08 | Signature form | OpenPGP detached **binary** over that input | M1 | FROZEN | Yes |
| INV-09 | Signature verification | Semantic OpenPGP verify — **not** packet byte equality | M1–M3 | FROZEN | Yes |
| INV-10 | Interop engines | GnuPG 2.4.x, Sequoia, openpgp.js 6.3.2 | M2/M3 | FROZEN (requirement) | Yes |
| INV-11 | KROOT | OpenPGP primary key | M1 | FROZEN | Yes |
| INV-12 | KSIGN | OpenPGP signing subkey | M1 | FROZEN | Yes |
| INV-13 | KROOT→KSIGN binding | Standard `0x18` + embedded `0x19` (where applicable) | M1 | FROZEN | Yes |
| INV-14 | OpenPGP v4 support | Required; 20-byte fingerprints | M1 | FROZEN | Yes |
| INV-15 | OpenPGP v6 support | Allowed; 32-byte fingerprints; Sequoia/openpgp.js tested | M3 | FROZEN | Yes |
| INV-16 | GnuPG v6 parse | GnuPG 2.4.8 cannot parse v6 | M3 | IMPLEMENTATION NOTE | No |
| INV-17 | Fingerprint representation | **Raw `bstr`** (not KeyReference map) | M1/M7 | FROZEN | Yes |
| INV-18 | Fingerprint lengths | v4 = 20 bytes; v6 = 32 bytes; must equal certificate fingerprint | M1/M3/M7 | FROZEN | Yes |

---

## Payment

| ID | Description | Current value | Source | Status | Normative? |
|----|-------------|---------------|--------|--------|------------|
| INV-19 | PaymentBindingV1 keys | `0=version`, `1=methods[]` | M4 | FROZEN | Yes |
| INV-20 | Bitcoin method | `type="bitcoin"`, `destination=scriptPubKey` bytes | M4 | FROZEN | Yes |
| INV-21 | Excluded from binding | amount, label, message, pop, request expiry | M4 | FROZEN | Yes |
| INV-22 | Method order | Lexicographic on `(UTF-8(type), destination bytes)` | M4 | FROZEN | Yes |
| INV-23 | Duplicates | Collapse identical `(type, destination)` | M4 | FROZEN | Yes |
| INV-24 | Payment domain separator | `BIP353-IDENTITY/PAYMENT/v1` | M1/M4 | FROZEN | Yes |
| INV-25 | Payment hash | `SHA256(PAYMENT_SEP \|\| CanonicalCBOR(PaymentBindingV1))` | M1/M4 | FROZEN | Yes |
| INV-26 | Input to binding | Semantic BIP-353/BIP-321 result — not raw DNS TXT / URI string | M4 | FROZEN | Yes |
| INV-27 | Lightning (`lno`) | Type string may appear; canonical payload **not** frozen | M4/M5 | V2 / FUTURE | No |

---

## Anchor & Bitcoin

| ID | Description | Current value | Source | Status | Normative? |
|----|-------------|---------------|--------|--------|------------|
| INV-28 | Anchor candidate | **A** = version+domain+identifier+KROOT | M4 | FROZEN | Yes |
| INV-29 | Candidates B/C | Documented, **not** V1 | M4 | NOT V1 | No |
| INV-30 | Anchor domain separator | `BIP353-IDENTITY/ANCHOR/v1` | M1/M4 | FROZEN | Yes |
| INV-31 | Identity commitment | `SHA256(ANCHOR_SEP \|\| CanonicalCBOR(AnchorMessageV1))` | M1/M4 | FROZEN | Yes |
| INV-32 | Commitment excludes | KSIGN, payment_hash, amount, label | M4 | FROZEN | Yes |
| INV-33 | OP_RETURN tag | `B353ID` (6 ASCII bytes) | M4/M7 | FROZEN | Yes |
| INV-34 | OP_RETURN version | `0x01` | M4/M7 | FROZEN | Yes |
| INV-35 | OP_RETURN payload | `B353ID \|\| 0x01 \|\| 32-byte commitment` (39 bytes) | M4/M7 | FROZEN | Yes |
| INV-36 | Multi B353ID outputs | **Reject ambiguous** (`AMBIGUOUS_B353ID_OUTPUTS`) | M6 | FROZEN | Yes |
| INV-37 | raw_tx → txid | `SHA256d(non-witness serialization)` mandatory | M6 | FROZEN | Yes |
| INV-38 | raw_tx → commitment | `extract_identity_commitment(raw_tx)` mandatory | M6 | FROZEN | Yes |
| INV-39 | Bundle txid/commitment fields | Auxiliary only — must match derived values | M6 | FROZEN | Yes |
| INV-40 | BitcoinAnchorProofV1 fields | protocol_version, chain, commitment, txid, raw_tx, block_height, block_header, tx_index, merkle_branch, tip_height_at_proof, confirmations_at_proof | M4/M6 | FROZEN | Yes |
| INV-41 | Header context | `trusted` \| `untrusted` | M6 | FROZEN | Yes |
| INV-42 | Reorg statuses | seen / included / confirmed / orphaned | M4/M6 | FROZEN | Yes |
| INV-43 | Absolute finality | Not claimed | M4–M6 | NOT PROVIDED | Yes (as non-claim) |
| INV-44 | Confirmation depth | Wallet policy | M4 | CONTEXT-DEPENDENT | Soft |
| INV-45 | Multi-anchor same commitment | Any valid inclusion may verify; no replacement rule | M5 | FROZEN (as AMBIGUOUS policy) | Yes |

---

## Trust, freshness, security claims

| ID | Description | Current value | Source | Status | Normative? |
|----|-------------|---------------|--------|--------|------------|
| INV-46 | Freshness | `unknown` without external layer | M4–M6 | NOT PROVIDED | Yes |
| INV-47 | Sequence field | Monotonic intent in signed doc — **not** currentness | M1/M5 | FROZEN (semantics) | Yes |
| INV-48 | Rollback resistance | NOT PROVIDED | M5/M6 | NOT PROVIDED | Yes |
| INV-49 | Revocation | UNKNOWN BY DESIGN; honor OpenPGP revocation if present | M6 | FROZEN | Yes |
| INV-50 | Human identity | `human_verified = false` always from protocol | M4–M6 | NOT PROVIDED | Yes |
| INV-51 | Trust states | first_seen / user_trusted / external_attestation / untrusted | M5 | FROZEN | Yes |
| INV-52 | Security claim matrix | See PROTOCOL_FREEZE_V1 | M5/M6 | FROZEN | Yes |
| INV-53 | Resource limits | `reference/limits.py` — PROVISIONAL numbers, recommended | M6 | PROVISIONAL | Soft |
| INV-54 | Transparency log | — | — | V2 | No |
| INV-55 | KROOT recovery / social recovery | — | — | V2 | No |
| INV-56 | Privacy protocol | — | — | V2 | No |
| INV-57 | PSBT | — | — | FUTURE | No |

---

## Error codes (observable)

| ID | Code | Condition | Source |
|----|------|-----------|--------|
| INV-E01 | `IDENTIFIER_MISMATCH` | Requested name ≠ document | M1 |
| INV-E02 | `ROOT_KEY_MISMATCH` | KROOT fpr ≠ certificate | M1 |
| INV-E03 | `SIGNING_KEY_MISMATCH` | KSIGN fpr ≠ certificate | M1 |
| INV-E04 | `INVALID_ROOT_BINDING` | Subkey binding fails | M1 |
| INV-E05 | `INVALID_IDENTITY_SIGNATURE` | Detached sig fails | M1 |
| INV-E06 | `IDENTITY_EXPIRED` | now ∉ [created, expires] | M1 |
| INV-E07 | `IDENTITY_REVOKED` | Revocation present in offered cert | M1/M6 |
| INV-E08 | `PAYMENT_BINDING_MISMATCH` | payment_hash ≠ computed | M1/M4 |
| INV-E09 | `ANCHOR_MISMATCH` | Anchor/commitment mismatch | M1 |
| INV-E10 | `UNSUPPORTED_VERSION` | protocol_version ≠ 1 | M1 |
| INV-E11 | `TXID_MISMATCH` | proof.txid ≠ SHA256d(raw_tx) | M6 |
| INV-E12 | `WRONG_TX_COMMITMENT` | Extracted OP_RETURN ≠ expected/field | M6 |
| INV-E13 | `WRONG_MERKLE_PROOF` | Merkle audit fails | M4 |
| INV-E14 | `BAD_BLOCK_HEADER` | Header not 80 bytes / unparsable | M6 |
| INV-E15 | `ORPHANED_ANCHOR` | Wallet marks header orphaned | M4 |
| INV-E16 | `AMBIGUOUS_B353ID_OUTPUTS` | >1 matching B353ID v1 output | M6 |
| INV-E17 | `NO_B353ID_OUTPUT` | No matching OP_RETURN | M6 |
| INV-E18 | `TX_PARSE_ERROR` | Malformed raw_tx | M6 |

---

## Vectors

| ID | Set | Status |
|----|-----|--------|
| INV-V01 | `vectors/valid/*` | FROZEN (checksummed M7) |
| INV-V02 | `vectors/invalid/*` | FROZEN |
| INV-V03 | `vectors/m4/*` | FROZEN |
| INV-V04 | `vectors/v6/*` | FROZEN (interop; does not replace v4) |
| INV-V05 | Checksums | `vectors/M7_CHECKSUMS.txt` |

---

## Inventory complete

All normative V1 decisions above map into `PROTOCOL_FREEZE_V1.md` and `M7_PROTOCOL_FREEZE.md`.

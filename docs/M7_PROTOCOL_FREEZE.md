# M7 — Final Protocol Freeze

**Date:** 2026-09-26  
**Objective:** Transform M1–M6 decisions into a complete, deterministic, unambiguous V1 specification.  
**Not:** a new audit; not transparency/recovery/privacy/PSBT/Lightning/freshness V2.

---

## Executive summary

M7 freezes BIP-XXX V1 wire formats, verification rules, non-claims, and test-vector checksums.

| Deliverable | Path |
|-------------|------|
| Inventory | `docs/M7_INVENTORY.md` |
| Normative freeze | `docs/PROTOCOL_FREEZE_V1.md` |
| This report | `docs/M7_PROTOCOL_FREEZE.md` |
| Vector checksums | `vectors/M7_CHECKSUMS.txt` |

**No silent vector mutation.** `vectors/valid`, `vectors/m4`, `vectors/v6` checksums recorded as-is.

### Final decisions closed in M7

1. **Fingerprints = raw `bstr`** (20 or 32 bytes by OpenPGP version) — not `KeyReference`.  
2. **OP_RETURN = `B353ID || 0x01 || commitment`** — FROZEN V1 (was provisional through M6).  
3. All other wire elements confirmed equal to repository constants/vectors.

---

## Freeze gate checklist

| # | Item | Status |
|---|------|--------|
| 1 | IdentityDocument exact | **DONE** |
| 2 | Canonical CBOR exact | **DONE** |
| 3 | Domain separator exact | **DONE** |
| 4 | OpenPGP signature exact | **DONE** |
| 5 | KROOT/KSIGN exact | **DONE** |
| 6 | Fingerprint representation exact | **DONE** (raw bstr) |
| 7 | PaymentBinding exact | **DONE** |
| 8 | Payment ordering exact | **DONE** |
| 9 | Payment hash exact | **DONE** |
| 10 | AnchorMessage exact | **DONE** |
| 11 | Identity commitment exact | **DONE** |
| 12 | OP_RETURN exact | **DONE** |
| 13 | Multiple OP_RETURN policy exact | **DONE** (reject ambiguous) |
| 14 | BitcoinAnchorProof exact | **DONE** |
| 15 | raw_tx → txid binding mandatory | **DONE** |
| 16 | OP_RETURN → commitment binding mandatory | **DONE** |
| 17 | Merkle verification exact | **DONE** |
| 18 | Header context exact | **DONE** |
| 19 | Reorg semantics exact | **DONE** |
| 20 | Freshness = UNKNOWN | **DONE** |
| 21 | Rollback = NOT PROVIDED | **DONE** |
| 22 | Revocation policy exact | **DONE** (UNKNOWN BY DESIGN) |
| 23 | Human identity = NOT PROVIDED | **DONE** |
| 24 | Error states exact | **DONE** |
| 25 | Resource limits documented | **DONE** (numbers PROVISIONAL) |
| 26 | Security claim matrix published | **DONE** |
| 27 | M1–M6 regression PASS | **DONE** (see below) |
| 28 | Test vectors checksummed | **DONE** |

**Normative remaining ambiguities:** empty.

**Non-normative provisional:** recommended size-limit *numbers* (caps exist; exact maxima may be tuned without wire change if documented).

---

## Regression

| Suite | Result |
|-------|--------|
| M1 `test/test_vectors.py` | PASS |
| M4 payment / bitcoin / e2e | PASS |
| M5 adversarial | PASS |
| M6 hardening + F-J2/F-J3 | PASS |
| Vector checksum file | `vectors/M7_CHECKSUMS.txt` |

---

## FROZEN (exhaustive)

- IdentityDocumentV1 map keys 0..9; signed 0..8  
- Deterministic CBOR subset rules  
- Domain separators (identity 17-byte, payment, anchor)  
- OpenPGP detached binary identity signature (semantic verify)  
- KROOT primary / KSIGN subkey + standard binding  
- Fingerprint raw bstr (20/32)  
- PaymentBindingV1 + bitcoin scriptPubKey method  
- Payment method sort + duplicate collapse  
- Payment hash formula + separator  
- AnchorMessage Candidate A + commitment formula  
- OP_RETURN `B353ID||0x01||32`  
- Multi-B353ID → reject ambiguous  
- BitcoinAnchorProof dual binding (txid + commitment from raw_tx)  
- Header context trusted/untrusted  
- Reorg status enum semantics  
- Freshness unknown; rollback not provided; revocation unknown-by-design  
- human_verified = false  
- Trust state names  
- Security claim matrix ceiling  
- Error code set listed in PROTOCOL_FREEZE_V1  
- Test vectors under checksum  

---

## NOT PROVIDED (exhaustive)

- Freshness / currentness  
- Rollback resistance  
- Split-view resistance  
- Absolute finality / reorg immunity  
- Human / legal identity  
- KROOT compromise resistance  
- KSIGN compromise resistance (beyond OpenPGP revoke-if-present)  
- Revocation freshness / mandatory revocation channel  
- Privacy as a hard guarantee  
- Best-chain validation without wallet header context  

---

## PROVISIONAL (exhaustive)

- Numeric resource-limit maxima (soft recommendations; raw_tx & merkle depth enforced in reference)  
- Wallet confirmation-depth policy threshold  

---

## V2 / FUTURE WORK (exhaustive)

- Transparency log / freshness protocol  
- KROOT recovery / social recovery  
- Privacy-hardening protocol  
- PSBT integration  
- Lightning (`lno`) canonical destination format  
- KeyReference-style fingerprint envelope (would be a **new version** if ever adopted)  
- Alternate OP_RETURN tags  

---

## REMAINING AMBIGUITIES

**Normative V1:** none.

**Non-normative:** exact DoS cap integers remain PROVISIONAL recommendations.

---

## M7 STATUS

# **PASS**

---

## BIP DRAFT AUTHORIZATION

# **AUTHORIZED**

V1 protocol is frozen.  

**Next step (only):** **M8 — rédaction du BIP-XXX** as a normative transcription of `PROTOCOL_FREEZE_V1.md`, without modifying the protocol or regenerating frozen vectors.

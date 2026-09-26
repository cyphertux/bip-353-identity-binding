# BIP-353 Identity Binding and Continuity

## Experimental Schnorr Identity Root

⚠️ **EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1**

This branch experiments with an identity root based on **secp256k1 x-only public keys** and **BIP-340 Schnorr signatures**, as an **experimental alternative** to the OpenPGP root used by protocol V1.

It does **not** claim that Schnorr is “better” than OpenPGP.  
It is **not** an official replacement for V1.  
It is **not** an accepted or official BIP.

Normative V1 specification (unchanged on this branch): [`BIP-XXX.md`](BIP-XXX.md).

Experimental design: [`docs/SCHNORR_V2_MINI_SPEC.md`](docs/SCHNORR_V2_MINI_SPEC.md)  
Design inventory: [`docs/SCHNORR_V2_DESIGN_NOTES.md`](docs/SCHNORR_V2_DESIGN_NOTES.md)  
Security review: [`docs/SCHNORR_V2_SECURITY_REVIEW.md`](docs/SCHNORR_V2_SECURITY_REVIEW.md)  
Security claims: [`docs/SCHNORR_V2_SECURITY_CLAIMS.md`](docs/SCHNORR_V2_SECURITY_CLAIMS.md)

---

## Status

| Layer | Status |
|-------|--------|
| V1 OpenPGP protocol | **FROZEN** (M7–M9 PASS on `main`) |
| This branch | **EXPERIMENTAL** research |
| Experimental Schnorr snapshot | **NON-NORMATIVE** experimental freeze (see below) |
| Official BIP / bitcoin/bips | **No** — draft only; number `XXX` not assigned |

Do **not** treat this branch as production-ready, standard, accepted BIP, or a drop-in replacement for V1.

---

## Experimental Freeze

This branch is frozen as an **experimental snapshot**.

The freeze means that the documented implementation and vectors are
**reproducible and internally consistent** at tag `schnorr-v2-experimental-1`.

It does **NOT** mean that the protocol is standardized, production-ready,
security-audited, or an official BIP.

See [`docs/SCHNORR_V2_SECURITY_CLAIMS.md`](docs/SCHNORR_V2_SECURITY_CLAIMS.md).

---

## Relationship with V1

```text
main
 └── V1 OpenPGP — FROZEN
     BIP-XXX.md, vectors/, reference/*.py (V1), M7_CHECKSUMS.txt

experiment/schnorr-identity-v2
 └── Experimental Schnorr identity root
     docs/SCHNORR_V2_*.md
     reference/schnorr_v2/
     vectors/schnorr/
```

**V1 remains the existing reference protocol.**

This branch:

* does **not** modify V1 wire formats, hashes, or OpenPGP rules;
* does **not** modify V1 vectors under `vectors/valid`, `invalid`, `m4`, `v6`;
* does **not** modify `vectors/M7_CHECKSUMS.txt`;
* is **not** automatically backward-compatible with V1 Proof Bundles;
* has its **own** experimental constructions, OP_RETURN tag, and vectors.

Cryptographic identity verified here means **key material and signatures**, not human or legal identity.

---

## Architecture

Experimental architecture (research hypothesis — not a frozen standard):

```text
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
                 IdentityDocument (exp. v2)
                       │          │
                Root pubkey    Signing pubkey
                 BIP-340          BIP-340
                       │          │
                       └────┬─────┘
                            │
                     Schnorr binding
                            │
                            ▼
                      Bitcoin Anchor
                            │
                            ▼
                        Verifier
```

---

## V1 → experimental differences

| Component | V1 | Experimental Schnorr branch |
|-----------|----|------------------------------|
| Identity root | OpenPGP `KROOT` | BIP-340 x-only `root_pubkey` (32 bytes) |
| Signing key | OpenPGP `KSIGN` | BIP-340 x-only `signing_pubkey` (32 bytes) |
| Root → signing binding | OpenPGP `0x18` / `0x19` | CBOR `SubkeyBinding` + BIP-340 over TaggedHash |
| Identity signature | OpenPGP detached binary | BIP-340 Schnorr (64 bytes) |
| Payment binding | PaymentBindingV1 | **Same semantic structure**; new TaggedHash payment domain |
| Bitcoin anchor | Candidate A + `B353ID` | Experimental equivalent + tag `B353S2` |
| OpenPGP certificates | Yes | No |
| RFC 9580 dependency | Yes | No |
| Status | **FROZEN** | **Experimental only** |

---

## Cryptographic model

**Root → signing authorization (Option B):**

```text
Root key
    ↓
CanonicalCBOR(SubkeyBinding)
    ↓
TaggedHash(TAG_SUBKEY_BINDING, …)
    ↓
BIP-340 Sign/Verify under root_pubkey
    ↓
Signing key authorized
```

**Identity document:**

```text
IdentityDocument (without signature field)
    ↓
Canonical CBOR
    ↓
TaggedHash(TAG_IDENTITY, …)
    ↓
BIP-340 Sign/Verify under signing_pubkey
```

**Anchor:**

```text
AnchorMessage { version, domain, identifier, root_pubkey }
    ↓
TaggedHash(TAG_ANCHOR, …) → 32-byte commitment
    ↓
OP_RETURN payload with experimental tag B353S2
```

Exact tags and constructions: [`docs/SCHNORR_V2_MINI_SPEC.md`](docs/SCHNORR_V2_MINI_SPEC.md).

---

## Payment Binding

Payment modeling stays conceptually aligned with V1:

```text
BIP-353 resolution
        ↓
semantic payment object
        ↓
PaymentBinding
        ↓
payment hash  (TaggedHash TAG_PAYMENT in this experiment)
        ↓
IdentityDocument
```

Payment binding proves **consistency** between the identity document and the resolved payment instructions.  
It does **not** prove that a payment occurred, settled, or was received.

---

## Experimental OP_RETURN tag: `B353S2`

| | V1 | This experiment |
|--|----|-----------------|
| Tag ASCII | `B353ID` | `B353S2` |
| Role | Frozen V1 identity commitment | Experimental Schnorr lab only |

* `B353ID` remains **exclusively** associated with V1.
* `B353S2` is **experimental**, not an external standard, and must not be confused with V1.
* Payload shape (lab): `B353S2 || 0x01 || 32-byte commitment`.

---

## Reference implementation

Path: [`reference/schnorr_v2/`](reference/schnorr_v2/)

| Item | Value |
|------|--------|
| Language | Python 3 |
| BIP-340 library | `embit==0.8.0` |
| Canonical CBOR | Reuses V1 encoder via `reference.cbor` (read-only) |

### Setup

```bash
uv venv reference/schnorr_v2/.venv
uv pip install --python reference/schnorr_v2/.venv/bin/python -r reference/schnorr_v2/requirements.txt
```

### Demo (happy path)

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python -m reference.schnorr_v2.demo
```

### Negative unit checks (not frozen vectors)

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python -m reference.schnorr_v2.test_negative
```

More detail: [`reference/schnorr_v2/README.md`](reference/schnorr_v2/README.md).

---

## Experimental Vectors

Directory: [`vectors/schnorr/`](vectors/schnorr/)

| Vector | Intent |
|--------|--------|
| `V2-VALID-001` | Full binding + payment + document + anchor verifies |
| `V2-INVALID-001` | Signing key substituted → `INVALID_SUBKEY_BINDING` |
| `V2-INVALID-002` | Document mutated after sign → `INVALID_IDENTITY_SIGNATURE` |
| `V2-INVALID-003` | Wrong-root anchor → `ANCHOR_MISMATCH` |
| `V2-INVALID-004` | PaymentBinding mutated → `PAYMENT_BINDING_MISMATCH` |
| `V2-INVALID-005` | Wrong TaggedHash tag → `INVALID_IDENTITY_SIGNATURE` |

Checksums: [`vectors/schnorr/SCHNORR_V2_CHECKSUMS.txt`](vectors/schnorr/SCHNORR_V2_CHECKSUMS.txt)  
(Independent of [`vectors/M7_CHECKSUMS.txt`](vectors/M7_CHECKSUMS.txt).)

### Verify frozen fixtures (does **not** call the generator)

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_vectors.py
```

Vectors are **experimental fixtures**, not a normative suite.  
Do not silently regenerate or edit them; see [`vectors/schnorr/README.md`](vectors/schnorr/README.md).

Manual regeneration (review diff afterwards):

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python -m reference.schnorr_v2.generate_vectors --write
```

---

## Security properties (demonstrated in this lab)

Properties exercised by the reference + vectors:

* Root → signing key binding authenticity (BIP-340)
* Identity document signature authenticity (BIP-340)
* Payment binding integrity (`payment_hash` match)
* Anchor commitment integrity (`B353S2` + TaggedHash)
* Continuity against a mismatched anchored root key

These verify **cryptographic identity binding** (keys and signatures), **not** human identity.

### Not provided

Aligned with the experimental mini-spec claim ceiling:

* Freshness  
* Rollback resistance  
* Split-view resistance  
* Human identity / legal identity  
* Current human control  
* Revocation freshness  
* Absolute Bitcoin finality  
* Privacy / anonymity  
* Root-key compromise resistance  
* Signing-key compromise resistance  

---

## Threat model (short)

| Scenario | What this experiment shows |
|----------|----------------------------|
| Compromised website / DNS | Attacker can change published payment data, but cannot produce a valid Schnorr proof under an established `root_pubkey` / authorized `signing_pubkey` without those secrets. |
| Compromised signing key | Attacker can forge IdentityDocuments until binding expiry / rotation policy; root binding still constrains which signing keys are authorized. **NOT PROVIDED:** full compromise resistance. |
| Compromised root key | Full usurpation of the cryptographic identity root for that identifier context. **NOT PROVIDED:** root compromise resistance (same ceiling as V1 KROOT). |
| Bitcoin reorg | Anchor inclusion is only as strong as the wallet’s header/confirmation policy. **No absolute finality.** |

---

## Experimental Roadmap

```text
Phase 0 — Branch isolation              PASS
Phase 1 — Design inventory              PASS
Phase 2 — Mini-spec                     PASS
Phase 3 — Reference implementation      PASS
Phase 4 — Experimental vectors          PASS
Phase 5 — Documentation                 PASS
Phase 6 — Security review               FAIL (F-S1)
Phase 6.1 — Bitcoin dual-binding        PASS (F-S1 RESOLVED)
Phase 7 — Experimental freeze gate      CURRENT
```

Possible future research (not promised):

* deeper interoperability testing  
* independent second implementation  
* security review  
* possible key-management model  
* possible revocation design  
* possible freshness mechanisms  

---

## Non-Goals

This branch does **not** attempt to:

* modify V1;
* define an official BIP;
* replace OpenPGP in V1;
* define HD derivation (`m/353'/…`);
* define recovery;
* define a revocation protocol;
* define freshness;
* define a transparency log;
* provide human identity verification.

---

## V1 on this repository

For the frozen OpenPGP protocol (still present and unchanged):

* Spec: [`BIP-XXX.md`](BIP-XXX.md)  
* Vectors: `vectors/valid`, `vectors/invalid`, `vectors/m4`, `vectors/v6`  
* Checksums: [`vectors/M7_CHECKSUMS.txt`](vectors/M7_CHECKSUMS.txt)  
* Reference: `reference/*.py` (not under `schnorr_v2/`)

This repository is **not** the official [bitcoin/bips](https://github.com/bitcoin/bips) repository. BIP number `XXX` is provisional.

---

## License

BSD-2-Clause — see [`LICENSE`](LICENSE).

# Milestone 4 — BIP-353 Semantic Payment Binding + Bitcoin Identity Anchor + Inclusion Proof

**Status:** PASS  
**Date:** 2026-09-26  
**Scope honored:** No transparency log, recovery, PSBT, UI, or final BIP text.

M1–M3 vectors **unchanged**. M4 adds `vectors/m4/` from a **real Bitcoin Knots regtest** transaction (not mainnet, not simulated).

---

## BIP-353 semantic model

Official BIP-353 resolves:

```
user@domain
  → DNS TXT at user.user._bitcoin-payment.<domain>
  → DNSSEC to root
  → reconstruct bitcoin: URI (BIP-321)
  → payment instructions
```

**What Identity Binding consumes**

| Source | Used? |
|--------|-------|
| Raw DNS TXT octets | **No** |
| Raw `bitcoin:` URI string | **No** |
| DNS wire response | **No** |
| Resolved BIP-321 payment instructions (semantic) | **Yes** |
| On-chain destinations as **scriptPubKey** | **Yes** |
| `amount` / `label` / `message` / `pop` | **No** |

BIP-353 already requires DNSSEC validation and URI reconstruction before parsing. M4 binds the **durable destination set**, not request metadata or DNS representation.

Pipeline:

```
identifier
  → BIP-353 DNS + DNSSEC
  → BIP-321 payment instructions
  → drop amount/label/message/pop
  → address → scriptPubKey
  → PaymentBindingV1
  → payment_hash
```

---

## PaymentBindingV1

```
PaymentBindingV1 = {
  0: version,          ; 1
  1: methods: [
       { 0: type, 1: destination_bytes },
       ...
     ]
}
```

Canonical encoding: deterministic CBOR. Methods sorted by `(UTF-8(type), destination)`.

Duplicates collapsed. Parse **rejects** non-canonical byte encodings (`parse_payment_binding`).

### What is kept vs excluded

| Kept | Excluded |
|------|----------|
| Destination method type | `amount` |
| Canonical destination payload | `label` |
| | `message` |
| | `pop` / `req-pop` |
| | ephemeral expiry of a single request |

**Consequence:** changing amount/label does **not** change `payment_hash`. Changing destination does.

---

## PaymentMethod registry

Minimal envelope registry (not a catalogue of all payment systems):

| `type` | Canonical payload | Status |
|--------|-------------------|--------|
| `bitcoin` | `scriptPubKey` bytes | **Defined in M4** |
| `test-method` | opaque bytes | Test-only |
| `sp` | BIP-352 identifier | **Reserved** — format owned by BIP-352 |
| `lno` | BOLT12 offer | **Reserved** — format owned by Lightning |

**Principle:** BIP-XXX defines the envelope; each payment protocol defines its own destination canonicalisation. No fake Lightning formats were invented.

Order rule (tested): `lexicographic(type_utf8 || destination_bytes)`.

---

## Payment hash

```
PAYMENT_HASH = SHA256(
  "BIP353-IDENTITY/PAYMENT/v1" || CanonicalCBOR(PaymentBindingV1)
)
```

Tag remains **provisional** (works; not BIP-number-assigned).

| Vector | Result |
|--------|--------|
| A same object | identical hash |
| B different destination | different hash |
| C amount change (excluded) | identical |
| D label change (excluded) | identical |
| E methods reordered | identical (+ identical CBOR) |
| F non-canonical CBOR | **rejected** on parse |

---

## Bitcoin script vs address

Always bind **scriptPubKey**, never address text.

Verified conversions (regtest):

| Type | Result |
|------|--------|
| P2PKH | PASS |
| P2SH | PASS |
| P2WPKH | PASS |
| P2WSH | classified |
| P2TR | PASS |

Same script ⇒ same `payment_hash` regardless of bech32 case / text encoding. The protocol does not depend on a particular address representation.

---

## Identity anchor

### Candidates compared

| Candidate | Contents | KSIGN rotate | Payment rotate | New Bitcoin tx? |
|-----------|----------|--------------|----------------|-----------------|
| **A (retained)** | domain + identifier + KROOT | no | no | only on KROOT change |
| B | A + payment_hash | no | **yes** | every destination change |
| C | A + KSIGN + payment_hash | **yes** | **yes** | frequent |

**Retained: Candidate A.**

Evidence in `vectors/m4/anchor-candidates.json` and tests `I_*`:

- Payment destination changes often (BIP-353 recommends rotating reused on-chain addresses).
- KSIGN should rotate without on-chain cost.
- Continuity of identity = continuity of **KROOT**, not of a UTXO destination.

```
IDENTITY_COMMITMENT = SHA256(
  "BIP353-IDENTITY/ANCHOR/v1" || CanonicalCBOR(AnchorMessageV1)
)

AnchorMessageV1 = { version, domain, identifier, root_fingerprint }
```

Sensitivity tests: domain / identifier / root / version each change the commitment.

**Consistency check:** M4 regtest commitment equals M1 fixture commitment when using the same `(domain, identifier, KROOT)`:

`82282ed2aebfcbe223a040db5689e569925503f321e643163eeab0ceb47968ae`

---

## OP_RETURN analysis

Provisional encoding:

```
scriptPubKey = OP_RETURN <push: tag || version || commitment>
tag     = "B353ID"   (6 bytes)   — NOT normative / not allocated
version = 0x01
commitment = 32 bytes
payload = 39 bytes  (within typical ≤80-byte policy)
```

| Concern | Assessment |
|---------|------------|
| Size | 39 B payload — fine under common relay policy |
| Standardness | Standard `OP_RETURN` data carrier |
| Namespace | ASCII tag is a **collision hedge only** until BIP process assigns something |
| Versioning | Version byte allows layout evolution |
| Alternatives considered | `BIP353`, `B353I\x01` — same size class; no official choice yet |

**Recommendation:** keep `B353ID||0x01||commitment` as **implementation provisional** for tests; freeze only after BIP number + registry discussion. Do not treat as final.

---

## Bitcoin proof

`BitcoinAnchorProofV1` (independent object — **not** a PSBT type):

| Field | Purpose |
|-------|---------|
| `chain` | must not be `main` in M4 tests |
| `commitment` | expected identity commitment |
| `txid` / `raw_tx` | locating OP_RETURN |
| `block_header` (80 B) | merkle root + chain link |
| `tx_index` + `merkle_branch` | SPV inclusion |
| `block_height` / tip / confirmations | depth policy |

### SPV model

Verifier checks:

1. `commitment` matches AnchorMessage  
2. Merkle branch links `txid` → header `merkle_root`  
3. (Wallet-local) header is on its best chain  
4. Confirmations ≥ wallet policy → `ANCHOR_CONFIRMED`

Full node can additionally validate the whole block/chain; SPV trusts headers.

### Real fixture

Generated with Bitcoin Knots **v29.1** regtest (`scripts/generate_m4_regtest.py`):

| Field | Value |
|-------|-------|
| chain | `regtest` |
| txid | `59fb1a68fe40e8b862c3fbcb1821385fe2ce217ef595a006a0909ced75dbd461` |
| height | 102 |
| commitment | `82282ed2…7968ae` |

---

## Reorg

Statuses (wallet-facing):

| Status | Meaning |
|--------|---------|
| `anchor_seen` | tx known, not in a block |
| `anchor_included` | in a block, depth < policy |
| `anchor_confirmed` | depth ≥ policy |
| `anchor_orphaned` | previous block orphaned / reorged out |
| `anchor_finality_unknown` | insufficient info |

**No absolute finality.** After reorg, verifier must **not** keep treating an orphaned inclusion as confirmed (`P_orphaned-anchor`, `P_reorged-anchor`).

---

## End-to-end verification

```
user@domain
  → BIP-353/DNSSEC (assumed valid for payment_verified)
  → PaymentBindingV1 → payment_hash
  → IdentityDocument (M1–M3 OpenPGP)
  → KROOT → identity_commitment
  → OP_RETURN tx → block → inclusion proof
  → VERIFIER
```

Actual M4 e2e result (`test/m4_e2e_result.json`):

```json
{
  "payment_verified": true,
  "identity_verified": true,
  "identity_anchored": true,
  "anchor_included": true,
  "freshness": "unknown",
  "human_verified": false
}
```

**Never** `HUMAN VERIFIED` from this protocol alone.

---

## Attack vectors

| Fixture | Expected | Result |
|---------|----------|--------|
| wrong-commitment | WRONG_COMMITMENT | PASS |
| wrong-merkle-proof | WRONG_MERKLE_PROOF | PASS |
| wrong-merkle-root | WRONG_MERKLE_PROOF | PASS |
| wrong-opreturn | WRONG_COMMITMENT | PASS |
| orphaned-anchor | ORPHANED_ANCHOR | PASS |
| reorged-anchor | ORPHANED_ANCHOR | PASS |

Protocol-layer payment attacks remain covered by M1 `wrong-payment*` vectors.

Canonicalisation attacks: non-canonical method order rejected; unknown CBOR fields change hash; duplicates collapsed.

---

## Deliverables

| Path | Role |
|------|------|
| `reference/payment_binding.py` | PaymentBindingV1, address→script, registry |
| `reference/bitcoin_anchor.py` | Candidates A/B/C, commitment, OP_RETURN |
| `reference/bitcoin_proof.py` | Merkle/SPV, statuses, proof object |
| `scripts/generate_m4_regtest.py` | Real regtest fixture generator |
| `vectors/m4/*` | Reproducible anchor + proof |
| `test/test_m4_payment.py` | Parts B–G, Q |
| `test/test_m4_bitcoin.py` | Parts H–P |
| `test/test_m4_e2e.py` | Part O |

Reproduce:

```bash
# regtest node (isolated datadir)
bitcoind -datadir=/tmp/bip353-regtest -daemon
# … wallet + 101 blocks as in generate script …
python3 scripts/generate_m4_regtest.py
python3 test/test_m4_payment.py
python3 test/test_m4_bitcoin.py
python3 test/test_m4_e2e.py
```

---

## Success criteria

| Requirement | Result |
|-------------|--------|
| Semantic BIP-353 → PaymentBinding | PASS |
| payment_hash vectors A–F | PASS |
| scriptPubKey not address text | PASS |
| Candidate A retained with evidence | PASS |
| Real Bitcoin tx (regtest) | PASS |
| Inclusion proof verified | PASS |
| freshness unknown | PASS |
| human_verified always false | PASS |

### Milestone 4 overall: **PASS**

---

## FROZEN

- Bind **semantic** BIP-321 destinations after BIP-353/DNSSEC — never raw TXT/URI bytes.  
- Exclude amount/label/message/pop from identity payment binding.  
- On-chain destinations as **scriptPubKey** bytes.  
- Method order: lexicographic `(type, destination)`; strict CBOR parse.  
- Anchor **Candidate A**: `domain + identifier + KROOT` only.  
- Separation: commitment ≠ inclusion ≠ confirmation.  
- `human_verified` is never set by this protocol.  
- freshness remains `unknown` in V1.  
- M4 tests use regtest/signet/testnet only — not mainnet.

## PROVISIONAL

- Domain separator strings `…/PAYMENT/v1` and `…/ANCHOR/v1`.  
- OP_RETURN tag `B353ID` + version byte (needs BIP allocation).  
- Confirmation depth policy (wallet-local; tests used `1` on regtest).  
- Reserved method types `sp` / `lno` without normative payloads yet.  
- `BitcoinAnchorProofV1` field set (pre-PSBT).

## OPEN

- Official OP_RETURN / commitment namespace registration.  
- Normative silent-payment / BOLT12 canonical destination encodings.  
- Header-chain authentication details for pure SPV wallets.  
- Exact confirmation recommendations per threat model.  
- Whether multiple on-chain scriptPubKeys in one binding need additional policy.  
- Transparency / recovery / PSBT (explicitly deferred).  
- Final BIP media-wiki text.

---

## Recommendation for M5

**Single next milestone:**

> **M5 — Adversarial protocol audit**

Attack the *composed* system (M1–M4) as a hostile reviewer:

1. Cross-layer attacks (DNS + HTTP + OpenPGP + Bitcoin).  
2. Replay / cross-identifier / cross-domain.  
3. Split-view without transparency.  
4. Weak confirmation / reorg games.  
5. Ambiguous payment methods / registry abuse.  
6. Implementation pitfalls (NUL separators, non-canonical CBOR, address malleability).  
7. Produce a go/no-go list before any BIP draft.

Still **no final BIP** until M5 completes.

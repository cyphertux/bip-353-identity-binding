# Experimental Schnorr V2 — Adversarial Review (Phase 10)

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

| Field | Value |
|-------|--------|
| Reference snapshot | `schnorr-v2-experimental-2` |
| Historical snapshot | `schnorr-v2-experimental-1` (unchanged) |
| Seed | `a3535210` (`0xA3535210`) |
| Harness | `test/schnorr_v2/test_adversarial.py` |
| Differential | `independent/schnorr_v2/src/adversarial_diff.mjs` |
| Results | `test/schnorr_v2/adversarial_results.json` |

This review does **not** claim formal verification, a complete security proof,
or absence of all vulnerabilities.

---

## Scope

Active search for malformed / mutated / adversarial inputs that the experimental
V2 stack would **accept** when it should **reject**, covering:

* canonical CBOR parser boundaries  
* BIP-340 signature mutations  
* domain separation  
* root/signing binding  
* IdentityDocument / PaymentBinding  
* Bitcoin serialization, B353S2, Merkle, dual-binding  
* claim / state separation  
* sequence / time boundaries  
* Python ↔ JavaScript differential behaviour  

**Out of scope:** PoW / best-chain / finality; production hardening; protocol
feature additions; silent patches of discovered issues.

---

## Environment

| Item | Value |
|------|--------|
| OS | Linux |
| Python reference | `reference/schnorr_v2/` + `embit` (existing venv) |
| Independent | Node.js + `@noble/curves@1.8.1` / `@noble/hashes@1.7.1` |
| Fuzz mode | Deterministic mutation generator (fixed seed) — no unreproducible RNG |

---

## Baseline

| Suite | Result |
|-------|--------|
| `test_vectors.py` | PASS |
| `test_bitcoin_proof.py` | PASS |
| Independent `run.mjs` (16 vectors) | PASS |
| Tag `schnorr-v2-experimental-2` | verified / unchanged |

**baseline = PASS**

---

## Fuzzing methodology

1. Build a known-good identity + dual-binding fixture from fixed test keys.  
2. Apply **named, seed-tagged mutations** (bit flips, field swaps, CBOR malformations,
   BTC proof matrix).  
3. Expect **reject** unless the case is an explicit positive control.  
4. Emit `adversarial_results.json` with `seed`, `expected`, `actual`.  
5. Cross-check a shared `differential_cases.json` in JS without importing the
   Python reference package.

No frozen vector JSON and no freeze checksum files were modified.

---

## Properties tested

| ID | Property | Result |
|----|----------|--------|
| A | `encode(x)` stable / canonical | PASS |
| B | `decode(encode(x))` round-trip for allowed structures | PASS |
| C | mutation of valid signed message → reject | PASS |
| D | semantic payment mutation → different `payment_hash` | PASS |
| E | invalid Bitcoin proof → not `identity_anchored` | PASS |
| F | duplicate `B353S2` → reject | PASS |
| G | wrong TaggedHash tag → verify fail | PASS |
| H | `identity_verified` ⇏ `identity_anchored` | PASS |

---

## Mutation classes

| Class | Cases (approx.) | Outcome |
|-------|-----------------|---------|
| CBOR non-canonical / truncated / indefinite / trailing | covered | reject |
| BIP-340 sig / pubkey / message cross | covered | reject |
| Domain-separation tag swap | covered | reject |
| Root/signing substitution | covered | reject |
| Identity field mutate / remove / type-sub | covered | reject |
| Payment SPK / method / excluded fields | covered | PASS |
| Anchor / B353S2 / B353ID confusion | covered | reject |
| Raw tx / Merkle / header / dual-binding matrix | covered | reject invalids |
| State separation | covered | PASS |
| Sequence / time | covered | see findings |

---

## Cross-implementation comparison

Shared cases: CBOR rejects, TaggedHash digests, Schnorr mutations, B353S2 scripts,
dual-binding subset.

| Result | Count |
|--------|-------|
| Agree | 21 |
| Documented divergence | 1 (`ADV-M1`) |
| Unexplained divergence | **0** |

---

## Findings

| ID | Severity | Title | Action |
|----|----------|-------|--------|
| **ADV-M1** | **MEDIUM** | JS CBOR accepts invalid UTF-8 text (`61ff`); Python rejects | **implementation defect** (Phase 11); **not patched** |
| ADV-L1 | LOW | F-S2 dict verify API (pre-existing) | accepted for freeze |
| ADV-L2 | LOW | `build_signed_map` accepts `created_at < 0` before CBOR | **DO NOT PATCH**; encode path rejects |
| ADV-I1 | INFORMATIONAL | Non-merkle header fields not validated | matches non-claim (no PoW) |
| ADV-I2 | INFORMATIONAL | `ROLLBACK RESISTANCE = NOT PROVIDED` | sequence not compared |
| ADV-I3 | INFORMATIONAL | F-S4 binding omits domain | by design |

### ADV-M1 — reproduction (Phase 10) + resolution (Phase 11)

```text
seed:              a3535210
minimal case:      ADV-M1-minimal
input_bytes_hex:   61ff          # CBOR major-type-3, length 1, payload 0xFF
python:            reject  CBORError("invalid UTF-8")
javascript:        ACCEPT  decoded U+FFFD; reencode 63efbfbd (≠ input)
expected (RFC 8949 + V2 subset): reject
```

**Layer:** UTF-8 validation inside CBOR text-string decode (not framing, not
application domain rules, not Unicode normalization).

**Root cause (decision C — implementation defect):**  
`independent/schnorr_v2/src/lib.mjs` uses `new TextDecoder().decode(...)` without
`{ fatal: true }`. Python `bytes.decode("utf-8")` is strict. Spec / RFC 8949
require well-formed UTF-8 for major type 3.

**Phase 11 matrix (seed `a3535210`):**

| Input class | Python | JavaScript | Encoding same? | Protocol impact |
|-------------|--------|------------|----------------|-----------------|
| ASCII / valid 2–4 byte / boundaries | accept | accept | **YES** | none |
| NFC vs NFD pair | accept | accept | each stable; NFC≠NFD | intentional (no Unicode norm) |
| overlong / surrogate / truncated / bad cont / `61ff` | reject | ACCEPT | n/a | **ADV-M1 class** |

Both-accept encoding mismatches: **0** (no CRITICAL dual-digest on valid UTF-8).

**Signature / hash impact:**  
If digests use **wire bytes**, Python never accepts `61ff` as a document.  
If JS **decodes → re-encodes** then hashes, `TaggedHash(TAG_IDENTITY, 61ff)` ≠
`TaggedHash(TAG_IDENTITY, 63efbfbd)` (demonstrated). That is decode/re-encode skew
on **invalid** UTF-8, not two different valid encodings of one accepted identity.

**Resolution:** Documented as implementation defect. **No silent patch in Phase 11.**  
Fix candidate for a future dedicated phase: `TextDecoder("utf-8", { fatal: true })`.  
Snapshot `schnorr-v2-experimental-2` **unchanged**.

**Remaining limitation:** Independent JS still accepts invalid UTF-8 CBOR text until fixed.

**Unicode normalization:** `NOT PART OF V2` — see [`SCHNORR_V2_CBOR_UTF8.md`](SCHNORR_V2_CBOR_UTF8.md).

### Dual-binding matrix (summary)

| Tx | Merkle | B353S2 | Commitment | Expected | Actual |
|----|--------|--------|------------|----------|--------|
| valid | valid | valid | valid | anchored | anchored |
| valid | invalid | valid | valid | reject | reject |
| valid | valid | missing | valid | reject | reject |
| valid | valid | duplicate | valid | reject | reject |
| valid | valid | valid | wrong | reject | reject |
| mutated | stale proof | valid | valid | reject | reject |
| valid | wrong header root | valid | valid | reject | reject |

No invalid case obtained `identity_anchored = true`.

### State separation

```text
valid identity + payment, no bitcoin_proof
→ identity_verified=true, payment_verified=true,
  identity_anchored=false, continuity_verified=false
```

Logical OP_RETURN alone does **not** set `identity_anchored`.

---

## Limitations

* Mutation coverage is extensive but not exhaustive (no infinite fuzz budget).  
* No consensus/PoW/chain validation.  
* No network / DNS / BIP-353 resolution adversarial tests.  
* Independent JS UTF-8 gap (`ADV-M1`) root-caused in Phase 11 as implementation
  defect; remains open until an explicit fix phase.  

---

## Freeze integrity

| Check | Result |
|-------|--------|
| `schnorr-v2-experimental-2` | **unchanged** |
| `schnorr-v2-experimental-1` | **unchanged** |
| V1 / V1 vectors / V1 checksums | **unchanged** |
| Frozen V2 vectors / freeze checksums | **unchanged** |

---

## Conclusion

Phase 10 adversarial properties behave as specified for dual-binding, signatures,
domain separation, and claim separation. **No CRITICAL or HIGH** findings.
One **MEDIUM** cross-implementation UTF-8 CBOR divergence is reproduced and
documented without a silent patch. Experimental V2 remains non-normative.

# Experimental Schnorr V2 — Adversarial Review (Phase 10–12)

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

| Field | Value |
|-------|--------|
| Reference snapshot | `schnorr-v2-experimental-2` |
| Historical snapshot | `schnorr-v2-experimental-1` (unchanged) |
| Seed | `a3535210` (`0xA3535210`) |
| Harness | `test/schnorr_v2/test_adversarial.py` |
| Differential | `independent/schnorr_v2/src/adversarial_diff.mjs` |
| UTF-8 matrix | `independent/schnorr_v2/src/phase11_utf8.mjs` |
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
feature additions (beyond independent-impl conformance fixes).

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

## Findings

| ID | Severity | Title | Action |
|----|----------|-------|--------|
| **ADV-M1** | **RESOLVED** | JS CBOR accepted invalid UTF-8 (`61ff`) | **RESOLVED — IMPLEMENTATION DEFECT** (Phase 12) |
| ADV-L1 | LOW | F-S2 dict verify API (pre-existing) | accepted for freeze |
| ADV-L2 | LOW | `build_signed_map` accepts `created_at < 0` before CBOR | open (encode path rejects) |
| ADV-I1 | INFORMATIONAL | Non-merkle header fields not validated | matches non-claim (no PoW) |
| ADV-I2 | INFORMATIONAL | `ROLLBACK RESISTANCE = NOT PROVIDED` | sequence not compared |
| ADV-I3 | INFORMATIONAL | F-S4 binding omits domain | by design |

### Open severity counts (post Phase 12)

| Severity | Open |
|----------|------|
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | **0** |
| LOW | 2 |
| INFORMATIONAL | 3 |

### ADV-M1 — history

| Field | Value |
|-------|--------|
| Status | **RESOLVED — IMPLEMENTATION DEFECT** |
| Root cause | independent implementation (`TextDecoder` non-fatal) |
| Fix | `TextDecoder("utf-8", { fatal: true })` in `independent/schnorr_v2/src/lib.mjs` |
| Protocol change | **NONE** |
| Snapshot change | **NONE** (`schnorr-v2-experimental-2` unchanged) |

```text
seed:              a3535210
minimal case:      ADV-M1-minimal
input_bytes_hex:   61ff

Phase 10/11 (before fix):
  python:      reject
  javascript:  ACCEPT (U+FFFD) → reencode 63efbfbd

Phase 12 (after fix):
  python:      reject
  javascript:  reject
```

**Layer:** UTF-8 validation inside CBOR text-string decode (not framing, not
application domain rules, not Unicode normalization).

**Phase 12 matrix:** ZERO UTF-8 divergence (31/31 agree; invalid → both reject;
valid → same canonical CBOR bytes).

**Signature / hash impact:** invalid UTF-8 rejected **before** any V2
signing/hashing path in both implementations.

**Unicode normalization:** `NOT PART OF V2` — see [`SCHNORR_V2_CBOR_UTF8.md`](SCHNORR_V2_CBOR_UTF8.md).

---

## Dual-binding matrix (summary)

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

---

## Cross-implementation comparison (Phase 12)

| Result | Count |
|--------|-------|
| UTF-8 matrix agree | 31/31 |
| Differential CBOR/crypto cases | 22/22 |
| Unexplained UTF-8 divergence | **0** |

---

## Limitations

* Mutation coverage is extensive but not exhaustive.  
* No consensus/PoW/chain validation.  
* Resolving ADV-M1 means the independent implementation conforms to the
  documented UTF-8 rule — **not** a new formal security guarantee for V2.  

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

Phase 10 found ADV-M1; Phase 11 root-caused it as an independent JS defect;
Phase 12 hardened JS UTF-8 decoding. Open MEDIUM findings: **0**. Experimental
V2 remains non-normative.

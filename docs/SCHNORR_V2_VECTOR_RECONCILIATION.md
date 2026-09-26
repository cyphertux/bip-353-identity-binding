# Experimental Schnorr V2 — Vector / Spec Reconciliation (Phase 9)

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

| Field | Value |
|-------|--------|
| Historical freeze | `schnorr-v2-experimental-1` (**UNCHANGED**) |
| Reconciled snapshot | `schnorr-v2-experimental-2` |
| Trigger | Phase 8 independent reproduction |

## Historical audit

| Fact | Evidence |
|------|----------|
| `V2-VALID-001` created | commit `f75efe0` (*Add experimental Schnorr V2 test vectors*) |
| `expected.identity_anchored: true` | written at creation (pre–F-S1) |
| Dual-binding hardening | commit `cf5ef0b` (*Harden Schnorr V2 Bitcoin anchor proof*, Phase 6.1) |
| Freeze | tag `schnorr-v2-experimental-1` @ `b456591` |
| Phase 4 fixtures kept byte-identical through freeze | SHA-256 `f1b96178…02e014` |

**Cause:** Phase 4 used a **logical OP_RETURN** check as sufficient for `identity_anchored`.  
Phase 6.1 / F-S1 hardened the mini-spec so `identity_anchored` requires full dual-binding.  
The freeze deliberately left `V2-VALID-001.json` immutable; Phase 8 independently applied the hardened rule and reported the mismatch.

This is **not** a Phase 8 failure. Phase 8 remains **PASS**.

## Source of truth (current experimental behaviour)

| Artifact | `identity_anchored` definition |
|----------|--------------------------------|
| `docs/SCHNORR_V2_MINI_SPEC.md` | Dual-binding required |
| `reference/schnorr_v2/verify.py` | Dual-binding required |
| `docs/SCHNORR_V2_SECURITY_CLAIMS.md` | Dual-binding required |
| `V2-VALID-001.expected` | **Historical / pre-F-S1** (do not rewrite) |

## LEGACY FROZEN VECTOR — `V2-VALID-001`

* Belongs to snapshot `schnorr-v2-experimental-1`.
* **Must not be modified** (content or checksum in `SCHNORR_V2_CHECKSUMS.txt`).
* Cryptography + logical `B353S2` OP_RETURN remain valid.
* Hardened verify yields `identity_anchored=false` without `bitcoin_proof`.
* Field `expected.identity_anchored=true` is **legacy evidence**, not the current claim semantics.

## Reconciled vectors (Phase 9)

| File | Role |
|------|------|
| `V2-VALID-002.json` | Full identity + dual-binding → `identity_anchored=true` |
| `V2-VALID-003.json` | Full identity, no BTC proof → `identity_anchored=false` |
| `SCHNORR_V2_RECONCILED_CHECKSUMS.txt` | Checksums for the reconciled set |
| `SCHNORR_V2_CHECKSUMS.txt` | **Historical freeze checksums — unchanged** |

## Claim separation matrix

```text
identity_verified  ≠  identity_anchored
payment_verified   ≠  payment_received   (payment_received still out of scope)
identity_anchored  ⇒  dual-binding Bitcoin proof
```

| Case | Fixture |
|------|---------|
| Valid identity, no Bitcoin proof | `V2-VALID-003` (+ legacy `V2-VALID-001` crypto path) |
| Valid identity, valid dual-binding anchor | `V2-VALID-002` / `V2-BTC-VALID-001` |
| Invalid txid / Merkle / header / missing / duplicate B353S2 / wrong commitment | `V2-BTC-INVALID-001` … `007` |

## Phase 8 interpretation

Independent reproduction **correctly** detected the vector/spec drift.  
Reconciliation adds new vectors; it does **not** rewrite the first freeze.

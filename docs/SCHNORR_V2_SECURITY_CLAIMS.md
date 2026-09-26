# Experimental Schnorr V2 — Security Claims

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP — NOT PRODUCTION-READY**

| Field | Value |
|-------|--------|
| Branch | `experiment/schnorr-identity-v2` |
| Snapshot | Experimental freeze candidate (Phase 7) |
| Companion review | [`SCHNORR_V2_SECURITY_REVIEW.md`](SCHNORR_V2_SECURITY_REVIEW.md) |
| Mini-spec | [`SCHNORR_V2_MINI_SPEC.md`](SCHNORR_V2_MINI_SPEC.md) |

These claims apply only to the **experimental Schnorr identity root** lab.
They do **not** apply to V1 OpenPGP (`BIP-XXX.md`), which remains separately FROZEN.

**Legend**

* **TESTED** — Demonstrated by frozen experimental vectors / reference tests under stated assumptions (e.g. correct BIP-340 library, supplied header context).
* **NOT PROVIDED** — Explicitly out of scope; absence is intentional.

Do not read **TESTED** as “production-audited” or “universally proven.”

---

## Claim matrix

| Property | Experimental V2 |
|----------|-----------------|
| Root → signing authenticity | **TESTED** |
| Identity signature authenticity | **TESTED** |
| Payment binding integrity | **TESTED** |
| Bitcoin anchor commitment integrity | **TESTED** |
| Bitcoin inclusion proof (dual-binding) | **TESTED** (synthetic regtest fixtures; no best-chain / PoW claim) |
| Continuity (same root for domain+identifier given `identity_anchored`) | **TESTED** |
| Freshness | **NOT PROVIDED** |
| Rollback resistance | **NOT PROVIDED** |
| Split-view resistance | **NOT PROVIDED** |
| Human identity | **NOT PROVIDED** |
| Legal identity | **NOT PROVIDED** |
| Current human control | **NOT PROVIDED** |
| Revocation freshness | **NOT PROVIDED** |
| Absolute Bitcoin finality | **NOT PROVIDED** |
| Privacy guarantee | **NOT PROVIDED** |
| Root-key compromise resistance | **NOT PROVIDED** |
| Signing-key compromise resistance | **NOT PROVIDED** |

---

## Claim meanings (short)

| Flag | Means | Does not mean |
|------|-------|----------------|
| `identity_verified` | Binding + IdentityDocument BIP-340 checks + field rules | Human identity; Bitcoin inclusion; freshness |
| `payment_verified` | PaymentBinding hash matches document / resolved semantics | Payment occurred, received, or settled |
| `identity_anchored` | Full dual-binding Bitcoin proof for expected commitment | Best chain; absolute finality |
| `continuity_verified` | Anchored root bytes equal presented root (with `identity_anchored`) | Non-compromise; current control |

---

## Open findings accepted for experimental freeze

| ID | Severity | Acceptance |
|----|----------|------------|
| F-S2 | LOW | **accepted for experimental freeze** — prefer CBOR-bytes verify API later |
| F-S4 | INFORMATIONAL | **accepted for experimental freeze** — binding omits domain by design |

| ID | Severity | Status |
|----|----------|--------|
| F-S1 | HIGH | **RESOLVED** (Phase 6.1 dual-binding) |
| F-S3 | INFORMATIONAL | **RESOLVED** (`AMBIGUOUS_B353S2_OUTPUTS`) |

---

## Independent implementation

**PASS** (Phase 8) — see [`SCHNORR_V2_INDEPENDENT_REVIEW.md`](SCHNORR_V2_INDEPENDENT_REVIEW.md).

Stack: Node.js + `@noble/curves` / `@noble/hashes` (not Python/embit).

Phase 8 discovered the `V2-VALID-001` / dual-binding expectation drift; that detection
is preserved as a positive independence result. Phase 9 reconciles with new vectors
(`V2-VALID-002`, `V2-VALID-003`) without rewriting `schnorr-v2-experimental-1` —
see [`SCHNORR_V2_VECTOR_RECONCILIATION.md`](SCHNORR_V2_VECTOR_RECONCILIATION.md).

Still explicitly:

* No formal proof  
* No production security audit  
* No human identity guarantee  
* No freshness guarantee  
* No rollback resistance  
* No split-view resistance  

**NOT AVAILABLE** previously (Phase 6); superseded by Phase 8 reproduction.

---

## Adversarial review (Phase 10–12)

See [`SCHNORR_V2_ADVERSARIAL_REVIEW.md`](SCHNORR_V2_ADVERSARIAL_REVIEW.md).

Open counts (post Phase 12):

* CRITICAL: 0  
* HIGH: 0  
* MEDIUM: 0 (`ADV-M1` **RESOLVED** — independent JS fatal UTF-8 decode)  
* LOW: 2  
* INFORMATIONAL: 3  

Dual-binding remains mandatory for `identity_anchored`. Resolving ADV-M1 means
the independent implementation conforms to the documented UTF-8 rule — not a new
formal security guarantee.

---

## Reproducibility (lab)

```bash
uv venv reference/schnorr_v2/.venv
uv pip install --python reference/schnorr_v2/.venv/bin/python -r reference/schnorr_v2/requirements.txt
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_vectors.py
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_bitcoin_proof.py
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python -m reference.schnorr_v2.demo
```

Do not regenerate vectors during normal verification.

# BIP-353 Identity Binding and Continuity

Cryptographic binding of [BIP-353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki)
payment identifiers to an identity root, a signed payment binding, and optional
Bitcoin historical anchoring.

**This repository is not [bitcoin/bips](https://github.com/bitcoin/bips).**  
BIP number `XXX` is **provisional / draft only** — not an assigned official BIP.

---

## Start here (external reader)

```text
README (this file)
  → docs/SCHNORR_V2_MINI_SPEC.md          experimental V2 design
  → vectors/schnorr/                      experimental fixtures
  → reference/schnorr_v2/                 Python reference
  → independent/schnorr_v2/               independent JS reproduction
  → docs/SCHNORR_V2_THREAT_MODEL.md       security boundary
  → docs/SCHNORR_V2_SECURITY_CLAIMS.md    claim matrix
```

Full publication / reproducibility notes: [`docs/SCHNORR_V2_PUBLICATION.md`](docs/SCHNORR_V2_PUBLICATION.md).

---

## What is V1 vs V2?

| | **V1** | **V2 (this branch’s experiment)** |
|--|--------|-----------------------------------|
| Identity root | OpenPGP `KROOT` / `KSIGN` | BIP-340 x-only `root_pubkey` / `signing_pubkey` |
| Spec | [`BIP-XXX.md`](BIP-XXX.md) | [`docs/SCHNORR_V2_MINI_SPEC.md`](docs/SCHNORR_V2_MINI_SPEC.md) |
| Status | **FROZEN** | **EXPERIMENTAL / NON-NORMATIVE** |
| Vectors | `vectors/valid`, `invalid`, `m4`, `v6` + `M7_CHECKSUMS.txt` | `vectors/schnorr/` |
| Code | `reference/*.py` (not `schnorr_v2/`) | `reference/schnorr_v2/`, `independent/schnorr_v2/` |
| OP_RETURN | `B353ID` | `B353S2` (experimental only) |
| Compatibility | — | **None claimed** with V1 Proof Bundles |

Cryptographic “identity” here means **key material and signatures**, **not** human or legal identity.

---

## Status

| Layer | Status |
|-------|--------|
| V1 OpenPGP protocol | **FROZEN** |
| V2 Schnorr experiment | **EXPERIMENTAL — NON-NORMATIVE** |
| Official BIP / production / audited | **No** |

Do **not** treat V2 as production-ready, standardized, formally verified, or an official Bitcoin BIP.

### Experimental snapshots (annotated git tags, not GPG-signed)

| Tag | Role |
|-----|------|
| `schnorr-v2-experimental-1` | First experimental freeze — **immutable historical evidence** |
| `schnorr-v2-experimental-2` | Reconciled snapshot — hardened dual-binding + reconciled vectors |

`experimental-1` still contains legacy `V2-VALID-001` with a historical
`expected.identity_anchored=true` that predates dual-binding hardening.  
Current semantics: `identity_anchored` requires full dual-binding (`V2-VALID-002`).  
See [`docs/SCHNORR_V2_VECTOR_RECONCILIATION.md`](docs/SCHNORR_V2_VECTOR_RECONCILIATION.md).

---

## What V2 does not provide

Confirmed by the threat model ([`docs/SCHNORR_V2_THREAT_MODEL.md`](docs/SCHNORR_V2_THREAT_MODEL.md)):

* Freshness / liveness of control  
* Rollback resistance  
* Split-view resistance  
* Absolute Bitcoin finality / reorg resistance  
* Human / legal identity  
* Revocation freshness  
* Privacy guarantees  
* Root- or signing-key non-compromise  
* DNS integrity by itself  
* That a payment was received or settled  

---

## Security documentation

| Document | Purpose |
|----------|---------|
| [`docs/SCHNORR_V2_SECURITY_CLAIMS.md`](docs/SCHNORR_V2_SECURITY_CLAIMS.md) | Claim matrix (TESTED vs NOT PROVIDED) |
| [`docs/SCHNORR_V2_THREAT_MODEL.md`](docs/SCHNORR_V2_THREAT_MODEL.md) | Adversaries and security boundary |
| [`docs/SCHNORR_V2_ADVERSARIAL_REVIEW.md`](docs/SCHNORR_V2_ADVERSARIAL_REVIEW.md) | Mutation / differential testing |
| [`docs/SCHNORR_V2_INDEPENDENT_REVIEW.md`](docs/SCHNORR_V2_INDEPENDENT_REVIEW.md) | Independent JS reproduction |
| [`docs/SCHNORR_V2_SPEC_AUDIT.md`](docs/SCHNORR_V2_SPEC_AUDIT.md) | Specification-first audit |

### How to read “PASS”

A test **PASS** means: *the tested property held for the tested cases under the
documented assumptions.*  
It does **not** mean: *the protocol is mathematically proven secure* or
*production-audited*.

---

## Environment (pinned for V2 lab)

| Component | Version used in this lab |
|-----------|---------------------------|
| Python | 3.14.x (3.11+ should work; use the project venv) |
| Node.js | v22.x |
| `embit` | `0.8.0` ([`reference/schnorr_v2/requirements.txt`](reference/schnorr_v2/requirements.txt)) |
| `@noble/curves` | `1.8.1` |
| `@noble/hashes` | `1.7.1` |
| CBOR | Hand-written V1 subset in `reference/cbor.py` (+ JS port in independent) |

Also useful: [`uv`](https://github.com/astral-sh/uv) for Python venv/install.

---

## Verification

### V2 reference setup

```bash
uv venv reference/schnorr_v2/.venv
uv pip install --python reference/schnorr_v2/.venv/bin/python -r reference/schnorr_v2/requirements.txt
```

### V2 tests & vectors

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_vectors.py
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_bitcoin_proof.py
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python -m reference.schnorr_v2.demo
```

### Checksums (artifact integrity only — not cryptographic security of the protocol)

```bash
sha256sum -c vectors/schnorr/SCHNORR_V2_CHECKSUMS.txt
sha256sum -c vectors/schnorr/SCHNORR_V2_RECONCILED_CHECKSUMS.txt
sha256sum -c vectors/M7_CHECKSUMS.txt   # V1
```

### Independent JavaScript reproduction

```bash
cd independent/schnorr_v2 && npm ci && npm run bip340 && npm run verify
```

### Adversarial / UTF-8 / spec-only

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_adversarial.py
cd independent/schnorr_v2 && npm run adversarial && npm run phase11-utf8
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_phase11_utf8.py
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python audit/schnorr_v2_spec_only/verify_from_spec.py
```

### V1 (OpenPGP) smoke checks

```bash
PYTHONPATH=. python3 test/test_cbor.py
PYTHONPATH=. python3 test/test_vectors.py
```

(Full V1 suites may require additional OpenPGP tooling; see milestone docs under `docs/`.)

### Git tags

```bash
git tag --verify schnorr-v2-experimental-1
git tag --verify schnorr-v2-experimental-2
```

These are **annotated tags**. They are **not** GPG-signed in this repository
(`error: no signature found` is expected).

---

## Experimental vectors (summary)

| Vector | Purpose / status |
|--------|------------------|
| `V2-VALID-001` | **LEGACY FROZEN** (`experimental-1`); crypto + logical OP_RETURN; do **not** treat `expected.identity_anchored` as current dual-binding semantics |
| `V2-VALID-002` | Reconciled: dual-binding → `identity_anchored=true` |
| `V2-VALID-003` | Crypto valid, no BTC proof → `identity_anchored=false` |
| `V2-INVALID-*` | Negative crypto / payment / logical anchor cases |
| `V2-BTC-*` | Dual-binding Bitcoin proof accept/reject matrix |

Details: [`vectors/schnorr/README.md`](vectors/schnorr/README.md).

---

## Architecture (experimental V2)

```text
BIP-353 / DNSSEC → PaymentBinding → IdentityDocument (v2)
        root_pubkey ──SubkeyBinding──► signing_pubkey
        AnchorMessage → B353S2 → dual-binding Bitcoin proof → Verifier
```

---

## V1 on this repository

* Spec: [`BIP-XXX.md`](BIP-XXX.md) (Status: **Draft**; number not assigned)  
* Freeze report: [`docs/PROTOCOL_FREEZE_V1.md`](docs/PROTOCOL_FREEZE_V1.md)  
* Vectors / checksums: `vectors/valid|invalid|m4|v6`, `vectors/M7_CHECKSUMS.txt`  

---

## License

BSD-2-Clause — see [`LICENSE`](LICENSE).

No separate `SECURITY.md` / `CONTRIBUTING.md` is published; treat the project as
**experimental research**. Do not file “production vulnerability” expectations
against V2 as if it were an official Bitcoin standard.

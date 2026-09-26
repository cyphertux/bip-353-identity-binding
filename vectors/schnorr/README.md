# Experimental Schnorr V2 vectors

**EXPERIMENTAL**  
**NON-NORMATIVE**  
**NOT PART OF V1**

These fixtures exercise the experimental Schnorr identity root described in:

* [`docs/SCHNORR_V2_MINI_SPEC.md`](../../docs/SCHNORR_V2_MINI_SPEC.md)
* [`docs/SCHNORR_V2_VECTOR_RECONCILIATION.md`](../../docs/SCHNORR_V2_VECTOR_RECONCILIATION.md)
* [`reference/schnorr_v2/`](../../reference/schnorr_v2/)

They are **independent** of V1 (`vectors/valid`, `vectors/m4`, `vectors/M7_CHECKSUMS.txt`).

## Snapshots

| Tag | Role |
|-----|------|
| `schnorr-v2-experimental-1` | Historical freeze (Phase 7) — **immutable** |
| `schnorr-v2-experimental-2` | Reconciled experimental snapshot (Phase 9) |

## Encoding

| Kind | Encoding |
|------|----------|
| Keys, signatures, hashes, CBOR, commitments, OP_RETURN | **hex lowercase** |
| Domain / identifier / tags | UTF-8 / ASCII text |

JSON is **transport only**. Signed/hashed material is always canonical CBOR + BIP-340 TaggedHash as in the mini-spec.

## Tags / OP_RETURN

| Constant | Value |
|----------|--------|
| `TAG_SUBKEY_BINDING` | `BIP353-IDENTITY/V2/SUBKEY-BINDING` |
| `TAG_IDENTITY` | `BIP353-IDENTITY/V2/IDENTITY` |
| `TAG_PAYMENT` | `BIP353-IDENTITY/V2/PAYMENT` |
| `TAG_ANCHOR` | `BIP353-IDENTITY/V2/ANCHOR` |
| OP_RETURN tag | `B353S2` (≠ V1 `B353ID`) |

## Private keys

Where present, private keys are:

```text
TEST VECTOR ONLY
NOT A SECRET
NOT FOR PRODUCTION
```

## Files

| File | Expected |
|------|----------|
| `V2-VALID-001.json` | **LEGACY FROZEN** (`schnorr-v2-experimental-1`): crypto + logical OP_RETURN; `expected.identity_anchored=true` is historical/pre-F-S1 |
| `V2-VALID-002.json` | Reconciled: dual-binding → `identity_anchored=true` |
| `V2-VALID-003.json` | Reconciled: crypto valid, no BTC proof → `identity_anchored=false` |
| `V2-INVALID-001.json` | `INVALID_SUBKEY_BINDING` |
| `V2-INVALID-002.json` | `INVALID_IDENTITY_SIGNATURE` |
| `V2-INVALID-003.json` | `ANCHOR_MISMATCH` |
| `V2-INVALID-004.json` | `PAYMENT_BINDING_MISMATCH` |
| `V2-INVALID-005.json` | `INVALID_IDENTITY_SIGNATURE` (wrong tag) |
| `V2-BTC-VALID-001.json` | Dual-binding Bitcoin proof PASS |
| `V2-BTC-INVALID-001.json` | `TXID_MISMATCH` |
| `V2-BTC-INVALID-002.json` | `WRONG_MERKLE_PROOF` |
| `V2-BTC-INVALID-003.json` | `WRONG_MERKLE_PROOF` |
| `V2-BTC-INVALID-004.json` | `WRONG_MERKLE_PROOF` |
| `V2-BTC-INVALID-005.json` | `WRONG_TX_COMMITMENT` |
| `V2-BTC-INVALID-006.json` | `NO_B353S2_OUTPUT` |
| `V2-BTC-INVALID-007.json` | `AMBIGUOUS_B353S2_OUTPUTS` |
| `SCHNORR_V2_CHECKSUMS.txt` | Historical freeze checksums (**do not change**) |
| `SCHNORR_V2_RECONCILED_CHECKSUMS.txt` | Phase 9 reconciled set checksums |

## Claim separation

```text
identity_verified  ≠  identity_anchored
payment_verified   ≠  payment_received
identity_anchored  ⇒  dual-binding Bitcoin proof
```

Phase 8 independent reproduction discovered that `V2-VALID-001.expected.identity_anchored`
does not match the hardened mini-spec. That detection is a **positive** result of
independence; Phase 8 remains PASS. Phase 9 adds `V2-VALID-002` / `V2-VALID-003`
without rewriting the frozen snapshot.

## Verify (independent of generator)

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_vectors.py
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_bitcoin_proof.py
cd independent/schnorr_v2 && npm ci && node src/run.mjs
```

The test **loads frozen JSON** from this directory and must **not** call
`reference.schnorr_v2.generate_vectors`.

## Checksums

```bash
# Historical freeze set (schnorr-v2-experimental-1)
sha256sum -c vectors/schnorr/SCHNORR_V2_CHECKSUMS.txt

# Reconciled set (includes VALID-002 / VALID-003)
sha256sum -c vectors/schnorr/SCHNORR_V2_RECONCILED_CHECKSUMS.txt
```

Never modify `vectors/M7_CHECKSUMS.txt` for this experiment.
Never rewrite `V2-VALID-001.json` or `SCHNORR_V2_CHECKSUMS.txt`.

# Experimental Schnorr V2 vectors

**EXPERIMENTAL**  
**NON-NORMATIVE**  
**NOT PART OF V1**  
**NOT FROZEN**

These fixtures exercise the experimental Schnorr identity root described in:

* [`docs/SCHNORR_V2_MINI_SPEC.md`](../../docs/SCHNORR_V2_MINI_SPEC.md)
* [`reference/schnorr_v2/`](../../reference/schnorr_v2/)

They are **independent** of V1 (`vectors/valid`, `vectors/m4`, `vectors/M7_CHECKSUMS.txt`).

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
| `V2-VALID-001.json` | full proof verifies |
| `V2-INVALID-001.json` | `INVALID_SUBKEY_BINDING` |
| `V2-INVALID-002.json` | `INVALID_IDENTITY_SIGNATURE` |
| `V2-INVALID-003.json` | `ANCHOR_MISMATCH` |
| `V2-INVALID-004.json` | `PAYMENT_BINDING_MISMATCH` |
| `V2-INVALID-005.json` | `INVALID_IDENTITY_SIGNATURE` (wrong tag) |
| `SCHNORR_V2_CHECKSUMS.txt` | SHA-256 of the JSON fixtures |

## Verify (independent of generator)

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_vectors.py
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python test/schnorr_v2/test_bitcoin_proof.py
```

Note: Phase 4 `V2-VALID-001` verifies identity/payment cryptography and logical OP_RETURN
consistency. **`identity_anchored=true` requires a dual-binding `bitcoin_proof`**
(see `V2-BTC-VALID-001`).

The test **loads frozen JSON** from this directory and must **not** call
`reference.schnorr_v2.generate_vectors`.

## Regenerate (manual only)

```bash
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python -m reference.schnorr_v2.generate_vectors --write
```

After regeneration, update `SCHNORR_V2_CHECKSUMS.txt` (the generator writes it) and review the diff. **Do not silently overwrite** published experimental vectors without an explicit decision.

## Checksums

```bash
cd repo-root
sha256sum -c vectors/schnorr/SCHNORR_V2_CHECKSUMS.txt
```

Never modify `vectors/M7_CHECKSUMS.txt` for this experiment.

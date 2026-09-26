# Experimental Schnorr Identity Root — reference (Phase 3)

**EXPERIMENTAL · NON-NORMATIVE · NOT PART OF V1 · NOT FROZEN**

Isolated BIP-340 / TaggedHash implementation of
[`docs/SCHNORR_V2_MINI_SPEC.md`](../../docs/SCHNORR_V2_MINI_SPEC.md).

Directory name is `reference/schnorr_v2/` (underscore) so Python can import
`reference.schnorr_v2` without colliding with V1 modules.

## Crypto library

| Item | Value |
|------|--------|
| Library | [embit](https://github.com/bitcoindevkit/embit) 0.8.0 |
| BIP-340 sign | `ec.PrivateKey.schnorr_sign(msg32)` |
| BIP-340 verify | `ec.PublicKey.schnorr_verify(sig, msg32)` |
| x-only encode | `PublicKey.xonly()` → 32 bytes |
| x-only parse/validate | `PublicKey.from_xonly(bytes)` |
| TaggedHash | `embit.hashes.tagged_hash(tag, msg)` |

`coincurve` was preferred first but failed to build on this Python 3.14 host; `embit` provides mature BIP-340 + tagged_hash.

## Setup

```bash
uv venv reference/schnorr_v2/.venv
uv pip install --python reference/schnorr_v2/.venv/bin/python -r reference/schnorr_v2/requirements.txt
```

## Run

```bash
# from repository root, with venv python (so embit is visible)
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python -m reference.schnorr_v2.demo
PYTHONPATH=. reference/schnorr_v2/.venv/bin/python -m reference.schnorr_v2.test_negative
```

## Experimental OP_RETURN tag

| | V1 | Experimental V2 |
|--|----|-----------------|
| Tag ASCII | `B353ID` | `B353S2` |
| Version | `0x01` | `0x01` |
| Commitment | 32 bytes | 32 bytes (`TaggedHash(TAG_ANCHOR, …)`) |

`B353S2` = BIP-353 **S**chnorr experimental lab tag — must never equal `B353ID`.

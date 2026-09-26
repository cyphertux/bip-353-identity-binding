# Experimental Schnorr V2 — CBOR UTF-8 rules (Phase 11–12)

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

Clarifies text-string handling for the V2 deterministic CBOR subset.
Does **not** change `schnorr-v2-experimental-2`.

## Spec chain

```text
RFC 8949 (text string = UTF-8)
        ↓
V2 mini-spec / V1 CBOR subset reuse (canonical encode + reject non-canonical)
        ↓
Python reference/cbor.py  →  strict UTF-8 decode
        ↓
JavaScript independent lib.mjs  →  TextDecoder("utf-8", { fatal: true })  (Phase 12)
```

## What is valid / invalid UTF-8

| Class | V2 CBOR text expectation |
|-------|---------------------------|
| Well-formed UTF-8 (incl. U+0000, controls, noncharacters such as U+FFFF) | **accept** at CBOR layer |
| Overlong, UTF-16 surrogates, truncated, bad continuation, >U+10FFFF | **reject** |
| Unicode NFC/NFD/NFKC/NFKD | **NOT PART OF V2** — different UTF-8 byte strings remain different CBOR |

Canonical CBOR (RFC 8949 §4.2.1) is **not** Unicode normalization.

## Application-level strings

Domain / identifier rules (`@` placement, etc.) apply **after** successful UTF-8 CBOR decode.
They are separate from UTF-8 well-formedness.

## ADV-M1

| Item | Value |
|------|--------|
| Minimal case | `ADV-M1-minimal` / `61ff` |
| Seed | `a3535210` |
| Root cause | **implementation defect** (JS `cborDecode` text path, non-fatal `TextDecoder`) |
| Status | **RESOLVED — IMPLEMENTATION DEFECT** (Phase 12) |
| Fix | `new TextDecoder("utf-8", { fatal: true })` |
| Protocol / snapshot | unchanged |

See [`SCHNORR_V2_ADVERSARIAL_REVIEW.md`](SCHNORR_V2_ADVERSARIAL_REVIEW.md).

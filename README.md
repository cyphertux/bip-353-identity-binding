# BIP-XXX — BIP-353 Identity Binding and Continuity

**Draft / Proposed BIP** (number `XXX` is provisional — not assigned).
This repository is **not** the official [bitcoin/bips](https://github.com/bitcoin/bips) repository.

## Status

| Item | Value |
|------|--------|
| Document | Draft / Proposed BIP |
| Protocol V1 | **FROZEN** |
| M7 | PASS |
| M8 | PASS |
| M8.1 | PASS |
| M9 | PASS |

## What this is

A **complement** to [BIP-353](https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki) (DNS payment instructions) and [BIP-321](https://github.com/bitcoin/bips/blob/master/bip-0321.mediawiki) (Bitcoin payment URIs).

It specifies cryptographic binding of:

* a BIP-353 identifier;
* OpenPGP identity (`KROOT` → `KSIGN`);
* a signed Identity Document and payment destination binding;
* an optional Bitcoin historical anchor (Candidate A).

Normative specification: [`BIP-XXX.md`](BIP-XXX.md).

## What a verifier can check

| Result | Meaning |
|--------|---------|
| `payment_verified` | BIP-353 semantics ↔ PaymentBinding ↔ IdentityDocument `payment_hash` |
| `identity_verified` | OpenPGP + IdentityDocument cryptographic validity (independent of Bitcoin) |
| `identity_anchored` | Valid BitcoinAnchorProof shows the commitment on-chain |
| `continuity_verified` | Same KROOT historically anchored for domain + identifier |

## What V1 does **not** guarantee

* human or legal identity
* freshness / “latest document”
* rollback resistance
* split-view resistance
* absolute Bitcoin finality
* KROOT / KSIGN compromise resistance
* privacy / anonymity

See the security claim matrix in `BIP-XXX.md`.

## Layout

```
BIP-XXX.md          # specification (V1 frozen)
README.md
LICENSE             # BSD-2-Clause
reference/          # reference implementation
test/               # regression and security tests
vectors/            # frozen fixtures + M7_CHECKSUMS.txt
docs/               # freeze notes, milestones, design history
scripts/            # vector generation helpers (do not regenerate silently)
```

## Quick checks

```bash
python3 test/test_cbor.py
python3 test/test_vectors.py
python3 test/test_m4_e2e.py
python3 test/m6/test_verification_hardening.py
```

Do **not** silently regenerate or edit files under `vectors/`.

## Related documents

| Path | Role |
|------|------|
| [`docs/PROTOCOL_FREEZE_V1.md`](docs/PROTOCOL_FREEZE_V1.md) | Normative freeze (M7) |
| [`docs/M7_PROTOCOL_FREEZE.md`](docs/M7_PROTOCOL_FREEZE.md) | Freeze gate |
| [`docs/MILESTONE_*.md`](docs/) | Milestone reports M2–M6 |
| [`vectors/M7_CHECKSUMS.txt`](vectors/M7_CHECKSUMS.txt) | Frozen vector checksums |

## License

BSD-2-Clause — see [`LICENSE`](LICENSE).

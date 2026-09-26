# Independent Schnorr V2 reproduction

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

Independent verifier for experimental Schnorr V2 vectors.

Does **not** import `reference/schnorr_v2/`.

| Snapshot | Role |
|----------|------|
| `schnorr-v2-experimental-1` | Historical freeze (immutable) |
| `schnorr-v2-experimental-2` | Reconciled vector set (Phase 9) |

## Stack

| Item | Value |
|------|--------|
| Language | JavaScript (ES modules) |
| Runtime | Node.js v22 |
| BIP-340 | `@noble/curves` 1.8.1 (`schnorr`) |
| SHA-256 / utils | `@noble/hashes` 1.7.1 |
| CBOR | hand-written RFC 8949 core subset |
| Bitcoin tx/Merkle | hand-written |

## Run

```bash
cd independent/schnorr_v2
npm install
npm run bip340
npm run verify
```

Produces `independent-results.json`.

## Sources used

* `docs/SCHNORR_V2_MINI_SPEC.md`
* `docs/SCHNORR_V2_VECTOR_RECONCILIATION.md`
* `vectors/schnorr/*.json`
* BIP-340 official verify vector 0

## Notes

* `V2-VALID-001` is a **LEGACY FROZEN** vector: crypto passes; hardened
  `identity_anchored` is `false` without `bitcoin_proof`.
* `V2-VALID-002` requires dual-binding → `identity_anchored=true`.
* `V2-VALID-003` is explicitly non-anchored.

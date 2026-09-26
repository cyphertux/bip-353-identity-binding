# Independent Schnorr V2 reproduction

**EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP**

Independent verifier for frozen snapshot `schnorr-v2-experimental-1`.

Does **not** import `reference/schnorr_v2/`.

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

Produces `independent-results.json` (blind results).

## Sources used

* `docs/SCHNORR_V2_MINI_SPEC.md`
* `vectors/schnorr/*.json`
* BIP-340 official verify vector 0

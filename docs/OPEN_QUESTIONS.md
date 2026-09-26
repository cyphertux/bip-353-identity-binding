# Open questions before normative BIP text

These items are **intentionally not frozen**. Milestone 1 produces real
octets under provisional choices; changing any of them invalidates vectors
and must bump a protocol version / domain separator.

## Cryptography / OpenPGP

1. **Fingerprint version:** M1 uses v4 (20 bytes). M3 adds a **real** OpenPGP
   v6 fixture under `vectors/v6/` (Sequoia `--profile rfc9580`, 32-byte
   fingerprints). openpgp.js 6.3.2 verifies v6; **GnuPG 2.4.8 cannot import
   v6**. Policy (v4-only wallets vs mandatory v6) remains OPEN.
2. **Signature packaging:** **FROZEN as detached** after M3 three-way tests
   (GnuPG, Sequoia, openpgp.js). Inline Literal Data works but is larger and
   adds framing ambiguity — rejected for the normative profile.
3. **KeyReference:** Compact `bstr` + cert-derived version/length checks are
   near-frozen. Explicit `{version, fingerprint}` map remains optional/OPEN.
3. **KSIGN selection:** When multiple signing subkeys exist, which one is
   “current”? Sequence number + expiration handle ordering; transparency
   (V2) is required for freshness.
4. **Root rotation & recovery:** Escrowed revocation (RFC 9580) is the
   preferred recovery story; exact Proof Bundle fields for
   `KROOT-A → KROOT-B` and recovery activation are TBD.
5. **Revocation transport:** How revocation certificates are discovered
   (WKD, keyservers, Proof Bundle field, transparency log) is TBD.

## Canonicalization

6. **CBOR profile:** Integer-keyed maps + RFC 8949 Core Deterministic
   Encoding are used. Full CDDL for all structures is TBD.
7. **Identifier normalization:** Must match BIP-353 exactly (case,
   IDNA, local-part rules) — deferred to normative cross-reference.
8. **Payment method registry:** `bitcoin` / `lightning` / `silent-payment`
   canonical destination encodings need a registry; Identity BIP must not
   redefine those formats.

## Bitcoin anchor / payment (updated by M4)

9. **OP_RETURN tag:** `B353ID || version || commitment` works in regtest
   (39-byte payload) but remains **provisional** until BIP namespace allocation.
10. **Proof format:** `BitcoinAnchorProofV1` with header + merkle branch is
    implemented for SPV-style checks; header-chain policy still OPEN.
11. **Confirmation policy:** Wallet-local; no universal constant frozen.
12. **Payment binding:** Semantic BIP-321 destinations as scriptPubKey;
    amount/label/message excluded. Method registry envelope frozen;
    `sp`/`lno` payloads still OPEN.

## Freshness

12. **Transparency log:** Required for rollback / split-view detection.
    Intentionally **out of milestone 1 core**. V2 should define Merkle
    STH + inclusion + consistency proofs; log MUST NOT be a CA.
13. **Sequence numbers:** Present but insufficient alone for stateless
    freshness (demonstrated by `vectors/invalid/rollback`).

## Trust / UX

14. **Bootstrap:** Bitcoin anchor ≠ human trust. UI must separate
    `IDENTITY_ANCHORED` from `TRUSTED` / `FIRST_SEEN`.
15. **Payment binding timing:** Every destination rotation requires a new
    Identity Document (new `payment_hash`) but not a new Bitcoin anchor.
    UX cost vs BIP-353 address rotation recommendations needs evaluation.

## Process

16. BIP number, PSBT `PSBT_OUT_IDENTITY_PROOF` allocation, and media-wiki
    draft text come **after** independent re-implementation of these
    vectors.

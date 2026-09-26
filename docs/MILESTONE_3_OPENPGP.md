# Milestone 3 — OpenPGP Ecosystem Compatibility

**Status:** PASS (core)  
**Date:** 2026-09-26  
**Constraint honored:** Milestone 1 vectors were **not** modified or regenerated.

M1 vector integrity (unchanged):

| File | SHA-256 |
|------|---------|
| `identity-signature.bin` | `cbf756b3716f4b943dc4a7138287c7fdea0bb3f87805206ae36d99ce7e8a8586` |
| `identity-payload.cbor` | `83f3a9f7fd6cce5bdb30fc7490b065c6a1f45660da37dbeec1b83527e4c7ae82` |
| `root.asc` | `5287dad7be7460318845514e4f9f02eaf45faa6acad87c08a7573c8dd1cf3fee` |

---

## Implementations

| Implementation | Version | Role in M3 |
|----------------|---------|------------|
| **GnuPG** | 2.4.8 | M1 signer; full protocol verifier; v4 only |
| **Sequoia `sq`** | 1.3.1 (`sequoia-openpgp` 2.1.0, Nettle 3.10) | M2/M3 verify; **v6 key generation** (`--profile rfc9580`) |
| **openpgp.js** | **6.3.2** (npm exact) | Browser/JS ecosystem verify + sign |

Node: v22.22.1. openpgp.js installed with `npm install openpgp@6 --save-exact`.

Reproduce:

```bash
npm install   # openpgp@6.3.2
export SQ=$PWD/.tools/sq-root/usr/bin/sq
export GNUPGHOME=/tmp/bip353-gnupg

node reference/openpgpjs_verify.mjs
node test/test_m3_openpgpjs.mjs
python3 scripts/generate_v6_vectors.py   # needs .tools/v6/secret-v6.pgp
node test/test_m3_v6.mjs
python3 scripts/build_m3_matrix.py
```

---

## Fingerprints

### Milestone 1 (v4) — all three implementations

| Key | Expected | GnuPG | Sequoia | openpgp.js |
|-----|----------|-------|---------|------------|
| KROOT | `de26bd614a4224ac0b704ed1c8f68e1738268297` | PASS | PASS | PASS |
| KSIGN | `55f38348c4a60b8ffd7b40c86186d1b88a7badea` | PASS | PASS | PASS |

openpgp.js: `cert.getFingerprint()`, `keyPacket.version === 4`, algorithm id `22` (EdDSA legacy).

### Milestone 3 independent v6 fixture

| Key | Real fingerprint (32 bytes) | Sequoia | openpgp.js | GnuPG |
|-----|----------------------------|---------|------------|-------|
| KROOT | `06951ac6b194ead55cb3b139a7a3e9d81f78a8c0521b2d65cf9df81ee36427bc` | PASS | PASS | **UNSUPPORTED** |
| KSIGN | `e855280752edb2622febf1da2b633bed3d0d83f01269a320881d1dd9aad32bc9` | PASS | PASS | **UNSUPPORTED** |

GnuPG 2.4.8 on import: `packet(6) with unknown version 6` / `Porte-clefs incorrect`.  
**No simulated v6 fingerprints.** Generated with `sq key generate --profile rfc9580`.

---

## Binding

| Check | GnuPG | Sequoia | openpgp.js |
|-------|-------|---------|------------|
| 0x18 SubkeyBinding present | PASS | PASS | PASS (`bindingSignatures[].signatureType === 24`) |
| 0x19 PrimaryKeyBinding embedded | PASS | PASS | PASS (`embeddedSignature.signatureType === 25`) |
| Direct `subkey.verify()` API | n/a | n/a | **Unreliable** in 6.3.2 (throws / false “expired”); **not used** as authority |

**Protocol rule unchanged:** never invent a custom `KROOT→KSIGN` signature. Authorization is native OpenPGP. For openpgp.js, binding is established by packet inspection + successful detached verify using the certificate’s signing subkey.

---

## Signature interoperability

Signed message (all three implementations):

```
DOMAIN_SEPARATOR (17 bytes) || identity-payload.cbor (130 bytes) = 147 bytes
DOMAIN_SEPARATOR hex = 4249503335332d4944454e544954590001
```

| Direction | Result | Signature size |
|-----------|--------|----------------|
| GnuPG → Sequoia (M1 bytes) | PASS | 119 B (M1) |
| GnuPG → openpgp.js | PASS | 119 B |
| Sequoia → GnuPG (M2) | PASS | ~191 B |
| **openpgp.js → GnuPG** | **PASS** | 189 B |
| **openpgp.js → Sequoia** | **PASS** | 189 B |
| Byte-identical across signers? | **No** (expected) | — |

Semantic equivalence holds; packet encodings differ (CTB, notations, salt, timestamps).

---

## Cross-implementation matrix

Source: `test/m3_matrix.json`.

| Check | GnuPG | Sequoia | openpgp.js |
|-------|-------|---------|------------|
| KROOT fingerprint | PASS | PASS | PASS |
| KSIGN fingerprint | PASS | PASS | PASS |
| binding | PASS | PASS | PASS |
| signature | PASS | PASS | PASS |
| wrong-domain | PASS | NOT_APPLICABLE | NOT_APPLICABLE |
| wrong-identifier | PASS | NOT_APPLICABLE | NOT_APPLICABLE |
| wrong-root | PASS | NOT_APPLICABLE | NOT_APPLICABLE |
| wrong-signing-key | PASS | NOT_APPLICABLE | NOT_APPLICABLE |
| invalid-signature | PASS | PASS | PASS |
| expired | PASS | NOT_APPLICABLE | NOT_APPLICABLE |
| wrong-payment | PASS | NOT_APPLICABLE | NOT_APPLICABLE |
| wrong-payment-hash | PASS | NOT_APPLICABLE | NOT_APPLICABLE |
| wrong-anchor | PASS | NOT_APPLICABLE | NOT_APPLICABLE |
| sequence-modified | PASS | NOT_APPLICABLE | NOT_APPLICABLE |
| rollback | PASS | PASS | PASS |

### How to read NOT_APPLICABLE

Sequoia/openpgp.js columns for many mutations test the **OpenPGP layer only** (`DOMAIN||payload` + detached sig). Those fixtures mutate **protocol fields** while leaving the original signed payload+signature intact. OpenPGP correctly still verifies; the **protocol verifier (GnuPG path)** catches the failure. That is intentional layering, not an interop bug.

`rollback` remains **cryptographically valid / freshness UNKNOWN** on all three.

---

## Detached vs Literal analysis

Measured on the same 147-byte signed message:

| Form | Approx. size | openpgp.js | Sequoia | GnuPG |
|------|--------------|------------|---------|-------|
| **A Detached** (payload + sig) | ~249 B (130+119 M1) | PASS verify | PASS | PASS |
| **B Inline** (OPS + Literal + Sig) | ~359 B (openpgp.js) | PASS verify | supported | supported |

| Criterion | Detached (A) | Literal / inline (B) |
|-----------|--------------|----------------------|
| GnuPG | PASS | supported |
| Sequoia | PASS | supported |
| openpgp.js | PASS | PASS |
| Canonicalisation | Protocol owns exact bytes | OpenPGP literal framing adds filename/date degrees of freedom |
| Wallet simplicity | Two clear blobs | Need message parser |
| Size | Smaller | Larger (~+110 B here) |
| Parsing | Simple | Heavier |
| Ambiguities | Low | Higher (literal metadata) |
| Interop risk | Low (proven 3-way) | Medium (framing differences) |
| Auditability | Hash CBOR independently | Must prove literal content == protocol bytes |

### Recommendation (now FROZEN for packaging)

**Use Option A — detached OpenPGP Binary signature over `DOMAIN_SEPARATOR || CanonicalCBOR`.**

The Identity Binding protocol defines the signed byte string. OpenPGP must not become a second canonicalisation layer. Detached signatures preserve that boundary on GnuPG, Sequoia, and openpgp.js.

---

## OpenPGP v6

| Question | Answer |
|----------|--------|
| Real v6 available? | **Yes** — Sequoia `--profile rfc9580` |
| Simulated fingerprints? | **No** |
| Location | `vectors/v6/` (independent of M1) |
| KROOT / KSIGN | 32-byte fingerprints (see above) |
| Sequoia sign+verify IdentityDocument | **PASS** |
| openpgp.js parse + verify | **PASS** |
| GnuPG 2.4.8 | **UNSUPPORTED** (`unknown version 6`) |
| Secret key in git? | **No** — `.tools/v6/secret-v6.pgp` (gitignored) |

`identity_commitment` (v6 fixture): `f23b639adfe69667b5b81ab8793e51fa0d697b833be01b8294530587b9c42e89`

---

## KeyReference

### Findings

1. **Certificate version is unambiguous** from the Public-Key packet (`Version: 4` or `6`).  
2. **Fingerprint length follows version:** v4 → 20 bytes; v6 → 32 bytes.  
3. **Length alone is insufficient** as a trust signal (could be arbitrary `bstr`), but combined with “fingerprint must equal `fingerprint(cert)` and `len` must match `cert.version`” it is unambiguous.  
4. Explicit `{version, fingerprint}` maps add clarity for cert-less contexts; not required when the Proof Bundle always carries the OpenPGP certificate.  
5. Future OpenPGP versions: enforce length/alg via cert parse; reject unknown versions.

### Classification

| Choice | Status |
|--------|--------|
| Compact `bstr` fingerprint in Identity Document | **PROVISIONAL → near-FROZEN** for V1 |
| Normative check: `len(fpr)` matches cert version; bytes equal derived fpr | **FROZEN** |
| Explicit CBOR `KeyReference` map | **OPEN** (optional V1.1 / clarity upgrade) |
| Require v6-only | **OPEN** — reject for now; support both |

---

## Hostile tests

| Test | Result |
|------|--------|
| Wrong domain separator (`…\x00\x02`) | PASS — rejected by openpgp.js |
| NUL-truncated separator (`BIP353-IDENTITY` only) | PASS — rejected |
| Mutated payload | PASS — rejected |
| Malformed certificate | PASS — throws |
| Non-canonical CBOR (M2, still enforced) | PASS |
| Short/long fingerprint (M2) | PASS |
| invalid-signature fixture | PASS — rejected by all three OpenPGP engines |

---

## Domain separator

**Exact binary form (17 bytes — not 18):**

```
42 49 50 33 35 33 2d 49 44 45 4e 54 49 54 59 00 01
= "BIP353-IDENTITY" || 0x00 || 0x01
```

Verified identical construction in:

- Python (`DOMAIN_SEPARATOR_IDENTITY`)
- Sequoia harness (`printf 'BIP353-IDENTITY\0\1'`)
- openpgp.js (`Uint8Array.from([0x42,…,0x00,0x01])`)

**Normative warning:** `0x00` is a **protocol byte**, not a C-string terminator. Never pass this separator through:

- bash variables,
- JS strings built with `"\0"` if the runtime/API truncates,
- any API that treats data as NUL-terminated text.

Use explicit byte arrays / `Uint8Array` / `printf` octal escapes / Python `bytes`.

Message length for M1 valid vector: **147**.

---

## Findings

1. **Three-implementation interop on v4 detached signatures works** (GnuPG ↔ Sequoia ↔ openpgp.js).  
2. **openpgp.js 6.3.2 supports OpenPGP v6** parse+verify for our fixture; **GnuPG 2.4.8 does not**.  
3. **Detached packaging is the clear winner** after three-way testing.  
4. **Layer separation matters:** many “invalid” fixtures fail at protocol layer while OpenPGP remains valid — wallets must run *both*.  
5. **Signature packets remain non-unique** across signers (119 / 189 / 191 B) — verify semantics, never commit to signature bytes.  
6. **v6 is real and usable** via Sequoia today; ecosystem support is uneven (GnuPG lag).

---

## Recommendations

1. Freeze detached Binary signature profile for the BIP.  
2. Require Proof Bundles to include the OpenPGP certificate; fingerprints are cross-checks against it.  
3. Accept OpenPGP v4 and v6; document GnuPG v6 gap as an implementation limitation, not a protocol ban.  
4. Keep M1 v4 vectors as the permanent interop corpus; keep `vectors/v6/` as a parallel suite.  
5. Proceed to **M4 = BIP-353 payment binding + Bitcoin anchor + inclusion proof** only.

---

## Success criteria

| Criterion | Result |
|-----------|--------|
| GnuPG core (KROOT, KSIGN, binding, signature, CBOR, domain sep) | **PASS** |
| Sequoia core | **PASS** |
| openpgp.js core | **PASS** |
| Differences documented | **Yes** |
| Real v6 tested (not simulated) | **Yes** (Sequoia + openpgp.js; GnuPG UNSUPPORTED) |

### Milestone 3 overall: **PASS**

---

## Deliverables

| Path | Role |
|------|------|
| `MILESTONE_3_OPENPGP.md` | This report |
| `reference/openpgpjs_verify.mjs` | openpgp.js inspect/verify/sign helpers |
| `test/test_m3_openpgpjs.mjs` | A–D, G, H tests |
| `test/test_m3_v6.mjs` | Real v6 suite |
| `scripts/generate_v6_vectors.py` | Independent v6 fixture generator |
| `scripts/build_m3_matrix.py` | Cross-implementation matrix |
| `vectors/v6/*` | Real v6 fixtures (no secret key) |
| `test/m3_*.json` | Machine-readable results |

---

## FROZEN

- M1 vector bytes (interop corpus).  
- Detached OpenPGP **Binary** signature over `BIP353-IDENTITY || 0x00 || 0x01 || CanonicalCBOR`.  
- Domain separator = **exactly 17 bytes** `4249503335332d4944454e544954590001`.  
- Native OpenPGP `0x18` / `0x19` for `KROOT → KSIGN`.  
- Semantic signature verification (not packet-byte equality).  
- Strict deterministic CBOR for signed/hashed structures.  
- V1 provides **no freshness** (`rollback` stays valid).  
- Fingerprint in document must match certificate-derived fingerprint; length must match certificate version (20 for v4, 32 for v6).  
- Three-way v4 detached interop: GnuPG, Sequoia, openpgp.js.

## PROVISIONAL

- Compact `bstr` fingerprints (vs explicit `KeyReference` map).  
- Accepting both v4 and v6 in V1 while some verifiers (GnuPG 2.4.8) lack v6.  
- openpgp.js binding validation via packet inspection + verify (until `subkey.verify` is trustworthy).  
- Illustrative Bitcoin `B353ID` OP_RETURN tag (untouched).

## OPEN

- Explicit CBOR `KeyReference = {version, fingerprint}`.  
- Whether wallets MUST support v6 or MAY be v4-only.  
- GnuPG v6 timeline / workaround.  
- Bitcoin anchor encoding, inclusion/SPV proofs, confirmation policy.  
- BIP-353 semantic `PaymentBinding` registry (→ **M4**).  
- Transparency / freshness protocol.  
- Root rotation + escrowed recovery Proof Bundle fields.  
- PSBT `PSBT_OUT_IDENTITY_PROOF` allocation.  
- Final BIP media-wiki text.

---

## Recommendation for M4

**Single next milestone:**

> **M4 — BIP-353 Semantic Payment Binding + Bitcoin Identity Anchor + Inclusion Proof**

Scope exclusively:

1. Canonical `PaymentBindingV1` derived from **resolved** BIP-353 payment semantics (not raw DNS TXT).  
2. Normative `IDENTITY_COMMITMENT` / OP_RETURN (or successor) encoding.  
3. Bitcoin inclusion proof format suitable for offline/PSBT verification.  
4. Attack tests: payment substitution, anchor mismatch, confirmation policy.  
5. Still **no** final BIP publication until M4 vectors pass independently.

Do **not** expand M4 into transparency or recovery — those remain later.

# Milestone 2 — Cross-Implementation Interoperability

**Status:** PASS  
**Date:** 2026-09-26  
**Constraint honored:** Milestone 1 vectors were **not** regenerated or modified.

Vector integrity (SHA-256, unchanged from M1):

| File | SHA-256 |
|------|---------|
| `identity-signature.bin` | `cbf756b3716f4b943dc4a7138287c7fdea0bb3f87805206ae36d99ce7e8a8586` |
| `identity-payload.cbor` | `83f3a9f7fd6cce5bdb30fc7490b065c6a1f45660da37dbeec1b83527e4c7ae82` |
| `root.asc` | `5287dad7be7460318845514e4f9f02eaf45faa6acad87c08a7573c8dd1cf3fee` |
| `expected.json` | `ce5000f57218131070911f903cee8adb0e025f306da0670d70f99541d58ecad6` |

---

## Environment

| Component | Version / notes |
|-----------|-----------------|
| **GnuPG** | 2.4.8 (libgcrypt 1.12.0) — original signer of M1 fixtures |
| **Sequoia `sq`** | **1.3.1** (extracted from Ubuntu `sq_1.3.1-6_arm64.deb`; not system-installed via apt/sudo) |
| **sequoia-openpgp** | 2.1.0 |
| **Crypto backend** | Nettle 3.10 |
| **OpenPGP key version in fixtures** | **v4** Ed25519 (20-byte fingerprints) |
| **Architecture** | aarch64 |
| **openpgp.js** | Not available in this environment — not tested |
| **Install method** | `apt-get download sq && dpkg-deb -x … .tools/sq-root` (user-local; root install blocked) |

Reproduce:

```bash
# If .tools/sq-root missing:
apt-get download sq
dpkg-deb -x sq_*.deb .tools/sq-root

export SQ=$PWD/.tools/sq-root/usr/bin/sq
export GNUPGHOME=/tmp/bip353-gnupg   # for Sequoia→GnuPG roundtrip only

./reference/sequoia_verify.sh
./reference/sequoia_gnupg_roundtrip.sh
python3 test/test_m2_interop.py
python3 test/test_hostile_parsing.py
```

---

## Fingerprint verification

| Key | Expected (M1) | Sequoia `sq inspect` | Result |
|-----|---------------|----------------------|--------|
| **KROOT** | `de26bd614a4224ac0b704ed1c8f68e1738268297` | `DE26BD614A4224AC0B704ED1C8F68E1738268297` | **PASS** |
| **KSIGN** | `55f38348c4a60b8ffd7b40c86186d1b88a7badea` | `55F38348C4A60B8FFD7B40C86186D1B88A7BADEA` | **PASS** |

Both `root.asc` and `signing.asc` (identical certificate export) parse cleanly under Sequoia.

Certificate details (Sequoia):

- Public-key algo: EdDSA, 256 bits  
- Key flags: primary = certification; subkey = signing  
- User ID: `BIP353 Identity Test <alice@example.test>`  
- Packet version: **4** (confirmed via `sq packet dump`)

---

## Binding verification

| Mechanism | OpenPGP type | Sequoia observation | Result |
|-----------|--------------|---------------------|--------|
| **0x18** | Subkey Binding Signature | `Type: SubkeyBinding` present on subkey | **PASS** |
| **0x19** | Primary Key Binding Signature | `Type: PrimaryKeyBinding` embedded in 0x18 unhashed area | **PASS** |

`sq cert lint` on the certificate: **0 issues** (binding + backsig use SHA-512, not SHA-1).

No proprietary `KROOT → KSIGN` signature was introduced. Authorization remains native OpenPGP.

---

## Signature interoperability

Signed message (exact M1 bytes):

```
DOMAIN_SEPARATOR || identity-payload.cbor
= "BIP353-IDENTITY" || 0x00 || 0x01 || <130 CBOR bytes>
= 147 bytes total
SHA-256(message) = d50192d5379ca1e4a525f05d7d299dacb849638091ea548da62634d0d52a5d51
```

| Direction | Result | Notes |
|-----------|--------|-------|
| **GnuPG → Sequoia** | **PASS** | Existing `identity-signature.bin` (119 bytes) verifies with `sq verify --signature-file` |
| **Sequoia → GnuPG** | **PASS** | New Sequoia detached sig (191 bytes) verifies with `gpg --verify` (`GOODSIG` / `VALIDSIG`) |
| **Byte-identical signatures?** | **No** (expected) | GnuPG 119 B vs Sequoia 191 B |

### What must match vs what must not

| Must be identical | Need not be identical |
|-------------------|------------------------|
| Signed message bytes | Signature packet octets |
| Semantic verification result | CTB old vs new |
| Signer fingerprint (`KSIGN`) | Optional hashed subpackets (e.g. Sequoia `salt@notations.sequoia-pgp.org`) |
| Domain separator + CBOR | Signature creation time / salt |

**Distinction (FROZEN for protocol wording):**  
Implementations MUST treat OpenPGP signatures as **semantically interchangeable**, not as fixed byte strings. Proof Bundles carry *a* valid detached signature over the canonical message; verifiers MUST NOT require a specific signer implementation’s packet encoding.

### Tooling pitfall (security finding)

Bash **cannot store NUL bytes in variables**. An early harness used:

```bash
DOMAIN_SEP=$'BIP353-IDENTITY\x00\x01'   # truncates at NUL → 15 bytes
```

This produced a 145-byte message and Sequoia correctly reported `Message has been manipulated`. Fixed harnesses write the separator with `printf 'BIP353-IDENTITY\0\1'` or Python. Documented so wallet implementers do not repeat this.

---

## Valid vector

| Check | Result |
|-------|--------|
| Sequoia fingerprint KROOT/KSIGN | PASS |
| Sequoia 0x18 / 0x19 | PASS |
| Sequoia verifies M1 detached signature | PASS |
| Reference verifier (GnuPG path) | PASS |
| `payment_hash` reproduced | `35bc7db73b5091938aa3e3c4a3da97e360b6b086fb95f9b084126d665e938629` PASS |
| `identity_commitment` reproduced | `82282ed2aebfcbe223a040db5689e569925503f321e643163eeab0ceb47968ae` PASS |

**Valid vector: PASS**

---

## Invalid vectors

Protocol checks via reference verifier; OpenPGP signature rejection also confirmed under Sequoia for `invalid-signature`.

| Fixture | Expected | Actual | Result |
|---------|----------|--------|--------|
| valid | VALID / freshness UNKNOWN | VALID CRYPTOGRAPHICALLY | PASS |
| wrong-domain | DOMAIN_IDENTIFIER_INCONSISTENT | DOMAIN_IDENTIFIER_INCONSISTENT | PASS |
| wrong-identifier | IDENTIFIER_MISMATCH | IDENTIFIER_MISMATCH | PASS |
| wrong-root | ROOT_KEY_MISMATCH | ROOT_KEY_MISMATCH | PASS |
| wrong-signing-key | SIGNING_KEY_MISMATCH | SIGNING_KEY_MISMATCH | PASS |
| invalid-signature | INVALID_IDENTITY_SIGNATURE | INVALID_IDENTITY_SIGNATURE (+ Sequoia reject) | PASS |
| expired | IDENTITY_EXPIRED | IDENTITY_EXPIRED | PASS |
| wrong-payment | PAYMENT_BINDING_MISMATCH | PAYMENT_BINDING_MISMATCH | PASS |
| wrong-payment-hash | INVALID_IDENTITY_SIGNATURE | INVALID_IDENTITY_SIGNATURE | PASS |
| wrong-anchor | ANCHOR_MISMATCH | ANCHOR_MISMATCH | PASS |
| sequence-modified | INVALID_IDENTITY_SIGNATURE | INVALID_IDENTITY_SIGNATURE | PASS |
| **rollback** | **VALID / freshness UNKNOWN** | **VALID / freshness=unknown** | **PASS** (intentional) |

Machine-readable copy: `test/m2_results.json`.

---

## Canonical CBOR tests

| Test | Result |
|------|--------|
| Trailing bytes rejected | PASS |
| Non-canonical map key order rejected | PASS |
| Duplicate map keys rejected | PASS |
| Non-shortest integer encoding rejected | PASS (decoder hardened in M2) |
| Same semantic map → identical dumps | PASS |
| Unknown extra field changes signed bytes | PASS |
| Short / long fingerprint field rejected by verifier | PASS |
| Signature over mutated message rejected (Sequoia) | PASS |

**Canonical CBOR tests: PASS**

M2 hardening (does not change vectors): `reference/cbor.py` now rejects non-shortest integer/length encodings per RFC 8949 Core Deterministic Encoding. Existing M1 CBOR fixtures remain valid under the stricter decoder.

---

## Detached signature analysis

### Option A — Detached (current M1)

```
identity-payload.cbor          (canonical signed content without signature field)
identity-signature.bin         (OpenPGP Signature packet, type Binary)
```

Message = `DOMAIN_SEPARATOR || payload`.

### Option B — Inline OpenPGP message

```
One-Pass Signature
Literal Data Packet   ← wraps message (format, optional filename/date)
Signature Packet
```

Measured on same 147-byte content (Sequoia):

| Form | Size |
|------|------|
| Raw message | 147 B |
| Detached sig (GnuPG M1) | 119 B → **total proof parts ≈ 249 B** |
| Inline signed message (Sequoia) | **361 B** |

### Comparison

| Criterion | Detached (A) | Literal / inline (B) |
|-----------|--------------|----------------------|
| Interop GnuPG ↔ Sequoia | Demonstrated PASS | Also supported by both |
| Exact signed bytes | Fully controlled by protocol | Signature covers literal framing rules; filename/date metadata risk |
| Canonicalisation | Protocol owns CBOR + domain sep | Must also specify literal packet fields |
| Size | Smaller | Larger (~+100 B here) |
| Parsing | Two clear artifacts | Need OpenPGP message parser |
| Wallet embedding (PSBT) | Easy: opaque sig + CBOR | Heavier |
| openpgp.js | Detached verify widely used | Inline also common |
| Ambiguity risk | Low if message construction is normative | Higher (literal headers) |

### Recommendation (PROVISIONAL → near-FROZEN)

**Prefer Option A (detached Binary signature over `DOMAIN_SEPARATOR || CanonicalCBOR`)**.

Rationale: M2 proved cross-implementation verify on the exact byte string the protocol defines, without OpenPGP literal metadata. Inline messages add size and framing degrees of freedom without improving the security model.

Not yet a normative BIP sentence until openpgp.js is also exercised — but no conflict was found that would favor B.

---

## v4/v6 analysis

### Current state

Fixtures use OpenPGP **v4** fingerprints (20 bytes). Sequoia and GnuPG agree. No fake v6 fingerprints were generated.

### Can version be derived from the certificate?

**Yes, unambiguously**, from the Public-Key / Public-Subkey packet `Version` field (Sequoia dumps `Version: 4`). Fingerprint algorithms differ by version (v4: truncated SHA-1 over key material; v6: SHA-256). The verifier that parses the certificate already knows the version before comparing fingerprints.

### CBOR field design options

**Option 1 — Implicit length (current M1):**

```
root-fingerprint: bstr   ; 20 or 32 bytes
```

Risk: a 32-byte value could be misread without checking the cert version.

**Option 2 — Explicit KeyReference:**

```
KeyReference = {
  0: version,        ; 4 or 6
  1: fingerprint     ; bstr matching version
}
```

Clearer, slightly larger, allows rejecting `version=4` with 32-byte fpr before touching OpenPGP.

**Option 3 — Fingerprint only + cert is authoritative:**

Document stores fingerprint bytes; verifier derives version from cert and checks length:

- v4 ⇒ exactly 20 bytes  
- v6 ⇒ exactly 32 bytes  
- mismatch ⇒ `ROOT_KEY_MISMATCH` / `SIGNING_KEY_MISMATCH`

### Recommendation (PROVISIONAL)

Use **Option 3 for V1 wire format** (keep compact `bstr` fingerprints as in M1) **plus normative length checks tied to certificate version**. Optionally add Option 2 later if multi-cert or cert-less contexts appear.

Do **not** choose v4-only or v6-only yet: wallets should accept both once generators exist; vectors can stay v4 until a real v6 fixture is produced with Sequoia/GnuPG that supports it.

---

## Security findings

1. **Cross-implementation signature verify works** — hosting-independent identity proofs are not GnuPG-specific.  
2. **Signature packets are not stable identifiers** — never hash the signature blob as a commitment; hash the canonical message / document.  
3. **NUL in domain separator** — correct for binary domain separation; dangerous in shell/C string APIs. Prefer languages with explicit byte arrays; document for implementers.  
4. **Non-canonical CBOR** — same semantic map ≠ same signed bytes. Strict decode (now in reference) or mandatory re-encode-before-verify is required.  
5. **Rollback remains undetectable in V1** — reconfirmed; freshness stays UNKNOWN without transparency.  
6. **Sequoia adds salt notation** — does not affect verification; illustrates packet non-uniqueness.

No conflict requiring vector changes was found.

---

## Remaining ambiguities

| # | Topic | Status after M2 |
|---|--------|-----------------|
| 1 | Detached vs literal | Strong evidence for detached; confirm with openpgp.js |
| 2 | v4 vs v6 policy | Accept both; length↔version checks; no fake v6 |
| 3 | Signature packet uniqueness | Resolved: semantic only |
| 4 | OP_RETURN / Bitcoin proof | Still out of scope (commitment bytes verified only) |
| 5 | Root rotation / recovery | Unchanged OPEN |
| 6 | Transparency log freshness | Unchanged OPEN (rollback demo) |
| 7 | Identifier normalization vs BIP-353 | Unchanged OPEN |
| 8 | Payment method registry | Unchanged OPEN |

---

## Recommendation

1. **Keep M1 vectors frozen** as the interop corpus.  
2. **Treat detached OpenPGP Binary signatures** over `DOMAIN_SEPARATOR || CBOR` as the working signature profile.  
3. **Require semantic OpenPGP verify**, not signature-byte equality, in the BIP.  
4. **Require strict deterministic CBOR** on decode (or equivalent re-encode check).  
5. **Defer Bitcoin OP_RETURN tag** and transparency log to later milestones.  
6. **Next useful milestone (M3):** openpgp.js (or second Sequoia-only signer without GnuPG secret) + optional real OpenPGP v6 fixture when tooling allows — still without rewriting M1 vectors.

---

## Success criteria checklist

| Criterion | Result |
|-----------|--------|
| KROOT fingerprint | **PASS** |
| KSIGN fingerprint | **PASS** |
| KROOT→KSIGN binding 0x18/0x19 | **PASS** |
| Identity signature (Sequoia) | **PASS** |
| Valid vector | **PASS** |
| All expected mutations | **PASS** |
| Canonical CBOR tests | **PASS** |
| GnuPG ↔ Sequoia | **PASS** |
| rollback | **VALID / freshness UNKNOWN** (exception honored) |

### Milestone 2 overall: **PASS**

---

## Deliverables

| Path | Role |
|------|------|
| `MILESTONE_2_INTEROP.md` | This report |
| `reference/sequoia_verify.sh` | Sequoia smoke checks on frozen vectors |
| `reference/sequoia_gnupg_roundtrip.sh` | Bidirectional signature interop |
| `test/test_m2_interop.py` | Fingerprints, binding, vectors table |
| `test/test_hostile_parsing.py` | Canonical CBOR / hostile inputs |
| `test/m2_results.json` | Machine-readable results |
| `.tools/sq-root/` | Local Sequoia binary (gitignored) |

---

## FROZEN / PROVISIONAL / OPEN

### FROZEN

- M1 vector byte strings (do not regenerate for interop).  
- Cross-implementation verify of detached Binary signatures over `BIP353-IDENTITY\x00\x01 || CBOR`.  
- Use of native OpenPGP `0x18` / `0x19` for `KROOT → KSIGN` (no parallel binding primitive).  
- Fingerprint equality is byte-for-byte against the value derived from the certificate.  
- Signature **semantics** matter; signature **packet encodings** need not match across implementations.  
- V1 does not provide freshness; `rollback` stays cryptographically valid.  
- Strict deterministic CBOR for signed/hashed structures (shortest form, sorted keys, no trailing bytes, no duplicate keys).

### PROVISIONAL

- Detached (Option A) as the preferred Proof Bundle signature packaging (pending openpgp.js confirmation).  
- Compact `bstr` fingerprints with length enforced from certificate version (vs explicit `KeyReference` map).  
- Domain separator exact form `BIP353-IDENTITY\x00\x01` (works; NUL hazards for some languages).  
- Sequoia 1.3.1 / GnuPG 2.4.8 as known-good interop pair for Ed25519 v4.  
- Illustrative OP_RETURN tag `B353ID` (unchanged; not validated as final).

### OPEN

- openpgp.js interoperability.  
- Real OpenPGP v6 test vectors (when generators exist).  
- Whether BIP text allows v4-only deployments or requires v6 readiness.  
- Bitcoin anchor proof format / confirmation policy / OP_RETURN namespace.  
- Transparency log / freshness protocol (V2).  
- Root rotation + escrowed recovery Proof Bundle fields.  
- BIP-353 payment object registry and identifier normalization cross-refs.  
- PSBT `PSBT_OUT_IDENTITY_PROOF` allocation.

**No final BIP text in this milestone.**

/**
 * Blind independent verification of vectors/schnorr/*
 * Does not import reference/schnorr_v2.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  TAG_SUBKEY_BINDING,
  TAG_IDENTITY,
  TAG_PAYMENT,
  TAG_ANCHOR,
  taggedHash,
  verifySchnorr,
  pubkeyFromSecret,
  cborDecode,
  cborEncode,
  parseTx,
  verifyMerkle,
  parseHeader,
  extractCommitmentFromTx,
  extractB353S2,
  eq,
  hexToBytes,
  bytesToHex,
} from "./lib.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../../..");
const VEC = path.join(ROOT, "vectors/schnorr");

function load(name) {
  return JSON.parse(fs.readFileSync(path.join(VEC, name), "utf8"));
}

const results = {
  stack: {
    language: "JavaScript",
    runtime: process.version,
    libraries: {
      "@noble/curves": "1.8.1",
      "@noble/hashes": "1.7.1",
      cbor: "hand-written subset (RFC 8949 core)",
      bitcoin: "hand-written tx/merkle/header parse",
    },
  },
  bip340: null,
  components: {},
  vectors: [],
  ambiguities: [],
  divergences: [],
};

// --- CBOR self-checks ---
function cborTests() {
  const cases = [];
  const enc = cborEncode({ 0: 1, 2: hexToBytes("ab"), 1: "x" });
  const enc2 = cborEncode({ 0: 1, 2: hexToBytes("ab"), 1: "x" });
  cases.push({ name: "deterministic", pass: bytesToHex(enc) === bytesToHex(enc2) });
  try {
    cborDecode(Uint8Array.of(0x18, 0x00));
    cases.push({ name: "reject-nonminimal", pass: false });
  } catch {
    cases.push({ name: "reject-nonminimal", pass: true });
  }
  try {
    cborDecode(Uint8Array.of(...enc, 0x00));
    cases.push({ name: "reject-trailing", pass: false });
  } catch {
    cases.push({ name: "reject-trailing", pass: true });
  }
  try {
    cborDecode(Uint8Array.of(0x9f, 0x01, 0xff));
    cases.push({ name: "reject-indefinite", pass: false });
  } catch {
    cases.push({ name: "reject-indefinite", pass: true });
  }
  return cases;
}

function verifyLogicalValid(vec) {
  const out = { id: vec.id, checks: {}, error: null, actual: {} };
  try {
    const rootSk = hexToBytes(vec.root_private_key);
    const rootPk = pubkeyFromSecret(rootSk);
    if (bytesToHex(rootPk) !== vec.root_pubkey) throw new Error("root pubkey mismatch");

    const bindingCbor = hexToBytes(vec.subkey_binding_cbor);
    const bindingHash = taggedHash(TAG_SUBKEY_BINDING, bindingCbor);
    out.checks.binding_hash =
      bytesToHex(bindingHash) === vec.subkey_binding_hash;
    if (!out.checks.binding_hash) throw new Error("binding hash");

    out.checks.binding_sig = verifySchnorr(
      hexToBytes(vec.root_pubkey),
      bindingHash,
      hexToBytes(vec.subkey_binding_signature)
    );
    if (!out.checks.binding_sig) throw new Error("binding sig");

    // re-encode decoded binding must match
    const bindingObj = cborDecode(bindingCbor);
    out.checks.binding_cbor_roundtrip =
      bytesToHex(cborEncode(bindingObj)) === vec.subkey_binding_cbor;

    const payCbor = hexToBytes(vec.payment_binding_cbor);
    const payHash = taggedHash(TAG_PAYMENT, payCbor);
    out.checks.payment_hash = bytesToHex(payHash) === vec.payment_hash;
    if (!out.checks.payment_hash) throw new Error("payment hash");

    const signedCbor = hexToBytes(vec.identity_signed_cbor);
    const idHash = taggedHash(TAG_IDENTITY, signedCbor);
    out.checks.identity_hash = bytesToHex(idHash) === vec.identity_message_hash;
    if (!out.checks.identity_hash) throw new Error("identity hash");

    out.checks.identity_sig = verifySchnorr(
      hexToBytes(vec.signing_pubkey),
      idHash,
      hexToBytes(vec.identity_signature)
    );
    if (!out.checks.identity_sig) throw new Error("identity sig");

    const doc = cborDecode(hexToBytes(vec.identity_document_cbor));
    const signed = { ...doc };
    delete signed[9];
    out.checks.signed_cbor_match =
      bytesToHex(cborEncode(signed)) === vec.identity_signed_cbor;

    // payment in doc
    out.checks.payment_in_doc = bytesToHex(doc[7]) === vec.payment_hash;

    const anchorCbor = hexToBytes(vec.anchor_message_cbor);
    const commit = taggedHash(TAG_ANCHOR, anchorCbor);
    out.checks.anchor_commitment =
      bytesToHex(commit) === vec.anchor_commitment;
    if (!out.checks.anchor_commitment) throw new Error("anchor commitment");

    // op_return logical
    const op = hexToBytes(vec.op_return);
    const extracted = extractB353S2(op);
    out.checks.op_return =
      extracted && bytesToHex(extracted) === vec.anchor_commitment;

    out.actual.identity_verified = out.checks.binding_sig && out.checks.identity_sig;
    out.actual.payment_verified = out.checks.payment_hash && out.checks.payment_in_doc;
    // Per mini-spec dual-binding (Phase 6.1): no bitcoin_proof ⇒ not anchored
    out.actual.identity_anchored = false;
    out.actual.continuity_verified = false;

    if (vec.expected?.identity_anchored === true && !vec.bitcoin_proof) {
      results.ambiguities.push(
        `${vec.id}: expected.identity_anchored=true in Phase-4 JSON, but mini-spec dual-binding requires bitcoin_proof; independent sets identity_anchored=false`
      );
    }

    out.result = "pass";
  } catch (e) {
    out.result = "fail";
    out.error = String(e.message || e);
  }
  return out;
}

function verifyLogicalInvalid(vec) {
  const out = { id: vec.id, expected: vec.expected.error_code, actual: null, result: null };
  try {
    if (vec.id === "V2-INVALID-001") {
      const hash = taggedHash(
        TAG_SUBKEY_BINDING,
        hexToBytes(vec.subkey_binding_cbor)
      );
      const ok = verifySchnorr(
        hexToBytes(vec.root_pubkey),
        hash,
        hexToBytes(vec.subkey_binding_signature)
      );
      out.actual = ok ? "ACCEPTED" : "INVALID_SUBKEY_BINDING";
    } else if (vec.id === "V2-INVALID-002" || vec.id === "V2-INVALID-005") {
      const doc = cborDecode(hexToBytes(vec.identity_document_cbor));
      const signed = { ...doc };
      delete signed[9];
      const hash = taggedHash(TAG_IDENTITY, cborEncode(signed));
      const ok = verifySchnorr(
        hexToBytes(vec.signing_pubkey),
        hash,
        hexToBytes(vec.identity_signature)
      );
      out.actual = ok ? "ACCEPTED" : "INVALID_IDENTITY_SIGNATURE";
    } else if (vec.id === "V2-INVALID-003") {
      // logical: op_return commitment != anchor from document root
      const commit = taggedHash(TAG_ANCHOR, hexToBytes(vec.anchor_message_cbor));
      const extracted = extractB353S2(hexToBytes(vec.op_return));
      out.actual =
        extracted && bytesToHex(extracted) === bytesToHex(commit)
          ? "ACCEPTED"
          : "ANCHOR_MISMATCH";
    } else if (vec.id === "V2-INVALID-004") {
      const payHash = taggedHash(
        TAG_PAYMENT,
        hexToBytes(vec.payment_binding_cbor)
      );
      const doc = cborDecode(hexToBytes(vec.identity_document_cbor));
      out.actual =
        bytesToHex(payHash) === bytesToHex(doc[7])
          ? "ACCEPTED"
          : "PAYMENT_BINDING_MISMATCH";
    }
    out.result =
      out.actual === vec.expected.error_code ||
      (out.actual !== "ACCEPTED" && vec.expected.result === "invalid")
        ? "pass"
        : "fail";
    // tighten: must match expected code when we set actual to that code
    if (out.actual !== vec.expected.error_code) out.result = "fail";
  } catch (e) {
    out.result = "fail";
    out.error = String(e.message || e);
  }
  return out;
}

function verifyBtc(vec) {
  const out = { id: vec.id, expected: vec.expected.error_code, actual: null, result: null };
  try {
    const proof = vec.bitcoin_proof;
    const raw = hexToBytes(proof.raw_tx);
    const parsed = parseTx(raw);
    const txidInternal = hexToBytes(proof.txid_internal);
    if (!eq(parsed.txidInternal, txidInternal)) {
      // if vector intends TXID_MISMATCH, aux field wrong
      if (vec.expected.error_code === "TXID_MISMATCH") {
        out.actual = "TXID_MISMATCH";
        out.result = "pass";
        return out;
      }
      throw new Error("txid calc mismatch unexpectedly");
    }
    // For non-txid tests, computed must match aux when valid path
    if (vec.expected.error_code === "TXID_MISMATCH") {
      // shouldn't reach if aux equals computed
      out.actual = "ACCEPTED";
      out.result = "fail";
      return out;
    }

    let extracted;
    try {
      extracted = extractCommitmentFromTx(raw);
    } catch (e) {
      out.actual = e.message;
      out.result = out.actual === vec.expected.error_code ? "pass" : "fail";
      return out;
    }

    const expectedCommit = hexToBytes(vec.anchor_commitment);
    if (!eq(extracted, expectedCommit)) {
      out.actual = "WRONG_TX_COMMITMENT";
      out.result = out.actual === vec.expected.error_code ? "pass" : "fail";
      return out;
    }
    if (!eq(extracted, hexToBytes(proof.commitment))) {
      out.actual = "WRONG_TX_COMMITMENT";
      out.result = out.actual === vec.expected.error_code ? "pass" : "fail";
      return out;
    }

    const hdr = parseHeader(hexToBytes(proof.block_header));
    const branch = (proof.merkle_branch || []).map(hexToBytes);
    const merkleOk = verifyMerkle(
      parsed.txidInternal,
      proof.tx_index,
      branch,
      hdr.merkleRoot
    );
    if (!merkleOk) {
      out.actual = "WRONG_MERKLE_PROOF";
      out.result = out.actual === vec.expected.error_code ? "pass" : "fail";
      return out;
    }

    if (vec.expected.result === "valid") {
      out.actual = "valid";
      out.result = "pass";
      out.dual_binding = true;
    } else {
      out.actual = "ACCEPTED";
      out.result = "fail";
    }
  } catch (e) {
    out.result = "fail";
    out.error = String(e.message || e);
  }
  return out;
}

// Run
results.bip340 = "see bip340_check.mjs";
results.components.cbor = cborTests();

const files = fs.readdirSync(VEC).filter((f) => f.endsWith(".json"));
for (const f of files.sort()) {
  const vec = load(f);
  if (f.startsWith("V2-BTC-")) results.vectors.push(verifyBtc(vec));
  else if (f === "V2-VALID-001.json") results.vectors.push(verifyLogicalValid(vec));
  else if (f.startsWith("V2-INVALID-")) results.vectors.push(verifyLogicalInvalid(vec));
}

const fails = results.vectors.filter((v) => v.result !== "pass");
results.summary = {
  vector_pass: results.vectors.length - fails.length,
  vector_fail: fails.length,
  fail_ids: fails.map((v) => v.id),
  cbor_pass: results.components.cbor.every((c) => c.pass),
};

const outPath = path.join(__dirname, "../independent-results.json");
fs.writeFileSync(outPath, JSON.stringify(results, null, 2) + "\n");
console.log(JSON.stringify(results.summary, null, 2));
console.log("wrote", outPath);
if (results.ambiguities.length) {
  console.log("AMBIGUITIES:");
  for (const a of results.ambiguities) console.log(" -", a);
}
process.exit(fails.length || !results.summary.cbor_pass ? 1 : 0);

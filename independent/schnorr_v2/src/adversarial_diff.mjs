/**
 * Phase 10 — cross-implementation differential checks (JS side).
 * Compares CBOR reject behaviour and TaggedHash digests against fixtures
 * emitted by the Python adversarial harness.
 *
 * Does NOT import reference/schnorr_v2.
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
  signSchnorr,
  pubkeyFromSecret,
  cborDecode,
  cborEncode,
  hexToBytes,
  bytesToHex,
  extractB353S2,
  extractCommitmentFromTx,
  parseTx,
  verifyMerkle,
  parseHeader,
  eq,
} from "./lib.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../../..");
const CASES_PATH = path.join(ROOT, "test/schnorr_v2/differential_cases.json");
const OUT_PATH = path.join(__dirname, "../differential-results.json");

const SEED = "a3535210";
const results = { seed: SEED, cases: [], divergences: [] };

function loadCases() {
  return JSON.parse(fs.readFileSync(CASES_PATH, "utf8"));
}

function record(name, expected, actual, ok, extra = {}) {
  const row = { name, expected, actual, ok, ...extra };
  results.cases.push(row);
  if (!ok) {
    results.divergences.push(row);
    console.log("DIFF/FAIL", name, { expected, actual });
  }
}

function run() {
  const cases = loadCases();
  // Documented Phase-10 divergence (DO NOT PATCH in this phase):
  // JS TextDecoder replaces invalid UTF-8; Python cbor.loads rejects.
  const DOCUMENTED = new Set(["cbor_reject:invalid_utf8"]);

  // CBOR rejects
  for (const c of cases.cbor_reject) {
    let rejected = false;
    try {
      cborDecode(hexToBytes(c.hex));
    } catch {
      rejected = true;
    }
    const name = `cbor_reject:${c.name}`;
    const actual = rejected ? "reject" : "ACCEPT";
    const matchesPython = rejected && c.python === "reject";
    if (DOCUMENTED.has(name) && !matchesPython) {
      record(name, "reject", actual, true, {
        documented_divergence: true,
        finding: "ADV-M1",
        note: "JS accepts invalid UTF-8 text (replacement); Python rejects — documented, not patched",
      });
    } else {
      record(name, "reject", actual, matchesPython);
    }
  }

  // TaggedHash cross-tag
  for (const c of cases.tagged_hash) {
    const got = bytesToHex(taggedHash(c.tag, hexToBytes(c.payload_hex)));
    record(
      `tagged_hash:${c.name}`,
      c.digest_hex,
      got,
      got === c.digest_hex
    );
  }

  // BIP-340 mutations
  for (const c of cases.schnorr) {
    const ok = verifySchnorr(
      hexToBytes(c.pubkey),
      hexToBytes(c.msg),
      hexToBytes(c.sig)
    );
    const actual = ok ? "accept" : "reject";
    record(`schnorr:${c.name}`, c.expected, actual, actual === c.expected);
  }

  // B353S2 extract from scripts
  for (const c of cases.b353s2) {
    let actual = "reject";
    try {
      const commit = extractB353S2(hexToBytes(c.script_hex));
      actual = commit ? bytesToHex(commit) : "reject";
    } catch {
      actual = "reject";
    }
    record(`b353s2:${c.name}`, c.expected, actual, actual === c.expected);
  }

  // Dual-binding matrix (subset)
  for (const c of cases.dual_binding) {
    let actual = "reject";
    try {
      const proof = c.proof;
      const raw = hexToBytes(proof.raw_tx);
      const parsed = parseTx(raw);
      if (!eq(parsed.txidInternal, hexToBytes(proof.txid_internal))) {
        throw new Error("TXID_MISMATCH");
      }
      const extracted = extractCommitmentFromTx(raw);
      if (!eq(extracted, hexToBytes(c.expected_commitment))) {
        throw new Error("WRONG_TX_COMMITMENT");
      }
      const hdr = parseHeader(hexToBytes(proof.block_header));
      const branch = (proof.merkle_branch || []).map(hexToBytes);
      if (
        !verifyMerkle(parsed.txidInternal, proof.tx_index, branch, hdr.merkleRoot)
      ) {
        throw new Error("WRONG_MERKLE_PROOF");
      }
      actual = "anchored";
    } catch (e) {
      actual = "reject";
    }
    record(`dual:${c.name}`, c.expected, actual, actual === c.expected);
  }

    results.summary = {
    total: results.cases.length,
    pass: results.cases.filter((x) => x.ok).length,
    fail: results.cases.filter((x) => !x.ok).length,
    divergences: results.divergences.length,
    documented_divergences: results.cases.filter((x) => x.documented_divergence)
      .length,
  };
  fs.writeFileSync(OUT_PATH, JSON.stringify(results, null, 2) + "\n");
  console.log(JSON.stringify(results.summary, null, 2));
  console.log("wrote", OUT_PATH);
  // Fail only on unexplained mismatches
  process.exit(results.summary.fail ? 1 : 0);
}

run();

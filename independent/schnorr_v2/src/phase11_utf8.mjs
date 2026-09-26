/**
 * Phase 11 — JS side of ADV-M1 UTF-8 / CBOR matrix.
 * Does NOT patch lib.mjs (investigation only).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cborDecode, cborEncode, bytesToHex, hexToBytes, taggedHash, TAG_IDENTITY } from "./lib.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, "../../..");
const CASES = path.join(ROOT, "test/schnorr_v2/phase11_utf8_cases.json");
const OUT = path.join(ROOT, "test/schnorr_v2/phase11_utf8_js_results.json");

const SEED = "a3535210";

function jsDecode(rawHex) {
  const raw = hexToBytes(rawHex);
  try {
    const obj = cborDecode(raw);
    if (typeof obj === "string") {
      const re = cborEncode(obj);
      return {
        status: "accept",
        decoded: obj,
        decoded_codepoints: [...obj].map(
          (c) => "U+" + c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")
        ),
        reencode_hex: bytesToHex(re),
        roundtrip_same: bytesToHex(re) === rawHex,
        error: null,
      };
    }
    return { status: "accept", decoded_type: typeof obj, error: null };
  } catch (e) {
    return { status: "reject", error: String(e.message || e), exception: "Error" };
  }
}

function main() {
  const cases = JSON.parse(fs.readFileSync(CASES, "utf8"));
  const rows = [];
  let agree = 0;
  let diverge = 0;
  let encoding_mismatch_on_accept = 0;

  for (const c of cases.cases) {
    const js = jsDecode(c.raw_hex);
    const status_same = js.status === c.python_status;
    let encoding_same = null;
    if (js.status === "accept" && c.python_status === "accept") {
      encoding_same = js.reencode_hex === c.python_reencode_hex;
      if (!encoding_same) encoding_mismatch_on_accept++;
    }
    if (status_same && encoding_same !== false) agree++;
    else diverge++;

    rows.push({
      name: c.name,
      raw_hex: c.raw_hex,
      python: c.python_status,
      javascript: js.status,
      status_same,
      encoding_same,
      python_reencode_hex: c.python_reencode_hex || null,
      javascript_reencode_hex: js.reencode_hex || null,
      javascript_detail: js,
    });
  }

  const minimal = jsDecode(cases.minimal_hex || "61ff");
  // Hash impact demo: digest of wire vs digest of re-encoded replacement
  const wire = hexToBytes("61ff");
  let reenc;
  try {
    const s = cborDecode(wire);
    reenc = cborEncode(s);
  } catch {
    reenc = null;
  }
  const hash_impact = {
    wire_hex: "61ff",
    js_accepts_wire: minimal.status === "accept",
    reencode_hex: reenc ? bytesToHex(reenc) : null,
    digest_wire: bytesToHex(taggedHash(TAG_IDENTITY, wire)),
    digest_reencode: reenc
      ? bytesToHex(taggedHash(TAG_IDENTITY, reenc))
      : null,
    digests_equal: reenc
      ? bytesToHex(taggedHash(TAG_IDENTITY, wire)) ===
        bytesToHex(taggedHash(TAG_IDENTITY, reenc))
      : null,
  };

  const report = {
    seed: SEED,
    minimal: {
      id: "ADV-M1-minimal",
      input_hex: "61ff",
      javascript: minimal,
      python_status: "reject",
    },
    hash_impact_demo: hash_impact,
    summary: {
      total: rows.length,
      status_or_encoding_agree: agree,
      diverge,
      encoding_mismatch_both_accept: encoding_mismatch_on_accept,
    },
    rows,
  };
  fs.writeFileSync(OUT, JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify({ wrote: OUT, ...report.summary, minimal_js: minimal.status, hash: hash_impact }, null, 2));
  // Fail only if both accept but encodings differ (CRITICAL investigation)
  process.exit(encoding_mismatch_on_accept ? 2 : 0);
}

main();

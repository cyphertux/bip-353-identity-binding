/**
 * Independent experimental Schnorr V2 reproduction.
 * Built from docs/SCHNORR_V2_MINI_SPEC.md + vectors/schnorr only.
 * Does NOT import reference/schnorr_v2.
 *
 * EXPERIMENTAL — NON-NORMATIVE — NOT AN OFFICIAL BIP
 */

import { createHash } from "node:crypto";
import { schnorr } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex, hexToBytes, concatBytes } from "@noble/hashes/utils";

export const TAG_SUBKEY_BINDING = "BIP353-IDENTITY/V2/SUBKEY-BINDING";
export const TAG_IDENTITY = "BIP353-IDENTITY/V2/IDENTITY";
export const TAG_PAYMENT = "BIP353-IDENTITY/V2/PAYMENT";
export const TAG_ANCHOR = "BIP353-IDENTITY/V2/ANCHOR";
export const OP_RETURN_TAG = new TextEncoder().encode("B353S2");

export function sha256d(data) {
  return sha256(sha256(data));
}

/** BIP-340 TaggedHash */
export function taggedHash(tag, msg) {
  const tagBytes = typeof tag === "string" ? new TextEncoder().encode(tag) : tag;
  const th = sha256(tagBytes);
  return sha256(concatBytes(th, th, msg));
}

export function verifySchnorr(pubkey32, msg, sig64) {
  return schnorr.verify(sig64, msg, pubkey32);
}

export function signSchnorr(secret32, msg) {
  return schnorr.sign(msg, secret32);
}

export function pubkeyFromSecret(secret32) {
  return schnorr.getPublicKey(secret32);
}

// --- Minimal deterministic CBOR (RFC 8949 core subset) ---

function encUint(major, value) {
  const ai = major << 5;
  if (value < 24) return Uint8Array.of(ai | value);
  if (value < 256) return Uint8Array.of(ai | 24, value);
  if (value < 65536) {
    const b = new Uint8Array(3);
    b[0] = ai | 25;
    new DataView(b.buffer).setUint16(1, value, false);
    return b;
  }
  if (value < 2 ** 32) {
    const b = new Uint8Array(5);
    b[0] = ai | 26;
    new DataView(b.buffer).setUint32(1, value, false);
    return b;
  }
  throw new Error("integer too large");
}

export function cborEncode(obj) {
  if (typeof obj === "number") {
    if (!Number.isInteger(obj) || obj < 0) throw new Error("unsigned int only");
    return encUint(0, obj);
  }
  if (typeof obj === "bigint") {
    if (obj < 0n) throw new Error("unsigned int only");
    if (obj > 0xffffffffffffffffn) throw new Error("too large");
    // encode via Number if safe else 8-byte
    if (obj <= 0xffffffffn) return encUint(0, Number(obj));
    const b = new Uint8Array(9);
    b[0] = 27;
    const dv = new DataView(b.buffer);
    dv.setBigUint64(1, obj, false);
    return b;
  }
  if (obj instanceof Uint8Array) {
    return concatBytes(encUint(2, obj.length), obj);
  }
  if (typeof obj === "string") {
    const u = new TextEncoder().encode(obj);
    return concatBytes(encUint(3, u.length), u);
  }
  if (Array.isArray(obj)) {
    let out = encUint(4, obj.length);
    for (const x of obj) out = concatBytes(out, cborEncode(x));
    return out;
  }
  if (obj && typeof obj === "object") {
    const items = [];
    for (const [k, v] of Object.entries(obj)) {
      const ki = Number(k);
      if (!Number.isInteger(ki) || ki < 0) throw new Error("int keys only");
      items.push([cborEncode(ki), cborEncode(v)]);
    }
    items.sort((a, b) => {
      const x = a[0],
        y = b[0];
      const n = Math.min(x.length, y.length);
      for (let i = 0; i < n; i++) if (x[i] !== y[i]) return x[i] - y[i];
      return x.length - y.length;
    });
    let out = encUint(5, items.length);
    for (const [kb, vb] of items) out = concatBytes(out, kb, vb);
    return out;
  }
  throw new Error("unsupported type");
}

function readUint(data, offset) {
  if (offset >= data.length) throw new Error("truncated");
  const initial = data[offset++];
  const major = initial >> 5;
  const ai = initial & 31;
  let value;
  if (ai < 24) value = ai;
  else if (ai === 24) {
    if (offset + 1 > data.length) throw new Error("truncated");
    value = data[offset++];
    if (value < 24) throw new Error("non-minimal");
  } else if (ai === 25) {
    if (offset + 2 > data.length) throw new Error("truncated");
    value = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    if (value < 256) throw new Error("non-minimal");
  } else if (ai === 26) {
    if (offset + 4 > data.length) throw new Error("truncated");
    value =
      ((data[offset] << 24) >>> 0) +
      (data[offset + 1] << 16) +
      (data[offset + 2] << 8) +
      data[offset + 3];
    offset += 4;
    if (value < 65536) throw new Error("non-minimal");
  } else if (ai === 27) {
    throw new Error("uint64 not needed for V2 vectors");
  } else throw new Error("indefinite/rejected");
  return { major, value, offset };
}

export function cborDecode(data) {
  const { value, offset } = decodeItem(data, 0);
  if (offset !== data.length) throw new Error("trailing bytes");
  return value;
}

function decodeItem(data, offset) {
  const { major, value, offset: o1 } = readUint(data, offset);
  offset = o1;
  if (major === 0) return { value, offset };
  if (major === 2) {
    const b = data.slice(offset, offset + value);
    if (b.length !== value) throw new Error("truncated bstr");
    return { value: b, offset: offset + value };
  }
  if (major === 3) {
    const b = data.slice(offset, offset + value);
    if (b.length !== value) throw new Error("truncated tstr");
    // RFC 8949 / V2: text strings MUST be well-formed UTF-8 (no U+FFFD replacement)
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(b);
    } catch {
      throw new Error("invalid UTF-8");
    }
    return { value: text, offset: offset + value };
  }
  if (major === 4) {
    const arr = [];
    for (let i = 0; i < value; i++) {
      const r = decodeItem(data, offset);
      arr.push(r.value);
      offset = r.offset;
    }
    return { value: arr, offset };
  }
  if (major === 5) {
    const map = {};
    let lastKeyEnc = null;
    for (let i = 0; i < value; i++) {
      const kr = decodeItem(data, offset);
      const keyEnc = data.slice(offset, kr.offset);
      offset = kr.offset;
      if (typeof kr.value !== "number") throw new Error("key type");
      if (Object.prototype.hasOwnProperty.call(map, String(kr.value)))
        throw new Error("duplicate key");
      if (lastKeyEnc) {
        const a = lastKeyEnc,
          b = keyEnc;
        let cmp = 0;
        const n = Math.min(a.length, b.length);
        for (let j = 0; j < n; j++)
          if (a[j] !== b[j]) {
            cmp = a[j] - b[j];
            break;
          }
        if (cmp === 0) cmp = a.length - b.length;
        if (cmp >= 0) throw new Error("unsorted keys");
      }
      lastKeyEnc = keyEnc;
      const vr = decodeItem(data, offset);
      map[kr.value] = vr.value;
      offset = vr.offset;
    }
    return { value: map, offset };
  }
  throw new Error("unsupported major " + major);
}

// --- Bitcoin tx (legacy + segwit enough for txid) ---

function readVarInt(data, offset) {
  const first = data[offset++];
  if (first < 0xfd) return [first, offset];
  if (first === 0xfd) {
    const v = data[offset] | (data[offset + 1] << 8);
    return [v, offset + 2];
  }
  if (first === 0xfe) {
    const v =
      ((data[offset] |
        (data[offset + 1] << 8) |
        (data[offset + 2] << 16) |
        (data[offset + 3] << 24)) >>>
        0);
    return [v, offset + 4];
  }
  throw new Error("varint ff unsupported");
}

export function parseTx(raw) {
  let offset = 0;
  const version = new DataView(raw.buffer, raw.byteOffset, raw.byteLength).getUint32(
    offset,
    true
  );
  offset += 4;
  const versionEnd = offset;
  let isSegwit = false;
  if (offset + 2 <= raw.length && raw[offset] === 0x00 && raw[offset + 1] !== 0x00) {
    isSegwit = true;
    offset += 2;
  }
  const bodyStart = offset;
  let nIn;
  [nIn, offset] = readVarInt(raw, offset);
  for (let i = 0; i < nIn; i++) {
    offset += 36;
    let sl;
    [sl, offset] = readVarInt(raw, offset);
    offset += sl + 4;
  }
  let nOut;
  [nOut, offset] = readVarInt(raw, offset);
  const outputs = [];
  for (let i = 0; i < nOut; i++) {
    offset += 8; // value
    let sl;
    [sl, offset] = readVarInt(raw, offset);
    const script = raw.slice(offset, offset + sl);
    offset += sl;
    outputs.push(script);
  }
  const bodyEnd = offset;
  if (isSegwit) {
    for (let i = 0; i < nIn; i++) {
      let nStack;
      [nStack, offset] = readVarInt(raw, offset);
      for (let j = 0; j < nStack; j++) {
        let il;
        [il, offset] = readVarInt(raw, offset);
        offset += il;
      }
    }
  }
  if (offset + 4 > raw.length) throw new Error("truncated locktime");
  const locktime = raw.slice(offset, offset + 4);
  offset += 4;
  if (offset !== raw.length) throw new Error("trailing");
  const preimage = concatBytes(
    raw.slice(0, versionEnd),
    raw.slice(bodyStart, bodyEnd),
    locktime
  );
  return { outputs, txidInternal: sha256d(preimage), isSegwit };
}

export function verifyMerkle(txidInternal, index, branch, merkleRootInternal) {
  let h = txidInternal;
  let idx = index;
  for (const sibling of branch) {
    if (idx % 2 === 0) h = sha256d(concatBytes(h, sibling));
    else h = sha256d(concatBytes(sibling, h));
    idx = Math.floor(idx / 2);
  }
  return bytesToHex(h) === bytesToHex(merkleRootInternal);
}

export function parseHeader(hdr) {
  if (hdr.length !== 80) throw new Error("BAD_BLOCK_HEADER");
  return {
    merkleRoot: hdr.slice(36, 68),
  };
}

export function extractB353S2(script) {
  if (script.length < 2 || script[0] !== 0x6a) return null;
  const push = script[1];
  const payload = script.slice(2);
  if (push !== payload.length || payload.length !== 39) return null;
  if (
    payload[0] !== OP_RETURN_TAG[0] ||
    payload[1] !== OP_RETURN_TAG[1] ||
    payload[2] !== OP_RETURN_TAG[2] ||
    payload[3] !== OP_RETURN_TAG[3] ||
    payload[4] !== OP_RETURN_TAG[4] ||
    payload[5] !== OP_RETURN_TAG[5] ||
    payload[6] !== 0x01
  )
    return null;
  return payload.slice(7, 39);
}

export function extractCommitmentFromTx(raw) {
  const { outputs } = parseTx(raw);
  const matches = [];
  for (const s of outputs) {
    const c = extractB353S2(s);
    if (c) matches.push(c);
  }
  if (matches.length === 0) throw new Error("NO_B353S2_OUTPUT");
  if (matches.length > 1) throw new Error("AMBIGUOUS_B353S2_OUTPUTS");
  return matches[0];
}

export function eq(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export { bytesToHex, hexToBytes, concatBytes, createHash };

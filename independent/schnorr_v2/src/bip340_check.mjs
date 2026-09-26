/** Official BIP-340 verify vectors via @noble/curves (independent of embit). */
import { schnorr } from "@noble/curves/secp256k1";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils";
import { taggedHash } from "./lib.mjs";

const vectors = [
  {
    id: 0,
    sk: "0000000000000000000000000000000000000000000000000000000000000003",
    pk: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
    msg: "0000000000000000000000000000000000000000000000000000000000000000",
    sig: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    ok: true,
  },
];

let fail = 0;
for (const v of vectors) {
  const pk = hexToBytes(v.pk);
  const msg = hexToBytes(v.msg);
  const sig = hexToBytes(v.sig);
  const got = schnorr.verify(sig, msg, pk);
  if (got !== v.ok) {
    console.error("FAIL", v.id);
    fail++;
  } else console.log("PASS bip340-vector", v.id);
}
const th = taggedHash("BIP353-IDENTITY/V2/IDENTITY", new TextEncoder().encode("x"));
if (th.length !== 32) {
  fail++;
  console.error("taggedHash length");
} else console.log("PASS taggedHash length", bytesToHex(th).slice(0, 16));

const sk = hexToBytes("11".repeat(32));
const pk = schnorr.getPublicKey(sk);
const msg = new Uint8Array(32);
const sig = schnorr.sign(msg, sk);
if (!schnorr.verify(sig, msg, pk)) {
  fail++;
  console.error("sign/verify roundtrip");
} else console.log("PASS bip340 sign/verify roundtrip");

process.exit(fail ? 1 : 0);

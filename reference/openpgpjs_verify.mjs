#!/usr/bin/env node
/**
 * openpgp.js verification harness for BIP-353 Identity Binding (Milestone 3).
 *
 * Does NOT regenerate Milestone 1 vectors.
 * Domain separator is built from explicit byte array (never via JS "\0" string truncations).
 */

import * as openpgp from 'openpgp';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const OPENPGP_VERSION = JSON.parse(
  fs.readFileSync(path.join(ROOT, 'node_modules/openpgp/package.json'), 'utf8')
).version;

/** Exact 17-byte domain separator — NOT a C string. */
export const DOMAIN_SEPARATOR = Uint8Array.from([
  0x42, 0x49, 0x50, 0x33, 0x35, 0x33, 0x2d, 0x49,
  0x44, 0x45, 0x4e, 0x54, 0x49, 0x54, 0x59, 0x00, 0x01,
]);

export const EXPECTED_KROOT = 'de26bd614a4224ac0b704ed1c8f68e1738268297';
export const EXPECTED_KSIGN = '55f38348c4a60b8ffd7b40c86186d1b88a7badea';

export function buildSignedMessage(payload) {
  const p = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const out = new Uint8Array(DOMAIN_SEPARATOR.length + p.length);
  out.set(DOMAIN_SEPARATOR, 0);
  out.set(p, DOMAIN_SEPARATOR.length);
  return out;
}

export async function readCertificate(ascPath) {
  const armored = fs.readFileSync(ascPath, 'utf8');
  return openpgp.readKey({ armoredKey: armored });
}

export async function inspectCertificate(ascPath) {
  const cert = await readCertificate(ascPath);
  const primary = cert.getFingerprint().toLowerCase();
  const version = cert.keyPacket.version;
  const algo = cert.keyPacket.algorithm;
  const subkeys = [];
  for (const sk of cert.getSubkeys()) {
    const binding = sk.bindingSignatures?.[0];
    subkeys.push({
      fingerprint: sk.getFingerprint().toLowerCase(),
      version: sk.keyPacket.version,
      algorithm: sk.keyPacket.algorithm,
      bindingType: binding?.signatureType ?? null, // 24 = 0x18
      hasEmbeddedPrimaryBinding:
        binding?.embeddedSignature?.signatureType === 25, // 0x19
      embeddedType: binding?.embeddedSignature?.signatureType ?? null,
    });
  }
  return { primary, version, algo, subkeys, cert };
}

export async function verifyDetachedSignature({
  payloadPath,
  signaturePath,
  certificatePath,
}) {
  const payload = fs.readFileSync(payloadPath);
  const sigBin = fs.readFileSync(signaturePath);
  const messageBytes = buildSignedMessage(payload);
  const cert = await readCertificate(certificatePath);
  const message = await openpgp.createMessage({ binary: messageBytes });
  const signature = await openpgp.readSignature({ binarySignature: sigBin });
  const verified = await openpgp.verify({
    message,
    signature,
    verificationKeys: cert,
    format: 'binary',
  });
  const [sig] = verified.signatures;
  let valid = false;
  let error = null;
  try {
    valid = await sig.verified;
  } catch (e) {
    error = e.message;
    valid = false;
  }
  return {
    valid,
    error,
    keyID: sig?.keyID?.toHex?.() ?? null,
    messageLength: messageBytes.length,
    domainSeparatorHex: Buffer.from(DOMAIN_SEPARATOR).toString('hex'),
  };
}

export async function createDetachedSignature({
  messageBytes,
  secretKeyPath,
  signingFingerprint,
}) {
  let armoredOrBinary = fs.readFileSync(secretKeyPath);
  let privateKey;
  if (secretKeyPath.endsWith('.asc') || armoredOrBinary[0] === 0x2d) {
    privateKey = await openpgp.readPrivateKey({
      armoredKey: armoredOrBinary.toString('utf8'),
    });
  } else {
    privateKey = await openpgp.readPrivateKey({
      binaryKey: armoredOrBinary,
    });
  }
  // Select signing subkey if fingerprint provided
  let signingKeys = privateKey;
  if (signingFingerprint) {
    const target = signingFingerprint.toLowerCase();
    const sub = privateKey
      .getSubkeys()
      .find((s) => s.getFingerprint().toLowerCase() === target);
    if (!sub) {
      throw new Error(`signing subkey ${target} not found`);
    }
  }
  const message = await openpgp.createMessage({ binary: messageBytes });
  const detached = await openpgp.sign({
    message,
    signingKeys: privateKey,
    detached: true,
    format: 'binary',
  });
  return Buffer.from(detached);
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0] || 'valid';

  if (cmd === 'version') {
    console.log(JSON.stringify({ openpgpjs: OPENPGP_VERSION }, null, 2));
    return;
  }

  if (cmd === 'inspect') {
    const asc = args[1] || path.join(ROOT, 'vectors/valid/root.asc');
    const info = await inspectCertificate(asc);
    delete info.cert;
    console.log(JSON.stringify(info, null, 2));
    return;
  }

  if (cmd === 'verify') {
    const base = args[1] || path.join(ROOT, 'vectors/valid');
    const result = await verifyDetachedSignature({
      payloadPath: path.join(base, 'identity-payload.cbor'),
      signaturePath: path.join(base, 'identity-signature.bin'),
      certificatePath: path.join(base, 'root.asc'),
    });
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  }

  // default: full valid check
  const info = await inspectCertificate(path.join(ROOT, 'vectors/valid/root.asc'));
  const checks = {
    openpgpjs: OPENPGP_VERSION,
    kroot_match: info.primary === EXPECTED_KROOT,
    kroot: info.primary,
    version: info.version,
    algo: info.algo,
    ksign_match: info.subkeys.some((s) => s.fingerprint === EXPECTED_KSIGN),
    ksign: info.subkeys.map((s) => s.fingerprint),
    binding_0x18: info.subkeys.some(
      (s) => s.fingerprint === EXPECTED_KSIGN && s.bindingType === 24
    ),
    binding_0x19: info.subkeys.some(
      (s) => s.fingerprint === EXPECTED_KSIGN && s.hasEmbeddedPrimaryBinding
    ),
  };
  const sig = await verifyDetachedSignature({
    payloadPath: path.join(ROOT, 'vectors/valid/identity-payload.cbor'),
    signaturePath: path.join(ROOT, 'vectors/valid/identity-signature.bin'),
    certificatePath: path.join(ROOT, 'vectors/valid/root.asc'),
  });
  checks.signature_valid = sig.valid;
  checks.message_length = sig.messageLength;
  checks.domain_separator_hex = sig.domainSeparatorHex;
  console.log(JSON.stringify(checks, null, 2));
  const ok =
    checks.kroot_match &&
    checks.ksign_match &&
    checks.binding_0x18 &&
    checks.binding_0x19 &&
    checks.signature_valid;
  process.exit(ok ? 0 : 1);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(e);
    process.exit(2);
  });
}

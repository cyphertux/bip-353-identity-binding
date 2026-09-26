#!/usr/bin/env node
/**
 * Milestone 3 — OpenPGP v6 vector tests (independent of M1).
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';
import * as openpgp from 'openpgp';
import {
  DOMAIN_SEPARATOR,
  buildSignedMessage,
  inspectCertificate,
  verifyDetachedSignature,
} from '../reference/openpgpjs_verify.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const V6 = path.join(ROOT, 'vectors/v6');
const SQ = process.env.SQ || path.join(ROOT, '.tools/sq-root/usr/bin/sq');

let PASS = 0;
let FAIL = 0;
const report = { checks: {} };

function check(name, cond, detail = '') {
  if (cond) {
    PASS++;
    console.log(`[PASS] ${name}`);
    report.checks[name] = { result: 'PASS', detail };
  } else {
    FAIL++;
    console.log(`[FAIL] ${name}${detail ? ': ' + detail : ''}`);
    report.checks[name] = { result: 'FAIL', detail };
  }
}

async function main() {
  if (!fs.existsSync(path.join(V6, 'expected-v6.json'))) {
    console.error('vectors/v6 not generated — run scripts/generate_v6_vectors.py');
    process.exit(2);
  }
  const expected = JSON.parse(fs.readFileSync(path.join(V6, 'expected-v6.json'), 'utf8'));

  // Sequoia inspect
  const insp = spawnSync(SQ, ['--cert-store=none', 'inspect', path.join(V6, 'root-v6.asc')], {
    encoding: 'utf8',
  });
  const text = insp.stdout + insp.stderr;
  check(
    'v6_sequoia_kroot',
    text.toUpperCase().includes(expected.kroot_fingerprint.toUpperCase()),
    expected.kroot_fingerprint
  );
  check(
    'v6_sequoia_ksign',
    text.toUpperCase().includes(expected.ksign_fingerprint.toUpperCase()),
    expected.ksign_fingerprint
  );

  const dump = spawnSync(SQ, ['--cert-store=none', 'packet', 'dump', path.join(V6, 'root-v6.asc')], {
    encoding: 'utf8',
  });
  const dtext = dump.stdout + dump.stderr;
  check('v6_packet_version_6', dtext.includes('Version: 6'));
  check('v6_binding_0x18', dtext.includes('Type: SubkeyBinding'));
  check('v6_binding_0x19', dtext.includes('Type: PrimaryKeyBinding'));

  // Sequoia verify signature
  const msg = buildSignedMessage(fs.readFileSync(path.join(V6, 'identity-payload.cbor')));
  fs.writeFileSync('/tmp/m3-v6-msg.bin', msg);
  const ver = spawnSync(
    SQ,
    [
      '--cert-store=none',
      'verify',
      '--signer-file',
      path.join(V6, 'root-v6.asc'),
      '--signature-file',
      path.join(V6, 'identity-v6.sig'),
      '/tmp/m3-v6-msg.bin',
    ],
    { encoding: 'utf8' }
  );
  check('v6_sequoia_signature', ver.status === 0, (ver.stderr || ver.stdout || '').slice(0, 200));

  // openpgp.js
  try {
    const info = await inspectCertificate(path.join(V6, 'root-v6.asc'));
    check('v6_openpgpjs_parse', info.version === 6, String(info.version));
    check(
      'v6_openpgpjs_kroot',
      info.primary === expected.kroot_fingerprint,
      info.primary
    );
    const sk = info.subkeys.find((s) => s.fingerprint === expected.ksign_fingerprint);
    check('v6_openpgpjs_ksign', !!sk, JSON.stringify(info.subkeys.map((s) => s.fingerprint)));
    check('v6_openpgpjs_0x18', sk?.bindingType === 24, String(sk?.bindingType));
    check('v6_openpgpjs_0x19', sk?.hasEmbeddedPrimaryBinding === true);

    const sig = await verifyDetachedSignature({
      payloadPath: path.join(V6, 'identity-payload.cbor'),
      signaturePath: path.join(V6, 'identity-v6.sig'),
      certificatePath: path.join(V6, 'root-v6.asc'),
    });
    check('v6_openpgpjs_signature', sig.valid === true, sig.error || '');
  } catch (e) {
    check('v6_openpgpjs_suite', false, e.message);
  }

  // GnuPG: expect limited/no v6 support — document actual result
  const gpgHome = fs.mkdtempSync('/tmp/m3-gpg-v6-');
  fs.chmodSync(gpgHome, 0o700);
  const imp = spawnSync('gpg', ['--batch', '--import', path.join(V6, 'root-v6.asc')], {
    env: { ...process.env, GNUPGHOME: gpgHome },
    encoding: 'utf8',
  });
  const gpgImportOk = imp.status === 0;
  const list = spawnSync('gpg', ['--batch', '--with-colons', '--list-keys'], {
    env: { ...process.env, GNUPGHOME: gpgHome },
    encoding: 'utf8',
  });
  const gpgSeesV6 =
    (list.stdout || '').includes(expected.kroot_fingerprint.toUpperCase()) ||
    (list.stdout || '').toLowerCase().includes(expected.kroot_fingerprint.slice(0, 16));
  report.checks['v6_gnupg_import'] = {
    result: gpgImportOk && gpgSeesV6 ? 'PASS' : 'UNSUPPORTED',
    detail: (imp.stderr || list.stdout || '').slice(0, 300),
  };
  console.log(
    `[${report.checks['v6_gnupg_import'].result}] v6_gnupg_import`
  );

  // Fingerprint lengths
  check('v6_fpr_len_32', expected.kroot_fingerprint_len === 32);
  check('H_domain_separator_unchanged', DOMAIN_SEPARATOR.length === 17);

  // Commitment length sanity via expected file
  check('v6_commitment_present', /^[0-9a-f]{64}$/.test(expected.identity_commitment));

  fs.writeFileSync(
    path.join(ROOT, 'test/m3_v6_results.json'),
    JSON.stringify({ expected, report }, null, 2) + '\n'
  );
  console.log(`\n${PASS} passed, ${FAIL} failed`);
  process.exit(FAIL === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error(e);
  process.exit(2);
});

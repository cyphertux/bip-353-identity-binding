#!/usr/bin/env bash
# Sequoia-based verification of Milestone 1 fixtures (does NOT regenerate vectors).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SQ="${SQ:-$ROOT/.tools/sq-root/usr/bin/sq}"

# NOTE: bash variables cannot hold NUL bytes. Never store the domain separator
# in a shell variable. Write it with printf octal escapes instead.
write_signed_message() {
  local payload="$1"
  local dest="$2"
  # DOMAIN_SEPARATOR = "BIP353-IDENTITY" || 0x00 || 0x01
  {
    printf 'BIP353-IDENTITY\0\1'
    cat "$payload"
  } > "$dest"
}

if [[ ! -x "$SQ" ]]; then
  echo "ERROR: sq not found at $SQ" >&2
  echo "Extract Sequoia with: apt-get download sq && dpkg-deb -x sq_*.deb .tools/sq-root" >&2
  exit 2
fi

echo "=== Environment ==="
"$SQ" version
echo "SQ=$SQ"
echo

check_cert() {
  local asc="$1"
  local expect_root="$2"
  local expect_sign="$3"
  echo "--- Certificate: $asc ---"
  local out
  out="$("$SQ" inspect --cert-store=none "$asc" 2>&1)"
  echo "$out"
  echo "$out" | grep -qi "Fingerprint: ${expect_root}" || {
    echo "FAIL: KROOT fingerprint mismatch"; return 1;
  }
  echo "$out" | grep -qi "Subkey: ${expect_sign}" || {
    echo "FAIL: KSIGN fingerprint mismatch"; return 1;
  }
  # Binding packets
  local dump
  dump="$("$SQ" packet dump --cert-store=none "$asc" 2>&1)"
  echo "$dump" | grep -q "Type: SubkeyBinding" || {
    echo "FAIL: missing 0x18 SubkeyBinding"; return 1;
  }
  echo "$dump" | grep -q "Type: PrimaryKeyBinding" || {
    echo "FAIL: missing 0x19 PrimaryKeyBinding"; return 1;
  }
  echo "PASS: fingerprints + 0x18/0x19 binding"
}

verify_detached() {
  local payload="$1"
  local sig="$2"
  local cert="$3"
  local msg
  msg="$(mktemp)"
  write_signed_message "$payload" "$msg"
  if "$SQ" verify --cert-store=none \
      --signer-file "$cert" \
      --signature-file "$sig" \
      "$msg" >/tmp/sq-verify-out.txt 2>&1; then
    cat /tmp/sq-verify-out.txt
    rm -f "$msg"
    return 0
  else
    cat /tmp/sq-verify-out.txt >&2 || true
    rm -f "$msg"
    return 1
  fi
}

EXPECTED_ROOT=DE26BD614A4224AC0B704ED1C8F68E1738268297
EXPECTED_SIGN=55F38348C4A60B8FFD7B40C86186D1B88A7BADEA

check_cert "$ROOT/vectors/valid/root.asc" "$EXPECTED_ROOT" "$EXPECTED_SIGN"
check_cert "$ROOT/vectors/valid/signing.asc" "$EXPECTED_ROOT" "$EXPECTED_SIGN"

echo
echo "=== Valid identity signature (GnuPG bytes → Sequoia) ==="
if verify_detached \
    "$ROOT/vectors/valid/identity-payload.cbor" \
    "$ROOT/vectors/valid/identity-signature.bin" \
    "$ROOT/vectors/valid/root.asc"; then
  echo "PASS: signature_valid=true"
else
  echo "FAIL: Sequoia rejected valid signature"
  exit 1
fi

echo
echo "=== Invalid signature fixture ==="
if verify_detached \
    "$ROOT/vectors/invalid/invalid-signature/identity-payload.cbor" \
    "$ROOT/vectors/invalid/invalid-signature/identity-signature.bin" \
    "$ROOT/vectors/invalid/invalid-signature/root.asc"; then
  echo "FAIL: Sequoia accepted tampered signature"
  exit 1
else
  echo "PASS: Sequoia rejected invalid-signature (as expected)"
fi

echo
echo "=== Commitment reproduction ==="
python3 - <<PY
import sys
sys.path.insert(0, "$ROOT")
from pathlib import Path
from reference import cbor
from reference.identity import identity_commitment, payment_hash

anchor = cbor.loads(Path("$ROOT/vectors/valid/anchor-message.cbor").read_bytes())
pay = cbor.loads(Path("$ROOT/vectors/valid/payment-binding.cbor").read_bytes())
c = identity_commitment(anchor).hex()
p = payment_hash(pay).hex()
assert c == "82282ed2aebfcbe223a040db5689e569925503f321e643163eeab0ceb47968ae", c
assert p == "35bc7db73b5091938aa3e3c4a3da97e360b6b086fb95f9b084126d665e938629", p
print("PASS: identity_commitment + payment_hash reproduced")
PY

echo
echo "All Sequoia smoke checks PASS"

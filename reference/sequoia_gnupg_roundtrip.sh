#!/usr/bin/env bash
# Bidirectional signature interop: GnuPG ↔ Sequoia on identical message bytes.
# Uses existing vectors + secret key from GNUPGHOME (not committed).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SQ="${SQ:-$ROOT/.tools/sq-root/usr/bin/sq}"
GNUPGHOME="${GNUPGHOME:-/tmp/bip353-gnupg}"
export GNUPGHOME

WORKDIR="$(mktemp -d /tmp/m2-roundtrip-XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

# Domain separator contains NUL — must not pass through a bash variable.
{
  printf 'BIP353-IDENTITY\0\1'
  cat "$ROOT/vectors/valid/identity-payload.cbor"
} > "$WORKDIR/msg.bin"

echo "=== Message ==="
wc -c "$WORKDIR/msg.bin"
sha256sum "$WORKDIR/msg.bin"

echo
echo "=== 1. Existing GnuPG signature → Sequoia verify ==="
"$SQ" verify --cert-store=none \
  --signer-file "$ROOT/vectors/valid/root.asc" \
  --signature-file "$ROOT/vectors/valid/identity-signature.bin" \
  "$WORKDIR/msg.bin"
echo "PASS: GnuPG → Sequoia"

echo
echo "=== 2. Sequoia sign → GnuPG verify ==="
if ! gpg --list-secret-keys alice@example.test >/dev/null 2>&1; then
  echo "SKIP: secret key not in GNUPGHOME=$GNUPGHOME (run scripts/setup_keys.sh)"
  exit 0
fi

gpg --export-secret-keys --armor alice@example.test > "$WORKDIR/secret.asc"
"$SQ" --home "$WORKDIR/sqhome" --cert-store=none sign \
  --signer-file "$WORKDIR/secret.asc" \
  --signature-file "$WORKDIR/sq.sig" \
  --binary \
  "$WORKDIR/msg.bin"

VERIFY_HOME="$WORKDIR/gnupg"
mkdir -p "$VERIFY_HOME" && chmod 700 "$VERIFY_HOME"
GNUPGHOME="$VERIFY_HOME" gpg --batch --import "$ROOT/vectors/valid/root.asc" >/dev/null 2>&1
GNUPGHOME="$VERIFY_HOME" gpg --batch --status-fd 1 \
  --verify "$WORKDIR/sq.sig" "$WORKDIR/msg.bin" 2>&1 | tee "$WORKDIR/gpg-verify.txt"
grep -q GOODSIG "$WORKDIR/gpg-verify.txt"
echo "PASS: Sequoia → GnuPG"

echo
echo "=== 3. Signature packets are NOT byte-identical (expected) ==="
python3 - <<PY
from pathlib import Path
g = Path("$ROOT/vectors/valid/identity-signature.bin").read_bytes()
s = Path("$WORKDIR/sq.sig").read_bytes()
print(f"GnuPG signature bytes:   {len(g)}")
print(f"Sequoia signature bytes: {len(s)}")
print(f"byte-identical: {g == s}")
assert g != s, "unexpected: signatures were byte-identical"
print("PASS: semantic equivalence without byte identity")
PY

echo
echo "Roundtrip interop PASS"

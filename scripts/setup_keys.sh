#!/usr/bin/env bash
# Generate the offline OpenPGP fixture keyring used by scripts/generate_vectors.py
set -euo pipefail

GNUPGHOME="${GNUPGHOME:-/tmp/bip353-gnupg}"
export GNUPGHOME
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

if gpg --list-keys alice@example.test >/dev/null 2>&1; then
  echo "Key alice@example.test already present in $GNUPGHOME"
  gpg --list-keys --with-subkey-fingerprint alice@example.test
  exit 0
fi

BATCH="$(mktemp)"
cat >"$BATCH" <<'EOF'
%no-protection
Key-Type: eddsa
Key-Curve: Ed25519
Key-Usage: cert
Subkey-Type: eddsa
Subkey-Curve: Ed25519
Subkey-Usage: sign
Name-Real: BIP353 Identity Test
Name-Email: alice@example.test
Expire-Date: 0
%commit
EOF

gpg --batch --generate-key "$BATCH"
rm -f "$BATCH"

echo "Generated keys in $GNUPGHOME"
gpg --list-keys --with-subkey-fingerprint alice@example.test
echo
echo "NOTE: GnuPG 2.4.x produces OpenPGP v4 keys (20-byte fingerprints)."
echo "OpenPGP v6 fingerprints are NOT simulated."

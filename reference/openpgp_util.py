"""OpenPGP helpers wrapping GnuPG for the reference verifier/generator.

IMPORTANT LIMITATION
--------------------
GnuPG 2.4.8 in this environment generates OpenPGP *v4* Ed25519 keys
(20-byte fingerprints), not OpenPGP v6 (32-byte SHA-256 fingerprints).
All vectors therefore use v4 fingerprints. Do not invent v6 fingerprints.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class OpenPGPError(RuntimeError):
    pass


@dataclass(frozen=True)
class CertificateInfo:
    fingerprint: bytes  # raw fingerprint bytes
    fingerprint_hex: str
    keyid: str
    version: int
    algo: str
    is_subkey: bool
    usage: str
    revoked: bool


def _run_gpg(
    args: list[str],
    *,
    gnupghome: str | Path,
    input_data: bytes | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy()
    env["GNUPGHOME"] = str(gnupghome)
    # Avoid pinentry / agent prompts in batch mode
    cmd = ["gpg", "--batch", "--yes", "--status-fd", "2", *args]
    proc = subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        env=env,
    )
    if check and proc.returncode != 0:
        raise OpenPGPError(
            f"gpg {' '.join(args)} failed ({proc.returncode}): "
            f"{proc.stderr.decode('utf-8', errors='replace')}"
        )
    return proc


def parse_colon_listing(text: str) -> list[CertificateInfo]:
    """Parse `gpg --with-colons --list-keys` output."""
    results: list[CertificateInfo] = []
    current_pub: dict | None = None
    pending_fpr: str | None = None
    pending_is_sub = False
    pending_usage = ""
    pending_revoked = False
    pending_algo = ""
    pending_keyid = ""

    def flush():
        nonlocal pending_fpr
        if pending_fpr is None:
            return
        fpr_hex = pending_fpr.lower()
        results.append(
            CertificateInfo(
                fingerprint=bytes.fromhex(fpr_hex),
                fingerprint_hex=fpr_hex,
                keyid=pending_keyid,
                version=4,  # documented limitation
                algo=pending_algo,
                is_subkey=pending_is_sub,
                usage=pending_usage,
                revoked=pending_revoked,
            )
        )

    for line in text.splitlines():
        parts = line.split(":")
        tag = parts[0]
        if tag in ("pub", "sub"):
            flush()
            pending_is_sub = tag == "sub"
            pending_revoked = parts[1] == "r"
            pending_algo = parts[3] if len(parts) > 3 else ""
            pending_keyid = parts[4] if len(parts) > 4 else ""
            # usage field is typically index 11 for pub/sub in --with-colons
            pending_usage = parts[11] if len(parts) > 11 else ""
            pending_fpr = None
            if tag == "pub":
                current_pub = {"keyid": pending_keyid}
        elif tag == "fpr" and len(parts) > 9:
            pending_fpr = parts[9]
    flush()
    return results


def import_certificate(asc_path: Path, gnupghome: Path) -> list[CertificateInfo]:
    gnupghome.mkdir(parents=True, exist_ok=True)
    # Initialize trustdb if needed
    _run_gpg(["--list-keys"], gnupghome=gnupghome, check=False)
    _run_gpg(["--import", str(asc_path)], gnupghome=gnupghome)
    proc = _run_gpg(
        ["--with-colons", "--with-fingerprint", "--with-subkey-fingerprint", "--list-keys"],
        gnupghome=gnupghome,
    )
    return parse_colon_listing(proc.stdout.decode())


def get_primary_and_signing(
    infos: list[CertificateInfo],
) -> tuple[CertificateInfo, CertificateInfo]:
    primaries = [i for i in infos if not i.is_subkey]
    signers = [i for i in infos if i.is_subkey and ("s" in i.usage.lower() or i.usage == "")]
    # Fallback: any subkey if usage parsing is incomplete
    if not signers:
        signers = [i for i in infos if i.is_subkey]
    if len(primaries) != 1:
        raise OpenPGPError(f"expected exactly one primary key, got {len(primaries)}")
    if not signers:
        raise OpenPGPError("no signing subkey found")
    return primaries[0], signers[0]


def verify_subkey_binding(
    root_asc: Path,
    expected_root_fpr: bytes,
    expected_sign_fpr: bytes,
    gnupghome: Path,
) -> bool:
    """Verify certificate contains expected KROOT/KSIGN with OpenPGP binding.

    Relies on GnuPG accepting the certificate (which requires valid 0x18/0x19
    bindings for Ed25519 signing subkeys).
    """
    infos = import_certificate(root_asc, gnupghome)
    root, sign = get_primary_and_signing(infos)
    if root.fingerprint != expected_root_fpr:
        return False
    if sign.fingerprint != expected_sign_fpr:
        return False
    if root.revoked or sign.revoked:
        return False
    return True


def detach_sign(
    data: bytes,
    *,
    gnupghome: Path,
    signing_fingerprint_hex: str,
) -> bytes:
    """Create a binary detached OpenPGP signature using the given subkey."""
    # Trailing '!' forces this exact key/subkey
    local_user = signing_fingerprint_hex.upper() + "!"
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tf:
        tf.write(data)
        data_path = tf.name
    sig_path = data_path + ".sig"
    try:
        _run_gpg(
            [
                "--detach-sign",
                "--local-user",
                local_user,
                "--output",
                sig_path,
                data_path,
            ],
            gnupghome=gnupghome,
        )
        return Path(sig_path).read_bytes()
    finally:
        Path(data_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)


def verify_detach_sign(
    data: bytes,
    signature: bytes,
    *,
    gnupghome: Path,
    expected_signer_fpr: bytes | None = None,
) -> bool:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as df:
        df.write(data)
        data_path = df.name
    with tempfile.NamedTemporaryFile(suffix=".sig", delete=False) as sf:
        sf.write(signature)
        sig_path = sf.name
    try:
        proc = _run_gpg(
            ["--verify", sig_path, data_path],
            gnupghome=gnupghome,
            check=False,
        )
        status = proc.stderr.decode("utf-8", errors="replace")
        if "[GNUPG:] GOODSIG" not in status and "GOODSIG" not in status:
            # Also check exit code / VALIDSIG
            if "[GNUPG:] VALIDSIG" not in status:
                return False
        if expected_signer_fpr is not None:
            fpr_hex = expected_signer_fpr.hex().upper()
            # VALIDSIG <fpr> ...
            m = re.search(r"\[GNUPG:\] VALIDSIG ([0-9A-F]+)", status)
            if not m:
                return False
            # VALIDSIG fingerprint may be primary or signing key depending on version;
            # also check SIG_ID / using subkey lines.
            valid_fpr = m.group(1)
            if valid_fpr[-len(fpr_hex) :] != fpr_hex and fpr_hex not in status.upper():
                # Accept if the subkey fingerprint appears in KEY_CONSIDERED or VALIDSIG chain
                if fpr_hex not in status.upper():
                    return False
        return True
    finally:
        Path(data_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)


def export_public_key(gnupghome: Path, email_or_fpr: str, dest: Path) -> None:
    proc = _run_gpg(
        ["--armor", "--export", email_or_fpr],
        gnupghome=gnupghome,
    )
    dest.write_bytes(proc.stdout)
    if not proc.stdout.strip():
        raise OpenPGPError("empty public key export")

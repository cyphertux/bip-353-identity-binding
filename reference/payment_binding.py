"""BIP-353 semantic PaymentBindingV1 (Milestone 4).

Works on the *semantic* result of BIP-353 resolution (a BIP-321 payment
instruction object), NEVER on raw DNS TXT bytes or raw bitcoin: URI strings.

Excluded from the identity binding (request-specific, not identity):
  amount, label, message, pop, expiry metadata.
"""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from reference import cbor
from reference.constants import (
    DOMAIN_SEPARATOR_PAYMENT,
    METHOD_DESTINATION,
    METHOD_TYPE,
    PAY_METHODS,
    PAY_VERSION,
    PROTOCOL_VERSION,
)

# Minimal PaymentMethod type registry (envelope only — not a catalogue of all
# payment protocols). Types listed here have canonical payload rules.
REGISTERED_TYPES = {
    "bitcoin": "scriptPubKey bytes (on-chain destination)",
    "test-method": "opaque bytes for registry/canonicalisation tests only",
    # Placeholders — payloads MUST be defined by their own BIPs before use:
    # "sp": BIP-352 silent payment identifier (canonical form TBD by BIP-352)
    # "lno": BOLT12 offer (canonical form TBD by Lightning)
}


class PaymentBindingError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Address → scriptPubKey (so text encoding never enters the commitment)
# ---------------------------------------------------------------------------

_B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_MAP = {c: i for i, c in enumerate(_B58)}


def _b58decode_check(s: str) -> bytes:
    n = 0
    for ch in s.encode("ascii"):
        if ch not in _B58_MAP:
            raise PaymentBindingError(f"invalid base58 char: {ch!r}")
        n = n * 58 + _B58_MAP[ch]
    # leading zeros
    pad = 0
    for ch in s.encode("ascii"):
        if ch == ord("1"):
            pad += 1
        else:
            break
    full = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    raw = b"\x00" * pad + full
    if len(raw) < 5:
        raise PaymentBindingError("base58 too short")
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise PaymentBindingError("base58 checksum mismatch")
    return payload


# Bech32 / Bech32m (BIP-173 / BIP-350)
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_MAP = {c: i for i, c in enumerate(_BECH32_CHARSET)}


def _bech32_polymod(values: list[int]) -> int:
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_verify(hrp: str, data: list[int], spec: str) -> bool:
    const = 1 if spec == "bech32" else 0x2BC830A3
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == const


def _convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or value >> frombits:
            raise PaymentBindingError("invalid convertbits value")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise PaymentBindingError("invalid convertbits padding")
    return ret


def decode_bech32_address(addr: str) -> tuple[str, int, bytes]:
    """Return (hrp, witver, witprog)."""
    addr = addr.lower()
    if addr.rfind("1") < 1:
        raise PaymentBindingError("invalid bech32")
    pos = addr.rfind("1")
    hrp, data_part = addr[:pos], addr[pos + 1 :]
    data = [_BECH32_MAP[c] for c in data_part]
    if len(data) < 6:
        raise PaymentBindingError("bech32 too short")
    if _bech32_verify(hrp, data, "bech32"):
        spec = "bech32"
    elif _bech32_verify(hrp, data, "bech32m"):
        spec = "bech32m"
    else:
        raise PaymentBindingError("bech32 checksum failed")
    witver = data[0]
    prog = bytes(_convertbits(data[1:-6], 5, 8, False))
    if witver == 0 and spec != "bech32":
        raise PaymentBindingError("v0 must use bech32")
    if witver != 0 and spec != "bech32m":
        raise PaymentBindingError("v1+ must use bech32m")
    if witver == 0 and len(prog) not in (20, 32):
        raise PaymentBindingError("invalid v0 program length")
    if witver == 1 and len(prog) != 32:
        raise PaymentBindingError("invalid taproot program length")
    return hrp, witver, prog


def witness_program_to_script(witver: int, prog: bytes) -> bytes:
    if witver == 0:
        return bytes([0x00, len(prog)]) + prog
    if 1 <= witver <= 16:
        return bytes([0x50 + witver, len(prog)]) + prog
    raise PaymentBindingError(f"unsupported witness version: {witver}")


def address_to_script_pubkey(address: str, *, network: str = "main") -> bytes:
    """Convert a Bitcoin address string to scriptPubKey bytes.

    Text address encoding NEVER enters payment_hash — only scriptPubKey bytes.
    """
    address = address.strip()
    if not address:
        raise PaymentBindingError("empty address")

    lower = address.lower()
    if lower.startswith(("bc1", "tb1", "bcrt1", "sb1")):
        _hrp, witver, prog = decode_bech32_address(address)
        return witness_program_to_script(witver, prog)

    # Base58Check P2PKH / P2SH
    payload = _b58decode_check(address)
    ver, h160 = payload[0], payload[1:]
    if len(h160) != 20:
        raise PaymentBindingError("unexpected hash160 length")
    # main: 0x00 P2PKH, 0x05 P2SH; testnet/regtest: 0x6f / 0xc4
    if ver in (0x00, 0x6F):
        return b"\x76\xa9\x14" + h160 + b"\x88\xac"  # P2PKH
    if ver in (0x05, 0xC4):
        return b"\xa9\x14" + h160 + b"\x87"  # P2SH
    raise PaymentBindingError(f"unsupported base58 version byte: {ver:#x}")


def classify_script(script: bytes) -> str:
    if len(script) == 25 and script[:3] == b"\x76\xa9\x14" and script[-2:] == b"\x88\xac":
        return "P2PKH"
    if len(script) == 23 and script[0] == 0xA9 and script[-1] == 0x87:
        return "P2SH"
    if len(script) == 22 and script[0] == 0x00 and script[1] == 0x14:
        return "P2WPKH"
    if len(script) == 34 and script[0] == 0x00 and script[1] == 0x20:
        return "P2WSH"
    if len(script) == 34 and script[0] == 0x51 and script[1] == 0x20:
        return "P2TR"
    return "UNKNOWN"


# ---------------------------------------------------------------------------
# PaymentBindingV1
# ---------------------------------------------------------------------------


def normalize_method(method_type: str, destination: bytes) -> dict[int, Any]:
    if not isinstance(method_type, str) or not method_type:
        raise PaymentBindingError("method type must be non-empty string")
    if not isinstance(destination, (bytes, bytearray)):
        raise PaymentBindingError("destination must be bytes")
    if method_type == "bitcoin" and classify_script(bytes(destination)) == "UNKNOWN":
        # Allow unknown scripts (forward-compat) but prefer known patterns in tests
        pass
    return {
        METHOD_TYPE: method_type,
        METHOD_DESTINATION: bytes(destination),
    }


def method_sort_key(method: dict[int, Any]) -> tuple[bytes, bytes]:
    """Deterministic order: lexicographic (UTF-8 type, destination bytes)."""
    return (method[METHOD_TYPE].encode("utf-8"), method[METHOD_DESTINATION])


def build_payment_binding(methods: Iterable[dict[int, Any] | tuple[str, bytes]]) -> dict[int, Any]:
    """Build canonical PaymentBindingV1.

    Duplicate (type, destination) pairs are collapsed. Order is sorted, so
    insertion order never affects the hash.
    """
    normalized: list[dict[int, Any]] = []
    seen: set[tuple[bytes, bytes]] = set()
    for m in methods:
        if isinstance(m, tuple):
            obj = normalize_method(m[0], m[1])
        else:
            obj = normalize_method(m[METHOD_TYPE], m[METHOD_DESTINATION])
        key = method_sort_key(obj)
        if key in seen:
            continue
        seen.add(key)
        normalized.append(obj)
    normalized.sort(key=method_sort_key)
    return {
        PAY_VERSION: PROTOCOL_VERSION,
        PAY_METHODS: normalized,
    }


def payment_binding_from_bip353_semantics(
    *,
    onchain_script_pubkeys: list[bytes] | None = None,
    extra_methods: list[tuple[str, bytes]] | None = None,
) -> dict[int, Any]:
    """Construct PaymentBinding from already-resolved BIP-353 semantics.

    Callers MUST:
      1. Resolve BIP-353 DNS + validate DNSSEC
      2. Reconstruct bitcoin: URI and parse BIP-321 instructions
      3. Convert on-chain addresses → scriptPubKey
      4. Drop amount/label/message/pop
      5. Pass only durable destination methods here
    """
    methods: list[tuple[str, bytes]] = []
    for spk in onchain_script_pubkeys or []:
        methods.append(("bitcoin", spk))
    for t, dest in extra_methods or []:
        methods.append((t, dest))
    return build_payment_binding(methods)


def encode_payment_binding(binding: dict[int, Any]) -> bytes:
    return cbor.dumps(binding)


def payment_hash(binding: dict[int, Any]) -> bytes:
    return hashlib.sha256(DOMAIN_SEPARATOR_PAYMENT + encode_payment_binding(binding)).digest()


def parse_payment_binding(data: bytes) -> dict[int, Any]:
    obj = cbor.loads(data)
    if not isinstance(obj, dict):
        raise PaymentBindingError("payment binding must be a map")
    if obj.get(PAY_VERSION) != PROTOCOL_VERSION:
        raise PaymentBindingError("unsupported payment binding version")
    methods = obj.get(PAY_METHODS)
    if not isinstance(methods, list):
        raise PaymentBindingError("methods must be an array")
    # Enforce canonical ordering on parse
    rebuilt = build_payment_binding(
        [(m[METHOD_TYPE], m[METHOD_DESTINATION]) for m in methods]
    )
    if cbor.dumps(rebuilt) != data:
        raise PaymentBindingError("non-canonical payment binding encoding")
    return rebuilt

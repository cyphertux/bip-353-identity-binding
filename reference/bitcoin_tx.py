"""Minimal Bitcoin transaction parse + txid (M6 verification hardening).

Supports legacy and BIP-141 (segwit) serialization enough to:
  - compute txid = SHA256d(non-witness serialization)
  - enumerate output scriptPubKeys for OP_RETURN extraction

Does NOT validate scripts, signatures, or amounts beyond structural parse.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass


class TxParseError(ValueError):
    pass


# Provisional resource bounds (see MILESTONE_6). Enforced during parse.
MAX_RAW_TX_BYTES = 100_000
MAX_TX_INPUTS = 1_000
MAX_TX_OUTPUTS = 1_000
MAX_SCRIPT_BYTES = 10_000


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise TxParseError("truncated varint")
    first = data[offset]
    offset += 1
    if first < 0xFD:
        return first, offset
    if first == 0xFD:
        if offset + 2 > len(data):
            raise TxParseError("truncated varint fd")
        return struct.unpack_from("<H", data, offset)[0], offset + 2
    if first == 0xFE:
        if offset + 4 > len(data):
            raise TxParseError("truncated varint fe")
        return struct.unpack_from("<I", data, offset)[0], offset + 4
    if offset + 8 > len(data):
        raise TxParseError("truncated varint ff")
    return struct.unpack_from("<Q", data, offset)[0], offset + 8


@dataclass
class TxOut:
    value: int
    script_pubkey: bytes


@dataclass
class ParsedTx:
    version: int
    is_segwit: bool
    outputs: list[TxOut]
    locktime: int
    raw: bytes
    txid_preimage: bytes

    @property
    def txid_internal(self) -> bytes:
        """Internal (little-endian) txid bytes — Merkle tree order."""
        return sha256d(self.txid_preimage)


def parse_transaction(raw: bytes) -> ParsedTx:
    """Parse a Bitcoin transaction; raise TxParseError on malformation."""
    if not isinstance(raw, (bytes, bytearray)):
        raise TxParseError("raw_tx must be bytes")
    raw = bytes(raw)
    if not raw:
        raise TxParseError("empty transaction")
    if len(raw) > MAX_RAW_TX_BYTES:
        raise TxParseError(f"raw_tx exceeds MAX_RAW_TX_BYTES ({MAX_RAW_TX_BYTES})")

    offset = 0
    if offset + 4 > len(raw):
        raise TxParseError("truncated version")
    version = struct.unpack_from("<I", raw, offset)[0]
    offset += 4
    version_end = offset

    is_segwit = False
    if offset + 2 <= len(raw) and raw[offset] == 0x00 and raw[offset + 1] != 0x00:
        is_segwit = True
        offset += 2

    body_start = offset  # vin_count

    n_in, offset = _read_varint(raw, offset)
    if n_in == 0 or n_in > MAX_TX_INPUTS:
        raise TxParseError(f"invalid input count {n_in}")

    for _ in range(n_in):
        if offset + 36 > len(raw):
            raise TxParseError("truncated input outpoint")
        offset += 36
        script_len, offset = _read_varint(raw, offset)
        if script_len > MAX_SCRIPT_BYTES:
            raise TxParseError("scriptSig too large")
        if offset + script_len + 4 > len(raw):
            raise TxParseError("truncated scriptSig/sequence")
        offset += script_len + 4

    n_out, offset = _read_varint(raw, offset)
    if n_out == 0 or n_out > MAX_TX_OUTPUTS:
        raise TxParseError(f"invalid output count {n_out}")

    outputs: list[TxOut] = []
    for _ in range(n_out):
        if offset + 8 > len(raw):
            raise TxParseError("truncated output value")
        value = struct.unpack_from("<Q", raw, offset)[0]
        offset += 8
        script_len, offset = _read_varint(raw, offset)
        if script_len > MAX_SCRIPT_BYTES:
            raise TxParseError("scriptPubKey too large")
        if offset + script_len > len(raw):
            raise TxParseError("truncated scriptPubKey")
        script = raw[offset : offset + script_len]
        offset += script_len
        outputs.append(TxOut(value=value, script_pubkey=script))

    body_end = offset

    if is_segwit:
        for _ in range(n_in):
            n_stack, offset = _read_varint(raw, offset)
            if n_stack > MAX_SCRIPT_BYTES:
                raise TxParseError("witness stack too large")
            for _ in range(n_stack):
                item_len, offset = _read_varint(raw, offset)
                if item_len > MAX_SCRIPT_BYTES:
                    raise TxParseError("witness item too large")
                if offset + item_len > len(raw):
                    raise TxParseError("truncated witness")
                offset += item_len

    if offset + 4 > len(raw):
        raise TxParseError("truncated locktime")
    locktime = struct.unpack_from("<I", raw, offset)[0]
    offset += 4
    if offset != len(raw):
        raise TxParseError(f"trailing bytes after transaction ({len(raw) - offset})")

    txid_preimage = raw[:version_end] + raw[body_start:body_end] + struct.pack("<I", locktime)

    return ParsedTx(
        version=version,
        is_segwit=is_segwit,
        outputs=outputs,
        locktime=locktime,
        raw=raw,
        txid_preimage=txid_preimage,
    )


def txid_from_raw(raw: bytes) -> bytes:
    """Return internal-byte-order txid = SHA256d(non-witness serialization)."""
    return parse_transaction(raw).txid_internal

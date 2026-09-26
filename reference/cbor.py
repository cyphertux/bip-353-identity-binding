"""Minimal deterministic CBOR encoder/decoder for BIP-353 Identity Binding.

Implements only the subset required by IdentityDocumentV1 / PaymentBindingV1 /
AnchorMessageV1: unsigned integers, byte strings, UTF-8 text, arrays, and
maps with integer keys. Encoding follows RFC 8949 §4.2.1 (Core Deterministic
Encoding Requirements): shortest form, sorted map keys by encoded key bytes.
"""

from __future__ import annotations

from typing import Any, Mapping, Sequence


class CBORError(ValueError):
    pass


def _encode_uint(major: int, value: int) -> bytes:
    if value < 0:
        raise CBORError(f"unsigned integer expected, got {value}")
    ai = major << 5
    if value < 24:
        return bytes([ai | value])
    if value < 256:
        return bytes([ai | 24, value])
    if value < 65536:
        return bytes([ai | 25]) + value.to_bytes(2, "big")
    if value < 2**32:
        return bytes([ai | 26]) + value.to_bytes(4, "big")
    if value < 2**64:
        return bytes([ai | 27]) + value.to_bytes(8, "big")
    raise CBORError(f"integer too large for CBOR: {value}")


def dumps(obj: Any) -> bytes:
    """Encode *obj* as deterministic CBOR."""
    if isinstance(obj, bool):
        raise CBORError("booleans are not used by this protocol")
    if obj is None:
        raise CBORError("null is not used by this protocol")
    if isinstance(obj, int):
        if obj < 0:
            raise CBORError("negative integers are not used by this protocol")
        return _encode_uint(0, obj)
    if isinstance(obj, bytes):
        return _encode_uint(2, len(obj)) + obj
    if isinstance(obj, str):
        encoded = obj.encode("utf-8")
        return _encode_uint(3, len(encoded)) + encoded
    if isinstance(obj, (list, tuple)):
        out = _encode_uint(4, len(obj))
        for item in obj:
            out += dumps(item)
        return out
    if isinstance(obj, dict):
        # Sort by encoded key bytes (RFC 8949 Core Deterministic Encoding)
        items: list[tuple[bytes, bytes]] = []
        for key, value in obj.items():
            if not isinstance(key, int) or key < 0:
                raise CBORError(
                    f"map keys must be non-negative integers, got {key!r}"
                )
            items.append((dumps(key), dumps(value)))
        items.sort(key=lambda kv: kv[0])
        out = _encode_uint(5, len(items))
        for kb, vb in items:
            out += kb + vb
        return out
    raise CBORError(f"unsupported type: {type(obj).__name__}")


def _decode_uint(data: bytes, offset: int) -> tuple[int, int, int]:
    """Return (additional_info_value, major_type, new_offset).

    Enforces RFC 8949 Core Deterministic Encoding: integers and lengths MUST
    use the shortest form. Non-shortest encodings are rejected.
    """
    if offset >= len(data):
        raise CBORError("unexpected end of input")
    initial = data[offset]
    major = initial >> 5
    ai = initial & 0x1F
    offset += 1
    if ai < 24:
        return ai, major, offset
    if ai == 24:
        if offset + 1 > len(data):
            raise CBORError("truncated 1-byte length")
        value = data[offset]
        if value < 24:
            raise CBORError("non-shortest CBOR integer encoding (1-byte)")
        return value, major, offset + 1
    if ai == 25:
        if offset + 2 > len(data):
            raise CBORError("truncated 2-byte length")
        value = int.from_bytes(data[offset : offset + 2], "big")
        if value < 256:
            raise CBORError("non-shortest CBOR integer encoding (2-byte)")
        return value, major, offset + 2
    if ai == 26:
        if offset + 4 > len(data):
            raise CBORError("truncated 4-byte length")
        value = int.from_bytes(data[offset : offset + 4], "big")
        if value < 65536:
            raise CBORError("non-shortest CBOR integer encoding (4-byte)")
        return value, major, offset + 4
    if ai == 27:
        if offset + 8 > len(data):
            raise CBORError("truncated 8-byte length")
        value = int.from_bytes(data[offset : offset + 8], "big")
        if value < 2**32:
            raise CBORError("non-shortest CBOR integer encoding (8-byte)")
        return value, major, offset + 8
    raise CBORError(f"unsupported additional info: {ai}")


def _loads_at(data: bytes, offset: int) -> tuple[Any, int]:
    value, major, offset = _decode_uint(data, offset)
    if major == 0:
        return value, offset
    if major == 2:
        end = offset + value
        if end > len(data):
            raise CBORError("truncated byte string")
        return data[offset:end], end
    if major == 3:
        end = offset + value
        if end > len(data):
            raise CBORError("truncated text string")
        try:
            return data[offset:end].decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise CBORError("invalid UTF-8") from exc
    if major == 4:
        items = []
        for _ in range(value):
            item, offset = _loads_at(data, offset)
            items.append(item)
        return items, offset
    if major == 5:
        mapping: dict[Any, Any] = {}
        prev_key_bytes: bytes | None = None
        for _ in range(value):
            key_start = offset
            key, offset = _loads_at(data, offset)
            key_bytes = data[key_start:offset]
            if prev_key_bytes is not None and key_bytes < prev_key_bytes:
                raise CBORError("map keys not in deterministic order")
            if prev_key_bytes is not None and key_bytes == prev_key_bytes:
                raise CBORError("duplicate map key")
            prev_key_bytes = key_bytes
            val, offset = _loads_at(data, offset)
            mapping[key] = val
        return mapping, offset
    raise CBORError(f"unsupported major type: {major}")


def loads(data: bytes) -> Any:
    """Decode deterministic CBOR; reject trailing bytes and non-canonical maps."""
    obj, offset = _loads_at(data, 0)
    if offset != len(data):
        raise CBORError(f"trailing bytes after CBOR value ({len(data) - offset})")
    return obj


def roundtrip(obj: Any) -> bytes:
    """Encode then decode to verify uniqueness; return canonical bytes."""
    encoded = dumps(obj)
    decoded = loads(encoded)
    if dumps(decoded) != encoded:
        raise CBORError("non-deterministic roundtrip")
    return encoded

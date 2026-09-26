#!/usr/bin/env python3
"""Unit tests for deterministic CBOR encoder."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference import cbor


def test_integer_shortest_form():
    assert cbor.dumps(0) == bytes([0x00])
    assert cbor.dumps(23) == bytes([0x17])
    assert cbor.dumps(24) == bytes([0x18, 0x18])
    assert cbor.dumps(256) == bytes([0x19, 0x01, 0x00])


def test_map_key_ordering():
    # Encoding must be identical regardless of insertion order
    a = cbor.dumps({2: "b", 0: 1, 1: "a"})
    b = cbor.dumps({0: 1, 1: "a", 2: "b"})
    assert a == b
    assert cbor.loads(a) == {0: 1, 1: "a", 2: "b"}


def test_bytes_and_text():
    assert cbor.dumps(b"\x00\x01") == bytes([0x42, 0x00, 0x01])
    assert cbor.dumps("ab") == bytes([0x62, 0x61, 0x62])


def test_reject_trailing():
    data = cbor.dumps({0: 1}) + b"\x00"
    try:
        cbor.loads(data)
        assert False, "should reject trailing bytes"
    except cbor.CBORError:
        pass


def main() -> int:
    test_integer_shortest_form()
    test_map_key_ordering()
    test_bytes_and_text()
    test_reject_trailing()
    print("cbor unit tests: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Experimental V2 Bitcoin dual-binding proof (B353S2).

Reuses V1 transaction parse + Merkle helpers without modifying V1 modules.
OP_RETURN tag is experimental B353S2 (never B353ID).

EXPERIMENTAL — NON-NORMATIVE — NOT PART OF V1
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

from reference.bitcoin_proof import (
    BlockHeader,
    HeaderContext,
    sha256d,
    verify_merkle_branch,
)
from reference.bitcoin_tx import TxParseError, parse_transaction
from reference.schnorr_v2.anchor import (
    AnchorError,
    extract_commitment_from_opreturn,
)
from reference.schnorr_v2.tags import OP_RETURN_TAG, OP_RETURN_VERSION


class BitcoinProofError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(code if not detail else f"{code}: {detail}")


@dataclass
class BitcoinAnchorProofV2:
    """Experimental proof object — not byte-compatible with V1 JSON."""

    raw_tx: bytes
    txid: bytes  # auxiliary internal-order 32 bytes
    block_header: bytes  # 80 bytes
    tx_index: int
    merkle_branch: list[bytes]  # internal-order siblings
    commitment: bytes  # auxiliary; must match extracted
    chain: str = "regtest"
    block_height: int = 0
    header_context: str = HeaderContext.TRUSTED.value


def _is_b353s2_script(script: bytes) -> bool:
    try:
        extract_commitment_from_opreturn(script)
        return True
    except AnchorError:
        return False


def extract_b353s2_commitment_from_raw_tx(raw_tx: bytes) -> bytes:
    """Parse outputs; require exactly one matching B353S2 OP_RETURN."""
    try:
        parsed = parse_transaction(raw_tx)
    except TxParseError as exc:
        raise BitcoinProofError("TX_PARSE_ERROR", str(exc)) from exc

    matches: list[bytes] = []
    for out in parsed.outputs:
        if _is_b353s2_script(out.script_pubkey):
            matches.append(extract_commitment_from_opreturn(out.script_pubkey))

    if len(matches) == 0:
        raise BitcoinProofError("NO_B353S2_OUTPUT")
    if len(matches) > 1:
        raise BitcoinProofError("AMBIGUOUS_B353S2_OUTPUTS")
    return matches[0]


def verify_bitcoin_anchor_proof_v2(
    proof: BitcoinAnchorProofV2,
    *,
    expected_commitment: bytes,
) -> None:
    """Dual-binding verify. Raises BitcoinProofError on failure.

    Authority:
      raw_tx → txid (SHA256d non-witness)
      raw_tx → unique B353S2 → commitment
      txid + merkle_branch + tx_index → header.merkle_root
    """
    if proof.chain == "main":
        raise BitcoinProofError("MAINNET_FORBIDDEN")

    if len(expected_commitment) != 32:
        raise BitcoinProofError("WRONG_TX_COMMITMENT", "expected commitment length")

    # --- Parse raw_tx / txid ---
    try:
        parsed = parse_transaction(proof.raw_tx)
    except TxParseError as exc:
        raise BitcoinProofError("TX_PARSE_ERROR", str(exc)) from exc
    computed_txid = parsed.txid_internal

    if proof.txid != computed_txid:
        raise BitcoinProofError("TXID_MISMATCH")

    # --- B353S2 from raw_tx ---
    extracted = extract_b353s2_commitment_from_raw_tx(proof.raw_tx)

    if extracted != expected_commitment:
        raise BitcoinProofError("WRONG_TX_COMMITMENT")

    # Auxiliary commitment field must agree (never authoritative alone)
    if proof.commitment != extracted:
        raise BitcoinProofError("WRONG_TX_COMMITMENT")

    # --- Header ---
    try:
        header = BlockHeader.deserialize(proof.block_header)
    except Exception as exc:  # noqa: BLE001
        raise BitcoinProofError("BAD_BLOCK_HEADER", str(exc)) from exc

    # --- Merkle ---
    if proof.tx_index < 0:
        raise BitcoinProofError("WRONG_MERKLE_PROOF", "negative tx_index")
    if not verify_merkle_branch(
        computed_txid,
        proof.tx_index,
        proof.merkle_branch,
        header.merkle_root,
    ):
        raise BitcoinProofError("WRONG_MERKLE_PROOF")


def build_minimal_legacy_tx(*, opreturn_script: bytes, extra_scripts: list[bytes] | None = None) -> bytes:
    """Build a minimal legacy (non-segwit) transaction for regtest fixtures."""
    # version
    raw = struct.pack("<I", 2)
    # vin count = 1
    raw += b"\x01"
    # prevout null + index
    raw += bytes(32) + struct.pack("<I", 0xFFFFFFFF)
    # empty scriptSig
    raw += b"\x00"
    # sequence
    raw += struct.pack("<I", 0xFFFFFFFF)
    scripts = [opreturn_script] + list(extra_scripts or [])
    raw += bytes([len(scripts)])
    for script in scripts:
        raw += struct.pack("<Q", 0)  # value
        raw += bytes([len(script)]) + script
    raw += struct.pack("<I", 0)  # locktime
    return raw


def build_header_for_txid(txid_internal: bytes, *, sibling: bytes | None = None, tx_index: int = 0) -> tuple[bytes, list[bytes]]:
    """Construct an 80-byte header whose merkle_root commits to txid (+ optional sibling)."""
    if sibling is None:
        merkle_root = txid_internal
        branch: list[bytes] = []
        assert tx_index == 0
    else:
        if tx_index == 0:
            merkle_root = sha256d(txid_internal + sibling)
            branch = [sibling]
        elif tx_index == 1:
            merkle_root = sha256d(sibling + txid_internal)
            branch = [sibling]
        else:
            raise ValueError("fixture only supports tx_index 0 or 1 with one sibling")

    header = BlockHeader(
        version=0x20000000,
        prev_hash=bytes(32),
        merkle_root=merkle_root,
        timestamp=1_700_000_000,
        bits=0x207FFFFF,
        nonce=0,
    )
    return header.serialize(), branch


def proof_from_parts(
    *,
    raw_tx: bytes,
    expected_commitment: bytes,
    sibling: bytes | None = None,
    tx_index: int = 0,
) -> BitcoinAnchorProofV2:
    parsed = parse_transaction(raw_tx)
    txid = parsed.txid_internal
    header, branch = build_header_for_txid(txid, sibling=sibling, tx_index=tx_index)
    return BitcoinAnchorProofV2(
        raw_tx=raw_tx,
        txid=txid,
        block_header=header,
        tx_index=tx_index,
        merkle_branch=branch,
        commitment=expected_commitment,
        chain="regtest",
        header_context=HeaderContext.TRUSTED.value,
    )


def proof_to_jsonable(proof: BitcoinAnchorProofV2) -> dict[str, Any]:
    return {
        "chain": proof.chain,
        "raw_tx": proof.raw_tx.hex(),
        "txid": proof.txid[::-1].hex(),  # display order like V1 fixtures
        "txid_internal": proof.txid.hex(),
        "block_header": proof.block_header.hex(),
        "tx_index": proof.tx_index,
        "merkle_branch": [s.hex() for s in proof.merkle_branch],
        "commitment": proof.commitment.hex(),
        "block_height": proof.block_height,
        "header_context": proof.header_context,
        "op_return_tag": OP_RETURN_TAG.decode("ascii"),
        "op_return_version": OP_RETURN_VERSION,
    }


def proof_from_jsonable(obj: dict[str, Any]) -> BitcoinAnchorProofV2:
    txid_internal = bytes.fromhex(obj["txid_internal"])
    return BitcoinAnchorProofV2(
        raw_tx=bytes.fromhex(obj["raw_tx"]),
        txid=txid_internal,
        block_header=bytes.fromhex(obj["block_header"]),
        tx_index=int(obj["tx_index"]),
        merkle_branch=[bytes.fromhex(x) for x in obj["merkle_branch"]],
        commitment=bytes.fromhex(obj["commitment"]),
        chain=obj.get("chain", "regtest"),
        block_height=int(obj.get("block_height", 0)),
        header_context=obj.get("header_context", HeaderContext.TRUSTED.value),
    )

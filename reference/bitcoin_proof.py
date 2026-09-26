"""Bitcoin inclusion proof + reorg-aware anchor status (M4 + M6 hardening).

Separates:
  ANCHOR COMMITMENT  — extracted from raw_tx OP_RETURN (authority)
  TRANSACTION VALID  — SHA256d(raw_tx) consistency
  ANCHOR INCLUSION   — txid → Merkle → header.merkle_root
  HEADER CONTEXT     — trusted vs untrusted (wallet-supplied)
  ANCHOR CONFIRMATION — depth / reorg-risk policy (wallet-local)

M6: proof.txid and proof.commitment are NEVER sources of truth.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from reference.bitcoin_anchor import (
    CommitmentExtractError,
    extract_identity_commitment,
)
from reference.bitcoin_tx import TxParseError, parse_transaction


class AnchorStatus(str, Enum):
    ANCHOR_ABSENT = "anchor_absent"
    ANCHOR_SEEN = "anchor_seen"  # tx known (mempool or unconfirmed)
    ANCHOR_INCLUDED = "anchor_included"  # in a block tip-side
    ANCHOR_CONFIRMED = "anchor_confirmed"  # depth >= policy
    ANCHOR_ORPHANED = "anchor_orphaned"  # was in orphaned block
    ANCHOR_FINALITY_UNKNOWN = "anchor_finality_unknown"


class HeaderContext(str, Enum):
    """Whether the block header is accepted under the wallet's chain view."""

    TRUSTED = "trusted"  # Mode A: wallet validated PoW/linkage/tip
    UNTRUSTED = "untrusted"  # Mode B: isolated proof only


def sha256d(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _hex_rev(b: bytes) -> str:
    """Bitcoin display hash (byte-reversed)."""
    return b[::-1].hex()


def merkle_parent(left: bytes, right: bytes) -> bytes:
    return sha256d(left + right)


def compute_merkle_root(txids_internal: list[bytes]) -> bytes:
    """txids_internal: little-endian (internal) 32-byte txids."""
    if not txids_internal:
        raise ValueError("empty tx list")
    layer = list(txids_internal)
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [merkle_parent(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
    return layer[0]


def build_merkle_branch(txids_internal: list[bytes], index: int) -> list[bytes]:
    """Return sibling hashes (internal byte order) for Merkle audit path."""
    if index < 0 or index >= len(txids_internal):
        raise ValueError("index out of range")
    branch: list[bytes] = []
    layer = list(txids_internal)
    idx = index
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        sibling = layer[idx ^ 1]
        branch.append(sibling)
        layer = [merkle_parent(layer[i], layer[i + 1]) for i in range(0, len(layer), 2)]
        idx //= 2
    return branch


def verify_merkle_branch(
    txid_internal: bytes,
    index: int,
    branch: list[bytes],
    merkle_root_internal: bytes,
) -> bool:
    h = txid_internal
    idx = index
    for sibling in branch:
        if idx % 2 == 0:
            h = merkle_parent(h, sibling)
        else:
            h = merkle_parent(sibling, h)
        idx //= 2
    return h == merkle_root_internal


@dataclass
class BlockHeader:
    version: int
    prev_hash: bytes  # internal (LE) 32 bytes
    merkle_root: bytes  # internal
    timestamp: int
    bits: int
    nonce: int

    def serialize(self) -> bytes:
        return (
            struct.pack("<I", self.version)
            + self.prev_hash
            + self.merkle_root
            + struct.pack("<I", self.timestamp)
            + struct.pack("<I", self.bits)
            + struct.pack("<I", self.nonce)
        )

    def block_hash(self) -> bytes:
        return sha256d(self.serialize())

    @classmethod
    def deserialize(cls, data: bytes) -> "BlockHeader":
        if len(data) != 80:
            raise ValueError("block header must be 80 bytes")
        version = struct.unpack_from("<I", data, 0)[0]
        prev_hash = data[4:36]
        merkle_root = data[36:68]
        timestamp = struct.unpack_from("<I", data, 68)[0]
        bits = struct.unpack_from("<I", data, 72)[0]
        nonce = struct.unpack_from("<I", data, 76)[0]
        return cls(version, prev_hash, merkle_root, timestamp, bits, nonce)


@dataclass
class BitcoinAnchorProofV1:
    """Independent inclusion proof object — NOT a PSBT type.

    Fields may be present for transport, but verifiers MUST recompute:
      txid from raw_tx
      commitment from raw_tx OP_RETURN
    Bundle fields are auxiliary cross-checks only.
    """

    protocol_version: int
    chain: str  # "regtest" | "testnet" | "signet" | "main"
    commitment: bytes  # auxiliary — MUST match extracted
    txid: bytes  # auxiliary internal order — MUST match SHA256d(raw_tx)
    raw_tx: bytes
    block_height: int
    block_header: bytes  # 80 bytes
    tx_index: int
    merkle_branch: list[bytes]  # internal order siblings
    tip_height_at_proof: int
    confirmations_at_proof: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "chain": self.chain,
            "commitment": self.commitment.hex(),
            "txid": _hex_rev(self.txid),
            "raw_tx": self.raw_tx.hex(),
            "block_height": self.block_height,
            "block_header": self.block_header.hex(),
            "tx_index": self.tx_index,
            "merkle_branch": [h.hex() for h in self.merkle_branch],
            "tip_height_at_proof": self.tip_height_at_proof,
            "confirmations_at_proof": self.confirmations_at_proof,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "BitcoinAnchorProofV1":
        return cls(
            protocol_version=d["protocol_version"],
            chain=d["chain"],
            commitment=bytes.fromhex(d["commitment"]),
            txid=bytes.fromhex(d["txid"])[::-1],
            raw_tx=bytes.fromhex(d["raw_tx"]),
            block_height=d["block_height"],
            block_header=bytes.fromhex(d["block_header"]),
            tx_index=d["tx_index"],
            merkle_branch=[bytes.fromhex(h) for h in d["merkle_branch"]],
            tip_height_at_proof=d["tip_height_at_proof"],
            confirmations_at_proof=d["confirmations_at_proof"],
        )


@dataclass
class BitcoinVerifyDetail:
    """Structured Bitcoin verification sub-result (M6)."""

    transaction_valid: bool = False
    inclusion_proof_valid: bool = False
    header_context: str = HeaderContext.UNTRUSTED.value
    status: str = AnchorStatus.ANCHOR_ABSENT.value
    extracted_commitment: str | None = None
    computed_txid: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    payment_verified: bool | None = None
    identity_verified: bool | None = None
    identity_anchored: bool = False
    anchor_included: bool = False
    anchor_status: str = AnchorStatus.ANCHOR_ABSENT.value
    freshness: str = "unknown"
    freshness_status: str = "unknown"  # explicit; never "current" in V1
    rollback_resistance: str = "not_provided"
    revocation_status: str = "unknown"
    trust_state: str = "first_seen"
    human_verified: bool = False  # ALWAYS false from this protocol alone
    header_context: str = HeaderContext.UNTRUSTED.value
    transaction_valid: bool = False
    inclusion_proof_valid: bool = False
    bitcoin: dict[str, Any] = field(default_factory=dict)
    freshness_detail: dict[str, Any] = field(
        default_factory=lambda: {"status": "unknown"}
    )
    revocation: dict[str, Any] = field(
        default_factory=lambda: {"status": "unknown"}
    )
    trust: dict[str, Any] = field(
        default_factory=lambda: {"status": "first_seen"}
    )
    errors: list[str] = field(default_factory=list)
    checks: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_anchor_status(
    *,
    included: bool,
    confirmations: int,
    confirmation_policy: int,
    orphaned: bool = False,
) -> AnchorStatus:
    if orphaned:
        return AnchorStatus.ANCHOR_ORPHANED
    if not included:
        return AnchorStatus.ANCHOR_SEEN if confirmations == 0 else AnchorStatus.ANCHOR_ABSENT
    if confirmations >= confirmation_policy:
        return AnchorStatus.ANCHOR_CONFIRMED
    if confirmations >= 1:
        return AnchorStatus.ANCHOR_INCLUDED
    return AnchorStatus.ANCHOR_FINALITY_UNKNOWN


def verify_bitcoin_anchor_proof(
    proof: BitcoinAnchorProofV1,
    *,
    expected_commitment: bytes,
    confirmation_policy: int = 1,
    known_orphaned: bool = False,
    header_context: str | HeaderContext = HeaderContext.UNTRUSTED,
) -> VerificationResult:
    """Verify raw_tx → OP_RETURN → commitment and raw_tx → txid → Merkle.

    Authority order:
      1. Parse raw_tx
      2. Extract commitment from OP_RETURN (source of truth for commitment)
      3. Compare extracted to expected_commitment
      4. Cross-check auxiliary proof.commitment field
      5. Compute txid = SHA256d(non-witness raw); cross-check proof.txid
      6. Merkle-include computed txid under block_header.merkle_root

    Does NOT claim human identity, freshness, best-chain membership (unless
    header_context=trusted), or absolute finality.
    """
    if isinstance(header_context, HeaderContext):
        header_context = header_context.value

    result = VerificationResult(
        freshness="unknown",
        freshness_status="unknown",
        rollback_resistance="not_provided",
        revocation_status="unknown",
        human_verified=False,
        header_context=header_context,
        freshness_detail={"status": "unknown"},
        revocation={"status": "unknown", "policy": "unknown_by_design"},
        trust={"status": "first_seen"},
    )

    if proof.chain == "main":
        result.errors.append("MAINNET_FORBIDDEN_IN_M4_TESTS")

    # --- Parse raw_tx ---
    try:
        parsed = parse_transaction(proof.raw_tx)
    except TxParseError as exc:
        result.errors.append(f"TX_PARSE_ERROR:{exc}")
        result.checks["transaction"] = False
        result.bitcoin = BitcoinVerifyDetail(header_context=header_context).to_dict()
        return result
    result.checks["transaction"] = True
    computed_txid = parsed.txid_internal

    # --- OP_RETURN commitment (authority) ---
    try:
        extracted = extract_identity_commitment(proof.raw_tx)
    except CommitmentExtractError as exc:
        result.errors.append(exc.code)
        result.checks["op_return"] = False
        result.transaction_valid = True  # parsed, but no usable B353ID
        result.bitcoin = BitcoinVerifyDetail(
            transaction_valid=True,
            header_context=header_context,
            computed_txid=_hex_rev(computed_txid),
        ).to_dict()
        return result
    result.checks["op_return"] = True

    if extracted != expected_commitment:
        # Tx body does not commit to the expected identity commitment
        result.errors.append("WRONG_TX_COMMITMENT")
        result.checks["commitment"] = False
        result.transaction_valid = True
        result.bitcoin = BitcoinVerifyDetail(
            transaction_valid=True,
            header_context=header_context,
            computed_txid=_hex_rev(computed_txid),
            extracted_commitment=extracted.hex(),
        ).to_dict()
        return result
    result.checks["commitment"] = True

    # Auxiliary bundle field — must agree with extracted (never authoritative alone)
    if proof.commitment != extracted:
        result.errors.append("WRONG_TX_COMMITMENT")
        result.checks["commitment_field"] = False
        result.transaction_valid = True
        result.bitcoin = BitcoinVerifyDetail(
            transaction_valid=True,
            header_context=header_context,
            computed_txid=_hex_rev(computed_txid),
            extracted_commitment=extracted.hex(),
        ).to_dict()
        return result
    result.checks["commitment_field"] = True
    result.identity_anchored = True

    # --- txid binding ---
    if proof.txid != computed_txid:
        result.errors.append("TXID_MISMATCH")
        result.checks["txid"] = False
        result.transaction_valid = False
        result.identity_anchored = False  # incomplete binding
        result.bitcoin = BitcoinVerifyDetail(
            transaction_valid=False,
            header_context=header_context,
            computed_txid=_hex_rev(computed_txid),
            extracted_commitment=extracted.hex(),
        ).to_dict()
        return result
    result.checks["txid"] = True
    result.transaction_valid = True

    # --- Merkle: computed txid → header ---
    try:
        header = BlockHeader.deserialize(proof.block_header)
    except ValueError as exc:
        result.errors.append(f"BAD_BLOCK_HEADER:{exc}")
        result.checks["block_header"] = False
        result.bitcoin = BitcoinVerifyDetail(
            transaction_valid=True,
            header_context=header_context,
            computed_txid=_hex_rev(computed_txid),
            extracted_commitment=extracted.hex(),
        ).to_dict()
        return result

    if len(proof.merkle_branch) > 32:
        result.errors.append("MERKLE_BRANCH_TOO_DEEP")
        result.checks["merkle"] = False
        result.bitcoin = BitcoinVerifyDetail(
            transaction_valid=True,
            inclusion_proof_valid=False,
            header_context=header_context,
            computed_txid=_hex_rev(computed_txid),
            extracted_commitment=extracted.hex(),
        ).to_dict()
        return result

    if not verify_merkle_branch(
        computed_txid, proof.tx_index, proof.merkle_branch, header.merkle_root
    ):
        result.errors.append("WRONG_MERKLE_PROOF")
        result.checks["merkle"] = False
        result.bitcoin = BitcoinVerifyDetail(
            transaction_valid=True,
            inclusion_proof_valid=False,
            header_context=header_context,
            computed_txid=_hex_rev(computed_txid),
            extracted_commitment=extracted.hex(),
        ).to_dict()
        return result
    result.checks["merkle"] = True
    result.checks["block_header"] = True
    result.inclusion_proof_valid = True
    result.checks["height_advisory"] = True

    if known_orphaned:
        result.anchor_status = AnchorStatus.ANCHOR_ORPHANED.value
        result.anchor_included = False
        result.errors.append("ORPHANED_ANCHOR")
        result.bitcoin = BitcoinVerifyDetail(
            transaction_valid=True,
            inclusion_proof_valid=True,
            header_context=header_context,
            status=AnchorStatus.ANCHOR_ORPHANED.value,
            computed_txid=_hex_rev(computed_txid),
            extracted_commitment=extracted.hex(),
        ).to_dict()
        return result

    status = evaluate_anchor_status(
        included=True,
        confirmations=proof.confirmations_at_proof,
        confirmation_policy=confirmation_policy,
        orphaned=False,
    )
    result.anchor_status = status.value

    # Cryptographic inclusion in the *claimed* header is inclusion_proof_valid.
    # anchor_included requires the wallet to treat that header as chain-accepted.
    if header_context == HeaderContext.TRUSTED.value:
        result.anchor_included = status in (
            AnchorStatus.ANCHOR_INCLUDED,
            AnchorStatus.ANCHOR_CONFIRMED,
        )
        result.checks["best_chain"] = True
    else:
        result.anchor_included = False
        result.checks["best_chain"] = False

    result.checks["inclusion"] = True
    result.bitcoin = BitcoinVerifyDetail(
        transaction_valid=True,
        inclusion_proof_valid=True,
        header_context=header_context,
        status=status.value,
        computed_txid=_hex_rev(computed_txid),
        extracted_commitment=extracted.hex(),
    ).to_dict()
    return result

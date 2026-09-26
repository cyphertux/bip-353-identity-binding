#!/usr/bin/env python3
"""Create a real regtest OP_RETURN anchor transaction + inclusion proof fixture."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from reference.bitcoin_anchor import (
    build_anchor_message_a,
    build_op_return_script,
    identity_commitment,
    parse_op_return_commitment,
)
from reference.bitcoin_proof import (
    BitcoinAnchorProofV1,
    BlockHeader,
    HeaderContext,
    build_merkle_branch,
    compute_merkle_root,
    verify_bitcoin_anchor_proof,
    verify_merkle_branch,
)
from reference.payment_binding import (
    address_to_script_pubkey,
    build_payment_binding,
    payment_hash,
)

DATADIR = Path(os.environ.get("BITCOIN_DATADIR", "/tmp/bip353-regtest"))
RPC = ["bitcoin-cli", f"-datadir={DATADIR}", "-rpcuser=bip353", "-rpcpassword=bip353test"]
OUT = ROOT / "vectors" / "m4"


def cli(*args: str) -> str:
    r = subprocess.run([*RPC, *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"bitcoin-cli {args}: {r.stderr}")
    return r.stdout.strip()


def cli_json(*args: str):
    return json.loads(cli(*args))


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)

    # Identity parameters (test identity — not a real person)
    domain = "example.test"
    identifier = "alice@example.test"
    # Use M1 KROOT fingerprint bytes for continuity of examples
    root_fpr = bytes.fromhex("de26bd614a4224ac0b704ed1c8f68e1738268297")

    # Payment destination from regtest wallet
    dest_addr = cli("-rpcwallet=m4", "getnewaddress", "", "bech32")
    spk = address_to_script_pubkey(dest_addr)
    binding = build_payment_binding([("bitcoin", spk)])
    pay_hash = payment_hash(binding)

    anchor = build_anchor_message_a(
        domain=domain, identifier=identifier, root_fingerprint=root_fpr
    )
    commitment = identity_commitment(anchor)
    opreturn_script = build_op_return_script(commitment)

    assert parse_op_return_commitment(opreturn_script) == commitment

    # Fund + create OP_RETURN tx via raw transaction
    # Use createrawtransaction with data output (Knots/Core support "data")
    change = cli("-rpcwallet=m4", "getrawchangeaddress")
    # data hex without OP_RETURN opcode — Core wraps it
    data_hex = opreturn_script[2:].hex()  # payload after OP_RETURN push header... 
    # Actually Core's "data" field is the raw data pushed after OP_RETURN.
    # So pass tag||version||commitment only.
    from reference.bitcoin_anchor import DEFAULT_OP_RETURN_TAG, DEFAULT_OP_RETURN_VERSION

    payload = DEFAULT_OP_RETURN_TAG + bytes([DEFAULT_OP_RETURN_VERSION]) + commitment
    outs = [{change: 49.999}, {"data": payload.hex()}]
    # Need inputs — use fundrawtransaction instead
    raw = cli(
        "-rpcwallet=m4",
        "createrawtransaction",
        "[]",
        json.dumps([{"data": payload.hex()}]),
    )
    funded = cli_json("-rpcwallet=m4", "fundrawtransaction", raw)
    signed = cli_json("-rpcwallet=m4", "signrawtransactionwithwallet", funded["hex"])
    if not signed.get("complete"):
        raise RuntimeError(f"sign incomplete: {signed}")
    txid_display = cli("-rpcwallet=m4", "sendrawtransaction", signed["hex"])
    raw_tx_hex = cli("getrawtransaction", txid_display)

    # Mine a block including the tx
    miner = cli("-rpcwallet=m4", "getnewaddress")
    blockhashes = cli_json("-rpcwallet=m4", "generatetoaddress", "1", miner)
    blockhash = blockhashes[0]
    block = cli_json("getblock", blockhash, "2")
    tip = int(cli("getblockcount"))
    height = int(block["height"])
    conf = tip - height + 1

    # Internal-order txids from block
    txids_internal = [bytes.fromhex(t["txid"])[::-1] for t in block["tx"]]
    # Find our tx index
    tx_index = next(i for i, t in enumerate(block["tx"]) if t["txid"] == txid_display)
    merkle_root_internal = bytes.fromhex(block["merkleroot"])[::-1]
    assert compute_merkle_root(txids_internal) == merkle_root_internal

    branch = build_merkle_branch(txids_internal, tx_index)
    assert verify_merkle_branch(
        txids_internal[tx_index], tx_index, branch, merkle_root_internal
    )

    header_hex = cli("getblockheader", blockhash, "false")
    header = BlockHeader.deserialize(bytes.fromhex(header_hex))
    assert header.merkle_root == merkle_root_internal

    proof = BitcoinAnchorProofV1(
        protocol_version=1,
        chain="regtest",
        commitment=commitment,
        txid=txids_internal[tx_index],
        raw_tx=bytes.fromhex(raw_tx_hex),
        block_height=height,
        block_header=bytes.fromhex(header_hex),
        tx_index=tx_index,
        merkle_branch=branch,
        tip_height_at_proof=tip,
        confirmations_at_proof=conf,
    )

    vr = verify_bitcoin_anchor_proof(
        proof,
        expected_commitment=commitment,
        confirmation_policy=1,
        header_context=HeaderContext.TRUSTED,
    )
    assert vr.identity_anchored and vr.anchor_included and not vr.errors, vr

    # Write fixtures
    from reference import cbor
    from reference.payment_binding import classify_script

    (OUT / "payment-binding.cbor").write_bytes(cbor.dumps(binding))
    (OUT / "anchor-message.cbor").write_bytes(cbor.dumps(anchor))
    (OUT / "opreturn-script.hex").write_text(opreturn_script.hex() + "\n")
    (OUT / "raw-tx.hex").write_text(raw_tx_hex + "\n")
    (OUT / "block-header.hex").write_text(header_hex + "\n")
    (OUT / "bitcoin-anchor-proof.json").write_text(
        json.dumps(proof.to_dict(), indent=2) + "\n"
    )

    expected = {
        "domain": domain,
        "identifier": identifier,
        "kroot_fingerprint": root_fpr.hex(),
        "destination_address": dest_addr,
        "script_pubkey": spk.hex(),
        "script_type": classify_script(spk),
        "payment_hash": pay_hash.hex(),
        "identity_commitment": commitment.hex(),
        "txid": txid_display,
        "block_hash": blockhash,
        "block_height": height,
        "tx_index": tx_index,
        "confirmations": conf,
        "chain": "regtest",
        "op_return_tag": "B353ID",
        "op_return_version": 1,
        "verification": {
            "payment_verified": True,
            "identity_verified": True,
            "identity_anchored": True,
            "anchor_included": True,
            "freshness": "unknown",
            "human_verified": False,
        },
        "anchor_candidate": "A",
        "note": "Real Bitcoin Knots regtest transaction. Not mainnet.",
    }
    (OUT / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")

    # Candidate comparison vectors (no chain needed)
    from reference.bitcoin_anchor import (
        build_anchor_message_b,
        build_anchor_message_c,
    )

    ksign = bytes.fromhex("55f38348c4a60b8ffd7b40c86186d1b88a7badea")
    pay2 = payment_hash(
        build_payment_binding(
            [("bitcoin", bytes.fromhex("00142222222222222222222222222222222222222222"))]
        )
    )
    candidates = {
        "A_stable_ksign_payment": {
            "base": identity_commitment(anchor).hex(),
            "after_payment_change": identity_commitment(anchor).hex(),  # same A
            "after_ksign_ignored": identity_commitment(anchor).hex(),
        },
        "B_changes_with_payment": {
            "base": identity_commitment(
                build_anchor_message_b(
                    domain=domain,
                    identifier=identifier,
                    root_fingerprint=root_fpr,
                    payment_hash_value=pay_hash,
                )
            ).hex(),
            "after_payment_change": identity_commitment(
                build_anchor_message_b(
                    domain=domain,
                    identifier=identifier,
                    root_fingerprint=root_fpr,
                    payment_hash_value=pay2,
                )
            ).hex(),
        },
        "C_changes_with_ksign_or_payment": {
            "base": identity_commitment(
                build_anchor_message_c(
                    domain=domain,
                    identifier=identifier,
                    root_fingerprint=root_fpr,
                    signing_fingerprint=ksign,
                    payment_hash_value=pay_hash,
                )
            ).hex(),
            "after_ksign_change": identity_commitment(
                build_anchor_message_c(
                    domain=domain,
                    identifier=identifier,
                    root_fingerprint=root_fpr,
                    signing_fingerprint=bytes(20),
                    payment_hash_value=pay_hash,
                )
            ).hex(),
        },
    }
    (OUT / "anchor-candidates.json").write_text(json.dumps(candidates, indent=2) + "\n")

    print("Wrote vectors/m4/")
    print(f"  txid={txid_display}")
    print(f"  commitment={commitment.hex()}")
    print(f"  payment_hash={pay_hash.hex()}")
    print(f"  height={height} conf={conf}")
    print(f"  verify: anchored={vr.identity_anchored} included={vr.anchor_included}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

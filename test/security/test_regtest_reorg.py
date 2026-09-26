#!/usr/bin/env python3
"""M5 J9 — real Bitcoin Knots/Core regtest reorg around an OP_RETURN anchor.

Does NOT overwrite frozen vectors/m4. Writes test/security/m5_reorg_result.json.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from reference.bitcoin_anchor import (  # noqa: E402
    build_anchor_message_a,
    build_op_return_script,
    identity_commitment,
)
from reference.bitcoin_proof import (  # noqa: E402
    AnchorStatus,
    HeaderContext,
    BitcoinAnchorProofV1,
    BlockHeader,
    build_merkle_branch,
    compute_merkle_root,
    evaluate_anchor_status,
    verify_bitcoin_anchor_proof,
    verify_merkle_branch,
)

DATADIR = Path(os.environ.get("BITCOIN_DATADIR", "/tmp/bip353-m5-reorg"))
RPC = [
    "bitcoin-cli",
    f"-datadir={DATADIR}",
    "-rpcuser=bip353",
    "-rpcpassword=bip353test",
]
OUT = Path(__file__).resolve().parent / "m5_reorg_result.json"


def cli(*args: str) -> str:
    r = subprocess.run([*RPC, *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"bitcoin-cli {args}: {r.stderr}")
    return r.stdout.strip()


def cli_json(*args: str):
    return json.loads(cli(*args))


def start_node() -> None:
    if DATADIR.exists():
        subprocess.run(
            ["bitcoin-cli", f"-datadir={DATADIR}", "stop"],
            capture_output=True,
        )
        time.sleep(1)
        shutil.rmtree(DATADIR, ignore_errors=True)
    DATADIR.mkdir(parents=True)
    conf = DATADIR / "bitcoin.conf"
    conf.write_text(
        "regtest=1\n"
        "server=1\n"
        "txindex=1\n"
        "rpcuser=bip353\n"
        "rpcpassword=bip353test\n"
        "fallbackfee=0.0002\n"
    )
    subprocess.Popen(
        [
            "bitcoind",
            f"-datadir={DATADIR}",
            "-daemon",
            "-regtest",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(40):
        try:
            cli("getblockchaininfo")
            return
        except RuntimeError:
            time.sleep(0.25)
    raise RuntimeError("bitcoind failed to start")


def stop_node() -> None:
    try:
        cli("stop")
    except RuntimeError:
        pass
    time.sleep(0.5)


def proof_from_txid(txid_display: str, commitment: bytes) -> BitcoinAnchorProofV1:
    raw_tx_hex = cli("getrawtransaction", txid_display)
    tip = int(cli("getblockcount"))
    # Find block containing tx
    tx = cli_json("getrawtransaction", txid_display, "true")
    blockhash = tx["blockhash"]
    block = cli_json("getblock", blockhash, "2")
    height = int(block["height"])
    conf = tip - height + 1
    txids_internal = [bytes.fromhex(t["txid"])[::-1] for t in block["tx"]]
    tx_index = next(i for i, t in enumerate(block["tx"]) if t["txid"] == txid_display)
    merkle_root_internal = bytes.fromhex(block["merkleroot"])[::-1]
    assert compute_merkle_root(txids_internal) == merkle_root_internal
    branch = build_merkle_branch(txids_internal, tx_index)
    assert verify_merkle_branch(
        txids_internal[tx_index], tx_index, branch, merkle_root_internal
    )
    header_hex = cli("getblockheader", blockhash, "false")
    return BitcoinAnchorProofV1(
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


def main() -> int:
    result: dict = {"ok": False, "steps": []}
    try:
        start_node()
        cli("createwallet", "m5")
        addr = cli("-rpcwallet=m5", "getnewaddress")
        cli("-rpcwallet=m5", "generatetoaddress", "101", addr)

        domain = "example.test"
        identifier = "alice@example.test"
        root_fpr = bytes.fromhex("de26bd614a4224ac0b704ed1c8f68e1738268297")
        anchor = build_anchor_message_a(
            domain=domain, identifier=identifier, root_fingerprint=root_fpr
        )
        commitment = identity_commitment(anchor)
        opreturn = build_op_return_script(commitment)
        data_hex = opreturn[2:].hex()  # Core "data" = push after OP_RETURN

        change = cli("-rpcwallet=m5", "getrawchangeaddress")
        utxos = cli_json("-rpcwallet=m5", "listunspent")
        vin = [{"txid": utxos[0]["txid"], "vout": utxos[0]["vout"]}]
        # Leave ~0.0001 BTC fee from 50 BTC coinbase maturity spend
        vout = [
            {"data": data_hex},
            {change: float(utxos[0]["amount"]) - 0.0001},
        ]
        raw = cli(
            "-rpcwallet=m5",
            "createrawtransaction",
            json.dumps(vin),
            json.dumps(vout),
        )
        signed = cli_json("-rpcwallet=m5", "signrawtransactionwithwallet", raw)
        txid = cli("-rpcwallet=m5", "sendrawtransaction", signed["hex"])
        result["steps"].append({"broadcast": txid})

        # Confirm once on branch A
        miner_a = cli("-rpcwallet=m5", "getnewaddress")
        block_a = cli_json("-rpcwallet=m5", "generatetoaddress", "1", miner_a)[0]
        proof_before = proof_from_txid(txid, commitment)
        vr_before = verify_bitcoin_anchor_proof(
            proof_before,
            expected_commitment=commitment,
            confirmation_policy=1,
            header_context=HeaderContext.TRUSTED,
        )
        result["steps"].append(
            {
                "branch_a_block": block_a,
                "proof_status": vr_before.anchor_status,
                "anchor_included": vr_before.anchor_included,
                "identity_anchored": vr_before.identity_anchored,
            }
        )
        assert vr_before.identity_anchored and vr_before.anchor_included

        # Invalidate the confirming block → orphan the branch containing the tx
        # (tx returns to mempool). Invalidateblock orphans that block and descendants.
        tip_before = int(cli("getblockcount"))
        cli("invalidateblock", block_a)
        tip_after = int(cli("getblockcount"))
        result["steps"].append(
            {
                "invalidate": block_a,
                "tip_before": tip_before,
                "tip_after": tip_after,
            }
        )

        # Wallet must treat previous proof as orphaned once it learns the header left best chain
        vr_orphaned = verify_bitcoin_anchor_proof(
            proof_before,
            expected_commitment=commitment,
            confirmation_policy=1,
            known_orphaned=True,
            header_context=HeaderContext.TRUSTED,
        )
        status_api = evaluate_anchor_status(
            included=False, confirmations=0, confirmation_policy=1, orphaned=True
        )
        result["steps"].append(
            {
                "after_reorg_api": {
                    "anchor_status": vr_orphaned.anchor_status,
                    "anchor_included": vr_orphaned.anchor_included,
                    "errors": vr_orphaned.errors,
                    "evaluate": status_api.value,
                }
            }
        )

        # Mine a competing longer chain without the anchor tx
        miner_b = cli("-rpcwallet=m5", "getnewaddress")
        # Empty mempool optionally — abandon is optional; generate new tip
        blocks_b = cli_json("-rpcwallet=m5", "generatetoaddress", "2", miner_b)
        tip_b = int(cli("getblockcount"))
        result["steps"].append({"branch_b_blocks": blocks_b, "tip": tip_b})

        ok = (
            vr_before.anchor_included
            and vr_orphaned.anchor_status == AnchorStatus.ANCHOR_ORPHANED.value
            and not vr_orphaned.anchor_included
            and "ORPHANED_ANCHOR" in vr_orphaned.errors
            and tip_after < tip_before
            and tip_b > tip_after
        )
        result["ok"] = ok
        result["conclusion"] = (
            "Reorg detected via wallet tip knowledge → ANCHOR_ORPHANED. "
            "Isolated SPV proof alone cannot observe reorg; wallet must re-check headers. "
            "No absolute finality claimed."
        )
        result["freshness"] = "unknown"
        result["human_verified"] = False
    except Exception as e:
        result["error"] = str(e)
        result["ok"] = False
    finally:
        stop_node()

    OUT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

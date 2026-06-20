import time

from ipv8.keyvault.crypto import default_eccrypto

from bonus.reorganize import MAX_REORG_DEPTH, reorg_depth, reorganize
from labs.three.chain import (
    GENESIS,
    GENESIS_HASH,
    Block,
    Chain,
    Mempool,
    Tx,
    compute_block_hash,
    compute_tx_hash,
    compute_txs_hash,
    mine_block,
    pack_header,
)
from common.banner import rule, rows, divider, section

NOW = 1_700_000_000
DIFFICULTY = 8
PAUSE = 0.4


# helper that signs and packages a transaction along with its tx_hash entry for the archive
def _make_tx(data: bytes, ts: int):
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    tx = Tx(sender, data, ts, sig)
    return tx, compute_tx_hash(sender, data, ts, sig)


# mines a single block on top of the supplied prev hash carrying the given body
def _mine_one(prev_hash: bytes, body: tuple, timestamp: int) -> Block:
    txs_hash = compute_txs_hash(body)
    nonce, _ = mine_block(prev_hash, txs_hash, DIFFICULTY, timestamp)
    return Block(prev_hash, txs_hash, timestamp, DIFFICULTY, nonce, body)


# scenario one shows a displaced transaction reappearing in the mempool
def scenario_mempool_restore():
    section("Scenario A Mempool Restore On Reorg")
    chain = Chain()
    mempool = Mempool()
    tx_archive: dict[bytes, Tx] = {}

    # one signed transaction lands in the current chain
    tx, tx_hash = _make_tx(b"hello reorg", NOW + 1)
    tx_archive[tx_hash] = tx
    block_a1 = _mine_one(GENESIS_HASH, (tx_hash,), NOW + 100)
    chain.append(block_a1)
    print(f"[Chain A] Mined Block 1 With Transaction tx_hash={tx_hash[:8].hex()}...")
    print(f"[Mempool] Size Before Reorg = {len(mempool)}")
    time.sleep(PAUSE)

    # a longer fork emerges that does not carry this transaction
    fork = [GENESIS]
    prev = GENESIS_HASH
    for i in range(2):
        block = _mine_one(prev, (), NOW + 500 + i)
        fork.append(block)
        prev = compute_block_hash(pack_header(block))
        print(f"[Chain B] Mined Block {i + 1} Empty Body")
        time.sleep(PAUSE)

    divider()
    print(f"[Reorg] Current Tip Height = {chain.height}")
    print(f"[Reorg] Candidate Chain Length = {len(fork) - 1}")
    print(f"[Reorg] Depth = {reorg_depth(chain, fork)}")
    accepted = reorganize(chain, mempool, fork, tx_archive)
    print(f"[Reorg] Accepted = {accepted}")
    time.sleep(PAUSE)

    divider()
    rows(
        [
            ("New Height", chain.height),
            ("Mempool Size", len(mempool)),
            ("Tx Restored", tx_hash in mempool.pending),
        ]
    )
    assert accepted and tx_hash in mempool.pending


# scenario two shows the depth cap rejecting a very deep reorg attempt
def scenario_depth_cap():
    section("Scenario B Depth Cap Rejects Deep Reorg")
    chain = Chain()
    prev = GENESIS_HASH
    for i in range(MAX_REORG_DEPTH + 2):
        block = _mine_one(prev, (), NOW + 1000 + i)
        chain.append(block)
        prev = compute_block_hash(pack_header(block))
    print(f"[Chain A] Built Linear Chain Of Height {chain.height}")
    time.sleep(PAUSE)

    fork = [GENESIS]
    prev = GENESIS_HASH
    for i in range(MAX_REORG_DEPTH + 3):
        block = _mine_one(prev, (), NOW + 5000 + i)
        fork.append(block)
        prev = compute_block_hash(pack_header(block))
    print(f"[Chain B] Built Competing Chain Of Length {len(fork) - 1}")
    time.sleep(PAUSE)

    depth = reorg_depth(chain, fork)
    divider()
    print(f"[Reorg] Computed Depth = {depth}")
    print(f"[Reorg] Max Allowed Depth = {MAX_REORG_DEPTH}")
    accepted = reorganize(chain, Mempool(), fork, tx_archive={})
    print(f"[Reorg] Accepted = {accepted}")
    time.sleep(PAUSE)

    divider()
    rows(
        [
            ("Original Tip", chain.height),
            ("Depth Exceeds Cap", depth > MAX_REORG_DEPTH),
            ("Reorg Rejected", not accepted),
        ]
    )
    assert not accepted and chain.height == MAX_REORG_DEPTH + 2


# entry point that walks the two reorganization scenarios end to end
def main():
    rule("Bonus Five Fork Convergence Polish")
    print("Two Scenarios. Atomic Reorg With Mempool Restore And Depth Cap.\n")
    scenario_mempool_restore()
    print()
    scenario_depth_cap()
    print()
    rule("Bonus Five Demo Passed")


if __name__ == "__main__":
    main()

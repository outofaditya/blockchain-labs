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
PAUSE = 0.3


# builds a real signed tx and registers it in the archive
def make_tx(data: bytes, ts: int):
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    tx = Tx(sender, data, ts, sig)
    return tx, compute_tx_hash(sender, data, ts, sig)


# mines a single block on top of prev hash carrying the supplied tx hashes
def mine_one(prev_hash: bytes, body: tuple, timestamp: int) -> Block:
    txs_hash = compute_txs_hash(body)
    nonce, _ = mine_block(prev_hash, txs_hash, DIFFICULTY, timestamp)
    return Block(prev_hash, txs_hash, timestamp, DIFFICULTY, nonce, body)


# scenario one shows a multi tx mempool restore on a moderate reorg
def scenario_multi_tx_restore():
    section("Scenario A Mempool Restore With Five Transactions")
    chain = Chain()
    mempool = Mempool()
    tx_archive: dict[bytes, Tx] = {}

    # five real signed txs land into the current chain across three blocks
    tx_pairs = [make_tx(f"payment-{i}".encode(), NOW + i) for i in range(5)]
    for tx, h in tx_pairs:
        tx_archive[h] = tx

    prev = GENESIS_HASH
    # block one carries the first two txs
    body = tuple(h for _, h in tx_pairs[:2])
    block_a1 = mine_one(prev, body, NOW + 100)
    chain.append(block_a1)
    prev = compute_block_hash(pack_header(block_a1))
    print(f"[Chain A] Mined Block 1 With {len(body)} Transactions")
    time.sleep(PAUSE)

    # block two carries the next two txs
    body = tuple(h for _, h in tx_pairs[2:4])
    block_a2 = mine_one(prev, body, NOW + 200)
    chain.append(block_a2)
    prev = compute_block_hash(pack_header(block_a2))
    print(f"[Chain A] Mined Block 2 With {len(body)} Transactions")
    time.sleep(PAUSE)

    # block three carries the last tx
    body = tuple(h for _, h in tx_pairs[4:5])
    block_a3 = mine_one(prev, body, NOW + 300)
    chain.append(block_a3)
    print(f"[Chain A] Mined Block 3 With {len(body)} Transactions")
    print(f"[Mempool] Size Before Reorg = {len(mempool)}")
    time.sleep(PAUSE)

    # competing fork five blocks long containing none of those txs
    fork = [GENESIS]
    prev = GENESIS_HASH
    for i in range(5):
        block = mine_one(prev, (), NOW + 1000 + i)
        fork.append(block)
        prev = compute_block_hash(pack_header(block))
    print(f"[Chain B] Built Empty Chain Of Length {len(fork) - 1}")
    time.sleep(PAUSE)

    divider()
    print(f"[Reorg] Current Tip Height = {chain.height}")
    print(f"[Reorg] Candidate Chain Length = {len(fork) - 1}")
    print(f"[Reorg] Depth = {reorg_depth(chain, fork)}")
    accepted = reorganize(chain, mempool, fork, tx_archive)
    print(f"[Reorg] Accepted = {accepted}")
    time.sleep(PAUSE)

    divider()
    restored_hashes = {h for _, h in tx_pairs if h in mempool.pending}
    rows(
        [
            ("New Height", chain.height),
            ("Mempool Size", len(mempool)),
            ("Restored Tx Count", len(restored_hashes)),
            ("All Five Restored", len(restored_hashes) == 5),
        ]
    )
    assert accepted and len(restored_hashes) == 5


# scenario two shows the depth cap rejecting a very deep reorg attempt
def scenario_depth_cap():
    section("Scenario B Depth Cap Rejects Reorg That Discards Too Many Blocks")
    chain = Chain()
    prev = GENESIS_HASH
    for i in range(MAX_REORG_DEPTH + 2):
        block = mine_one(prev, (), NOW + 1000 + i)
        chain.append(block)
        prev = compute_block_hash(pack_header(block))
    print(f"[Chain A] Built Linear Chain Of Height {chain.height}")
    time.sleep(PAUSE)

    fork = [GENESIS]
    prev = GENESIS_HASH
    for i in range(MAX_REORG_DEPTH + 3):
        block = mine_one(prev, (), NOW + 5000 + i)
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


# scenario three shows a reorg accepted exactly at the cap edge
def scenario_at_cap_edge():
    section("Scenario C Reorg At Exactly Max Allowed Depth")
    chain = Chain()
    prev = GENESIS_HASH
    # build a chain whose tip sits exactly MAX_REORG_DEPTH above genesis
    for i in range(MAX_REORG_DEPTH):
        block = mine_one(prev, (), NOW + 7000 + i)
        chain.append(block)
        prev = compute_block_hash(pack_header(block))
    print(f"[Chain A] Built Linear Chain Of Height {chain.height}")
    time.sleep(PAUSE)

    fork = [GENESIS]
    prev = GENESIS_HASH
    for i in range(MAX_REORG_DEPTH + 1):
        block = mine_one(prev, (), NOW + 9000 + i)
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
            ("New Height", chain.height),
            ("Depth At Cap", depth == MAX_REORG_DEPTH),
            ("Reorg Accepted", accepted),
        ]
    )
    assert accepted and chain.height == MAX_REORG_DEPTH + 1


# entry point that walks the three reorganization scenarios end to end
def main():
    rule("Bonus Five Fork Convergence Polish")
    print("Three Scenarios. Atomic Reorg With Mempool Restore And Depth Cap.\n")
    scenario_multi_tx_restore()
    print()
    scenario_depth_cap()
    print()
    scenario_at_cap_edge()
    print()
    rule("Bonus Five Demo Passed")


if __name__ == "__main__":
    main()

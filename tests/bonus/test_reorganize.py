from ipv8.keyvault.crypto import default_eccrypto

from bonus.reorganize import (
    reorganize,
    reorg_depth,
    MAX_REORG_DEPTH,
    find_common_ancestor_height,
)
from labs.three.chain import (
    Tx,
    Block,
    Chain,
    GENESIS,
    Mempool,
    mine_block,
    GENESIS_HASH,
    compute_tx_hash,
    compute_txs_hash,
)

NOW = 1_700_000_000


# builds a tx signed by a fresh keypair plus an archive entry mapping tx_hash to Tx
def _make_tx(data: bytes, ts: int) -> tuple[Tx, bytes]:
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    tx = Tx(sender, data, ts, sig)
    return tx, compute_tx_hash(sender, data, ts, sig)


# mines and returns a chain of empty blocks of the requested length starting from genesis
def _mine_chain(length: int, base_timestamp: int = NOW + 100) -> list[Block]:
    chain = Chain()
    blocks = [GENESIS]
    prev = GENESIS_HASH
    empty_txs = compute_txs_hash(())
    for i in range(length):
        ts = base_timestamp + i
        nonce, h = mine_block(prev, empty_txs, 8, ts)
        block = Block(prev, empty_txs, ts, 8, nonce, ())
        chain.append(block)
        blocks.append(block)
        prev = h
    return blocks


# identical chains agree at every height so the ancestor is the last block
def test_find_common_ancestor_identical_chains():
    chain = Chain()
    blocks = _mine_chain(3)
    for b in blocks[1:]:
        chain.append(b)
    assert find_common_ancestor_height(chain, blocks) == 3


# divergent chains share only genesis when the very first non genesis block differs
def test_find_common_ancestor_only_genesis():
    chain = Chain()
    one = _mine_chain(3, base_timestamp=NOW + 100)
    other = _mine_chain(3, base_timestamp=NOW + 500)
    for b in one[1:]:
        chain.append(b)
    assert find_common_ancestor_height(chain, other) == 0


# depth equals the number of blocks the current chain would have to discard
def test_reorg_depth_counts_discarded_blocks():
    chain = Chain()
    main_blocks = _mine_chain(5, base_timestamp=NOW + 100)
    for b in main_blocks[1:]:
        chain.append(b)
    fork = _mine_chain(6, base_timestamp=NOW + 500)
    assert reorg_depth(chain, fork) == 5


# reorganize refuses any candidate not strictly longer than the current chain
def test_reorganize_rejects_non_longer_candidate():
    chain = Chain()
    main_blocks = _mine_chain(4)
    for b in main_blocks[1:]:
        chain.append(b)
    assert not reorganize(chain, Mempool(), main_blocks, tx_archive={})


# reorganize refuses any candidate whose depth exceeds the configured cap
def test_reorganize_rejects_too_deep_candidate():
    chain = Chain()
    main_blocks = _mine_chain(5)
    for b in main_blocks[1:]:
        chain.append(b)
    fork = _mine_chain(6, base_timestamp=NOW + 500)
    assert not reorganize(chain, Mempool(), fork, tx_archive={}, max_depth=2)


# reorganize accepts a strictly longer valid candidate within the depth cap
def test_reorganize_accepts_strictly_longer_candidate():
    chain = Chain()
    main_blocks = _mine_chain(3)
    for b in main_blocks[1:]:
        chain.append(b)
    fork = _mine_chain(5, base_timestamp=NOW + 500)
    assert reorganize(chain, Mempool(), fork, tx_archive={})
    assert chain.height == 5


# txs included only on the displaced branch return to the mempool after reorg
def test_reorganize_restores_displaced_txs():
    chain = Chain()
    mempool = Mempool()
    tx, tx_hash = _make_tx(b"alpha", NOW + 1)
    tx_archive = {tx_hash: tx}

    # current chain holds the tx in block one
    prev = GENESIS_HASH
    body = (tx_hash,)
    txs_hash = compute_txs_hash(body)
    nonce, h = mine_block(prev, txs_hash, 8, NOW + 100)
    block1 = Block(prev, txs_hash, NOW + 100, 8, nonce, body)
    chain.append(block1)
    assert chain.height == 1
    assert len(mempool) == 0

    # competing fork is longer and does not include this tx
    fork = _mine_chain(2, base_timestamp=NOW + 500)
    assert reorganize(chain, mempool, fork, tx_archive)
    assert chain.height == 2
    assert tx_hash in mempool.pending


# txs that appear in the new chain are not duplicated back into the mempool
def test_reorganize_skips_txs_already_in_new_chain():
    chain = Chain()
    mempool = Mempool()
    tx, tx_hash = _make_tx(b"beta", NOW + 2)
    tx_archive = {tx_hash: tx}

    # tx lands in the current chain at block one
    body = (tx_hash,)
    txs_hash = compute_txs_hash(body)
    nonce, h = mine_block(GENESIS_HASH, txs_hash, 8, NOW + 100)
    block1 = Block(GENESIS_HASH, txs_hash, NOW + 100, 8, nonce, body)
    chain.append(block1)

    # competing fork is longer and also includes the same tx in its first block
    fork = [GENESIS]
    nonce2, h2 = mine_block(GENESIS_HASH, txs_hash, 8, NOW + 500)
    fork_block1 = Block(GENESIS_HASH, txs_hash, NOW + 500, 8, nonce2, body)
    fork.append(fork_block1)
    prev = h2
    for i in range(2):
        empty_txs = compute_txs_hash(())
        ts = NOW + 600 + i
        n, hh = mine_block(prev, empty_txs, 8, ts)
        fork.append(Block(prev, empty_txs, ts, 8, n, ()))
        prev = hh

    assert reorganize(chain, mempool, fork, tx_archive)
    assert tx_hash not in mempool.pending


# default depth cap matches the published constant so callers see the same limit
def test_max_reorg_depth_constant_matches_default():
    chain = Chain()
    main_blocks = _mine_chain(MAX_REORG_DEPTH + 2)
    for b in main_blocks[1:]:
        chain.append(b)
    fork = _mine_chain(MAX_REORG_DEPTH + 3, base_timestamp=NOW + 500)
    assert not reorganize(chain, Mempool(), fork, tx_archive={})

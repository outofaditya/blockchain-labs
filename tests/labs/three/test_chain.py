import asyncio
from os import urandom
from hashlib import sha256

import pytest
from ipv8.keyvault.crypto import default_eccrypto

from labs.three.chain import (
    Tx,
    Block,
    Chain,
    GENESIS,
    Mempool,
    mine_block,
    mining_loop,
    pack_header,
    AppendStatus,
    GENESIS_HASH,
    validate_block,
    compute_tx_hash,
    compute_txs_hash,
    compute_block_hash,
    has_leading_zero_bits,
)

NOW = 1_700_000_000
ZERO_HASH = b"\x00" * 32


# helper that mines a valid parent and child pair for shared use across tests
def _mine_pair(difficulty: int = 8):
    empty = compute_txs_hash(())
    p_nonce, p_hash = mine_block(ZERO_HASH, empty, difficulty, NOW)
    parent = Block(ZERO_HASH, empty, NOW, difficulty, p_nonce, ())
    body = (urandom(32), urandom(32))
    child_txs = compute_txs_hash(body)
    c_nonce, _ = mine_block(p_hash, child_txs, difficulty, NOW + 1)
    child = Block(p_hash, child_txs, NOW + 1, difficulty, c_nonce, body)
    return parent, child


# empty body hashes as sha256 of empty bytes not 32 zero bytes
def test_empty_body_uses_sha256_of_empty_bytes():
    assert compute_txs_hash(()) == sha256(b"").digest()


# tx hash differs when any input field changes
def test_compute_tx_hash_uniqueness():
    sender = urandom(74)
    sig = b"\x00" * 64
    h1 = compute_tx_hash(sender, b"a", NOW, sig)
    h2 = compute_tx_hash(sender, b"b", NOW, sig)
    h3 = compute_tx_hash(sender, b"a", NOW + 1, sig)
    assert len({h1, h2, h3}) == 3


# leading zero bit check honors full bytes and remainder bits
def test_has_leading_zero_bits_byte_boundary():
    assert has_leading_zero_bits(b"\x00\x00\xff", 16)
    assert not has_leading_zero_bits(b"\x00\x00\xff", 17)
    assert has_leading_zero_bits(b"\x00\x0f", 12)
    assert not has_leading_zero_bits(b"\x00\x10", 12)


# header serialization produces exactly 84 bytes per spec
def test_header_packs_to_exactly_84_bytes():
    _, child = _mine_pair()
    assert len(pack_header(child)) == 84


# honest parent and child passes the three check validator
def test_validate_block_accepts_honest_child():
    parent, child = _mine_pair()
    assert validate_block(child, parent)


# tampering prev_hash or txs_hash or nonce breaks validation
@pytest.mark.parametrize("field", ["prev_hash", "txs_hash", "nonce"])
def test_validate_block_rejects_tampered_field(field):
    parent, child = _mine_pair()
    if field == "prev_hash":
        tampered = Block(
            urandom(32),
            child.txs_hash,
            child.timestamp,
            child.difficulty,
            child.nonce,
            child.tx_hashes,
        )
    elif field == "txs_hash":
        tampered = Block(
            child.prev_hash,
            urandom(32),
            child.timestamp,
            child.difficulty,
            child.nonce,
            child.tx_hashes,
        )
    else:
        tampered = Block(
            child.prev_hash,
            child.txs_hash,
            child.timestamp,
            child.difficulty,
            child.nonce ^ 1,
            child.tx_hashes,
        )
    assert not validate_block(tampered, parent)


# invalid signature transaction is dropped before entering the pool
def test_mempool_rejects_invalid_signature():
    pool = Mempool()
    bogus = Tx(urandom(74), b"hi", NOW, b"\x00" * 64)
    assert pool.add(bogus) is None
    assert len(pool) == 0


# resubmitting the same tx silently dedups by tx_hash
def test_mempool_dedups_by_tx_hash():
    pool = Mempool()
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    data = b"hello"
    ts = NOW
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    tx = Tx(sender, data, ts, sig)
    assert pool.add(tx) is not None
    assert pool.add(tx) is None
    assert len(pool) == 1


# linear extension of four valid blocks raises height to 4
def test_chain_append_validates():
    chain = Chain()
    empty_txs = compute_txs_hash(())
    prev = GENESIS_HASH
    for ts in range(NOW + 100, NOW + 104):
        n, h = mine_block(prev, empty_txs, 8, ts)
        block = Block(prev, empty_txs, ts, 8, n, ())
        assert chain.append(block)
        prev = h
    assert chain.height == 4


# block already in the chain reports KNOWN_BLOCK
def test_try_extend_reports_known_block_on_duplicate():
    chain = Chain()
    status, _ = chain.try_extend(GENESIS)
    assert status is AppendStatus.KNOWN_BLOCK


# child of a known but non tip ancestor reports FORK_BRANCH
def test_try_extend_reports_fork_branch_for_sibling():
    chain = Chain()
    empty_txs = compute_txs_hash(())
    prev = GENESIS_HASH
    main_blocks = [GENESIS]
    for ts in range(NOW + 100, NOW + 103):
        n, h = mine_block(prev, empty_txs, 8, ts)
        blk = Block(prev, empty_txs, ts, 8, n, ())
        main_blocks.append(blk)
        assert chain.append(blk)
        prev = h

    sibling_parent = main_blocks[1]
    sibling_parent_hash = compute_block_hash(pack_header(sibling_parent))
    n, _ = mine_block(sibling_parent_hash, empty_txs, 8, NOW + 999)
    sibling = Block(sibling_parent_hash, empty_txs, NOW + 999, 8, n, ())
    status, _ = chain.try_extend(sibling)
    assert status is AppendStatus.FORK_BRANCH


# orphan block surfaces NEEDS_PARENT plus the unknown parent hash
def test_try_extend_reports_needs_parent_for_orphan():
    chain = Chain()
    empty_txs = compute_txs_hash(())
    orphan_parent_hash = urandom(32)
    n, _ = mine_block(orphan_parent_hash, empty_txs, 8, NOW + 1)
    orphan = Block(orphan_parent_hash, empty_txs, NOW + 1, 8, n, ())
    status, parent_hash = chain.try_extend(orphan)
    assert status is AppendStatus.NEEDS_PARENT
    assert parent_hash == orphan_parent_hash


# adopt_fork refuses any candidate not strictly longer than the current chain
def test_adopt_fork_rejects_shorter_or_invalid():
    chain = Chain()
    short = [GENESIS]
    assert not chain.adopt_fork(short)


# strictly longer valid chain replaces the tip and rebuilds both indexes
def test_adopt_fork_swaps_to_longer_chain():
    chain = Chain()
    empty_txs = compute_txs_hash(())
    main_blocks = [GENESIS]
    prev = GENESIS_HASH
    for ts in range(NOW + 100, NOW + 104):
        n, h = mine_block(prev, empty_txs, 8, ts)
        blk = Block(prev, empty_txs, ts, 8, n, ())
        main_blocks.append(blk)
        assert chain.append(blk)
        prev = h
    assert chain.height == 4

    fork = main_blocks[:3]
    prev = compute_block_hash(pack_header(fork[-1]))
    for ts in range(NOW + 200, NOW + 203):
        n, h = mine_block(prev, empty_txs, 8, ts)
        blk = Block(prev, empty_txs, ts, 8, n, ())
        fork.append(blk)
        prev = h

    assert chain.adopt_fork(fork)
    assert chain.height == 5
    assert chain.tip is fork[-1]
    assert chain.by_height[3] is fork[3]


# end to end integration tx enters mempool mining_loop mines it pool clears chain grows
async def test_mining_loop_clears_mempool_and_grows_chain():
    chain = Chain()
    pool = Mempool()
    stop = asyncio.Event()

    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    data = b"hello chain"
    ts = NOW + 500
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    expected = compute_tx_hash(sender, data, ts, sig)
    assert pool.add(Tx(sender, data, ts, sig))

    async def stop_after(_block):
        stop.set()

    await mining_loop(chain, pool, 8, stop_after, stop)
    assert chain.height == 1
    assert len(pool) == 0
    assert chain.tip.tx_hashes == (expected,)

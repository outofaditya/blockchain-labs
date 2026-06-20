from ipv8.keyvault.crypto import default_eccrypto

from bonus.compact import (
    SHORT_ID_BYTES,
    build_short_index,
    compact_wire_size,
    fill_missing,
    full_wire_size,
    make_compact_block,
    reconstruct,
    short_id,
)
from labs.three.chain import (
    Block,
    Mempool,
    Tx,
    compute_tx_hash,
    compute_txs_hash,
)


# builds a real signed tx alongside its precomputed tx hash for archive use
def _make_tx(data: bytes, ts: int):
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    tx = Tx(sender, data, ts, sig)
    return tx, compute_tx_hash(sender, data, ts, sig)


# builds a Block over the supplied tx hashes without doing real proof of work
def _make_block(tx_hashes: tuple[bytes, ...], nonce: int = 42) -> Block:
    return Block(
        prev_hash=b"\x00" * 32,
        txs_hash=compute_txs_hash(tx_hashes),
        timestamp=1_700_000_000,
        difficulty=8,
        nonce=nonce,
        tx_hashes=tx_hashes,
    )


# short id is exactly the configured number of bytes
def test_short_id_is_six_bytes():
    full = b"\xff" * 32
    assert len(short_id(full, salt=0)) == SHORT_ID_BYTES


# salt mixing produces different short ids for the same tx hash across blocks
def test_short_id_changes_with_salt():
    full = bytes(range(32))
    assert short_id(full, salt=1) != short_id(full, salt=2)


# salt mixing is deterministic identical inputs yield identical short ids
def test_short_id_is_deterministic():
    full = bytes(range(32))
    assert short_id(full, salt=42) == short_id(full, salt=42)


# make compact block preserves every header field intact
def test_make_compact_block_preserves_header_fields():
    block = _make_block((b"\x11" * 32, b"\x22" * 32))
    compact = make_compact_block(block)
    assert compact.prev_hash == block.prev_hash
    assert compact.txs_hash == block.txs_hash
    assert compact.timestamp == block.timestamp
    assert compact.difficulty == block.difficulty
    assert compact.nonce == block.nonce


# make compact block derives short ids using the block nonce as the salt
def test_make_compact_block_emits_short_ids_with_block_nonce_salt():
    h1, h2 = b"\x11" * 32, b"\x22" * 32
    block = _make_block((h1, h2), nonce=7)
    compact = make_compact_block(block)
    assert compact.short_ids == (short_id(h1, 7), short_id(h2, 7))


# reconstruct succeeds when the mempool has every transaction the block needs
def test_reconstruct_succeeds_with_full_mempool_overlap():
    tx1, h1 = _make_tx(b"alpha", 1)
    tx2, h2 = _make_tx(b"beta", 2)
    pool = Mempool()
    pool.add(tx1)
    pool.add(tx2)

    block = _make_block((h1, h2))
    compact = make_compact_block(block)
    rebuilt, missing = reconstruct(compact, build_short_index(pool, block.nonce))
    assert missing == []
    assert rebuilt is not None
    assert rebuilt.tx_hashes == (h1, h2)


# reconstruct reports missing slot indices when the mempool lacks transactions
def test_reconstruct_reports_missing_indices():
    tx1, h1 = _make_tx(b"alpha", 1)
    _, h2 = _make_tx(b"beta", 2)
    pool = Mempool()
    pool.add(tx1)

    block = _make_block((h1, h2))
    compact = make_compact_block(block)
    rebuilt, missing = reconstruct(compact, build_short_index(pool, block.nonce))
    assert rebuilt is None
    assert missing == [1]


# prefilled txs supplied by the sender plug holes the mempool cannot fill
def test_reconstruct_uses_prefilled_txs():
    tx1, h1 = _make_tx(b"alpha", 1)
    tx2, h2 = _make_tx(b"beta", 2)
    pool = Mempool()
    pool.add(tx1)

    block = _make_block((h1, h2))
    compact = make_compact_block(block)
    prefilled = {1: tx2}
    rebuilt, missing = reconstruct(
        compact, build_short_index(pool, block.nonce), prefilled=prefilled
    )
    assert missing == []
    assert rebuilt is not None
    assert rebuilt.tx_hashes == (h1, h2)


# reconstruct signals abandon when commitment mismatch detected on a single slot
def test_reconstruct_signals_abandon_on_commitment_mismatch_single_tx():
    tx1, h1 = _make_tx(b"alpha", 1)
    pool = Mempool()
    pool.add(tx1)

    # forge a block whose advertised txs_hash does not match the real txs in the slot
    fake_hash = b"\xff" * 32
    block = Block(
        prev_hash=b"\x00" * 32,
        txs_hash=fake_hash,
        timestamp=1,
        difficulty=8,
        nonce=1,
        tx_hashes=(h1,),
    )
    compact = make_compact_block(block)
    rebuilt, missing = reconstruct(compact, build_short_index(pool, block.nonce))
    assert rebuilt is None
    assert missing is None


# reconstruct signals abandon even when block carries multiple slots
def test_reconstruct_signals_abandon_on_commitment_mismatch_multi_tx():
    tx1, h1 = _make_tx(b"alpha", 1)
    tx2, h2 = _make_tx(b"beta", 2)
    pool = Mempool()
    pool.add(tx1)
    pool.add(tx2)

    # forge a block whose advertised txs_hash does not match the real body
    fake_hash = b"\xff" * 32
    block = Block(
        prev_hash=b"\x00" * 32,
        txs_hash=fake_hash,
        timestamp=1,
        difficulty=8,
        nonce=1,
        tx_hashes=(h1, h2),
    )
    compact = make_compact_block(block)
    rebuilt, missing = reconstruct(compact, build_short_index(pool, block.nonce))
    assert rebuilt is None
    assert missing is None


# fill missing pulls the requested indices from the sender tx archive
def test_fill_missing_returns_requested_indices():
    tx1, h1 = _make_tx(b"alpha", 1)
    tx2, h2 = _make_tx(b"beta", 2)
    archive = {h1: tx1, h2: tx2}
    block = _make_block((h1, h2))
    fills = fill_missing(block, [1], archive)
    assert set(fills.keys()) == {1}
    assert fills[1] is tx2


# fill missing silently skips indices that fall outside the block range
def test_fill_missing_ignores_out_of_range_indices():
    tx1, h1 = _make_tx(b"alpha", 1)
    archive = {h1: tx1}
    block = _make_block((h1,))
    fills = fill_missing(block, [-1, 5, 99], archive)
    assert fills == {}


# build short index groups collisions under the same short id without dropping txs
def test_build_short_index_groups_candidates():
    tx1, _ = _make_tx(b"alpha", 1)
    tx2, _ = _make_tx(b"beta", 2)
    pool = Mempool()
    pool.add(tx1)
    pool.add(tx2)
    index = build_short_index(pool, block_nonce=0)
    # every short id maps to a list at least one element long
    assert all(isinstance(v, list) and len(v) >= 1 for v in index.values())


# compact wire size is strictly smaller than the full wire size for any non empty block
def test_compact_wire_size_is_smaller():
    block = _make_block(tuple(bytes([i]) * 32 for i in range(1, 6)))
    compact = make_compact_block(block)
    assert compact_wire_size(compact) < full_wire_size(block)


# fully empty block wire sizes match because there are no tx bytes either way
def test_wire_sizes_equal_for_empty_block():
    block = _make_block(())
    compact = make_compact_block(block)
    assert compact_wire_size(compact) == full_wire_size(block)

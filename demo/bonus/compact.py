import time

from ipv8.keyvault.crypto import default_eccrypto

from bonus.compact import (
    build_short_index,
    compact_wire_size,
    fill_missing,
    full_wire_size,
    make_compact_block,
    reconstruct,
)
from labs.three.chain import (
    Block,
    Mempool,
    Tx,
    compute_tx_hash,
    compute_txs_hash,
)
from common.banner import rule, rows, divider, section

# how many transactions the demo block carries
_TX_COUNT = 12
PAUSE = 0.4


# builds a real signed tx and returns it alongside its precomputed tx hash
def _make_tx(idx: int):
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    data = f"payment-{idx}".encode()
    ts = 1_700_000_000 + idx
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    tx = Tx(sender, data, ts, sig)
    return tx, compute_tx_hash(sender, data, ts, sig)


# assembles a synthetic block carrying the supplied transactions
def _build_block(tx_hashes: tuple[bytes, ...], nonce: int = 99) -> Block:
    return Block(
        prev_hash=b"\x00" * 32,
        txs_hash=compute_txs_hash(tx_hashes),
        timestamp=1_700_000_000,
        difficulty=8,
        nonce=nonce,
        tx_hashes=tx_hashes,
    )


# scenario one shows full mempool overlap reconstructing the block in one exchange
def scenario_full_overlap(txs: list[Tx], hashes: list[bytes]):
    section("Scenario A Full Mempool Overlap")
    block = _build_block(tuple(hashes))
    compact = make_compact_block(block)

    print(f"[Sender] Block Has {len(hashes)} Transactions")
    full = full_wire_size(block)
    short = compact_wire_size(compact)
    saved = full - short
    rows(
        [
            ("Full Wire Size", f"{full} bytes"),
            ("Compact Wire Size", f"{short} bytes"),
            ("Bytes Saved", f"{saved} bytes"),
            ("Reduction", f"{100 * saved // full}%"),
        ]
    )
    time.sleep(PAUSE)

    # peer holds every tx in its mempool already
    peer_pool = Mempool()
    for tx in txs:
        peer_pool.add(tx)
    short_index = build_short_index(peer_pool, block.nonce)
    print(f"[Receiver] Mempool Carries {len(peer_pool)} Transactions")
    time.sleep(PAUSE)

    rebuilt, missing = reconstruct(compact, short_index)
    print(f"[Receiver] Reconstruction Missing Indices = {missing}")
    print(f"[Receiver] Block Reconstructed = {rebuilt is not None}")
    print(f"[Receiver] Body Hash Matches = {rebuilt.txs_hash == block.txs_hash}")
    assert rebuilt is not None and missing == []


# scenario two shows partial overlap requiring a fill round trip to complete
def scenario_partial_overlap(txs: list[Tx], hashes: list[bytes]):
    section("Scenario B Partial Mempool Overlap")
    block = _build_block(tuple(hashes))
    compact = make_compact_block(block)
    sender_archive = {hashes[i]: txs[i] for i in range(len(txs))}

    # peer mempool intentionally missing the last three transactions
    peer_pool = Mempool()
    for tx in txs[:-3]:
        peer_pool.add(tx)
    print(f"[Receiver] Mempool Carries {len(peer_pool)} Of {len(txs)} Transactions")
    time.sleep(PAUSE)

    rebuilt, missing = reconstruct(compact, build_short_index(peer_pool, block.nonce))
    print(f"[Receiver] First Pass Missing = {missing}")
    assert rebuilt is None and missing
    time.sleep(PAUSE)

    # sender fills the missing slots from its archive of mined txs
    fills = fill_missing(block, missing, sender_archive)
    print(f"[Sender]   Fills Returned For Indices = {sorted(fills.keys())}")
    time.sleep(PAUSE)

    rebuilt, missing = reconstruct(
        compact, build_short_index(peer_pool, block.nonce), prefilled=fills
    )
    print(f"[Receiver] Second Pass Missing = {missing}")
    print(f"[Receiver] Block Reconstructed = {rebuilt is not None}")
    assert rebuilt is not None and missing == []


# entry point that walks the two compact block scenarios end to end
def main():
    rule("Bonus Two Compact Block Propagation")
    print(f"Block Carries {_TX_COUNT} Real Signed Transactions")
    print("Wire Sizes Estimated As Header Plus Identifier Bytes")
    print()

    pairs = [_make_tx(i) for i in range(_TX_COUNT)]
    txs = [t for t, _ in pairs]
    hashes = [h for _, h in pairs]

    scenario_full_overlap(txs, hashes)
    print()
    scenario_partial_overlap(txs, hashes)
    print()
    divider()
    rule("Bonus Two Demo Passed")


if __name__ == "__main__":
    main()

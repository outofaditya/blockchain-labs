import time

from ipv8.keyvault.crypto import default_eccrypto

from bonus.compact import (
    reconstruct,
    fill_missing,
    SHORT_ID_BYTES,
    full_wire_size,
    build_short_index,
    compact_wire_size,
    make_compact_block,
)
from labs.three.chain import (
    Tx,
    Block,
    Mempool,
    compute_tx_hash,
    compute_txs_hash,
)
from common.banner import rule, rows, divider, section

# scale parameters that drive how observable each scenario is
TX_COUNT = 100
PARTIAL_GAP = 15
PAUSE = 0.4


# builds a real signed tx and returns it alongside its precomputed tx hash
def make_tx(idx: int):
    key = default_eccrypto.generate_key("curve25519")
    sender = key.pub().key_to_bin()
    data = f"payment-{idx}-amount-{idx * 7}".encode()
    ts = 1_700_000_000 + idx
    sig = default_eccrypto.create_signature(key, sender + data + ts.to_bytes(8, "big"))
    tx = Tx(sender, data, ts, sig)
    return tx, compute_tx_hash(sender, data, ts, sig)


# assembles a synthetic block carrying the supplied transactions
def build_block(tx_hashes: tuple[bytes, ...], nonce: int = 99) -> Block:
    return Block(
        prev_hash=b"\x00" * 32,
        txs_hash=compute_txs_hash(tx_hashes),
        timestamp=1_700_000_000,
        difficulty=8,
        nonce=nonce,
        tx_hashes=tx_hashes,
    )


# prints a bandwidth comparison table for the block and its compact form
def print_wire_breakdown(block, compact):
    full = full_wire_size(block)
    short = compact_wire_size(compact)
    saved = full - short
    rows(
        [
            ("Tx Count", len(block.tx_hashes)),
            ("Full Block Bytes", full),
            ("Compact Block Bytes", short),
            ("Bytes Saved", saved),
            ("Reduction", f"{100 * saved // full}%"),
            ("Short Id Bytes", SHORT_ID_BYTES),
        ]
    )


# scenario one shows full mempool overlap reconstructing the block in one exchange
def scenario_full_overlap(txs, hashes):
    section("Scenario A Full Mempool Overlap")
    block = build_block(tuple(hashes))
    compact = make_compact_block(block)
    print(f"[Sender] Mined Block With {len(hashes)} Real Signed Transactions")
    print_wire_breakdown(block, compact)
    time.sleep(PAUSE)

    peer_pool = Mempool()
    for tx in txs:
        peer_pool.add(tx)
    short_index = build_short_index(peer_pool, block.nonce)
    print(
        f"[Receiver] Mempool Holds {len(peer_pool)} Of {len(txs)} Required Transactions"
    )
    time.sleep(PAUSE)

    rebuilt, missing = reconstruct(compact, short_index)
    print(f"[Receiver] Reconstruction Pass One Missing = {missing}")
    print(f"[Receiver] Block Reconstructed = {rebuilt is not None}")
    print(f"[Receiver] Commitment Verified = {rebuilt.txs_hash == block.txs_hash}")
    assert rebuilt is not None and missing == []


# scenario two shows partial overlap requiring a fill round trip to complete
def scenario_partial_overlap(txs, hashes):
    section("Scenario B Partial Mempool Overlap Requires Fill Round")
    block = build_block(tuple(hashes))
    compact = make_compact_block(block)
    sender_archive = {hashes[i]: txs[i] for i in range(len(txs))}
    print_wire_breakdown(block, compact)
    time.sleep(PAUSE)

    # peer mempool intentionally missing every fifteenth transaction
    peer_pool = Mempool()
    missing_real = set()
    for i, tx in enumerate(txs):
        if i % PARTIAL_GAP == 0:
            missing_real.add(i)
            continue
        peer_pool.add(tx)
    print(
        f"[Receiver] Mempool Holds {len(peer_pool)} Of {len(txs)} "
        f"({len(missing_real)} Missing By Design)"
    )
    time.sleep(PAUSE)

    rebuilt, missing = reconstruct(compact, build_short_index(peer_pool, block.nonce))
    print(f"[Receiver] Pass One Missing Count = {len(missing)} Indices")
    print(f"[Receiver] Sample Missing Indices = {missing[:5]}")
    assert rebuilt is None and missing
    time.sleep(PAUSE)

    fills = fill_missing(block, missing, sender_archive)
    print(f"[Sender]   Fills Returned For {len(fills)} Indices")
    print(f"[Sender]   Fill Bytes Approx = {sum(96 for _ in fills.values())}")
    time.sleep(PAUSE)

    rebuilt, missing = reconstruct(
        compact, build_short_index(peer_pool, block.nonce), prefilled=fills
    )
    print(f"[Receiver] Pass Two Missing Count = {len(missing) if missing else 0}")
    print(f"[Receiver] Block Reconstructed = {rebuilt is not None}")
    assert rebuilt is not None and missing == []


# scenario three shows the abandon signal firing on a forged commitment
def scenario_abandon_on_mismatch(txs, hashes):
    section("Scenario C Forged Commitment Triggers Abandon Signal")
    # forge a block whose advertised txs_hash does not match its body
    forged_hash = b"\xff" * 32
    block = Block(
        prev_hash=b"\x00" * 32,
        txs_hash=forged_hash,
        timestamp=1_700_000_000,
        difficulty=8,
        nonce=99,
        tx_hashes=tuple(hashes),
    )
    compact = make_compact_block(block)
    print("[Sender] Block Carries Real Tx Hashes But Forged Body Commitment")
    print(
        f"[Sender] Real Body Hash    = {compute_txs_hash(tuple(hashes))[:8].hex()}..."
    )
    print(f"[Sender] Forged Commitment = {forged_hash[:8].hex()}...")
    time.sleep(PAUSE)

    peer_pool = Mempool()
    for tx in txs:
        peer_pool.add(tx)

    rebuilt, missing = reconstruct(compact, build_short_index(peer_pool, block.nonce))
    print(f"[Receiver] Rebuilt = {rebuilt}")
    print(f"[Receiver] Missing Sentinel = {missing}")
    print("[Receiver] Action = Abandon Compact Path Fetch Full Block")
    assert rebuilt is None and missing is None


# entry point that walks the three compact block scenarios end to end
def main():
    rule("Bonus Two Compact Block Propagation")
    print(f"Block Carries {TX_COUNT} Real Signed Transactions Per Scenario")
    print(f"Short Id Width Is {SHORT_ID_BYTES} Bytes Per Transaction")
    print()

    pairs = [make_tx(i) for i in range(TX_COUNT)]
    txs = [t for t, _ in pairs]
    hashes = [h for _, h in pairs]

    scenario_full_overlap(txs, hashes)
    print()
    scenario_partial_overlap(txs, hashes)
    print()
    scenario_abandon_on_mismatch(txs, hashes)
    print()
    divider()
    rule("Bonus Two Demo Passed")


if __name__ == "__main__":
    main()

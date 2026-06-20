from dataclasses import dataclass

from labs.three.chain import (
    Tx,
    Block,
    Mempool,
    compute_tx_hash,
    compute_txs_hash,
)

# how many bytes from each tx hash form the on wire short id
SHORT_ID_BYTES = 6


# six byte prefix of the tx hash used as the on wire identifier
def short_id(tx_hash: bytes) -> bytes:
    return tx_hash[:SHORT_ID_BYTES]


# wire form of a freshly mined block carrying only header plus short ids
@dataclass(frozen=True)
class CompactBlock:
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    short_ids: tuple[bytes, ...]


# packages a freshly mined block into its compact wire form
def make_compact_block(block: Block) -> CompactBlock:
    return CompactBlock(
        prev_hash=block.prev_hash,
        txs_hash=block.txs_hash,
        timestamp=block.timestamp,
        difficulty=block.difficulty,
        nonce=block.nonce,
        short_ids=tuple(short_id(h) for h in block.tx_hashes),
    )


# builds the short id to Tx lookup table the receiver uses for reconstruction
def build_short_index(mempool: Mempool) -> dict[bytes, Tx]:
    return {short_id(h): tx for h, tx in mempool.pending.items()}


# attempts to reconstruct the full block from the compact form using local mempool
def reconstruct(
    compact: CompactBlock,
    short_index: dict[bytes, Tx],
    prefilled: dict[int, Tx] | None = None,
) -> tuple[Block | None, list[int]]:
    prefilled = prefilled or {}
    resolved: list[Tx | None] = [None] * len(compact.short_ids)

    # apply any prefills supplied by the sender or a previous fill round
    for idx, tx in prefilled.items():
        resolved[idx] = tx

    # try to resolve every remaining slot from the receiver mempool by short id
    for idx, sid in enumerate(compact.short_ids):
        if resolved[idx] is not None:
            continue
        tx = short_index.get(sid)
        if tx is not None:
            resolved[idx] = tx

    # surface the still missing slot indices so a fill request can target them
    missing = [i for i, t in enumerate(resolved) if t is None]
    if missing:
        return None, missing

    # all slots resolved compute the full tx hashes and verify the body commitment
    full_hashes = tuple(
        compute_tx_hash(t.sender_key, t.data, t.timestamp, t.signature)
        for t in resolved
    )
    if compute_txs_hash(full_hashes) != compact.txs_hash:
        # short id collision left an incorrect resolution surface the failure to the caller
        return None, list(range(len(compact.short_ids)))

    # commitment matches build the full block from the resolved transactions
    block = Block(
        prev_hash=compact.prev_hash,
        txs_hash=compact.txs_hash,
        timestamp=compact.timestamp,
        difficulty=compact.difficulty,
        nonce=compact.nonce,
        tx_hashes=full_hashes,
    )
    return block, []


# sender side helper that returns Tx data for the requested missing indices
def fill_missing(
    block: Block,
    missing_indices: list[int],
    tx_archive: dict[bytes, Tx],
) -> dict[int, Tx]:
    fills: dict[int, Tx] = {}
    for idx in missing_indices:
        tx_hash = block.tx_hashes[idx]
        tx = tx_archive.get(tx_hash)
        if tx is not None:
            fills[idx] = tx
    return fills


# approximate wire size of a compact block in bytes for bandwidth comparisons
def compact_wire_size(compact: CompactBlock) -> int:
    # 32 prev_hash plus 32 txs_hash plus 8 timestamp plus 4 difficulty plus 8 nonce
    header = 32 + 32 + 8 + 4 + 8
    return header + SHORT_ID_BYTES * len(compact.short_ids)


# approximate wire size of a full block with concatenated tx hashes for comparison
def full_wire_size(block: Block) -> int:
    header = 32 + 32 + 8 + 4 + 8
    return header + 32 * len(block.tx_hashes)

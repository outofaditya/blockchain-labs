from labs.three.chain import (
    Tx,
    Block,
    Chain,
    Mempool,
    pack_header,
    compute_block_hash,
)

# refuses any reorganization that would discard more than this many blocks
MAX_REORG_DEPTH = 20


# locates the highest block height where the current chain and the candidate still agree
def find_common_ancestor_height(chain: Chain, candidate: list[Block]) -> int:
    common = 0
    upper = min(len(candidate), len(chain.blocks))
    for h in range(upper):
        candidate_hash = compute_block_hash(pack_header(candidate[h]))
        chain_hash = compute_block_hash(pack_header(chain.blocks[h]))
        if candidate_hash == chain_hash:
            common = h
        else:
            break
    return common


# returns the depth of a candidate reorg measured in blocks discarded from the current chain
# callers should treat the return as meaningful only when the candidate is strictly longer
# than the current chain otherwise the value reflects mere divergence not an actual reorg
def reorg_depth(chain: Chain, candidate: list[Block]) -> int:
    ancestor = find_common_ancestor_height(chain, candidate)
    return chain.height - ancestor


# atomically swaps the chain to the candidate while restoring displaced transactions
def reorganize(
    chain: Chain,
    mempool: Mempool,
    candidate: list[Block],
    tx_archive: dict[bytes, Tx],
    max_depth: int = MAX_REORG_DEPTH,
) -> bool:
    # short circuit when the candidate cannot improve on the current chain
    if len(candidate) <= len(chain.blocks):
        return False

    # refuse very deep reorgs to defend against long range fakery
    depth = reorg_depth(chain, candidate)
    if depth > max_depth:
        return False

    # snapshot the tx hashes that would be discarded before any state change
    ancestor = find_common_ancestor_height(chain, candidate)
    displaced_tx_hashes = []
    for block in chain.blocks[ancestor + 1 :]:
        displaced_tx_hashes.extend(block.tx_hashes)

    # apply the atomic swap through the chain primitive that validates every block
    if not chain.adopt_fork(candidate):
        return False

    # restore displaced txs that did not land in any block of the new chain
    # callers must populate tx_archive with verified Txs only since Mempool.add silently
    # discards anything that fails verification leaving the mempool partially restored
    new_tx_hashes = set()
    for block in candidate:
        new_tx_hashes.update(block.tx_hashes)
    for tx_hash in displaced_tx_hashes:
        if tx_hash in new_tx_hashes:
            continue
        tx = tx_archive.get(tx_hash)
        if tx is not None:
            mempool.add(tx)

    return True

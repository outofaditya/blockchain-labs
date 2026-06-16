import os
import time
import asyncio
from struct import Struct
from enum import Enum, auto
from hashlib import sha256
from dataclasses import dataclass
from multiprocessing import Event, Queue, Process

from ipv8.keyvault.crypto import default_eccrypto

# precompiled structs and cached empty body hash used everywhere in this module
_U64_STRUCT = Struct(">Q")
_PREFIX_STRUCT = Struct(">32s32sQI")
_HEADER_STRUCT = Struct(">32s32sQIQ")
_EMPTY_TXS_HASH = sha256(b"").digest()


# signed transaction frozen so its signature and tx_hash stay stable
@dataclass(frozen=True)
class Tx:
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes


# immutable header fields plus body tx hashes so the chain stays tamper evident
@dataclass(frozen=True)
class Block:
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    tx_hashes: tuple[bytes, ...]


GENESIS = Block(b"\x00" * 32, _EMPTY_TXS_HASH, 0, 0, 0, ())


# produces the exact 84 byte header that the server hashes and walks the chain on
def pack_header(block: Block) -> bytes:
    return _HEADER_STRUCT.pack(
        block.prev_hash,
        block.txs_hash,
        block.timestamp,
        block.difficulty,
        block.nonce,
    )


# single sha256 over the header serves as both identity and pow target
def compute_block_hash(header_bytes: bytes) -> bytes:
    return sha256(header_bytes).digest()


# three independent checks any failure means the block is rejected
def validate_block(block: Block, parent: Block) -> bool:
    return (
        block.prev_hash == compute_block_hash(pack_header(parent))
        and block.txs_hash == compute_txs_hash(block.tx_hashes)
        and has_leading_zero_bits(
            compute_block_hash(pack_header(block)), block.difficulty
        )
    )


# flat hash over all tx hashes with empty body using sha256 of empty bytes
def compute_txs_hash(tx_hashes: tuple[bytes, ...]) -> bytes:
    if not tx_hashes:
        return _EMPTY_TXS_HASH
    return sha256(b"".join(tx_hashes)).digest()


# byte by byte zero check skips the slower bit by bit loop
def has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    full, rem = divmod(bits, 8)
    return not any(digest[:full]) and (not rem or digest[full] < (1 << (8 - rem)))


# unique fingerprint covering all four transaction fields including signature
def compute_tx_hash(
    sender_key: bytes, data: bytes, timestamp: int, signature: bytes
) -> bytes:
    return sha256(sender_key + data + _U64_STRUCT.pack(timestamp) + signature).digest()


# prefix cached search since only the nonce bytes change per iteration
def mine_block(
    prev_hash: bytes, txs_hash: bytes, difficulty: int, timestamp: int
) -> tuple[int, bytes]:
    # seed the hash with the static header prefix so the inner loop only mixes the nonce
    base = sha256(_PREFIX_STRUCT.pack(prev_hash, txs_hash, timestamp, difficulty))
    nonce = 0
    while True:
        # clone the cached state and append the candidate nonce
        h = base.copy()
        h.update(_U64_STRUCT.pack(nonce))
        digest = h.digest()
        # short circuit once the digest satisfies the difficulty target
        if has_leading_zero_bits(digest, difficulty):
            return nonce, digest
        nonce += 1


# strided nonce search in a subprocess so multiple cores can race without overlap
def _chain_worker(
    prefix: bytes,
    difficulty: int,
    worker_id: int,
    num_workers: int,
    result_queue,
    stop_event,
) -> None:
    # seed sha256 with the static prefix the parent already serialized
    base = sha256(prefix)
    # each worker starts at its index so strides never overlap
    nonce = worker_id
    while True:
        # clone the cached state and mix in the worker specific nonce
        h = base.copy()
        h.update(_U64_STRUCT.pack(nonce))
        digest = h.digest()
        # winning digest pushes the nonce up and signals every sibling worker
        if has_leading_zero_bits(digest, difficulty):
            result_queue.put((nonce, digest))
            stop_event.set()
            return
        nonce += num_workers
        # cheap probe every 16384 attempts so siblings exit shortly after a winner
        if nonce & 0x3FFF == 0 and stop_event.is_set():
            return


# spawns one worker per core and returns the first valid nonce racing across all workers
def mine_block_parallel(
    prev_hash: bytes, txs_hash: bytes, difficulty: int, timestamp: int
) -> tuple[int, bytes]:
    # build a shared prefix once so each worker can reuse the same bytes
    num_workers = os.cpu_count() or 1
    prefix = _PREFIX_STRUCT.pack(prev_hash, txs_hash, timestamp, difficulty)
    # shared queue plus stop event coordinate winner detection
    result_queue, stop_event = Queue(), Event()
    workers = [
        Process(
            target=_chain_worker,
            args=(prefix, difficulty, i, num_workers, result_queue, stop_event),
        )
        for i in range(num_workers)
    ]
    # start every worker before blocking on the queue
    for w in workers:
        w.start()
    nonce, digest = result_queue.get()
    # terminate and join every sibling worker before returning
    for w in workers:
        w.terminate()
    for w in workers:
        w.join()
    return nonce, digest


GENESIS_HASH = compute_block_hash(pack_header(GENESIS))


# enumerates the five outcomes the gossip handler must branch on
class AppendStatus(Enum):
    INVALID = auto()
    EXTENDS_TIP = auto()
    KNOWN_BLOCK = auto()
    NEEDS_PARENT = auto()
    FORK_BRANCH = auto()


# in memory ledger with two derived indexes for fast lookups by hash and height
class Chain:
    # starts with just the genesis block and both indexes prepopulated
    def __init__(self) -> None:
        self.blocks: list[Block] = [GENESIS]
        self.by_hash: dict[bytes, Block] = {GENESIS_HASH: GENESIS}
        self.by_height: dict[int, Block] = {0: GENESIS}
        self.tip_hash: bytes = GENESIS_HASH

    # returns the latest block in constant time
    @property
    def tip(self) -> Block:
        return self.blocks[-1]

    # blocks list length minus one because genesis sits at height zero
    @property
    def height(self) -> int:
        return len(self.blocks) - 1

    # strict extend used when we mine a fresh block locally
    def append(self, block: Block) -> bool:
        if not validate_block(block, self.tip):
            return False
        self._apply(block, compute_block_hash(pack_header(block)))
        return True

    # atomically swaps to a longer valid chain rebuilding both indexes
    def adopt_fork(self, blocks: list[Block]) -> bool:
        # refuse any candidate that is not strictly longer or does not start at genesis
        if len(blocks) <= len(self.blocks) or blocks[0] != GENESIS:
            return False
        # build fresh indexes off to the side without touching live state
        new_by_hash = {GENESIS_HASH: GENESIS}
        new_by_height = {0: GENESIS}
        new_tip_hash = GENESIS_HASH
        # validate every successive block against its parent before recording it
        for height in range(1, len(blocks)):
            block = blocks[height]
            if not validate_block(block, blocks[height - 1]):
                return False
            new_tip_hash = compute_block_hash(pack_header(block))
            new_by_hash[new_tip_hash] = block
            new_by_height[height] = block
        # swap the live state to the fresh indexes in one step
        self.blocks = list(blocks)
        self.by_hash = new_by_hash
        self.by_height = new_by_height
        self.tip_hash = new_tip_hash
        return True

    # shared mutation that updates blocks indexes and tip hash together
    def _apply(self, block: Block, block_hash: bytes) -> None:
        self.blocks.append(block)
        self.by_hash[block_hash] = block
        self.by_height[len(self.blocks) - 1] = block
        self.tip_hash = block_hash

    # categorizes incoming gossip blocks into five distinct outcomes
    def try_extend(self, block: Block) -> tuple[AppendStatus, bytes | None]:
        # report duplicates first so we never reapply an existing block
        block_hash = compute_block_hash(pack_header(block))
        if block_hash in self.by_hash:
            return AppendStatus.KNOWN_BLOCK, None
        # block that links to the current tip either extends or is rejected
        if block.prev_hash == self.tip_hash:
            if not validate_block(block, self.tip):
                return AppendStatus.INVALID, None
            self._apply(block, block_hash)
            return AppendStatus.EXTENDS_TIP, None
        # block linked to a non tip ancestor enters the side pool as a fork branch
        parent = self.by_hash.get(block.prev_hash)
        if parent is not None:
            if not validate_block(block, parent):
                return AppendStatus.INVALID, None
            return AppendStatus.FORK_BRANCH, None
        # otherwise the block is an orphan waiting for its parent to land
        return AppendStatus.NEEDS_PARENT, block.prev_hash


# verifies the ed25519 signature over sender_key data and timestamp at the mempool boundary
def verify_tx(tx: Tx) -> bool:
    try:
        pubkey = default_eccrypto.key_from_public_bin(tx.sender_key)
        msg = tx.sender_key + tx.data + _U64_STRUCT.pack(tx.timestamp)
        return bool(default_eccrypto.is_valid_signature(pubkey, msg, tx.signature))
    except Exception:
        return False


# per node buffer of unconfirmed transactions deduped by tx_hash
class Mempool:
    # starts empty waiting for incoming transactions
    def __init__(self) -> None:
        self.pending: dict[bytes, Tx] = {}

    # convenience for empty checks and progress logging
    def __len__(self) -> int:
        return len(self.pending)

    # gates on signature then dedups returning the tx_hash so callers can reuse it
    def add(self, tx: Tx) -> bytes | None:
        # reject any transaction that does not pass signature verification
        if not verify_tx(tx):
            return None
        # drop duplicates so a resubmission is silently absorbed
        h = compute_tx_hash(tx.sender_key, tx.data, tx.timestamp, tx.signature)
        if h in self.pending:
            return None
        self.pending[h] = tx
        return h

    # drops included txs once a block has successfully landed
    def remove(self, tx_hashes: list[bytes]) -> None:
        for h in tx_hashes:
            self.pending.pop(h, None)

    # returns oldest first using dict insertion order without removing
    def take(self, max_count: int) -> list[tuple[bytes, Tx]]:
        return list(self.pending.items())[:max_count]


# snapshots up to max_txs from the mempool and precomputes the body commitment for mining
def assemble_candidate(
    mempool: Mempool, max_txs: int = 1000
) -> tuple[bytes, tuple[bytes, ...]]:
    tx_hashes = tuple(h for h, _ in mempool.take(max_txs))
    return compute_txs_hash(tx_hashes), tx_hashes


# continuously mines blocks against the current tip
async def mining_loop(
    chain: Chain,
    mempool: Mempool,
    difficulty: int,
    broadcast=None,
    stop_event: asyncio.Event | None = None,
) -> None:
    loop = asyncio.get_event_loop()
    while stop_event is None or not stop_event.is_set():
        # snapshot the candidate inputs from the current chain tip and mempool
        prev_hash = chain.tip_hash
        txs_hash, tx_hashes = assemble_candidate(mempool)
        timestamp = int(time.time())
        # off load the parallel mining search to the default executor
        nonce, _ = await loop.run_in_executor(
            None, mine_block_parallel, prev_hash, txs_hash, difficulty, timestamp
        )
        # apply the freshly mined block then clear its txs from the mempool
        block = Block(prev_hash, txs_hash, timestamp, difficulty, nonce, tx_hashes)
        if chain.append(block):
            mempool.remove(list(tx_hashes))
            # fire the broadcast hook so the owning community can ship the block
            if broadcast is not None:
                await broadcast(block)

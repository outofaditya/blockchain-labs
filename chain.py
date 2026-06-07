from struct import Struct
from enum import Enum, auto
from hashlib import sha256
from dataclasses import dataclass

_U64_STRUCT = Struct(">Q")
_PREFIX_STRUCT = Struct(">32s32sQI")
_HEADER_STRUCT = Struct(">32s32sQIQ")
_EMPTY_TXS_HASH = sha256(b"").digest()


@dataclass(frozen=True)
class Block:
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    tx_hashes: tuple[bytes, ...]


GENESIS = Block(b"\x00" * 32, _EMPTY_TXS_HASH, 0, 0, 0, ())


def pack_header(block: Block) -> bytes:
    return _HEADER_STRUCT.pack(
        block.prev_hash,
        block.txs_hash,
        block.timestamp,
        block.difficulty,
        block.nonce,
    )


def compute_block_hash(header_bytes: bytes) -> bytes:
    return sha256(header_bytes).digest()


def validate_block(block: Block, parent: Block) -> bool:
    return (
        block.prev_hash == compute_block_hash(pack_header(parent))
        and block.txs_hash == compute_txs_hash(block.tx_hashes)
        and has_leading_zero_bits(
            compute_block_hash(pack_header(block)), block.difficulty
        )
    )


def compute_txs_hash(tx_hashes: tuple[bytes, ...]) -> bytes:
    if not tx_hashes:
        return _EMPTY_TXS_HASH
    return sha256(b"".join(tx_hashes)).digest()


def has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    full, rem = divmod(bits, 8)
    return not any(digest[:full]) and (not rem or digest[full] < (1 << (8 - rem)))


def compute_tx_hash(
    sender_key: bytes, data: bytes, timestamp: int, signature: bytes
) -> bytes:
    return sha256(sender_key + data + _U64_STRUCT.pack(timestamp) + signature).digest()


def mine_block(
    prev_hash: bytes, txs_hash: bytes, difficulty: int, timestamp: int
) -> tuple[int, bytes]:
    base = sha256(_PREFIX_STRUCT.pack(prev_hash, txs_hash, timestamp, difficulty))
    nonce = 0
    while True:
        h = base.copy()
        h.update(_U64_STRUCT.pack(nonce))
        digest = h.digest()
        if has_leading_zero_bits(digest, difficulty):
            return nonce, digest
        nonce += 1


GENESIS_HASH = compute_block_hash(pack_header(GENESIS))


class AppendStatus(Enum):
    INVALID = auto()
    EXTENDS_TIP = auto()
    KNOWN_BLOCK = auto()
    NEEDS_PARENT = auto()


class Chain:
    def __init__(self) -> None:
        self.blocks: list[Block] = [GENESIS]
        self.by_hash: dict[bytes, Block] = {GENESIS_HASH: GENESIS}
        self.by_height: dict[int, Block] = {0: GENESIS}
        self.tip_hash: bytes = GENESIS_HASH

    @property
    def tip(self) -> Block:
        return self.blocks[-1]

    @property
    def height(self) -> int:
        return len(self.blocks) - 1

    def append(self, block: Block) -> bool:
        if not validate_block(block, self.tip):
            return False
        self._apply(block, compute_block_hash(pack_header(block)))
        return True

    def adopt_fork(self, blocks: list[Block]) -> bool:
        if len(blocks) <= len(self.blocks) or blocks[0] != GENESIS:
            return False
        new_by_hash = {GENESIS_HASH: GENESIS}
        new_by_height = {0: GENESIS}
        new_tip_hash = GENESIS_HASH
        for height in range(1, len(blocks)):
            block = blocks[height]
            if not validate_block(block, blocks[height - 1]):
                return False
            new_tip_hash = compute_block_hash(pack_header(block))
            new_by_hash[new_tip_hash] = block
            new_by_height[height] = block
        self.blocks = list(blocks)
        self.by_hash = new_by_hash
        self.by_height = new_by_height
        self.tip_hash = new_tip_hash
        return True

    def _apply(self, block: Block, block_hash: bytes) -> None:
        self.blocks.append(block)
        self.by_hash[block_hash] = block
        self.by_height[len(self.blocks) - 1] = block
        self.tip_hash = block_hash

    def try_extend(self, block: Block) -> tuple[AppendStatus, bytes | None]:
        block_hash = compute_block_hash(pack_header(block))
        if block_hash in self.by_hash:
            return AppendStatus.KNOWN_BLOCK, None
        if block.prev_hash != self.tip_hash:
            if block.prev_hash in self.by_hash:
                return AppendStatus.INVALID, None
            return AppendStatus.NEEDS_PARENT, block.prev_hash
        if not validate_block(block, self.tip):
            return AppendStatus.INVALID, None
        self._apply(block, block_hash)
        return AppendStatus.EXTENDS_TIP, None


if __name__ == "__main__":
    from os import urandom

    NOW = 1_700_000_000
    ZERO_HASH = b"\x00" * 32

    # empty body uses sha256(b"") not 32 zero bytes
    assert compute_txs_hash(()) == sha256(b"").digest()

    parent_txs = compute_txs_hash(())
    p_nonce, p_hash = mine_block(ZERO_HASH, parent_txs, 8, NOW)
    parent = Block(ZERO_HASH, parent_txs, NOW, 8, p_nonce, ())

    body = (urandom(32), urandom(32))
    child_txs = compute_txs_hash(body)
    c_nonce, _ = mine_block(p_hash, child_txs, 8, NOW + 1)
    child = Block(p_hash, child_txs, NOW + 1, 8, c_nonce, body)

    # header packs to the spec-mandated 84 bytes
    assert len(pack_header(child)) == 84

    # honest child validates against its parent
    assert validate_block(child, parent)

    # any tampered field fails validation
    tampered = [
        Block(urandom(32), child_txs, NOW + 1, 8, c_nonce, body),
        Block(p_hash, urandom(32), NOW + 1, 8, c_nonce, body),
        Block(p_hash, child_txs, NOW + 1, 8, c_nonce ^ 1, body),
    ]
    assert not any(validate_block(b, parent) for b in tampered)

    # fork-switch scenario: branch at height 2 then longer fork wins
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
    assert chain.height == 4 and chain.tip is main_blocks[-1]

    # alternate shares blocks 0-2 then diverges with 3 fresh blocks for length 6
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

    print("tests passed!")

from struct import Struct
from hashlib import sha256
from dataclasses import dataclass

U64_FORMAT = ">Q"
PREFIX_FORMAT = ">32s32sQI"
HEADER_FORMAT = ">32s32sQIQ"
# pre-compiled for the mining hot path
_U64_STRUCT = Struct(U64_FORMAT)
_HEADER_STRUCT = Struct(HEADER_FORMAT)
_PREFIX_STRUCT = Struct(PREFIX_FORMAT)
_EMPTY_TXS_HASH = sha256(b"").digest()


@dataclass(frozen=True)
class Block:
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    tx_hashes: tuple[bytes, ...]


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
    if block.prev_hash != compute_block_hash(pack_header(parent)):
        return False
    if block.txs_hash != compute_txs_hash(block.tx_hashes):
        return False
    return has_leading_zero_bits(
        compute_block_hash(pack_header(block)), block.difficulty
    )


def compute_txs_hash(tx_hashes: tuple[bytes, ...]) -> bytes:
    if not tx_hashes:
        return _EMPTY_TXS_HASH
    return sha256(b"".join(tx_hashes)).digest()


def has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    full, rem = divmod(bits, 8)
    if any(digest[:full]):
        return False
    return not rem or digest[full] < (1 << (8 - rem))


def compute_tx_hash(
    sender_key: bytes, data: bytes, timestamp: int, signature: bytes
) -> bytes:
    h = sha256(sender_key)
    h.update(data)
    h.update(_U64_STRUCT.pack(timestamp))
    h.update(signature)
    return h.digest()


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

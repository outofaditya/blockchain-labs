from struct import Struct
from hashlib import sha256
from dataclasses import dataclass

TIMESTAMP_FORMAT = ">Q"
HEADER_FORMAT = ">32s32sQIQ"
# pre-compiled for the mining hot path
_HEADER_STRUCT = Struct(HEADER_FORMAT)
_EMPTY_TXS_HASH = sha256(b"").digest()
_TIMESTAMP_STRUCT = Struct(TIMESTAMP_FORMAT)


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
    h.update(_TIMESTAMP_STRUCT.pack(timestamp))
    h.update(signature)
    return h.digest()

from struct import Struct
from dataclasses import dataclass

HEADER_FORMAT = ">32s32sQIQ"
# pre-compiled for the mining hot path
_HEADER_STRUCT = Struct(HEADER_FORMAT)


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

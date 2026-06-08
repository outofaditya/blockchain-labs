import os
import logging
import dataclasses

from ipv8.messaging.payload_dataclass import DataClassPayload, convert_to_payload

logging.basicConfig(level=logging.CRITICAL)

_DIR = os.path.dirname(os.path.abspath(__file__))

# registration community is fixed by the assignment so the lab 3 server can hear us
REGISTRATION_COMMUNITY_ID = bytes.fromhex("4c616233426c6f636b636861696e323032365057")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)

# our own chain community 20 bytes we pick so all three nodes agree on the same overlay
CHAIN_COMMUNITY_ID = b"QuickFoxJumpsLazyDog"

# group identity carried over from lab 2 since the lab 3 server checks group membership
GROUP_ID = "814ee89d4621f005"

# members in registration order
MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3aa3387dfd20b578dfce201978aea6f25dfa3b3127e6825ce7bd2fb8ce07797f7c8bf427fa376e6eaf58391430e63eb86dc93aebb3f68c89bc9d99c63882034a90",  # pedro
    "4c69624e61434c504b3acb4cf8cd94d4c0b6513dde5ac3e713421243fe03acd9f81c44a3c59d665af57e9372a84599691d8ca03efbe0095cc5eb4a14d68700ab81356a4da03be942c848",  # danil
    "4c69624e61434c504b3af9e8ecfcb5968c5438c65adf621afcb336895329da741ef0e1ff846db37f3a1dd4188afcad7d8f8a890571930a4bb7b982904911437c2aba97922746c5fdb176",  # aditya
]
MEMBER_KEYS = [bytes.fromhex(h) for h in MEMBER_KEYS_HEX]


# tells the lab 3 server which 20 byte chain community to join for this group
@dataclasses.dataclass
class RegisterBlockchain(DataClassPayload[1]):
    group_id: str
    community_id: bytes


# server reply confirming registration was recorded
@dataclasses.dataclass
class RegisterResponse(DataClassPayload[2]):
    success: bool
    message: str


# server pushes a signed transaction into our mempool
@dataclasses.dataclass
class SubmitTransaction(DataClassPayload[1]):
    sender_key: bytes
    data: bytes
    timestamp: int
    signature: bytes


# our reply carrying the tx_hash so the server can later track inclusion
@dataclasses.dataclass
class SubmitTransactionResponse(DataClassPayload[2]):
    success: bool
    tx_hash: bytes
    message: str


# server asks how tall our chain is and what the tip hash is
@dataclasses.dataclass
class GetChainHeight(DataClassPayload[3]):
    request_id: int


# our reply with current height plus tip hash
@dataclasses.dataclass
class ChainHeightResponse(DataClassPayload[4]):
    request_id: int
    height: int
    tip_hash: bytes


# server fetches a specific block by height to walk the chain
@dataclasses.dataclass
class GetBlock(DataClassPayload[5]):
    height: int


# our reply with full header fields plus concatenated tx hashes for body verification
@dataclasses.dataclass
class BlockResponse(DataClassPayload[6]):
    height: int
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    block_hash: bytes
    tx_hashes: bytes


# internal gossip block we broadcast to teammates when we mine
@dataclasses.dataclass
class NewBlock(DataClassPayload[100]):
    prev_hash: bytes
    txs_hash: bytes
    timestamp: int
    difficulty: int
    nonce: int
    tx_hashes: bytes


for cls in (
    RegisterBlockchain,
    RegisterResponse,
    SubmitTransaction,
    SubmitTransactionResponse,
    GetChainHeight,
    ChainHeightResponse,
    GetBlock,
    BlockResponse,
    NewBlock,
):
    convert_to_payload(cls)

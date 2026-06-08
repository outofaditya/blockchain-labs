import os
import asyncio
import logging
import dataclasses

from ipv8_service import IPv8
from ipv8.configuration import (
    Strategy,
    ConfigBuilder,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8.community import Community, CommunitySettings
from ipv8.messaging.payload_dataclass import DataClassPayload, convert_to_payload

from chain import Chain, Mempool

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


# light overlay used once to tell the lab 3 server about our chain community
class RegistrationCommunity(Community):
    community_id = REGISTRATION_COMMUNITY_ID

    # binds the handler and tracks whether we have heard back from the server
    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.registered = False
        self.add_message_handler(RegisterResponse, self.on_register_response)

    # filters discovered peers down to the one matching the published server key
    def _server_peer(self):
        for p in self.get_peers():
            if p.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                return p
        return None

    # one shot send guarded by registered flag and server peer discovery
    async def _register(self) -> None:
        if self.registered or (server := self._server_peer()) is None:
            return
        self.ez_send(server, RegisterBlockchain(GROUP_ID, CHAIN_COMMUNITY_ID))

    # verifies the reply came from the published server key then prints the verdict
    def on_register_response(self, source_address: tuple, data: bytes) -> None:
        try:
            auth, _, payload = self._ez_unpack_auth(RegisterResponse, data)
        except Exception as e:
            logging.debug(f"Bad RegisterResponse from {source_address}: {e}")
            return
        if auth.public_key_bin != SERVER_PUBLIC_KEY:
            return
        status = "OK" if payload.success else "FAIL"
        print(f"Registration [{status}]: {payload.message}")


# main overlay holding the chain mempool and the four handlers for server and gossip messages
class ChainCommunity(Community):
    community_id = CHAIN_COMMUNITY_ID

    # owns the chain and mempool then wires all four handlers in one loop
    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.chain = Chain()
        self.mempool = Mempool()
        for cls, handler in (
            (SubmitTransaction, self.on_submit_transaction),
            (GetChainHeight, self.on_get_chain_height),
            (GetBlock, self.on_get_block),
            (NewBlock, self.on_new_block),
        ):
            self.add_message_handler(cls, handler)

    # stub for atom 6 will verify sig add to mempool and reply with tx_hash
    def on_submit_transaction(self, source_address: tuple, data: bytes) -> None:
        print(f"[chain] SubmitTransaction from {source_address}")

    # stub for atom 6 will reply with current height and tip hash
    def on_get_chain_height(self, source_address: tuple, data: bytes) -> None:
        print(f"[chain] GetChainHeight from {source_address}")

    # stub for atom 6 will reply with the block at that height
    def on_get_block(self, source_address: tuple, data: bytes) -> None:
        print(f"[chain] GetBlock from {source_address}")

    # stub for atom 7 will try_extend and rebroadcast on success
    def on_new_block(self, source_address: tuple, data: bytes) -> None:
        print(f"[chain] NewBlock from {source_address}")


# boots ipv8 with both overlays bound to the same key and blocks forever
async def main(pem_path: str, port: int) -> None:
    walker = [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})]
    builder = (
        ConfigBuilder(clean=True)
        .set_port(port)
        .set_address("0.0.0.0")
        .set_log_level("CRITICAL")
        .set_walker_interval(0.5)
        .set_working_directory(_DIR)
        .add_key("my key", "curve25519", pem_path)
        .add_overlay(
            "RegistrationCommunity", "my key", walker, default_bootstrap_defs, {}, []
        )
        .add_overlay("ChainCommunity", "my key", walker, default_bootstrap_defs, {}, [])
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "RegistrationCommunity": RegistrationCommunity,
            "ChainCommunity": ChainCommunity,
        },
    )
    await ipv8.start()

    chain_overlay = ipv8.get_overlay(ChainCommunity)
    print(
        f"{'=' * 80}\nLAB 3 BLOCKCHAIN NODE\n{'=' * 80}\n"
        f"{'Key File':<12}: {pem_path}\n"
        f"{'Port':<12}: {port}\n"
        f"{'Group ID':<12}: {GROUP_ID}\n"
        f"{'Chain ID':<12}: {CHAIN_COMMUNITY_ID.decode()}\n"
        f"{'Public Key':<12}: {chain_overlay.my_peer.public_key.key_to_bin().hex()}\n"
        f"{'-' * 80}\nBOTH COMMUNITIES JOINED\n{'-' * 80}"
    )

    # never set so the node runs until ctrl c
    await asyncio.Event().wait()
    await ipv8.stop()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python node.py <pem_path> <port>")
        print("Example: python node.py key.pem 8094")
        sys.exit(1)

    pem_path = sys.argv[1]
    port = int(sys.argv[2])
    asyncio.run(main(pem_path, port))

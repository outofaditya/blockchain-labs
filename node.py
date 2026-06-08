import os
import time
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

from chain import (
    Tx,
    Block,
    Chain,
    Mempool,
    pack_header,
    mining_loop,
    AppendStatus,
    compute_block_hash,
)

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

# tuned so each block takes a few seconds making the demo readable in real time
MINING_DIFFICULTY = 18

# blocks to mine after a server transaction one for the tx plus three confirmations
CONFIRMATION_DEPTH = 4

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
    height: int
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

    # binds the handler and schedules the retry until the server replies once
    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.registered = False
        self.rekicked = False
        self.add_message_handler(RegisterResponse, self.on_register_response)
        self.register_task("register", self._register, interval=2.0, delay=3.0)

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

    # second registration fires after discovery settles so the server retry budget resets
    async def _rekick(self) -> None:
        server = self._server_peer()
        if server is None:
            return
        print("Registration: re-registering to reset the server retry budget")
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
        self.registered = True
        if not self.rekicked:
            self.rekicked = True
            self.register_task("rekick", self._rekick, delay=60.0)


# main overlay holding the chain mempool and the four handlers for server and gossip messages
class ChainCommunity(Community):
    community_id = CHAIN_COMMUNITY_ID

    # owns the chain and mempool wires all handlers and prepares the walk back buffer
    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.chain = Chain()
        self.mempool = Mempool()
        my_key = self.my_peer.public_key.key_to_bin()
        self._teammate_keys = set(MEMBER_KEYS) - {my_key}
        self._pending: dict[bytes, Block] = {}
        self._seen: set[bytes] = set()
        self._mining_gate = asyncio.Event()
        self._mining_target = 0
        for cls, handler in (
            (SubmitTransaction, self.on_submit_transaction),
            (GetChainHeight, self.on_get_chain_height),
            (GetBlock, self.on_get_block),
            (NewBlock, self.on_new_block),
            (BlockResponse, self.on_block_response),
        ):
            self.add_message_handler(cls, handler)
        self.register_task("status", self._status_tick, interval=5.0, delay=5.0)

    # periodic snapshot so the human can see discovery progress while idle
    async def _status_tick(self) -> None:
        peers = list(self.get_peers())
        teammates = sum(
            1 for p in peers if p.public_key.key_to_bin() in self._teammate_keys
        )
        has_server = any(p.public_key.key_to_bin() == SERVER_PUBLIC_KEY for p in peers)
        mining = "active" if self._mining_gate.is_set() else "idle"
        self._log(
            "STATUS",
            f"peers={len(peers)} server={'yes' if has_server else 'no'} "
            f"teammates={teammates}/2 height={self.chain.height} mining={mining}",
        )

    # one line structured log with a wall clock prefix for cross terminal correlation
    def _log(self, event: str, detail: str = "") -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {event:<11} {detail}")

    # opens the gate so mining_loop runs until the chain reaches the new target
    def _enable_mining(self, target: int) -> None:
        if target <= self._mining_target:
            return
        self._mining_target = target
        self._mining_gate.set()
        self._log("MINING", f"enabled target_height={target}")

    # closes the gate once the chain has caught up with the target
    def _maybe_pause_mining(self) -> None:
        if self._mining_gate.is_set() and self.chain.height >= self._mining_target:
            self._mining_gate.clear()
            self._log("MINING", f"paused tip_height={self.chain.height}")

    # yields the currently discovered teammate peers excluding ourselves
    def _teammate_peers(self):
        for p in self.get_peers():
            if p.public_key.key_to_bin() in self._teammate_keys:
                yield p

    # convenience shortcut for the server identity lookup
    def _server_peer(self):
        return self._peer_with_key(SERVER_PUBLIC_KEY)

    # serializes a freshly mined block and pushes it to every discovered teammate
    def broadcast_block(self, block: Block, height: int) -> None:
        payload = NewBlock(
            height,
            block.prev_hash,
            block.txs_hash,
            block.timestamp,
            block.difficulty,
            block.nonce,
            b"".join(block.tx_hashes),
        )
        for peer in self._teammate_peers():
            self.ez_send(peer, payload)

    # resolves the peer matching a verified sender key for replies
    def _peer_with_key(self, pubkey: bytes):
        for p in self.get_peers():
            if p.public_key.key_to_bin() == pubkey:
                return p
        return None

    # generic decode plus sender check returns (sender_key, payload) or (None, None)
    def _unpack(self, payload_cls, data, source_address, allowed):
        try:
            auth, _, payload = self._ez_unpack_auth(payload_cls, data)
        except Exception as e:
            logging.debug(f"Bad {payload_cls.__name__} from {source_address}: {e}")
            return None, None
        if auth.public_key_bin not in allowed:
            return None, None
        return auth.public_key_bin, payload

    # rebuilds the tx from the wire fields and gates it through the mempool signature check
    def on_submit_transaction(self, source_address: tuple, data: bytes) -> None:
        _, payload = self._unpack(
            SubmitTransaction, data, source_address, (SERVER_PUBLIC_KEY,)
        )
        server = self._server_peer()
        if payload is None or server is None:
            return
        self._log("SERVER", "SubmitTransaction")
        tx = Tx(payload.sender_key, payload.data, payload.timestamp, payload.signature)
        tx_hash = self.mempool.add(tx)
        if tx_hash is not None:
            self.ez_send(server, SubmitTransactionResponse(True, tx_hash, "accepted"))
            self._enable_mining(self.chain.height + CONFIRMATION_DEPTH)
        else:
            self.ez_send(server, SubmitTransactionResponse(False, b"", "rejected"))

    # echoes back the request_id so the server can match concurrent queries
    def on_get_chain_height(self, source_address: tuple, data: bytes) -> None:
        _, payload = self._unpack(
            GetChainHeight, data, source_address, (SERVER_PUBLIC_KEY,)
        )
        server = self._server_peer()
        if payload is None or server is None:
            return
        self._log("SERVER", f"GetChainHeight request_id={payload.request_id}")
        self.ez_send(
            server,
            ChainHeightResponse(
                payload.request_id, self.chain.height, self.chain.tip_hash
            ),
        )

    # serves both the server's grading queries and teammate walk-back requests
    def on_get_block(self, source_address: tuple, data: bytes) -> None:
        sender, payload = self._unpack(
            GetBlock, data, source_address, (SERVER_PUBLIC_KEY, *MEMBER_KEYS)
        )
        if payload is None:
            return
        origin = "SERVER" if sender == SERVER_PUBLIC_KEY else "PEER"
        self._log(f"{origin}", f"GetBlock height={payload.height}")
        block = self.chain.by_height.get(payload.height)
        target = self._peer_with_key(sender)
        if block is None or target is None:
            return
        block_hash = compute_block_hash(pack_header(block))
        self.ez_send(
            target,
            BlockResponse(
                payload.height,
                block.prev_hash,
                block.txs_hash,
                block.timestamp,
                block.difficulty,
                block.nonce,
                block_hash,
                b"".join(block.tx_hashes),
            ),
        )

    # gossip entry from a teammate broadcast triggers rebroadcast on success
    def on_new_block(self, source_address: tuple, data: bytes) -> None:
        sender, payload = self._unpack(NewBlock, data, source_address, MEMBER_KEYS)
        if payload is None:
            return
        self._log("RECV", f"NewBlock height={payload.height}")
        self._ingest_block(
            sender, self._block_from_wire(payload), payload.height, rebroadcast=True
        )

    # walk back reply we asked for so no rebroadcast on success
    def on_block_response(self, source_address: tuple, data: bytes) -> None:
        sender, payload = self._unpack(BlockResponse, data, source_address, MEMBER_KEYS)
        if payload is None:
            return
        self._log("PARENT_RECV", f"height={payload.height}")
        self._ingest_block(
            sender,
            self._block_from_wire(payload),
            payload.height,
            rebroadcast=False,
        )

    # shared dedup plus try_extend dispatcher used by both gossip and walk back paths
    def _ingest_block(
        self, sender_key: bytes, block: Block, height: int, rebroadcast: bool
    ) -> None:
        block_hash = compute_block_hash(pack_header(block))
        if block_hash in self._seen:
            return
        self._seen.add(block_hash)
        status, parent_hash = self.chain.try_extend(block)
        if status is AppendStatus.EXTENDS_TIP:
            self.mempool.remove(list(block.tx_hashes))
            self._log("EXTEND", f"height={self.chain.height}")
            if rebroadcast:
                self.broadcast_block(block, height)
            self._drain_pending(block)
            self._maybe_pause_mining()
        elif status is AppendStatus.NEEDS_PARENT:
            self._kick_walk_back(sender_key, block, parent_hash, height)

    # reconstructs a Block from any wire payload sharing the canonical header fields
    def _block_from_wire(self, payload) -> Block:
        tx_hashes = tuple(
            payload.tx_hashes[i : i + 32] for i in range(0, len(payload.tx_hashes), 32)
        )
        return Block(
            payload.prev_hash,
            payload.txs_hash,
            payload.timestamp,
            payload.difficulty,
            payload.nonce,
            tx_hashes,
        )

    # buffers the orphan and requests its claimed parent so we can fill the gap
    def _kick_walk_back(
        self, sender_key: bytes, orphan: Block, parent_hash: bytes, orphan_height: int
    ) -> None:
        if parent_hash in self._pending:
            return
        self._pending[parent_hash] = orphan
        target = self._peer_with_key(sender_key)
        if target is not None:
            self._log("PARENT_REQ", f"height={orphan_height - 1}")
            self.ez_send(target, GetBlock(orphan_height - 1))

    # after a block lands replays any orphans that were waiting on its hash
    def _drain_pending(self, applied: Block) -> None:
        applied_hash = compute_block_hash(pack_header(applied))
        orphan = self._pending.pop(applied_hash, None)
        while orphan is not None:
            status, _ = self.chain.try_extend(orphan)
            if status is not AppendStatus.EXTENDS_TIP:
                return
            self.mempool.remove(list(orphan.tx_hashes))
            applied_hash = compute_block_hash(pack_header(orphan))
            orphan = self._pending.pop(applied_hash, None)


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

    async def broadcast(block: Block) -> None:
        height = chain_overlay.chain.height
        chain_overlay._log("MINED", f"height={height} nonce={block.nonce}")
        chain_overlay.broadcast_block(block, height)
        chain_overlay._maybe_pause_mining()

    asyncio.create_task(
        mining_loop(
            chain_overlay.chain,
            chain_overlay.mempool,
            MINING_DIFFICULTY,
            broadcast,
            gate=chain_overlay._mining_gate,
        )
    )

    print(
        f"{'=' * 80}\nLAB 3 BLOCKCHAIN NODE\n{'=' * 80}\n"
        f"{'Key File':<12}: {pem_path}\n"
        f"{'Port':<12}: {port}\n"
        f"{'Group ID':<12}: {GROUP_ID}\n"
        f"{'Chain ID':<12}: {CHAIN_COMMUNITY_ID.decode()}\n"
        f"{'Difficulty':<12}: {MINING_DIFFICULTY} leading zero bits\n"
        f"{'Public Key':<12}: {chain_overlay.my_peer.public_key.key_to_bin().hex()}\n"
        f"{'-' * 80}\nIDLE UNTIL SERVER SUBMITS A TRANSACTION\n{'-' * 80}"
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

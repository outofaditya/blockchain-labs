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
from ipv8.lazy_community import lazy_wrapper
from ipv8.community import Community, CommunitySettings
from ipv8.messaging.payload_dataclass import DataClassPayload, convert_to_payload

from labs.three.chain import (
    Tx,
    Block,
    Chain,
    GENESIS,
    Mempool,
    pack_header,
    mining_loop,
    AppendStatus,
    GENESIS_HASH,
    compute_block_hash,
)
from common.paths import REPO_ROOT
from common.banner import rule, rows, section

logging.basicConfig(level=logging.CRITICAL)

UNI_EMAIL = os.getenv("UNI_EMAIL")
KEY_PATH = os.getenv("KEY_PATH")

# registration community published by the lab 3 server
REGISTRATION_COMMUNITY_ID = bytes.fromhex("4c616233426c6f636b636861696e323032365057")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3ae3fc099fb56ca3b5e1de9a1c843387f2acdbb78b1bd4350ffde518068a0d246344b10d0d8c355fd0d76873e7d7f7838f3715e025af08f791324495e083331ce6"
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)

# our own chain community 20 bytes we pick so all three nodes agree on the same overlay
CHAIN_COMMUNITY_ID = b"QuickFoxJumpsLazyDog"

# group identity carried over from lab 2 since the lab 3 server checks group membership
GROUP_ID = "814ee89d4621f005"

# leading zero bits required on every mined block header
MINING_DIFFICULTY = 18

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
        # initial state plus a slot for the sibling chain overlay reference
        self.registered = False
        self.chain = None
        self._quorum_logged = False
        # first member in the canonical group order is the sole registrar
        self.is_registrar = self.my_peer.public_key.key_to_bin() == MEMBER_KEYS[0]
        # always register the response handler so observers still see the verdict
        self.add_message_handler(RegisterResponse, self.on_register_response)
        # only the registrar runs the periodic send task
        if self.is_registrar:
            self.register_task("register", self._register, interval=2.0, delay=3.0)
        role = "registrar" if self.is_registrar else "observer"
        print(
            f"Joined RegistrationCommunity id={REGISTRATION_COMMUNITY_ID.hex()} role={role}"
        )

    # filters discovered peers down to the one matching the published server key
    def _server_peer(self):
        for p in self.get_peers():
            if p.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                return p
        return None

    # one shot send guarded by registered flag server peer discovery and chain overlay quorum
    async def _register(self) -> None:
        # skip once we already received a verdict or the server peer is missing
        if self.registered or (server := self._server_peer()) is None:
            return
        # block sending until the chain overlay has all three nodes mutually discovered
        if not self._chain_quorum():
            return
        self.ez_send(server, RegisterBlockchain(GROUP_ID, CHAIN_COMMUNITY_ID))

    # returns true only when the chain overlay has both teammates already as peers
    def _chain_quorum(self) -> bool:
        if self.chain is None:
            return False
        # snapshot the current chain overlay peers and check teammate presence
        present = {p.public_key.key_to_bin() for p in self.chain.get_peers()}
        ready = self.chain._teammate_keys.issubset(present)
        # log the transition exactly once so the operator sees the gate fire
        if ready and not self._quorum_logged:
            self._quorum_logged = True
            print(
                "Quorum: all 3 nodes present in chain community sending RegisterBlockchain"
            )
        return ready

    # verifies the reply came from the published server key then prints the verdict
    @lazy_wrapper(RegisterResponse)
    def on_register_response(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        status = "OK" if payload.success else "FAIL"
        print(f"Registration [{status}]: {payload.message}")
        self.registered = True


# main overlay holding the chain mempool and the four handlers for server and gossip messages
class ChainCommunity(Community):
    community_id = CHAIN_COMMUNITY_ID

    # owns the chain and mempool wires all handlers and prepares the reorg buffer
    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        # local chain and mempool seed the protocol state
        self.chain = Chain()
        self.mempool = Mempool()
        # capture our own key so teammate filters can exclude us
        my_key = self.my_peer.public_key.key_to_bin()
        self._teammate_keys = set(MEMBER_KEYS) - {my_key}
        # side pool keeps every non tip block reachable for reorg or walk back
        self._pool: dict[bytes, Block] = {GENESIS_HASH: GENESIS}
        self._inflight: set[bytes] = set()
        # bind each payload class to its handler so ipv8 dispatches correctly
        for cls, handler in (
            (SubmitTransaction, self.on_submit_transaction),
            (GetChainHeight, self.on_get_chain_height),
            (GetBlock, self.on_get_block),
            (NewBlock, self.on_new_block),
            (BlockResponse, self.on_block_response),
        ):
            self.add_message_handler(cls, handler)
        # periodic status print so the operator can see discovery progress
        self.register_task("status", self._status_tick, interval=5.0, delay=5.0)
        print(f"Joined ChainCommunity id={CHAIN_COMMUNITY_ID!r}")

    # periodic snapshot so the human can see discovery progress while idle
    async def _status_tick(self) -> None:
        peers = list(self.get_peers())
        teammates = sum(
            1 for p in peers if p.public_key.key_to_bin() in self._teammate_keys
        )
        has_server = any(p.public_key.key_to_bin() == SERVER_PUBLIC_KEY for p in peers)
        self._log(
            "STATUS",
            f"peers={len(peers)} server={'yes' if has_server else 'no'} "
            f"teammates={teammates}/2 height={self.chain.height} mempool={len(self.mempool)}",
        )

    # one line structured log with a wall clock prefix for cross terminal correlation
    def _log(self, event: str, detail: str = "") -> None:
        print(f"[{time.strftime('%H:%M:%S')}] {event:<11} {detail}")

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

    # rebuilds the tx from the wire fields and gates it through the mempool signature check
    @lazy_wrapper(SubmitTransaction)
    def on_submit_transaction(self, peer, payload):
        # only the published server is allowed to push transactions
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        server = self._server_peer()
        if server is None:
            return
        # add to the mempool and reply with the resulting tx hash or a rejection
        self._log("SERVER", "SubmitTransaction")
        tx = Tx(payload.sender_key, payload.data, payload.timestamp, payload.signature)
        tx_hash = self.mempool.add(tx)
        if tx_hash is not None:
            self.ez_send(server, SubmitTransactionResponse(True, tx_hash, "accepted"))
        else:
            self.ez_send(server, SubmitTransactionResponse(False, b"", "rejected"))

    # echoes back the request_id so the server can match concurrent queries
    @lazy_wrapper(GetChainHeight)
    def on_get_chain_height(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        server = self._server_peer()
        if server is None:
            return
        self._log("SERVER", f"GetChainHeight request_id={payload.request_id}")
        self.ez_send(
            server,
            ChainHeightResponse(
                payload.request_id, self.chain.height, self.chain.tip_hash
            ),
        )

    # serves both the server grading queries and teammate walk back requests
    @lazy_wrapper(GetBlock)
    def on_get_block(self, peer, payload):
        # allow the server plus the three registered members
        sender = peer.public_key.key_to_bin()
        if sender != SERVER_PUBLIC_KEY and sender not in MEMBER_KEYS:
            return
        # log which side asked so the operator can read the flow at a glance
        origin = "SERVER" if sender == SERVER_PUBLIC_KEY else "PEER"
        self._log(f"{origin}", f"GetBlock height={payload.height}")
        # look up the requested block and resolve the asking peer for the reply
        block = self.chain.by_height.get(payload.height)
        target = self._peer_with_key(sender)
        if block is None or target is None:
            return
        # build the full block response with header fields plus concatenated tx hashes
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
    @lazy_wrapper(NewBlock)
    def on_new_block(self, peer, payload):
        sender = peer.public_key.key_to_bin()
        if sender not in MEMBER_KEYS:
            return
        self._log("RECV", f"NewBlock height={payload.height}")
        self._ingest_block(
            sender, self._block_from_wire(payload), payload.height, rebroadcast=True
        )

    # walk back reply we asked for so no rebroadcast on success
    @lazy_wrapper(BlockResponse)
    def on_block_response(self, peer, payload):
        sender = peer.public_key.key_to_bin()
        if sender not in MEMBER_KEYS:
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
        # silently drop any block we already hold either on chain or in the pool
        block_hash = compute_block_hash(pack_header(block))
        if block_hash in self.chain.by_hash or block_hash in self._pool:
            return
        # park the block and mark any pending walk back request as fulfilled
        self._pool[block_hash] = block
        self._inflight.discard(block_hash)
        # dispatch on the chain status
        status, parent_hash = self.chain.try_extend(block)
        if status is AppendStatus.INVALID:
            self._log("INVALID", f"height={height}")
            self._pool.pop(block_hash, None)
            return
        if status is AppendStatus.NEEDS_PARENT:
            self._kick_walk_back(sender_key, block, parent_hash, height)
            return
        # extend or branch both clear matching mempool txs and feed the reorg pass
        if status is AppendStatus.EXTENDS_TIP:
            self.mempool.remove(list(block.tx_hashes))
            self._log("EXTEND", f"height={self.chain.height}")
        else:
            self._log("FORK", f"height={height}")
        self._try_drain_and_reorg()
        # rebroadcast only when we are on the gossip path and the block became the new tip
        if self.chain.tip_hash == block_hash and rebroadcast:
            self.broadcast_block(block, self.chain.height)

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

    # asks the gossiping peer for the orphan parent unless that request is already inflight
    def _kick_walk_back(
        self, sender_key: bytes, orphan: Block, parent_hash: bytes, orphan_height: int
    ) -> None:
        # dedup repeated walk back requests for the same missing parent
        if parent_hash in self._inflight or parent_hash in self._pool:
            return
        self._inflight.add(parent_hash)
        # send a GetBlock at the parent height back to the gossiping peer
        target = self._peer_with_key(sender_key)
        if target is not None:
            self._log("PARENT_REQ", f"height={orphan_height - 1}")
            self.ez_send(target, GetBlock(orphan_height - 1))

    # greedily extends tip from pool blocks then adopts any strictly longer sibling chain
    def _try_drain_and_reorg(self) -> None:
        # drain phase tries to extend the tip from pool blocks linking cleanly
        extended = True
        while extended:
            extended = False
            for cand_hash, cand in self._pool.items():
                if cand_hash in self.chain.by_hash:
                    continue
                if cand.prev_hash != self.chain.tip_hash:
                    continue
                status, _ = self.chain.try_extend(cand)
                if status is AppendStatus.EXTENDS_TIP:
                    self.mempool.remove(list(cand.tx_hashes))
                    self._log("EXTEND", f"height={self.chain.height} drained")
                    extended = True
                    break
        # reorg phase scans the pool for a strictly longer chain ending at genesis
        best_chain = None
        for cand_hash, cand in self._pool.items():
            if cand_hash in self.chain.by_hash:
                continue
            candidate = self._walk_to_genesis(cand_hash)
            if candidate is None:
                continue
            if best_chain is None or len(candidate) > len(best_chain):
                best_chain = candidate
        # adopt the best candidate when it strictly beats our current chain length
        if best_chain is not None and len(best_chain) > len(self.chain.blocks):
            if self.chain.adopt_fork(best_chain):
                self._log("REORG", f"new_tip_height={self.chain.height}")
                for adopted in best_chain[1:]:
                    self.mempool.remove(list(adopted.tx_hashes))

    # walks prev_hash links back through pool union chain returning a full chain or None
    def _walk_to_genesis(self, block_hash: bytes) -> list[Block] | None:
        # collect ancestors by following prev_hash until genesis or a missing parent
        ancestors: list[Block] = []
        cursor = block_hash
        seen: set[bytes] = set()
        while cursor != GENESIS_HASH:
            # break on a cycle which can only mean a malformed pool entry
            if cursor in seen:
                return None
            seen.add(cursor)
            block = self._pool.get(cursor) or self.chain.by_hash.get(cursor)
            if block is None:
                return None
            ancestors.append(block)
            cursor = block.prev_hash
        # prepend genesis and reverse so the result reads from genesis to tip
        ancestors.append(GENESIS)
        ancestors.reverse()
        return ancestors


# boots ipv8 with both overlays bound to the same key and blocks forever
async def main(port: int) -> None:
    # build the ipv8 configuration with both lab 3 overlays bound to the same key
    walker = [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})]
    builder = (
        ConfigBuilder(clean=True)
        .set_port(port)
        .set_address("0.0.0.0")
        .set_log_level("CRITICAL")
        .set_walker_interval(0.5)
        .set_working_directory(REPO_ROOT)
        .add_key(UNI_EMAIL, "curve25519", KEY_PATH)
        .add_overlay(
            "RegistrationCommunity", UNI_EMAIL, walker, default_bootstrap_defs, {}, []
        )
        .add_overlay(
            "ChainCommunity", UNI_EMAIL, walker, default_bootstrap_defs, {}, []
        )
    )

    # bootstrap ipv8 and start both communities
    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "RegistrationCommunity": RegistrationCommunity,
            "ChainCommunity": ChainCommunity,
        },
    )
    await ipv8.start()

    # cross link the registration overlay to the chain overlay for quorum checks
    chain_overlay = ipv8.get_overlay(ChainCommunity)
    reg_overlay = ipv8.get_overlay(RegistrationCommunity)
    reg_overlay.chain = chain_overlay

    # broadcast callback hooks the mining loop into the chain community
    async def broadcast(block: Block) -> None:
        height = chain_overlay.chain.height
        chain_overlay._log("MINED", f"height={height} nonce={block.nonce}")
        chain_overlay.broadcast_block(block, height)

    # launch the mining loop as a background asyncio task
    asyncio.create_task(
        mining_loop(
            chain_overlay.chain,
            chain_overlay.mempool,
            MINING_DIFFICULTY,
            broadcast,
        )
    )

    rule("LAB 3 BLOCKCHAIN NODE")
    rows(
        [
            ("Key File", KEY_PATH),
            ("Port", port),
            ("Group ID", GROUP_ID),
            ("Chain ID", CHAIN_COMMUNITY_ID.decode()),
            ("Difficulty", f"{MINING_DIFFICULTY} leading zero bits"),
            ("Public Key", chain_overlay.my_peer.public_key.key_to_bin().hex()),
        ],
        label_width=12,
    )
    section("MINING CONTINUOUSLY WAITING FOR PEER DISCOVERY AND SERVER TRAFFIC")

    # never set so the node runs until ctrl c
    await asyncio.Event().wait()
    await ipv8.stop()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m labs.three.node <port>")
        print("Example: python -m labs.three.node 8094")
        sys.exit(1)

    port = int(sys.argv[1])
    asyncio.run(main(port))

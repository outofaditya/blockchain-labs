import os
import asyncio
import logging
import dataclasses

from ipv8.configuration import (
    Strategy,
    ConfigBuilder,
    WalkerDefinition,
    default_bootstrap_defs,
)

from ipv8_service import IPv8
from ipv8.community import Community, CommunitySettings
from ipv8.messaging.payload_dataclass import DataClassPayload, convert_to_payload

# logging configuration
logging.basicConfig(level=logging.CRITICAL)

# paths
_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(_DIR, "key.pem")

# server identity
COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)

# group identity (pre-registered)
GROUP_ID = "814ee89d4621f005"

# members in registration order (pedro - danil - aditya)
MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3aa3387dfd20b578dfce201978aea6f25dfa3b3127e6825ce7bd2fb8ce07797f7c8bf427fa376e6eaf58391430e63eb86dc93aebb3f68c89bc9d99c63882034a90",  # member 1: pedro
    "4c69624e61434c504b3acb4cf8cd94d4c0b6513dde5ac3e713421243fe03acd9f81c44a3c59d665af57e9372a84599691d8ca03efbe0095cc5eb4a14d68700ab81356a4da03be942c848",  # member 2: danil
    "4c69624e61434c504b3af9e8ecfcb5968c5438c65adf621afcb336895329da741ef0e1ff846db37f3a1dd4188afcad7d8f8a890571930a4bb7b982904911437c2aba97922746c5fdb176",  # member 3: aditya
]

MEMBER_KEYS = [bytes.fromhex(h) for h in MEMBER_KEYS_HEX]

# round-robin submitter index
SUBMITTER_BY_ROUND = {1: 1, 2: 2, 3: 3}


# server-facing payloads
# message_id=1: register a group with the server
@dataclasses.dataclass
class RegisterGroup(DataClassPayload[1]):
    member1_key: bytes
    member2_key: bytes
    member3_key: bytes


# message_id=2: server response to registration
@dataclasses.dataclass
class GroupResponse(DataClassPayload[2]):
    success: bool
    group_id: str
    message: str


# message_id=3: request a fresh challenge for the active round
@dataclasses.dataclass
class ChallengeRequest(DataClassPayload[3]):
    group_id: str


# message_id=4: server's challenge with 32-byte nonce
@dataclasses.dataclass
class ChallengeResponse(DataClassPayload[4]):
    nonce: bytes
    round_number: int
    deadline: float


# message_id=5: bundle the 3 signatures and submit
@dataclasses.dataclass
class SignatureBundle(DataClassPayload[5]):
    group_id: str
    round_number: int
    sig1: bytes
    sig2: bytes
    sig3: bytes


# message_id=6: server's verdict on the bundle (or early rejection)
@dataclasses.dataclass
class RoundResult(DataClassPayload[6]):
    success: bool
    round_number: int
    rounds_completed: int
    message: str


# internal peer-to-peer payloads
# message_id=100: submitter shares the nonce with teammates
@dataclasses.dataclass
class NonceShare(DataClassPayload[100]):
    round_number: int
    nonce: bytes


# message_id=101: teammate sends their signature back to submitter
@dataclasses.dataclass
class SignatureShare(DataClassPayload[101]):
    round_number: int
    member_index: int
    signature: bytes


# register all payloads with IPv8 for serialization/deserialization
for cls in (
    RegisterGroup,
    GroupResponse,
    ChallengeRequest,
    ChallengeResponse,
    SignatureBundle,
    RoundResult,
    NonceShare,
    SignatureShare,
):
    convert_to_payload(cls)


# community definition
class SignerCommunity(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        # figure out which member we are
        my_key_bin = self.my_peer.public_key.key_to_bin()
        self.my_member_index = MEMBER_KEYS.index(my_key_bin) + 1

        # signals end of protocol so main() can exit
        self.done = asyncio.Event()

        # per-round state (reset on each round)
        self.current_round = 0
        self.current_nonce: bytes | None = None
        self.signatures: dict[int, bytes] = {}
        self.signed_this_round = False
        self.bundle_submitted = False

        # register handlers for all incoming server + peer messages
        self.add_message_handler(GroupResponse, self.on_group_response)
        self.add_message_handler(ChallengeResponse, self.on_challenge_response)
        self.add_message_handler(RoundResult, self.on_round_result)
        self.add_message_handler(NonceShare, self.on_nonce_share)
        self.add_message_handler(SignatureShare, self.on_signature_share)

        # start round-driver after some delay for peer discovery
        self.register_task("run_rounds", self.run_rounds, delay=3.0)

    # find the server peer from peer list
    def _server_peer(self):
        for p in self.get_peers():
            if p.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                return p
        return None

    # find a teammate peer by their member index (1, 2, or 3)
    def _member_peer(self, index: int):
        target = MEMBER_KEYS[index - 1]
        for p in self.get_peers():
            if p.public_key.key_to_bin() == target:
                return p
        return None

    # sign 32-byte nonce with our private key
    def _sign(self, data: bytes) -> bytes:
        return self.crypto.create_signature(self.my_peer.key, data)

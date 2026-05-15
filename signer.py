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

        # event coordination between handlers and driver
        self.nonce_event = asyncio.Event()
        self.sigs_event = asyncio.Event()
        self.round_done_event = asyncio.Event()

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

    # reset per-round state and events
    def _reset_round(self, round_num: int) -> None:
        self.current_round = round_num
        self.current_nonce = None
        self.signatures = {}
        self.signed_this_round = False
        self.bundle_submitted = False
        self.nonce_event.clear()
        self.sigs_event.clear()
        self.round_done_event.clear()

    # handler functions
    # handler: server's response to RegisterGroup
    def on_group_response(self, source_address, data):
        try:
            auth, _, payload = self._ez_unpack_auth(GroupResponse, data)
        except Exception as e:
            logging.debug(f"Bad GroupResponse from {source_address}: {e}")
            return
        if auth.public_key_bin != SERVER_PUBLIC_KEY:
            return
        print(
            f"Registration: success={payload.success} group_id={payload.group_id} msg={payload.message}"
        )

    # handler: server's challenge with the nonce (received by submitter)
    def on_challenge_response(self, source_address, data):
        try:
            auth, _, payload = self._ez_unpack_auth(ChallengeResponse, data)
        except Exception as e:
            logging.debug(f"Bad ChallengeResponse from {source_address}: {e}")
            return
        if auth.public_key_bin != SERVER_PUBLIC_KEY:
            return
        if payload.round_number != self.current_round:
            return
        self.current_nonce = payload.nonce
        self.nonce_event.set()

    # handler: a teammate forwarded the nonce to me (received by non-submitter)
    def on_nonce_share(self, source_address, data):
        try:
            auth, _, payload = self._ez_unpack_auth(NonceShare, data)
        except Exception as e:
            logging.debug(f"Bad NonceShare from {source_address}: {e}")
            return
        if auth.public_key_bin not in MEMBER_KEYS:
            return
        if payload.round_number != self.current_round:
            return
        self.current_nonce = payload.nonce
        self.nonce_event.set()

    # handler: a teammate sent their signature (received by submitter)
    def on_signature_share(self, source_address, data):
        try:
            auth, _, payload = self._ez_unpack_auth(SignatureShare, data)
        except Exception as e:
            logging.debug(f"Bad SignatureShare from {source_address}: {e}")
            return
        if auth.public_key_bin not in MEMBER_KEYS:
            return
        if payload.round_number != self.current_round:
            return
        self.signatures[payload.member_index] = payload.signature
        if len(self.signatures) == 3:
            self.sigs_event.set()

    # handler: server's verdict on the bundle (or early rejection)
    def on_round_result(self, source_address, data):
        try:
            auth, _, payload = self._ez_unpack_auth(RoundResult, data)
        except Exception as e:
            logging.debug(f"Bad RoundResult from {source_address}: {e}")
            return
        if auth.public_key_bin != SERVER_PUBLIC_KEY:
            return
        status = "OK" if payload.success else "FAIL"
        print(f"Round {payload.round_number} [{status}]: {payload.message}")
        self.round_done_event.set()

    # driver functions
    # wait until we've discovered both teammates and the server
    async def _wait_for_peers(self) -> None:
        teammates = [i for i in (1, 2, 3) if i != self.my_member_index]
        while True:
            have_server = self._server_peer() is not None
            have_teammates = all(self._member_peer(i) is not None for i in teammates)
            if have_server and have_teammates:
                return
            await asyncio.sleep(0.5)

    # main round driver — runs the 3-round protocol
    async def run_rounds(self) -> None:
        print("=" * 80)
        print("LAB 2 SIGNATURE CLIENT")
        print("=" * 80)
        print(f"{'Member Index':<14}: {self.my_member_index}")
        print(f"{'Group ID':<14}: {GROUP_ID}")
        print("-" * 80)

        await self._wait_for_peers()
        print("Peers Discovered. Starting 3 Rounds.\n")

        start = asyncio.get_event_loop().time()
        for round_num in (1, 2, 3):
            self._reset_round(round_num)
            am_submitter = self.my_member_index == SUBMITTER_BY_ROUND[round_num]
            role = "submitter" if am_submitter else "signer"
            print(f"Round {round_num} [{role}]")

            if am_submitter:
                await self._submitter_flow(round_num)
            else:
                await self._non_submitter_flow(round_num)

            # the flow is complete but the round_done_event was not set
            if not self.round_done_event.is_set():
                print(f"Round {round_num} Did Not Complete: Aborting")
                break

        elapsed = asyncio.get_event_loop().time() - start
        print("-" * 80)
        print(f"{'Total Time':<14}: {elapsed:.2f}s")
        print("=" * 80)
        self.done.set()

    # submitter: request challenge, share nonce, collect sigs, submit bundle
    async def _submitter_flow(self, round_num: int) -> None:
        server = self._server_peer()
        teammates = [i for i in (1, 2, 3) if i != self.my_member_index]

        # 1. request challenge; retry until nonce arrives or round ends early
        while not self.nonce_event.is_set() and not self.round_done_event.is_set():
            self.ez_send(server, ChallengeRequest(GROUP_ID))
            try:
                await asyncio.wait_for(self.nonce_event.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass

        if self.round_done_event.is_set():
            return  # server rejected early (e.g., group already completed)

        # 2. forward nonce to both teammates
        for idx in teammates:
            peer = self._member_peer(idx)
            if peer:
                self.ez_send(peer, NonceShare(round_num, self.current_nonce))

        # 3. sign our own nonce immediately
        self.signatures[self.my_member_index] = self._sign(self.current_nonce)
        if len(self.signatures) == 3:
            self.sigs_event.set()

        # 4. wait for both teammates' sigs; resend NonceShare on timeout
        while len(self.signatures) < 3:
            try:
                await asyncio.wait_for(self.sigs_event.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                for idx in teammates:
                    if idx not in self.signatures:
                        peer = self._member_peer(idx)
                        if peer:
                            self.ez_send(
                                peer, NonceShare(round_num, self.current_nonce)
                            )

        # 5. submit bundle; retry until server replies with a RoundResult
        bundle = SignatureBundle(
            GROUP_ID,
            round_num,
            self.signatures[1],
            self.signatures[2],
            self.signatures[3],
        )
        while not self.round_done_event.is_set():
            self.ez_send(server, bundle)
            try:
                await asyncio.wait_for(self.round_done_event.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass

    # non-submitter: wait for nonce share, sign, return signature
    async def _non_submitter_flow(self, round_num: int) -> None:
        # wait for the submitter to forward the nonce
        await self.nonce_event.wait()

        # sign and send to the submitter; fire 3 times for UDP loss resilience
        sig = self._sign(self.current_nonce)
        submitter = self._member_peer(SUBMITTER_BY_ROUND[round_num])
        if submitter:
            for _ in range(3):
                self.ez_send(
                    submitter,
                    SignatureShare(round_num, self.my_member_index, sig),
                )
                await asyncio.sleep(0.05)

        # non-submitters receive no server feedback; mark round done locally
        self.round_done_event.set()


# main entry point
async def main(pem_path: str, port: int) -> None:
    builder = (
        ConfigBuilder(clean=True)
        .set_port(port)
        .set_address("0.0.0.0")
        .set_log_level("CRITICAL")
        .set_walker_interval(0.5)
        .set_working_directory(_DIR)
        .add_key("my key", "curve25519", pem_path)
        .add_overlay(
            "SignerCommunity",
            "my key",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs,
            {},
            [],
        )
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={"SignerCommunity": SignerCommunity},
    )
    await ipv8.start()

    community = ipv8.get_overlay(SignerCommunity)
    await community.done.wait()
    await ipv8.stop()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python signer.py <pem_path> <port>")
        print("Example: python signer.py key.pem 8091")
        sys.exit(1)

    pem_path = sys.argv[1]
    port = int(sys.argv[2])
    asyncio.run(main(pem_path, port))

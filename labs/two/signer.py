import asyncio
import logging
import contextlib
import dataclasses

from ipv8_service import IPv8
from ipv8.configuration import (
    Strategy,
    ConfigBuilder,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8.community import Community, CommunitySettings
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload, convert_to_payload

from common.banner import rule, rows, divider
from common.paths import REPO_ROOT

logging.basicConfig(level=logging.CRITICAL)

COMMUNITY_ID = bytes.fromhex("4c61623247726f75705369676e696e6732303236")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a82e33614a342774e084af80835838d6dbdb64a537d3ddb6c1d82011a7f101553cda40cf5fa0e0fc23abd0a9c4f81322282c5b34566f6b8401f5f683031e60c96"
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)

GROUP_ID = "814ee89d4621f005"

# members in registration order
MEMBER_KEYS_HEX = [
    "4c69624e61434c504b3aa3387dfd20b578dfce201978aea6f25dfa3b3127e6825ce7bd2fb8ce07797f7c8bf427fa376e6eaf58391430e63eb86dc93aebb3f68c89bc9d99c63882034a90",  # pedro
    "4c69624e61434c504b3acb4cf8cd94d4c0b6513dde5ac3e713421243fe03acd9f81c44a3c59d665af57e9372a84599691d8ca03efbe0095cc5eb4a14d68700ab81356a4da03be942c848",  # danil
    "4c69624e61434c504b3af9e8ecfcb5968c5438c65adf621afcb336895329da741ef0e1ff846db37f3a1dd4188afcad7d8f8a890571930a4bb7b982904911437c2aba97922746c5fdb176",  # aditya
]
MEMBER_KEYS = [bytes.fromhex(h) for h in MEMBER_KEYS_HEX]


# initial registration sending the three member public keys to the server
@dataclasses.dataclass
class RegisterGroup(DataClassPayload[1]):
    member1_key: bytes
    member2_key: bytes
    member3_key: bytes


# server reply carrying the assigned group id after registration
@dataclasses.dataclass
class GroupResponse(DataClassPayload[2]):
    success: bool
    group_id: str
    message: str


# request a fresh round nonce from the server during signing
@dataclasses.dataclass
class ChallengeRequest(DataClassPayload[3]):
    group_id: str


# server reply with the round nonce and the budget deadline
@dataclasses.dataclass
class ChallengeResponse(DataClassPayload[4]):
    nonce: bytes
    round_number: int
    deadline: float


# three signatures over the round nonce shipped to the server for verification
@dataclasses.dataclass
class SignatureBundle(DataClassPayload[5]):
    group_id: str
    round_number: int
    sig1: bytes
    sig2: bytes
    sig3: bytes


# server verdict after a bundle submission or an early rejection
@dataclasses.dataclass
class RoundResult(DataClassPayload[6]):
    success: bool
    round_number: int
    rounds_completed: int
    message: str


# submitter forwards the server nonce to teammates so they can sign
@dataclasses.dataclass
class NonceShare(DataClassPayload[100]):
    round_number: int
    nonce: bytes


# teammate sends their signature back to the submitter for bundling
@dataclasses.dataclass
class SignatureShare(DataClassPayload[101]):
    round_number: int
    member_index: int
    signature: bytes


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


# round robin signing community where each member submits one round
class SignerCommunity(Community):
    community_id = COMMUNITY_ID

    # sets up state events handlers and the run rounds task with a short delay
    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.my_member_index = (
            MEMBER_KEYS.index(self.my_peer.public_key.key_to_bin()) + 1
        )
        self.done = asyncio.Event()
        self.current_round = 0
        self.current_nonce: bytes | None = None
        self.signatures: dict[int, bytes] = {}
        self.nonce_event = asyncio.Event()
        self.sigs_event = asyncio.Event()
        self.round_done_event = asyncio.Event()

        for cls, handler in (
            (GroupResponse, self.on_group_response),
            (ChallengeResponse, self.on_challenge_response),
            (RoundResult, self.on_round_result),
            (NonceShare, self.on_nonce_share),
            (SignatureShare, self.on_signature_share),
        ):
            self.add_message_handler(cls, handler)

        self.register_task("run_rounds", self.run_rounds, delay=3.0)

    # filters discovered peers down to the one matching the published server key
    def _server_peer(self):
        for p in self.get_peers():
            if p.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                return p
        return None

    # resolves a teammate peer by their registration index one through three
    def _member_peer(self, index: int):
        target = MEMBER_KEYS[index - 1]
        for p in self.get_peers():
            if p.public_key.key_to_bin() == target:
                return p
        return None

    # clears per round state between iterations so events do not leak
    def _reset_round(self, round_num: int) -> None:
        self.current_round = round_num
        self.current_nonce = None
        self.signatures = {}
        self.nonce_event.clear()
        self.sigs_event.clear()
        self.round_done_event.clear()

    # handler for the registration acknowledgement from the server
    @lazy_wrapper(GroupResponse)
    def on_group_response(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        print(
            f"Registration: success={payload.success} "
            f"group_id={payload.group_id} msg={payload.message}"
        )

    # handler for the server nonce received by the round submitter
    @lazy_wrapper(ChallengeResponse)
    def on_challenge_response(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        if payload.round_number != self.current_round:
            return
        self.current_nonce = payload.nonce
        self.nonce_event.set()

    # handler for the submitter forwarding the nonce to a non submitter
    @lazy_wrapper(NonceShare)
    def on_nonce_share(self, peer, payload):
        if peer.public_key.key_to_bin() not in MEMBER_KEYS:
            return
        if payload.round_number != self.current_round:
            return
        self.current_nonce = payload.nonce
        self.nonce_event.set()

    # handler for a teammate signature received by the submitter
    @lazy_wrapper(SignatureShare)
    def on_signature_share(self, peer, payload):
        if peer.public_key.key_to_bin() not in MEMBER_KEYS:
            return
        if payload.round_number != self.current_round:
            return
        self.signatures[payload.member_index] = payload.signature
        if len(self.signatures) == 3:
            self.sigs_event.set()

    # handler for the server verdict on a bundle or early rejection
    @lazy_wrapper(RoundResult)
    def on_round_result(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        status = "OK" if payload.success else "FAIL"
        print(f"Round {payload.round_number} [{status}]: {payload.message}")
        self.round_done_event.set()

    # blocks the driver until both teammates and the server are discovered
    async def _wait_for_peers(self) -> None:
        teammates = [i for i in (1, 2, 3) if i != self.my_member_index]
        while True:
            if self._server_peer() and all(self._member_peer(i) for i in teammates):
                return
            await asyncio.sleep(0.5)

    # main driver looping the three rounds and dispatching by role
    async def run_rounds(self) -> None:
        rule("LAB 2 SIGNATURE CLIENT")
        rows(
            [("Member Index", self.my_member_index), ("Group ID", GROUP_ID)],
            label_width=14,
        )
        divider()

        await self._wait_for_peers()
        print("Peers Discovered. Starting 3 Rounds.\n")

        start = asyncio.get_event_loop().time()
        for round_num in (1, 2, 3):
            self._reset_round(round_num)
            am_submitter = self.my_member_index == round_num
            role = "submitter" if am_submitter else "signer"
            print(f"Round {round_num} [{role}]")

            if am_submitter:
                await self._submitter_flow(round_num)
            else:
                await self._non_submitter_flow(round_num)

            if not self.round_done_event.is_set():
                print(f"Round {round_num} Did Not Complete: Aborting")
                break

        elapsed = asyncio.get_event_loop().time() - start
        divider()
        rows([("Total Time", f"{elapsed:.2f}s")], label_width=14)
        rule()
        self.done.set()

    # active path requesting challenge sharing nonce collecting sigs and submitting bundle
    async def _submitter_flow(self, round_num: int) -> None:
        server = self._server_peer()
        teammates = [i for i in (1, 2, 3) if i != self.my_member_index]

        while not self.nonce_event.is_set() and not self.round_done_event.is_set():
            self.ez_send(server, ChallengeRequest(GROUP_ID))
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.nonce_event.wait(), timeout=1.0)

        if self.round_done_event.is_set():
            return  # server rejected early

        for idx in teammates:
            peer = self._member_peer(idx)
            if peer:
                self.ez_send(peer, NonceShare(round_num, self.current_nonce))

        self.signatures[self.my_member_index] = self.crypto.create_signature(
            self.my_peer.key, self.current_nonce
        )
        if len(self.signatures) == 3:
            self.sigs_event.set()

        while len(self.signatures) < 3:
            try:
                await asyncio.wait_for(self.sigs_event.wait(), timeout=1.0)
            except TimeoutError:
                for idx in teammates:
                    if idx not in self.signatures:
                        peer = self._member_peer(idx)
                        if peer:
                            self.ez_send(
                                peer, NonceShare(round_num, self.current_nonce)
                            )

        bundle = SignatureBundle(
            GROUP_ID,
            round_num,
            self.signatures[1],
            self.signatures[2],
            self.signatures[3],
        )
        while not self.round_done_event.is_set():
            self.ez_send(server, bundle)
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.round_done_event.wait(), timeout=1.0)

    # passive path waiting for nonce signing and firing the signature three times
    async def _non_submitter_flow(self, round_num: int) -> None:
        await self.nonce_event.wait()

        # fire 3 times for udp loss resilience
        sig = self.crypto.create_signature(self.my_peer.key, self.current_nonce)
        submitter = self._member_peer(round_num)
        if submitter:
            for _ in range(3):
                self.ez_send(
                    submitter, SignatureShare(round_num, self.my_member_index, sig)
                )
                await asyncio.sleep(0.05)

        # non submitters get no server feedback so mark done locally
        self.round_done_event.set()

    # sends the three member public keys to the server to (re)register the group
    def _register_group(self) -> None:
        server = self._server_peer()
        if server is None:
            return
        self.ez_send(
            server, RegisterGroup(MEMBER_KEYS[0], MEMBER_KEYS[1], MEMBER_KEYS[2])
        )


# wires up ipv8 starts the signer community and waits for the round protocol to finish
async def main(pem_path: str, port: int) -> None:
    builder = (
        ConfigBuilder(clean=True)
        .set_port(port)
        .set_address("0.0.0.0")
        .set_log_level("CRITICAL")
        .set_walker_interval(0.5)
        .set_working_directory(REPO_ROOT)
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
        builder.finalize(), extra_communities={"SignerCommunity": SignerCommunity}
    )
    await ipv8.start()

    community = ipv8.get_overlay(SignerCommunity)
    await community.done.wait()
    await ipv8.stop()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print("Usage: python -m labs.two.signer <pem_path> <port>")
        print("Example: python -m labs.two.signer keys/aditya.pem 8091")
        sys.exit(1)

    pem_path = sys.argv[1]
    port = int(sys.argv[2])
    asyncio.run(main(pem_path, port))

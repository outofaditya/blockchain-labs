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
from ipv8.lazy_community import lazy_wrapper
from ipv8.community import Community, CommunitySettings
from ipv8.messaging.payload_dataclass import DataClassPayload, convert_to_payload

from common.paths import REPO_ROOT
from labs.one.miner import EMAIL, GITHUB_URL
from common.banner import rule, rows, section

logging.basicConfig(level=logging.CRITICAL)
COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)


# payload bundling email url and nonce sent to the lab1 server
@dataclasses.dataclass
class SubmissionPayload(DataClassPayload[1]):
    email: str
    github_url: str
    nonce: int


# payload carrying the server verdict after submission
@dataclasses.dataclass
class ResponsePayload(DataClassPayload[2]):
    success: bool
    message: str


convert_to_payload(SubmissionPayload)
convert_to_payload(ResponsePayload)


# ipv8 community that finds the lab1 server and submits the mined nonce
class Lab1Community(Community):
    community_id = COMMUNITY_ID

    # sets up state event handler and the periodic submit task
    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.submitted = False
        self.last_peer_count = 0
        self.nonce: int | None = None
        self.done: asyncio.Event = asyncio.Event()
        self.add_message_handler(ResponsePayload, self.on_response)
        self.register_task(
            "find_and_submit", self.find_and_submit, interval=2.0, delay=3.0
        )

    # scheduled periodically because peer discovery takes time after boot
    async def find_and_submit(self) -> None:
        # bail out before the nonce is supplied or once the submission has fired
        if self.nonce is None or self.submitted:
            return

        # report any change in the discovered peer count so the operator sees progress
        peers = self.get_peers()
        if len(peers) != self.last_peer_count:
            print(f"{'Peers Found':<15}: {len(peers)}")
            self.last_peer_count = len(peers)

        # scan peers for the published server key and send exactly once
        for peer in peers:
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                self.submitted = True
                print(f"{'Server':<15}: {peer.address}")
                self.ez_send(peer, SubmissionPayload(EMAIL, GITHUB_URL, self.nonce))
                return

    # handles the server reply and signals the main coroutine to exit
    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer, payload):
        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY:
            return
        section("SERVER RESPONSE")
        rows([("Success", payload.success), ("Message", payload.message)])
        rule()
        self.done.set()


# wires up ipv8 community and waits for the server response before stopping
async def main(nonce: int) -> None:
    # resolve the key file path from the environment with a default per member
    key_file = os.environ.get("KEY_PATH", os.path.join(REPO_ROOT, "keys", "aditya.pem"))

    # build the ipv8 configuration including the lab1 overlay
    builder = (
        ConfigBuilder(clean=True)
        .set_port(8090)
        .set_address("0.0.0.0")
        .set_log_level("CRITICAL")
        .set_walker_interval(0.5)
        .set_working_directory(REPO_ROOT)
        .add_key("my key", "curve25519", key_file)
        .add_overlay(
            "Lab1Community",
            "my key",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs,
            {},
            [],
        )
    )

    # bootstrap the ipv8 service and start the overlay
    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()

    # bind the nonce on the live overlay so the scheduled task can pick it up
    community = ipv8.get_overlay(Lab1Community)
    community.nonce = nonce

    rule("IPv8 SUBMISSION CLIENT")
    rows(
        [
            ("Key File", key_file),
            ("Public Key", community.my_peer.public_key.key_to_bin().hex()),
            ("Nonce", nonce),
        ]
    )
    section("DISCOVERY AND SUBMISSION")

    # block until the response handler reports the server verdict
    await community.done.wait()
    await ipv8.stop()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python -m labs.one.client <nonce>")
        print("Example: python -m labs.one.client 123456789")
        sys.exit(1)

    nonce = int(sys.argv[1])
    asyncio.run(main(nonce))

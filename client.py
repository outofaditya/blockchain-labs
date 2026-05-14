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
from miner import EMAIL, GITHUB_URL
from ipv8.community import Community, CommunitySettings
from ipv8.messaging.payload_dataclass import DataClassPayload, convert_to_payload

# logging configuration
logging.basicConfig(level=logging.CRITICAL)

# constant variables
_DIR = os.path.dirname(os.path.abspath(__file__))
COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"

# convert the hex string to bytes
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)


# server request payload
# wire types are inferred from the python type annotations
@dataclasses.dataclass
class SubmissionPayload(DataClassPayload[1]):
    email: str
    github_url: str
    nonce: int


# server response payload
# wire types are inferred from the python type annotations
@dataclasses.dataclass
class ResponsePayload(DataClassPayload[2]):
    success: bool
    message: str


# register with IPv8 for serialization and deserialization
convert_to_payload(SubmissionPayload)
convert_to_payload(ResponsePayload)


# community definition
class Lab1Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.submitted = False
        self.nonce: int | None = None
        self.done: asyncio.Event = asyncio.Event()
        self.add_message_handler(ResponsePayload, self.on_response)
        self.register_task(
            "find_and_submit", self.find_and_submit, interval=2.0, delay=3.0
        )

    # find the server and submit the nonce – schedule every 2 seconds
    async def find_and_submit(self) -> None:
        # guard checks
        if self.nonce is None:
            print("Waiting for Nonce")
            return
        if self.submitted:
            return

        peers = self.get_peers()
        print(f"Peers: {len(peers)}")

        # iterate over the peers and find the server
        for peer in peers:
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                self.submitted = True
                print(f"Server: {peer.address}")
                self.ez_send(peer, SubmissionPayload(EMAIL, GITHUB_URL, self.nonce))
                return

        print("Finding Target Server")

    # message handler for the server response
    def on_response(self, source_address: tuple, data: bytes) -> None:
        try:
            auth, _, payload = self._ez_unpack_auth(ResponsePayload, data)
        except Exception as e:
            logging.debug(f"Bad Packet from {source_address}: {e}")
            return
        if auth.public_key_bin != SERVER_PUBLIC_KEY:
            return
        print("\nServer Response")
        print(f"Success: {payload.success}")
        print(f"Message: {payload.message}")
        self.done.set()


async def main(nonce: int) -> None:
    key_file = os.path.join(_DIR, "key.pem")

    # build the start-up IPv8 configuration
    builder = (
        ConfigBuilder(clean=True)
        .set_port(8090)  # UDP port to listen on
        .set_address("0.0.0.0")  # listen on all interfaces
        .set_log_level("CRITICAL")
        .set_walker_interval(0.5)  # interval for peer discovery
        .set_working_directory(_DIR)
        .add_key("my key", "curve25519", key_file)  # load or generate the key pair
        .add_overlay(
            "Lab1Community",
            "my key",
            [WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            default_bootstrap_defs,
            {},
            [],
        )
    )

    # create the IPv8 instance and start it
    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()

    # get the community instance
    community = ipv8.get_overlay(Lab1Community)
    # set the nonce
    community.nonce = nonce

    print("Joining Community and Discovering Peers")
    print(f"Key File: {key_file}")
    print(f"Key: {community.my_peer.public_key.key_to_bin().hex()}\n")

    await community.done.wait()
    await ipv8.stop()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python client.py <nonce>")
        print("Example: python client.py 123456789")
        sys.exit(1)

    nonce = int(sys.argv[1])
    asyncio.run(main(nonce))

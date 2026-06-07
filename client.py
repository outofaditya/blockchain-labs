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
from miner import EMAIL, GITHUB_URL
from ipv8.community import Community, CommunitySettings
from ipv8.messaging.payload_dataclass import DataClassPayload, convert_to_payload

logging.basicConfig(level=logging.CRITICAL)

_DIR = os.path.dirname(os.path.abspath(__file__))
COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")
SERVER_PUBLIC_KEY_HEX = "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac4136c501ce5c09364e0ebb"
SERVER_PUBLIC_KEY = bytes.fromhex(SERVER_PUBLIC_KEY_HEX)


@dataclasses.dataclass
class SubmissionPayload(DataClassPayload[1]):
    email: str
    github_url: str
    nonce: int


@dataclasses.dataclass
class ResponsePayload(DataClassPayload[2]):
    success: bool
    message: str


convert_to_payload(SubmissionPayload)
convert_to_payload(ResponsePayload)


class Lab1Community(Community):
    community_id = COMMUNITY_ID

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

    async def find_and_submit(self) -> None:
        if self.nonce is None or self.submitted:
            return

        peers = self.get_peers()
        if len(peers) != self.last_peer_count:
            print(f"{'Peers Found':<15}: {len(peers)}")
            self.last_peer_count = len(peers)

        for peer in peers:
            if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY:
                self.submitted = True
                print(f"{'Server':<15}: {peer.address}")
                self.ez_send(peer, SubmissionPayload(EMAIL, GITHUB_URL, self.nonce))
                return

    def on_response(self, source_address: tuple, data: bytes) -> None:
        try:
            auth, _, payload = self._ez_unpack_auth(ResponsePayload, data)
        except Exception as e:
            logging.debug(f"Bad Packet from {source_address}: {e}")
            return
        if auth.public_key_bin != SERVER_PUBLIC_KEY:
            return

        print(
            f"{'-' * 80}\nSERVER RESPONSE\n{'-' * 80}\n"
            f"{'Success':<15}: {payload.success}\n"
            f"{'Message':<15}: {payload.message}\n{'=' * 80}"
        )
        self.done.set()


async def main(nonce: int) -> None:
    key_file = os.path.join(_DIR, "key.pem")

    builder = (
        ConfigBuilder(clean=True)
        .set_port(8090)
        .set_address("0.0.0.0")
        .set_log_level("CRITICAL")
        .set_walker_interval(0.5)
        .set_working_directory(_DIR)
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

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()

    community = ipv8.get_overlay(Lab1Community)
    community.nonce = nonce

    print(
        f"{'=' * 80}\nIPv8 SUBMISSION CLIENT\n{'=' * 80}\n"
        f"{'Key File':<15}: {key_file}\n"
        f"{'Public Key':<15}: {community.my_peer.public_key.key_to_bin().hex()}\n"
        f"{'Nonce':<15}: {nonce}\n"
        f"{'-' * 80}\nDISCOVERY AND SUBMISSION\n{'-' * 80}"
    )

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

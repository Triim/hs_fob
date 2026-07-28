import hashlib
from asyncio import run
from dataclasses import dataclass

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import (
    ConfigBuilder,
    Strategy,
    WalkerDefinition,
    default_bootstrap_defs,
)
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayload
from ipv8.peer import Peer
from ipv8.util import run_forever
from ipv8_service import IPv8


NAME = "Ilia Mogilev"
K = 6


def solve_puzzle(name: str, k: int) -> tuple[int, str]:

    x = 0
    target = 1 << (256 - k)

    while True:
        puzzle_input = f"{name}{x}".encode("utf-8")
        digest = hashlib.sha256(puzzle_input).digest()

        if int.from_bytes(digest, byteorder="big") < target:
            return x, digest.hex()

        x += 1


@dataclass
class MyMessage(DataClassPayload[1]):
    text: str


class MyCommunity(Community):
    community_id = b"harbourspaceuniverse"

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)

        self.add_message_handler(MyMessage, self.on_message)

        self.solution, self.digest = solve_puzzle(NAME, K)
        self.sent_to: set[bytes] = set()

        self.message = f"{NAME} {self.solution}"

        print("Puzzle solved")
        print("Input:", f"{NAME}{self.solution}")
        print("Hash:", self.digest)
        print("Message to send:", self.message)

    def started(self) -> None:
        async def send_message() -> None:
            for peer in self.get_peers():
                if peer.mid in self.sent_to:
                    continue

                self.ez_send(peer, MyMessage(self.message))
                self.sent_to.add(peer.mid)

                print(f"Sent to peer: {self.message}")

        self.register_task(
            "send_message",
            send_message,
            interval=2.0,
            delay=0,
        )

    @lazy_wrapper(MyMessage)
    def on_message(self, peer: Peer, payload: MyMessage) -> None:
        print(f"Received from peer: {payload.text}")


async def start_community() -> None:
    builder = ConfigBuilder().clear_keys().clear_overlays()

    builder.add_key(
        "my peer",
        "medium",
        "ec.pem",
    )

    builder.add_overlay(
        "MyCommunity",
        "my peer",
        [
            WalkerDefinition(
                Strategy.RandomWalk,
                10,
                {"timeout": 3.0},
            )
        ],
        default_bootstrap_defs,
        {},
        [("started",)],
    )

    ipv8 = IPv8(
        builder.finalize(),
        extra_communities={
            "MyCommunity": MyCommunity,
        },
    )

    await ipv8.start()
    await run_forever()

run(start_community())
from dataclasses import dataclass
from rsa import PublicKey
from collections.abc import Callable
import rsa, certificate


type Sender = Callable[[ bytes ], ...]
type Receiver = Callable[[], bytes ]

@dataclass
class ClientSeedGenerator:
    ca_public: PublicKey
    server_public: PublicKey

    def send(self, data: bytes, sender: Sender) -> None:

    def receive(self, receiver: Receive) -> bytes:

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
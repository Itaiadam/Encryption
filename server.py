from dataclasses import dataclass
from rsa import PublicKey, PrivateKey
from certificate import Certificate
from collections.abc import Callable
import rsa, certificate

type Sender = Callable[[ bytes ], ... ]
type Receiver = Callable[[], bytes ]

@dataclass
class ServerSeedGenerator:
    certificate: Certificate
    public: PublicKey
    private: PrivateKey

    def send(self, data: bytes, sender: Sender) -> None:
        sender

    def receive(self, receiver: Receive) -> bytes:

    def exchange(self, sender: Sender, receiver: Receiver) -> int:


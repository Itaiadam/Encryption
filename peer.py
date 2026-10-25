from dataclasses import dataclass
from abc import ABC
from rsa import RSA
from certificate import Certificate
from rsa import PublicKey
from collections.abc import Callable
import rsa

type Sender = Callable[[ bytes ], ... ]
type Receiver = Callable[[], bytes ]

@dataclass
class PeerSeedGenerator(ABC):
    ca_public: PublicKey
    certificate: Certificate
    my: RSA
    peer: RSA

    def send(self, data: bytes, sender: Sender):
        encrypted_data = rsa.encrypt_bytes(data, self.peer.peer_public_key)
        sender(rsa.sign_bytes(data, encrypted_data))

    def receive(self, receiver: Receiver) -> bytes:
        pass

    def certification(self, sender: Sender, receiver: Receiver)-> int:
        pass

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
        pass

    def derive(self, sender: Sender, receiver: Receiver) -> int:
        pass

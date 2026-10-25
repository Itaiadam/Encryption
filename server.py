from dataclasses import dataclass
from rsa import PublicKey, PrivateKey
from certificate import Certificate
from collections.abc import Callable
import rsa
from dhe import DHE

type Sender = Callable[[ bytes ], ... ]
type Receiver = Callable[[], bytes ]

def int_to_bytes(value: int) -> bytes:
    """Convert the numeric value itself (not its digits) to bytes."""
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")

@dataclass
class ServerSeedGenerator:
    certificate: Certificate
    public: PublicKey
    private: PrivateKey

    def send(self, data: bytes, sender: Sender) -> None:
        sender(data)
        sender(rsa.sign_bytes(data, self.private))

    def receive(self, receiver: Receiver) -> bytes:
        encrypted_data = receiver()
        data = rsa.decrypt_bytes(encrypted_data, self.private)
        return data

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
        pass

    def certification(self, sender: Sender) -> None:
        sender(self.certificate.dump_base64())

    def derive(self, sender: Sender, receiver: Receiver) -> int:
        self.certification(sender)
        return self.exchange(sender, receiver)

@dataclass
class ServerAutoSeedGenerator(ServerSeedGenerator):

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
        return bytes_to_int(self.receive(receiver))

@dataclass
class ServerDHESeedGenerator(ServerSeedGenerator):
    dhe: DHE

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
        self.send(int_to_bytes(self.dhe.n), sender)
        self.send(int_to_bytes(self.dhe.send()), sender)
        return self.dhe.receive(bytes_to_int(self.receive(receiver)))

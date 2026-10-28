from dataclasses import dataclass
from collections.abc import Callable
import rsa
from rsa import PublicKey
from certificate import Certificate
from dhe import DHE

type Sender = Callable[[bytes], ...]
type Receiver = Callable[[], bytes]

def int_to_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

def bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, "big")

@dataclass
class ClientSeedGenerator:
    ca_public: PublicKey
    server_public: PublicKey = None

    def send(self, data: bytes, sender: Sender) -> None:
        sender(rsa.encrypt_bytes(data, self.server_public))

    def receive(self, receiver: Receiver) -> bytes:
        data = receiver()
        signature = receiver()
        if rsa.verify_bytes(signature, data, self.server_public):
            return data
        raise ValueError("Signature not verified")

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
        pass

    def certification(self, receiver: Receiver) -> None:
        cert = Certificate.load_base64(receiver())
        if cert.verify(self.ca_public):
            self.server_public = cert.public_key
        else:
            raise ValueError("Certificate not verified")

    def derive(self, sender: Sender, receiver: Receiver) -> int:
        self.certification(receiver)
        return self.exchange(sender, receiver)

@dataclass
class ClientAutoSeedGenerator(ClientSeedGenerator):
    seed: int = None

    def exchange(self, sender: Sender, receiver: Receiver = None) -> int:
        if self.seed is None:
            raise ValueError("No seed was chosen")
        self.send(int_to_bytes(self.seed), sender)
        return self.seed

@dataclass
class ClientDHESeedGenerator(ClientSeedGenerator):
    my_public: bytes = None

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
        n = bytes_to_int(self.receive(receiver))
        dhe = DHE(n)
        server_value = bytes_to_int(self.receive(receiver))
        self.my_public = int_to_bytes(dhe.send())
        self.send(self.my_public, sender)
        return dhe.receive(server_value)
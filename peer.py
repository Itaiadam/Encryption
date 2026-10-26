from dataclasses import dataclass
from abc import ABC
from rsa import RSA
from certificate import Certificate
from rsa import PublicKey
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
class PeerSeedGenerator(ABC):
    ca_public: PublicKey
    certificate: Certificate
    my: RSA
    peer: RSA

    def send(self, data: bytes, sender: Sender):
        encrypted_data = rsa.encrypt_bytes(data, self.peer.my_public_key)
        sender(encrypted_data)
        sender(rsa.sign_bytes(encrypted_data, self.my.my_private_key))

    def receive(self, receiver: Receiver) -> bytes:
        encrypted_data = receiver()
        signed_data = receiver()
        if rsa.verify_bytes(signed_data, encrypted_data, self.peer.my_public_key):
            return rsa.decrypt_bytes(encrypted_data, self.my.my_private_key)
        else:
            raise ValueError('Invalid signature')

    def certification(self, sender: Sender, receiver: Receiver)-> int:
        sender(self.certificate.dump_base64())
        peer_certificate = Certificate.load_base64(receiver())
        if peer_certificate.verify(self.ca_public):
            self.peer.my_public_key = peer_certificate.public_key
        else:
            raise ValueError('Invalid signature')

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
        pass

    def derive(self, sender: Sender, receiver: Receiver) -> int:
        self.certification(sender, receiver)
        return self.exchange(sender, receiver)

@dataclass
class PeerAutoSeedGenerator(PeerSeedGenerator):
    seed: int

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
        self.send(int_to_bytes(self.seed), sender)
        peer_seed = bytes_to_int(self.receive(receiver))
        return self.seed * peer_seed


@dataclass
class PeerDHESeedGenerator(PeerSeedGenerator):
    dhe: DHE

    def exchange(self, sender: Sender, receiver: Receiver) -> int:
        my = self.dhe
        self.send(int_to_bytes(my.n), sender)
        peer = DHE(bytes_to_int(self.receive(receiver)))
        self.send(int_to_bytes(my.send()), sender)
        self.send(int_to_bytes(peer.send()), sender)
        peer_result = peer.receive(bytes_to_int(self.receive(receiver)))
        my_result = my.receive(bytes_to_int(self.receive(receiver)))
        return peer_result * my_result



from dataclasses import dataclass
from rsa import PublicKey, PrivateKey
import rsa, json, base64, hashlib

@dataclass
class Certificate:
    public_key: PublicKey
    signature: int

    def verify(self, ca_public_key: PublicKey) -> bool:
        return rsa.verify(digest_public_key(self.public_key), self.signature, ca_public_key)

    def dump_base64(self) -> bytes:
        dic = {"public_key": rsa.dump_public_key(self.public_key).decode(), "signature": self.signature}
        return base64.urlsafe_b64encode(json.dumps(dic).encode())

    @classmethod
    def load_base64(cls, data: bytes) -> "Certificate":
        dic = json.loads(base64.urlsafe_b64decode(data).decode())
        return cls(rsa.load_public_key(dic["public_key"].encode()), dic["signature"])

def digest_public_key(key: PublicKey) -> int:
    return int.from_bytes(hashlib.sha256(json.dumps({"n": key.n, "e": key.e}).encode()).digest(), "big")

def generate_certificate(public_key: PublicKey, ca_private_key: PrivateKey) -> Certificate:
    digest = digest_public_key(public_key)
    signature = rsa.sign(digest, ca_private_key)
    return Certificate(public_key, signature)
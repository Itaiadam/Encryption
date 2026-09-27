import hashlib
from dataclasses import dataclass

@dataclass
class HMAC:
    algorithm: str
    data: bytes
    key: bytes
    size: int = 64

    def hash(self, data: bytes) -> bytes:
        h = hashlib.new(self.algorithm)
        h.update(data)
        return h.digest()

    def sized_key(self):
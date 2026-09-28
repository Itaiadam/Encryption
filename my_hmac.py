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

    def sized_key(self) -> bytes:
        key = self.key
        if len(key) > self.size:
            key = self.hash(key)
        while len(key) < self.size:
            key += bytes(1)
        return key

    def derive(self) -> bytes:
        key = self.sized_key()
        k1, k2 = b"", b""
        for byte in range(len(key)):
            k1 += bytes([key[byte] ^ 0x36])
            k2 += bytes([key[byte] ^ 0x5c])
        code = self.hash(k2 + self.hash(k1 + self.data))
        return code

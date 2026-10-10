import hashlib
from dataclasses import dataclass
import my_hmac

def int_to_bytes(number: int, size: int) -> bytes:
    return number.to_bytes(size, "big")


@dataclass
class KDF:
    algorithm: str
    key: bytes
    size: int

    def hash(self, data: bytes) -> bytes:
        gen = hashlib.new(self.algorithm, data)
        return gen.digest()

    def digest(self, counter: int) -> bytes:
        return self.hash(self.key)

    def derive(self) -> bytes:
        counter, total_size, blocks = 1, 0, []
        while total_size < self.size:
            blocks.append(self.digest(counter))
            total_size += len(blocks[-1])
            counter += 1
        return b"".join(blocks)[:self.size]


@dataclass
class KDF2(KDF):
    def digest(self, counter: int) -> bytes:
        return self.hash(self.key + int_to_bytes(counter, size=4))


@dataclass
class PBKDF2(KDF2):
    salt: bytes
    iterations: int

    @property
    def starter(self) -> bytes:
        return self.key + self.salt

    def digest(self, counter: int) -> bytes:
        result = self.hash(self.starter + int_to_bytes(counter, size=4))
        current = result
        for _ in range(self.iterations - 1):
            current = self.hash(current)
            result_int = int.from_bytes(result, "big") ^ int.from_bytes(current, "big")
            result = int_to_bytes(result_int, size=len(current))
        return result

@dataclass
class PBKDF2HMAC(PBKDF2):
    def hash(self, data: bytes) -> bytes:
        hmac = my_hmac.HMAC(self.algorithm, data, self.key)
        return hmac.derive()

    @property
    def starter(self) -> bytes:
        return self.salt

key = b'secret key'
salt = b'This is a salt'
out = 128

generators = [
    KDF("sha256", key=key, size=out),
    KDF2("sha256", key=key, size=out),
    PBKDF2("sha256", key=key, salt=salt, size=out, iterations=1000),
    PBKDF2HMAC("sha256", key=key, salt=salt, size=out, iterations=1000),
]

for generator in generators:
    print(generator.__class__.__name__)
    d = generator.derive().hex()
    for i in range(0, len(d), 64):
        print(d[i:i+64])
    print()
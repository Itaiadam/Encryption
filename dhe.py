from dataclasses import dataclass
import secrets

@dataclass
class DHE:
    n: int
    g: int = 2
    e: int = None

    def __post_init__(self):
        if self.e is None:
            self.e = 2 + secrets.randbelow(self.n - 3)

    def int_to_bytes(self, size: int, value: int) -> bytes:
        return value.to_bytes(size, "big")

    def bytes_to_int(self, b: bytes) -> int:
        return int.from_bytes(b, "big")

    def send(self) -> int:
        return pow(self.g, self.e, self.n)

    def receive(self, value: int) ->int:
        return pow(value, self.e, self.n)
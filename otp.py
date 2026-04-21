import hashlib

class RBG:
    def __init__(self, seed: bytes):
        self.seed = seed

    def next(self, size: int) -> bytes:
        count = 0
        values = []
        while count < size:
            rb = hashlib.sha256(self.seed).digest()
            self.seed = hashlib.sha256(rb).digest()
            count += len(rb)
            values.append(rb)

        return b''.join(values)[:size]

def otp_encrypt(pt: bytes, key:bytes) -> bytes:
    ct = list()
    for b1, b2 in zip(pt, key):
        ct.append(int(b1) ^ int(b2))
    return bytes(ct)

def otp_decrypt(ct: bytes, key:bytes) -> bytes:
    pt = list()
    for b1, b2 in zip(ct, key):
        pt.append(int(b1) ^ int(b2))
    return bytes(pt)
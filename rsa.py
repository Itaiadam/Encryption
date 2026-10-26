import json, base64, sympy, math
from dataclasses import dataclass

def distant_random_primes(size: int) -> tuple[int, int]:
    while True:
        p = sympy.randprime(2**(size-1), 2**size)
        q = sympy.randprime(2**(size-2), 2**(size-1))
        if (p * q).bit_length() == 2 * size - 2:
            return p,q

@dataclass
class PublicKey:
    n: int
    e: int

@dataclass
class PrivateKey:
    n: int
    d: int

@dataclass
class RSA:
    my_public_key: PublicKey
    my_private_key: PrivateKey
    peer_public_key: PublicKey = None

    def dump_my_public_key(self) -> bytes:
        return dump_public_key(self.my_public_key)

    def load_peer_public_key(self, dumped_public_key: bytes) -> None:
        self.peer_public_key = load_public_key(dumped_public_key)

    def send(self, data: bytes, sign_data: bytes = None) -> bytes:
        dic = {"data": base64.urlsafe_b64encode(data).decode()}
        if sign_data is not None:
            signature = sign_bytes(sign_data, self.my_private_key)
            dic["sign_data"] = base64.urlsafe_b64encode(sign_data).decode()
            dic["signature"] = base64.urlsafe_b64encode(signature).decode()
        return encrypt_bytes(json.dumps(dic).encode(), self.peer_public_key)

    def receive(self, encrypted_data: bytes, verify: bool = True) -> bytes:
        data = json.loads(decrypt_bytes(encrypted_data, self.my_private_key))
        if verify:
            if "signature" not in data:
                raise ValueError("Message has no signature")
            signature = base64.urlsafe_b64decode(data["signature"])
            sign_data = base64.urlsafe_b64decode(data["sign_data"])
            if not verify_bytes(signature, sign_data, self.peer_public_key):
                raise ValueError("Signature doesn't match the signed data")
        return base64.urlsafe_b64decode(data["data"])

def rsa_keys(primes: tuple[int, int]) -> tuple[PublicKey, PrivateKey]:
    n = primes[0] * primes[1]
    phi = (primes[0] - 1) * (primes[1] - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = pow(e, -1, phi)
    return PublicKey(n, e), PrivateKey(n, d)

def encrypt(data: int, key: PublicKey) -> int:
    return pow(data, key.e, key.n)

def decrypt(data: int, key: PrivateKey) -> int:
    return pow(data, key.d, key.n)

def sign(data: int, key: PrivateKey) -> int:
    return pow(data, key.d, key.n)

def verify(data: int, signature: int, key: PublicKey) -> bool:
    return data == pow(signature, key.e, key.n)

def _bytes_to_ints(data: bytes, n: int) -> list[int]:
    size = (n.bit_length() - 1) // 8
    padded = data + b"\x01"
    padded += b"\x00" * (-len(padded) % size)
    return [int.from_bytes(padded[i:i + size], "big") for i in range(0, len(padded), size)]

def sign_bytes(data: bytes, key: PrivateKey) -> bytes:
    int_list = _bytes_to_ints(data, key.n)
    signature_list = [sign(chunk, key) for chunk in int_list]
    json_list = json.dumps(signature_list).encode()
    return base64.urlsafe_b64encode(json_list)

def encrypt_bytes(data: bytes, key: PublicKey) -> bytes:
    int_list = _bytes_to_ints(data, key.n)
    encrypt_list = [encrypt(chunk, key) for chunk in int_list]
    json_list = json.dumps(encrypt_list).encode()
    return base64.urlsafe_b64encode(json_list)

def decrypt_bytes(data: bytes, key: PrivateKey) -> bytes:
    json_list = base64.urlsafe_b64decode(data).decode()
    decrypt_list = json.loads(json_list)
    int_list = [decrypt(chunk, key) for chunk in decrypt_list]
    size = (key.n.bit_length() - 1) // 8
    data = b"".join(chunk.to_bytes(size, "big") for chunk in int_list)
    return data.rstrip(b"\x00")[:-1]

def verify_bytes(signature: bytes, data: bytes, key: PublicKey) -> bool:
    signatures = json.loads(base64.urlsafe_b64decode(signature))
    int_list = _bytes_to_ints(data, key.n)
    if len(int_list) != len(signatures):
        return False
    return all(verify(num, sig, key) for num, sig in zip(int_list, signatures))

def dump_public_key(key: PublicKey) -> bytes:
    return base64.urlsafe_b64encode(json.dumps({"n": key.n, "e": key.e}).encode())

def load_public_key(data: bytes) -> PublicKey:
    key_dict = json.loads(base64.urlsafe_b64decode(data))
    return PublicKey(key_dict["n"], key_dict["e"])


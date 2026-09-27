from abc import ABC, abstractmethod
from dataclasses import dataclass
import secrets
import aes
from otp_udp_peer_2 import encrypted_message

Size = 16
Key = secrets.token_bytes(Size)
IV = secrets.token_bytes(Size)
Nonce = secrets.token_bytes(Size // 2)

class PKCS7:

    # Pads the last block into a 16 sized one.
    @staticmethod
    def pad(data: bytes, size: int = 16) -> bytes:
        pad_len = size - (len(data) % size)
        return data + bytes([pad_len]) * pad_len

    @staticmethod
    def unpad(data: bytes) -> bytes:
        return data[:-data[-1]]

def split_chunks(data: bytes, size: int = 16):
    for i in range(0, len(data), size):
        yield data[i:i + size]

@dataclass
class AES_Modes(ABC):
    key: bytes = Key

    @abstractmethod
    def encrypt(self, pt: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, ct: bytes) -> bytes:
        pass

@dataclass
class ECB(AES_Modes):
    def encrypt(self, pt: bytes) -> bytes:
        padded_pt = PKCS7.pad(pt, Size)
        chunks_list = list(split_chunks(padded_pt, Size))
        ct = b""
        for chunk in chunks_list:
            ct += aes.aes128_encrypt(self.key, chunk)
        return ct

    def decrypt(self, ct: bytes) -> bytes:
        chunks_list = list(split_chunks(ct, Size))
        pt = b""
        for chunk in chunks_list:
            pt += aes.aes128_decrypt(self.key, chunk)
        unpadded_pt = PKCS7.unpad(pt)
        return unpadded_pt

@dataclass
class CBC(AES_Modes):
    iv: bytes = IV

    def encrypt(self, pt: bytes) -> bytes:
        padded_pt = PKCS7.pad(pt, Size)
        chunks_list = list(split_chunks(padded_pt, Size))
        ct, xor_chunk = b"", b""
        prev_block = self.iv
        for chunk in chunks_list:
            for byte in range(16):
                xor_chunk += bytes([chunk[byte] ^ prev_block[byte]])
            ct_block = aes.aes128_encrypt(self.key, xor_chunk)
            ct += ct_block
            prev_block = ct_block
            xor_chunk = b""
        return ct

    def decrypt(self, ct: bytes) -> bytes:
        chunks_list = list(split_chunks(ct, Size))
        xor_chunk, pt = b"", b""
        prev_block = self.iv
        for chunk in chunks_list:
            pt_block = aes.aes128_decrypt(self.key, chunk)
            for byte in range(16):
                xor_chunk += bytes([pt_block[byte] ^ prev_block[byte]])
            pt += xor_chunk
            prev_block = chunk
            xor_chunk = b""
        unpadded_pt = PKCS7.unpad(pt)
        return unpadded_pt

@dataclass
class CFB(AES_Modes):
    iv: bytes = IV

    def encrypt(self, pt: bytes) -> bytes:
        padded_pt = PKCS7.pad(pt, Size)
        chunks_list = list(split_chunks(padded_pt, Size))
        xor_chunk, ct = b"", b""
        prev_block = self.iv
        for chunk in chunks_list:
            encrypted_prev_block = aes.aes128_encrypt(self.key, prev_block)
            for byte in range(16):
                xor_chunk += bytes([encrypted_prev_block[byte] ^ chunk[byte]])
            ct += xor_chunk
            prev_block = xor_chunk
            xor_chunk = b""
        return ct

    def decrypt(self, ct: bytes) -> bytes:
        chunks_list = list(split_chunks(ct, Size))
        xor_chunk, pt = b"", b""
        prev_block = self.iv
        for chunk in chunks_list:
            encrypted_prev_block = aes.aes128_encrypt(self.key, prev_block)
            for byte in range(16):
                xor_chunk += bytes([encrypted_prev_block[byte] ^ chunk[byte]])
            pt += xor_chunk
            xor_chunk = b""
            prev_block = chunk
        unpadded_pt = PKCS7.unpad(pt)
        return unpadded_pt

@dataclass
class OFB(AES_Modes):
    iv: bytes = IV

    def encrypt(self, pt: bytes) -> bytes:
        padded_pt = PKCS7.pad(pt, Size)
        chunks_list = list(split_chunks(padded_pt, Size))
        xor_chunk, ct = b"", b""
        prev_block = self.iv
        for chunk in chunks_list:
            encrypted_prev_block = aes.aes128_encrypt(self.key, prev_block)
            for byte in range(16):
                xor_chunk += bytes([encrypted_prev_block[byte] ^ chunk[byte]])
            ct += xor_chunk
            prev_block = encrypted_prev_block
            xor_chunk = b""
        return ct

    def decrypt(self, ct: bytes) -> bytes:
        chunks_list = list(split_chunks(ct, Size))
        xor_chunk, pt = b"", b""
        prev_block = self.iv
        for chunk in chunks_list:
            encrypted_prev_block = aes.aes128_encrypt(self.key, prev_block)
            for byte in range(16):
                xor_chunk += bytes([encrypted_prev_block[byte] ^ chunk[byte]])
            pt += xor_chunk
            xor_chunk = b""
            prev_block = encrypted_prev_block
        unpadded_pt = PKCS7.unpad(pt)
        return unpadded_pt

@dataclass
class CTR(AES_Modes):
    nonce: bytes = Nonce

    def encrypt(self, pt: bytes) -> bytes:
        padded_pt = PKCS7.pad(pt, Size)
        chunks_list = list(split_chunks(padded_pt, Size))
        xor_chunk, ct = b"", b""
        for i, chunk in enumerate(chunks_list):
            encrypted_block = aes.aes128_encrypt(self.key, self.nonce + i.to_bytes(8, "big"))
            for byte in range(16):
                xor_chunk += bytes([encrypted_block[byte] ^ chunk[byte]])
            ct += xor_chunk
            xor_chunk = b""
        return ct

    def decrypt(self, ct: bytes) -> bytes:
        chunks_list = list(split_chunks(ct, Size))
        xor_chunk, pt = b"", b""
        for i, chunk in enumerate(chunks_list):
            encrypted_block = aes.aes128_encrypt(self.key, self.nonce + i.to_bytes(8, "big"))
            for byte in range(16):
                xor_chunk += bytes([encrypted_block[byte] ^ chunk[byte]])
            pt += xor_chunk
            xor_chunk = b""
        unpadded_pt = PKCS7.unpad(pt)
        return unpadded_pt
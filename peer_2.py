import dhe
import socket
import shlex

IP = "127.0.0.1"
PORT = 5555
LABEL = b"public value: "

peer2 = socket.socket()
peer2.connect((IP, PORT))

n = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
g = 2
dh = dhe.DHE(n, g)
size = (n.bit_length() + 7) // 8

encoded_out: bytes = b"modulus: " + dh.int_to_bytes(size, n) + b"base: " + dh.int_to_bytes(size, g) + b"public value: " + dh.int_to_bytes(size, dh.send())
peer2.sendall(encoded_out)

data: bytes = peer2.recv(2048)
public_value: int = dh.bytes_to_int(data[len(LABEL):])
print(f"Peer1's public_value: {public_value}")

shared_key = dh.receive(public_value)
print(f"Shared Key: {shared_key}")

peer2.close()
print("Connection Closed.")
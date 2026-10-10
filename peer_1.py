import dhe
import socket

IP = "127.0.0.1"
PORT = 5555

peer1 = socket.socket()
peer1.bind((IP, PORT))
peer1.listen(1)
peer2, addr = peer1.accept()

SIZE = 256
MODULUS_LABEL = b"modulus: "
BASE_LABEL = b"base: "
PUBLIC_VALUE_LABEL = b"public value: "

data = peer2.recv(2048)

position = len(MODULUS_LABEL)
n = int.from_bytes(data[position : position + SIZE], "big")
position += len(BASE_LABEL) + SIZE
g = int.from_bytes(data[position : position + SIZE], "big")
position += len(PUBLIC_VALUE_LABEL) + SIZE
public_value = int.from_bytes(data[position : position + SIZE], "big")

print(f"Peer2's public value: {public_value}")
dh = dhe.DHE(n, g)
shared_key = dh.receive(public_value)
print(f"Shared Key: {shared_key}")

size = (n.bit_length() + 7) // 8

encoded_out: bytes = b"public value: " + dh.int_to_bytes(size, dh.send())
peer2.sendall(encoded_out)




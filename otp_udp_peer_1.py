import socket
import otp

IP = "192.168.68.51"
PORT = 5555
ADDRESS = (IP, PORT)
SEED = b"seed_seed_seed"
SIZE = 64
KEY = otp.RBG(SEED).next(SIZE)

server = socket.socket(type=socket.SOCK_DGRAM)

server.bind(ADDRESS)

BUFFER = 2048

while True:
    received, addr = server.recvfrom(BUFFER)
    received_decrypted = otp.otp_decrypt(received, KEY).decode()
    if received_decrypted == "stop connection" or not received_decrypted:
        break
    print(f"Received from {addr}: {received_decrypted}")
    message = input("Enter a message: ")
    encrypted_message = otp.otp_encrypt(message.encode(), KEY)
    server.sendto(encrypted_message, addr)
    if not message or message == "stop connection":
        break


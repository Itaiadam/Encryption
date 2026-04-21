import socket
import otp

IP = "192.168.68.51"
SERVER_PORT = 5555
CLIENT_PORT = 5556
ADDRESS = (IP, SERVER_PORT)
SEED = b"seed_seed_seed"
SIZE = 64
KEY = otp.RBG(SEED).next(SIZE)

client = socket.socket(type=socket.SOCK_DGRAM)

client.bind((IP, CLIENT_PORT))

BUFFER = 2048

while True:
    message = input("Enter a message: ")
    encrypted_message = otp.otp_encrypt(message.encode(), KEY)
    client.sendto(encrypted_message, ADDRESS)
    if not message or message == "stop connection":
        break
    received, addr = client.recvfrom(BUFFER)
    received_decrypted = otp.otp_decrypt(received, KEY).decode()
    if received_decrypted == "stop connection" or not received_decrypted:
        break
    print(f"Received from {addr}: {received_decrypted}")



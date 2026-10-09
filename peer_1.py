import dhe
import socket

from otp_udp_peer_1 import received

PORT = 9999
IP = "127.0.0.1"
ADDRESS = (IP, PORT)

server = socket.socket()
server.bind(ADDRESS)
server.listen()
server.accept()
received, addr = server.recvfrom(2048)



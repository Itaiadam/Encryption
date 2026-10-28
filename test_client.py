import rsa, socket, client as client_module, hmac
from kdf import PBKDF2HMAC_DRBG
from aes_modes import CBC
from my_hmac import HMAC

CA_PUBLIC = rsa.PublicKey(n=29220375997813350083278338607879541229804718703569575219004658786852186214053691610899857738173833101541981664676820397058550831191561578453054949962727521296357479486481112658394390902408571279715496453156831571729473098438430176277485695014133918328368543207963825852083074695989797906145149036950036228995501199971842860748900398534687436766811995398913837106879632501437600217549423753958596903114842255830521477068520101934509934520575089151006005951441198872714138469197375139246002178104928884876278588042278544704706180461207483591482177451669313083355605898518281092982965421633108926949348640285019707703347, e=65537)

LENGTH_SIZE = 4

def send(sock: socket.socket, data: bytes) -> None:
    sock.sendall(len(data).to_bytes(LENGTH_SIZE, "big") + data)

def receive_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed before the full message arrived")
        data += chunk
    return data

def receive(sock: socket.socket) -> bytes:
    length = int.from_bytes(receive_exact(sock, LENGTH_SIZE), "big")
    return receive_exact(sock, length)

IP = "127.0.0.1"
PORT = 5555

client = socket.socket()
client.connect((IP, PORT))

generator = client_module.ClientDHESeedGenerator(CA_PUBLIC)
seed = generator.derive(lambda data: send(client, data), lambda: receive(client))

drbg = PBKDF2HMAC_DRBG("sha256", client_module.int_to_bytes(seed), 16, generator.my_public, 1000)

keys_dict: dict[str, bytes] = {"AES1": b"", "AES2": b"", "IV1": b"", "IV2": b"", "HMAC1": b"", "HMAC2": b""}
for key in keys_dict:
    keys_dict[key] = drbg.generate(16)

cbc_encrypt = CBC(keys_dict["AES1"], keys_dict["IV1"])
cbc_decrypt = CBC(keys_dict["AES2"], keys_dict["IV2"])

while True:
    message = input("Enter a message: ")
    encoded_out: bytes = message.encode()
    ciphertext = cbc_encrypt.encrypt(encoded_out)
    send(client, ciphertext + HMAC("sha256", ciphertext, keys_dict["HMAC1"]).derive())

    if message == "stop connection":
        break

    try:
        encoded_in: bytes = receive(client)
    except ConnectionError:
        print("Server closed the connection.")
        break
    ciphertext, tag = encoded_in[:-32], encoded_in[-32:]
    expected = HMAC("sha256", ciphertext, keys_dict["HMAC2"]).derive()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("HMAC check failed: message was changed or forged")
    plaintext = cbc_decrypt.decrypt(ciphertext)
    decoded_in: str = plaintext.decode()
    print(f"Server responded: {decoded_in}")

    if decoded_in == "stop connection":
        break

client.close()
print("Client closed.")

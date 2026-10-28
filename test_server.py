import rsa, certificate, socket, server as servr, hmac
from dhe import DHE
from kdf import PBKDF2HMAC_DRBG
from aes_modes import CBC
from my_hmac import HMAC

SERVER_PUBLIC = rsa.PublicKey(n=119245967775431683909420740576542004741376850140944989314756772449749647091702332403714983387597498481447193876036567798209396314105950935729860834321132794523958352517626225567928699740053919585955247443783957120091794341251650470268672672831613309537675034335283002151454754356741823664364457720727072540499, e=65537)
SERVER_PRIVATE = rsa.PrivateKey(n=119245967775431683909420740576542004741376850140944989314756772449749647091702332403714983387597498481447193876036567798209396314105950935729860834321132794523958352517626225567928699740053919585955247443783957120091794341251650470268672672831613309537675034335283002151454754356741823664364457720727072540499, d=75883136031163745326188137780867056895175573113326987493659020019482262416031337609242616875654266661103731031327419015583912496449161294758897204561741340314373870251655511442219658476642735335735840792419499158183858523414554492099115579414220934799299446115461523693350122667622894932892389140165797396673)

CERTIFICATE = certificate.Certificate(SERVER_PUBLIC, signature=14662592585677011780197686157386262682310003090287225368210356536020199241127395803392329519405619674045134206102840984576560892270683077100118500191520837210160934130319740506646998396514981702488435606309592538308111864291408978364408822756148797161312482021015373943035258444856616264972330464822272770651601814477552400466077419290937774407722303042825016252727042584023134246757253083531904498199106805920251516797264742945156405563629291943886292856641796251054182049014083692223690491774706095617360048612599185512526395769434031565262082034243843262234961055373515150386896899028422852881723061004302244035745)

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

DHE_N = int(
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

IP ="127.0.0.1"
PORT = 5555

def handle_client(client: socket.socket, client_address) -> None:
    generator = servr.ServerDHESeedGenerator(CERTIFICATE, SERVER_PUBLIC, SERVER_PRIVATE, DHE(DHE_N))
    seed = generator.derive(lambda data: send(client, data), lambda: receive(client))

    drbg = PBKDF2HMAC_DRBG("sha256", servr.int_to_bytes(seed), 16, generator.client_public, 1000)

    keys_dict: dict[str, bytes] = {"AES1": b"", "AES2": b"", "IV1": b"", "IV2": b"", "HMAC1": b"", "HMAC2": b""}
    for key in keys_dict:
        keys_dict[key] = drbg.generate(16)

    cbc_encrypt = CBC(keys_dict["AES2"], keys_dict["IV2"])
    cbc_decrypt = CBC(keys_dict["AES1"], keys_dict["IV1"])

    while True:
        try:
            encoded_in: bytes = receive(client)
        except ConnectionError:
            print("Client closed the connection.")
            break
        ciphertext, tag = encoded_in[:-32], encoded_in[-32:]
        expected = HMAC("sha256", ciphertext, keys_dict["HMAC1"]).derive()
        if not hmac.compare_digest(tag, expected):
            raise ValueError("HMAC check failed: message was changed or forged")
        plaintext = cbc_decrypt.decrypt(ciphertext)
        decoded_in: str = plaintext.decode()

        if decoded_in == "stop connection":
            print("Client requested to close connection.")
            break

        print(f"{client_address}: {decoded_in}")

        response = input("Send back a message: ")
        encoded_out: bytes = response.encode()
        ciphertext = cbc_encrypt.encrypt(encoded_out)
        send(client, ciphertext + HMAC("sha256", ciphertext, keys_dict["HMAC2"]).derive())

        if response == "stop connection":
            print("Server requested to close connection.")
            break

    client.close()

def main():
    server = socket.socket()
    server.bind((IP, PORT))
    server.listen()

    while True:
        client, client_address = server.accept()
        handle_client(client, client_address)

if __name__ == "__main__":
    main()

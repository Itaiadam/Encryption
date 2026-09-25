import hashlib
import secrets
import base64

USER_TABLE: list[tuple[int, str, str]] = []
SIZE: int = 16
PEPPER: bytes = secrets.token_bytes(SIZE)


def write_user(user: str, digest: str) -> None:
    for user_row in USER_TABLE:
        if user_row[1] == user:
            raise ValueError("User already exists")
    USER_TABLE.append((len(USER_TABLE), user, digest))


def read_user(user: str) -> tuple[int, str, str]:
    for user_row in USER_TABLE:
        if user_row[1] == user:
            return user_row
    raise ValueError("User doesn't exist")


def read_all_users():
    for user_row in USER_TABLE:
        yield user_row


def sign_up(user: str, password: str) -> None:
    salt: bytes = secrets.token_bytes(SIZE)
    password_bytes = password.encode('utf-8')
    digest = hashlib.sha256(password_bytes + salt + PEPPER).digest()
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    digest_b64 = base64.b64encode(digest).decode('utf-8')
    record_string = f"sha256${salt_b64}${digest_b64}"
    write_user(user=user, digest=record_string)


def authenticate(user: str, password: str) -> bool:
    try:
        user_row = read_user(user)
    except ValueError:
        return False
    password_bytes = password.encode('utf-8')
    user_split = user_row[2].split('$')
    salt_b64 = user_split[1]
    saved_digest_b64 = user_split[2]
    salt = base64.b64decode(salt_b64)
    new_digest = hashlib.sha256(password_bytes + salt + PEPPER).digest()
    new_digest_b64 = base64.b64encode(new_digest).decode('utf-8')
    return secrets.compare_digest(new_digest_b64, saved_digest_b64)


if __name__ == "__main__":
    sign_up(user="israeli_broker", password="my_password123")
    sign_up(user="user2", password="another_pass")
    print(authenticate(user="user2", password="another_pass"))

    for row in read_all_users():
        print(row)
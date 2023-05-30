from hashlib import sha256


def hash_pass(password: str) -> int:
    hash_user_0 = sha256()
    hash_user_0.update(password.encode())
    return int(hash_user_0.hexdigest(), 16)

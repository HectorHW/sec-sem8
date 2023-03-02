from sec_sem8.entities import PasswordHash
from sec_sem8.impl import Sha1Hasher


def solve_task(pasword_hash: PasswordHash, nonce: str) -> PasswordHash:
    hasher = Sha1Hasher()
    return hasher(pasword_hash + nonce)

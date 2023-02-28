from pydantic import BaseModel
from sec_sem8.entities import PasswordHash
from sec_sem8.impl import Sha1Hasher


class AuthRequest(BaseModel):
    username: str


class AuthTask(BaseModel):
    nonce: str


class AuthAnswer(BaseModel):
    username: str
    hash: PasswordHash


def solve_task(pasword_hash: PasswordHash, nonce: str) -> PasswordHash:
    hasher = Sha1Hasher()
    return hasher(pasword_hash + nonce)


class DiffieHellmanParameters(BaseModel):
    p: int
    g: int


class KeypairSetupAnswer(BaseModel):
    auth_data: AuthAnswer
    user_pub_value: int

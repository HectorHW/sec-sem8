from fastapi import FastAPI, HTTPException
from sec_sem8.messages import (
    AuthRequest,
    AuthTask,
    AuthAnswer,
    solve_task,
    DiffieHellmanParameters,
    KeypairSetupAnswer,
)
from sec_sem8.impl import SqliteDatabase
from expiringdict import ExpiringDict
import random
import uvicorn
from functools import cache
from typing import Dict
from primes import get_random
from pydantic import BaseModel

app = FastAPI()

database = SqliteDatabase("users.sqlite")

nonces = ExpiringDict(max_age_seconds=60, max_len=10_000)


class PreparedKey(BaseModel):
    private_key: int
    public_value: int


class InitializedKey(BaseModel):
    key: int


keypairs: Dict[str, PreparedKey | InitializedKey] = {}


@cache
def get_diffie_hellman_params() -> DiffieHellmanParameters:
    from sec_sem8.primes import get_random_prime
    from sec_sem8.diffie_hellman import find_primitive_root

    prime = get_random_prime(64)
    g = find_primitive_root(32, prime)
    return DiffieHellmanParameters(p=prime, g=g)


@app.post("/auth_request")
def request_auth_data(req: AuthRequest) -> AuthTask:
    maybe_user = database.find_user(req.username)

    if maybe_user is None:
        raise HTTPException(404)
    nonce = random.randbytes(32).hex()
    nonces[maybe_user.username] = nonce

    return AuthTask(nonce=nonce)


def check_auth(data: AuthAnswer) -> bool:
    username, provided = data.username, data.hash
    maybe_used_nonce = nonces.get(username)
    if maybe_used_nonce is None:
        return False
    user = database.find_user(username)
    assert user is not None
    expected = solve_task(user.password_hash, maybe_used_nonce)  # type: ignore
    del nonces[username]
    return expected == provided


@app.post("/auth_answer")
def answer_challenge(req: AuthAnswer):
    if check_auth(req):
        username = req.username
        diffie_params = get_diffie_hellman_params()
        # A = g^a mod p

        private_a = get_random(62)
        public_a = pow(int(diffie_params.g), private_a, int(diffie_params.p))

        keypairs[username] = PreparedKey(private_key=private_a, public_value=public_a)
        return public_a
    else:
        raise HTTPException(403)


@app.get("/diffie_params")
def diffie_hellman_params() -> DiffieHellmanParameters:
    return get_diffie_hellman_params()


@app.post("/setup_keypair")
def setup_keypair(req: KeypairSetupAnswer):
    if not check_auth(req.auth_data):
        raise HTTPException(status_code=403)
    if keypairs.get(req.auth_data.username) is None or not isinstance(
        keypairs[req.auth_data.username], PreparedKey
    ):
        raise HTTPException(
            status_code=404,
            detail="you need to request auth params first via /auth_answer",
        )
    diffie_params = get_diffie_hellman_params()
    prepared_key: PreparedKey = keypairs[req.auth_data.username]  # type: ignore
    shared_key = pow(req.user_pub_value, prepared_key.private_key, diffie_params.p)
    keypairs[req.auth_data.username] = InitializedKey(key=shared_key)
    print("shared key for", req.auth_data.username, "is", shared_key)
    return "ok"


async def set_body(request, body: bytes):
    async def receive():
        return {"type": "http.request", "body": body}

    request._receive = receive


async def get_body(request) -> bytes:
    body = await request.body()
    await set_body(request, body)
    return body


@app.middleware("http")
async def app_entry(request, call_next):
    await set_body(request, await request.body())

    print(await get_body(request))

    response = await call_next(request)
    return response


if __name__ == "__main__":
    print("initializing diffie-hellman parameters")
    get_diffie_hellman_params()
    uvicorn.run(app, host="0.0.0.0", port=8080)

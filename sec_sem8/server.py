from fastapi import FastAPI, HTTPException
from sec_sem8.messages import AuthRequest, AuthTask, AuthAnswer, solve_task
from sec_sem8.impl import SqliteDatabase
from expiringdict import ExpiringDict
import random
import uvicorn

app = FastAPI()

database = SqliteDatabase("users.sqlite")

nonces = ExpiringDict(max_age_seconds=60, max_len=10_000)


@app.post("/auth_request")
def request_auth_data(req: AuthRequest) -> AuthTask:
    maybe_user = database.find_user(req.username)

    if maybe_user is None:
        raise HTTPException(404)
    nonce = random.randbytes(32).hex()
    nonces[maybe_user.username] = nonce

    return AuthTask(nonce=nonce)


@app.post("/auth_answer")
def answer_challenge(req: AuthAnswer):
    username, provided = req.username, req.hash
    maybe_used_nonce = nonces.get(username)
    if maybe_used_nonce is None:
        return HTTPException(403)

    user = database.find_user(username)
    assert user is not None

    expected = solve_task(user.password_hash, maybe_used_nonce)  # type: ignore
    del nonces[username]

    if provided == expected:
        return "ok"
    raise HTTPException(403)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)

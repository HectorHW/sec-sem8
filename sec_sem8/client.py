import PySimpleGUI as sg
import httpx
from sec_sem8 import messages, impl
from typing import Callable, Any
from sec_sem8.diffie_hellman import get_random

fontsize = 35


username_form = sg.InputText(key="username", font=fontsize)
password_form = sg.InputText(key="password", password_char="*", font=fontsize)


form = [
    [sg.Text("username: ", font=fontsize), username_form],
    [sg.Text("password: ", font=fontsize), password_form],
    [sg.Button("login", key="LOGIN", font=fontsize)],
]

window = sg.Window(title="client", layout=form, font=fontsize)

hasher = impl.Sha1Hasher()


def post_with_logging(path, body):
    print("post to", path, "with", body)
    resp = httpx.post(
        path,
        json=body.dict(),
    )
    print("answer:", resp.json())
    return resp


def send_authenticated_request(
    path: str, username: str, password: str, body: Callable[[messages.AuthAnswer], Any]
):
    maybe_nonce = post_with_logging(
        "http://localhost:8080/auth_request",
        messages.AuthRequest(username=username),
    )
    if maybe_nonce.status_code != 200:
        return maybe_nonce
    task = messages.AuthTask.parse_obj(maybe_nonce.json())
    password_hash = hasher(password)
    hash_solution = messages.solve_task(password_hash, task.nonce)
    answer = messages.AuthAnswer(username=username, hash=hash_solution)

    req_body = body(answer)
    return post_with_logging(f"http://localhost:8080/{path}", req_body)


def get_diffie_hellman_params() -> messages.DiffieHellmanParameters:
    return messages.DiffieHellmanParameters.parse_obj(
        httpx.get(
            "http://localhost:8080/diffie_params",
        ).json()
    )


while True:
    event, data = window.read()  # type: ignore
    if event == sg.WIN_CLOSED:
        break
    if event == "LOGIN":
        username = data["username"].strip()
        password = data["password"]
        if not username:
            sg.Popup("username cannot be empty")
            continue
        if not password:
            sg.Popup("password cannot be empty")
            continue

        resp = send_authenticated_request(
            "auth_answer",
            username=username,
            password=password,
            body=lambda auth: auth,
        )

        if resp.status_code == 404:
            sg.Popup("unknown user")
            continue

        if resp.status_code != 200:
            print(resp.json())
            sg.Popup("incorrect password")
            continue

        server_public_value = int(resp.json())
        diffie_params = get_diffie_hellman_params()

        client_private_key = get_random(62)
        client_pub_value = pow(diffie_params.g, client_private_key, diffie_params.p)
        shared_secret = pow(server_public_value, client_private_key, diffie_params.p)

        resp = send_authenticated_request(
            "setup_keypair",
            username=username,
            password=password,
            body=lambda auth: messages.KeypairSetupAnswer(
                auth_data=auth, user_pub_value=client_pub_value
            ),
        )

        if resp.status_code == 200:
            sg.Popup(f"auth successful\nshared key: {shared_secret}")

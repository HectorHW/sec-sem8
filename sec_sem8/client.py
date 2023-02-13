import PySimpleGUI as sg
import httpx
from sec_sem8 import messages, impl
import pydantic

username_form = sg.InputText(key="username")
password_form = sg.InputText(key="password", password_char="*")

form = [
    [sg.Text("username: "), username_form],
    [sg.Text("password: "), password_form],
    [sg.Button("login", key="LOGIN")],
]

window = sg.Window(title="client", layout=form)

hasher = impl.Sha1Hasher()

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

        req = messages.AuthRequest(username=username)

        maybe_nonce = httpx.post("http://localhost:8080/auth_request", json=req.dict())
        if maybe_nonce.status_code != 200:
            sg.Popup("unknown user")
            continue

        task = messages.AuthTask.parse_obj(maybe_nonce.json())

        password_hash = hasher(password)

        hash_solution = messages.solve_task(password_hash, task.nonce)

        answer = messages.AuthAnswer(username=username, hash=hash_solution)

        maybe_ok = httpx.post("http://localhost:8080/auth_answer", json=answer.dict())

        if maybe_ok.status_code == 200:
            sg.Popup("auth successful")
        else:
            sg.Popup("incorrect password")

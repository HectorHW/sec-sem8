import PySimpleGUI as sg
from sec_sem8.impl import Sha1Hasher

from sec_sem8.connection.active_connection import (
    ActiveConnection,
    UnknownUserError,
    IncorrectPasswordError,
)

fontsize = 35


username_form = sg.InputText(key="username", font=fontsize)
password_form = sg.InputText(key="password", password_char="*", font=fontsize)


form = [
    [sg.Text("username: ", font=fontsize), username_form],
    [sg.Text("password: ", font=fontsize), password_form],
    [sg.Button("login", key="LOGIN", font=fontsize)],
]

window = sg.Window(title="client", layout=form, font=fontsize)

hasher = Sha1Hasher()

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

        class user(object):
            username = username
            password_hash = hasher(password)

        conn = ActiveConnection(user)  # type: ignore

        try:
            ok = conn.handshake()
            sg.Popup(f"established connection, shared key: {ok.key}")
        except UnknownUserError:
            sg.Popup(f"unknown user")
        except IncorrectPasswordError:
            sg.Popup("incorrect password")
        except ValueError as e:
            sg.Popup(f"other connection error: {e}")

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

text_form = sg.InputText(disabled=True, font=fontsize)

send_btn = sg.Button("send", key="SEND", font=fontsize, disabled=True)
close_btn = sg.Button("close", key="CLOSE", font=fontsize, disabled=True)

form = [
    [sg.Text("username: ", font=fontsize), username_form],
    [sg.Text("password: ", font=fontsize), password_form],
    [sg.Button("login", key="LOGIN", font=fontsize)],
    [text_form, send_btn, close_btn],
]

window = sg.Window(title="client", layout=form, font=fontsize)

hasher = Sha1Hasher()

conn = None

while True:
    event, data = window.read()  # type: ignore
    if event == sg.WIN_CLOSED:
        if conn is not None and conn.is_open():
            conn.say_goodbye()
        break
    elif event == "LOGIN":
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

        except UnknownUserError:
            sg.Popup(f"unknown user")
            continue
        except IncorrectPasswordError:
            sg.Popup("incorrect password")
            continue
        except ValueError as e:
            sg.Popup(f"other connection error: {e}")
            continue

        text_form.update(disabled=False)
        send_btn.update(disabled=False)
        close_btn.update(disabled=False)
        sg.Popup(f"established connection, shared key: {ok.key}")

    elif event == "SEND":
        pass
        text = text_form.get()
        conn.write(text)  # type: ignore
    elif event == "CLOSE":
        conn.say_goodbye()  # type: ignore
        text_form.update(disabled=True)
        send_btn.update(disabled=True)
        close_btn.update(disabled=True)

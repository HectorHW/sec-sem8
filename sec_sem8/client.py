import sys

import PySimpleGUI as sg

from sec_sem8.connection.active_connection import (
    SyncActiveConnection,
    IncorrectPasswordError,
    UnknownUserError,
)
from sec_sem8.impl import Sha1Hasher
from sec_sem8.entities import ReadRequest, WriteRequest, Message
import time
from pydantic import parse_raw_as
import threading
from queue import Queue
import contextlib

try:
    SERVER_ADDRESS = sys.argv[1]
except:
    SERVER_ADDRESS = "127.0.0.1"

fontsize = 35


username_form = sg.InputText(key="username", font=fontsize)
password_form = sg.InputText(key="password", password_char="*", font=fontsize)

chat = sg.Multiline(size=(80, 20))

text_form = sg.InputText(disabled=True, font=fontsize)

send_btn = sg.Button("send", key="SEND", font=fontsize, disabled=True)
close_btn = sg.Button("close", key="CLOSE", font=fontsize, disabled=True)

form = [
    [sg.Text("username: ", font=fontsize), username_form],
    [sg.Text("password: ", font=fontsize), password_form],
    [sg.Button("login", key="LOGIN", font=fontsize)],
    [chat],
    [text_form, send_btn, close_btn],
]

window = sg.Window(title="client", layout=form, font=fontsize, finalize=True)

hasher = Sha1Hasher()

conn = None

lock = threading.Lock()

updates: Queue[list[Message]] = Queue()


def pull_messages_work():
    while True:
        time.sleep(0.25)

        with lock:
            if conn is None or not conn.is_open():
                continue

            conn.write(ReadRequest().json())

            raw_reply = conn.read()
            # print(raw_reply)
            messages = parse_raw_as(list[Message], raw_reply)

            updates.put(messages)


puller = threading.Thread(target=pull_messages_work, daemon=True)
puller.start()


while True:
    event, data = window.read(timeout=0.1)  # type: ignore

    with contextlib.suppress(Exception):
        update = updates.get_nowait()
        chat.update(
            value="\n".join(map(lambda msg: f"{msg.author}: {msg.content}", update))
        )

    if event == sg.WIN_CLOSED:
        with lock:
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

        with lock:
            try:
                if conn is not None and conn.is_open():
                    conn.say_goodbye()
                conn = SyncActiveConnection(user, server=SERVER_ADDRESS, verbose=True)  # type: ignore
                conn.connect()
            except ConnectionRefusedError:
                sg.Popup("could not connect to server")
                continue

        with lock:
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

        data = WriteRequest(content=text)

        with lock:
            assert conn is not None
            conn.write(data.json())
            _ = conn.read()
    elif event == "CLOSE":
        time.sleep(0.5)
        with lock:
            assert conn is not None
            conn.say_goodbye()
            conn = None
        text_form.update(disabled=True)
        send_btn.update(disabled=True)
        close_btn.update(disabled=True)

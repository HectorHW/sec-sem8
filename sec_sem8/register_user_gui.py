import PySimpleGUI as sg

from sec_sem8 import impl, entities

db = impl.SqliteDatabase("users.sqlite")
hasher = impl.Sha1Hasher()

style_params = dict(font=("Ubuntu Mono", 24))

block_params = dict(expand_x=True, expand_y=True, **style_params)


username_form = sg.InputText(key="username", **style_params, size=(25, 1))
password_form = sg.InputText(
    password_char="*", key="password", **style_params, size=(25, 1)
)
register_button = sg.Button("register", key="REGISTER", **style_params)

user_register = sg.Tab(
    title="register",
    layout=[
        [sg.Text("username: ", **style_params), username_form],
        [sg.Text("password: ", **style_params), password_form],
        [register_button],
    ],
    **block_params,
)


users_table = sg.Table(
    values=[[user.username, user.password_hash] for user in db.list_users()],
    headings=["username", "password hash"],
    # auto_size_columns=True,
    # vertical_scroll_only=False,
    # def_col_width=8,
    # col_widths=[len("username") + 2, 35],
    **block_params,
)

user_list = sg.Tab(title="users", layout=[[users_table]], **block_params)

tabs = sg.TabGroup([[user_register, user_list]], enable_events=True, **block_params)

window = sg.Window(
    "register", [[tabs]], size=(1000, 500), resizable=True, finalize=True
)


def update_table():
    users = db.list_users()
    users_table.update(values=[[user.username, user.password_hash] for user in users])


while True:
    event, values = window.read()

    if event == sg.WIN_CLOSED:
        break
    update_table()
    if event == "REGISTER":
        username = values["username"].strip()
        if not username:
            sg.popup("username cannot be empty")
            continue
        if len(username) >= 60:
            sg.Popup("username is too long")
            continue
        password = values["password"].strip()
        if not password:
            sg.popup("password cannot be empty")
            continue

        password_hash = hasher(password)
        try:
            db.add_user(entities.User(username=username, password_hash=password_hash))
            sg.popup(f"user '{username}' registered succesfully")
        except entities.UserExistsError:
            sg.popup(f"user '{username}' already exists")
            continue

window.close()

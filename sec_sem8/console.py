import sys
from typing import Iterable, List, Optional

import environs
import prettytable
import typer

from sec_sem8.entities import User, UserExistsError
from sec_sem8.impl import Md5Hash, SqliteDatabase

env = environs.Env()
env.read_env()


class Config:
    SQLITE_PATH = env("SQLITE_PATH", "users.sqlite")


app = typer.Typer()

database = SqliteDatabase(Config.SQLITE_PATH)
hasher = Md5Hash()


def print_users(users: Iterable[User]):
    table = prettytable.PrettyTable()
    table.field_names = ["username", "password_hash"]
    for user in users:
        table.add_row((user.username, user.password_hash))

    print(table)


@app.command(name="list")
def list_users():
    print_users(database.list_users())


@app.command()
def get(username: str):
    if (user := database.find_user(username)) is not None:
        print_users([user])
    else:
        print("no such user exists")


@app.command()
def add(username: str, password: str):
    user = User(username=username, password_hash=hasher(password))
    try:
        database.add_user(user)
        print(f"added user {username}")
    except UserExistsError:
        print("user already exists")
        sys.exit(1)


def main():
    app()


if __name__ == "__main__":
    main()

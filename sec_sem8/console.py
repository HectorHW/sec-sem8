import sys
from typing import Iterable

import environs
from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich import box
import typer

from sec_sem8.entities import User, UserExistsError
from sec_sem8.impl import Sha1Hasher, SqliteDatabase

env = environs.Env()
env.read_env()


class Config:
    SQLITE_PATH = env("SQLITE_PATH", "users.sqlite")


app = typer.Typer()

database = SqliteDatabase(Config.SQLITE_PATH)
hasher = Sha1Hasher()

console = Console()


def print_users(users: Iterable[User]):
    table = Table(
        "username",
        "password hash",
        box=box.ROUNDED,
    )

    for user in users:
        table.add_row(user.username, user.password_hash)

    console.print(Panel(table, title="users", border_style="white", expand=False))


def print_error(text: str):
    console.print(
        Panel(
            text,
            title="Error",
            title_align="left",
            border_style="red",
        )
    )


def print_confirmation(text: str):
    console.print(
        Panel(text, title="Confirmation", title_align="left", border_style="green")
    )


@app.command(name="list")
def list_users():
    print_users(database.list_users())


@app.command()
def get(username: str):
    if (user := database.find_user(username)) is not None:
        print_users([user])
    else:
        print_error("no such user exists")


@app.command()
def add(username: str, password: str, override: bool = False):
    user = User(username=username, password_hash=hasher(password))

    if override:
        database.delete_user(username)

    try:
        database.add_user(user)
        print_confirmation(f"saved user {username} to database")
    except UserExistsError:
        print_error("this user already exists, use --force to do this anyway")
        sys.exit(1)


def main():
    app()


if __name__ == "__main__":
    main()

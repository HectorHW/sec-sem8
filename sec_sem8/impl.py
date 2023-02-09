from hashlib import sha1
from sqlite3 import IntegrityError, Row, connect
from typing import Iterable, Optional

from sec_sem8.entities import Database, Hasher, PasswordHash, User, UserExistsError


class Sha1Hasher(Hasher):
    def __call__(self, password: str) -> PasswordHash:
        return PasswordHash(sha1(password.encode()).hexdigest())


class SqliteDatabase(Database):
    def __init__(self, db_path: str) -> None:
        self.db = connect(db_path)
        self.db.row_factory = Row
        cursor = self.db.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS users(
            name VARCHAR(60) PRIMARY KEY,
            password_hash VARCHAR(60) NOT NULL
            )
            WITHOUT ROWID"""
        )

    def list_users(self) -> Iterable[User]:
        cursor = self.db.cursor()
        cursor.execute("SELECT name AS username, password_hash FROM users")
        rows = cursor.fetchall()
        return map(lambda row: User(**row), rows)

    def add_user(self, user: User) -> None:
        cursor = self.db.cursor()
        try:
            cursor.execute(
                "INSERT INTO users VALUES(?, ?)", (user.username, user.password_hash)
            )
            self.db.commit()
        except IntegrityError as e:
            raise UserExistsError from e

    def find_user(self, username: str) -> Optional[User]:
        cursor = self.db.cursor()

        cursor.execute("SELECT * FROM users WHERE name=?", (username,))

        if (row := cursor.fetchone()) is not None:
            return User(
                username=row["name"], password_hash=PasswordHash(row["password_hash"])
            )
        return None

    def delete_user(self, username: str) -> None:
        cursor = self.db.cursor()
        cursor.execute("DELETE FROM users WHERE name=?", (username,))

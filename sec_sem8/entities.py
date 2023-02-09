from abc import ABC, abstractmethod
from typing import Iterable, NewType, Optional

from pydantic import BaseModel

PasswordHash = NewType("PasswordHash", str)


class User(BaseModel, orm_mode=True):
    username: str
    password_hash: PasswordHash


class Hasher(ABC):
    @abstractmethod
    def __call__(self, password: str) -> PasswordHash:
        """generate hash from provided password

        Args:
            password (str): password in utf8 plaintext

        Returns:
            PasswordHash: hash of generated password as hex
        """


class UserExistsError(ValueError):
    pass


class Database(ABC):
    @abstractmethod
    def list_users(self) -> Iterable[User]:
        """

        Returns:
            Iterable[User]: all users in system
        """

    @abstractmethod
    def add_user(self, user: User) -> None:
        """store new user in database

        Args:
            user (User): user to store in database

        Raises:
            UserExistsError: if provided user already exists in database
        """

    @abstractmethod
    def find_user(self, username: str) -> Optional[User]:
        """get user by username if it exists

        Args:
            username (str): username in question

        Returns:
            Optional[User]: user with such username, if any
        """

    def delete_user(self, username: str) -> None:
        """delete user with provided username if it exists

        Args:
            username (str): username of user to delete

        """

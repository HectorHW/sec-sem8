import pytest

from sec_sem8.entities import PasswordHash, User, UserExistsError
from sec_sem8.impl import SqliteDatabase


@pytest.fixture
def database():
    return SqliteDatabase(":memory:")


@pytest.fixture
def user():
    return User(username="user", password_hash=PasswordHash("1f2e3d4c5b"))


def test_database_should_return_none_by_default(database):
    assert database.find_user("user") is None


def test_database_should_allow_saving_user(database, user):
    database.add_user(user)


@pytest.fixture
def database_with_user(database, user):
    database.add_user(user)
    return database


def test_database_should_return_saved_user(database_with_user, user):
    assert database_with_user.find_user("user") == user


def test_database_should_raise_on_duplicate_user(database_with_user, user):
    with pytest.raises(UserExistsError):
        database_with_user.add_user(user)


def test_database_allows_listing_users(database_with_user, user):
    assert list(database_with_user.list_users()) == [user]


def test_database_allows_deleting_user(database_with_user):
    database_with_user.delete_user("user")
    assert database_with_user.find_user("user") is None

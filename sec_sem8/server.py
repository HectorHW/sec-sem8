import asyncio
from functools import cache

from sec_sem8.connection.passive_connection import PassiveConnection, World
from sec_sem8.hash_task import PasswordHash
from sec_sem8.impl import SqliteDatabase

database = SqliteDatabase("users.sqlite")


@cache
def get_diffie_hellman_params() -> tuple[int, int]:
    from sec_sem8.diffie_hellman import find_primitive_root
    from sec_sem8.primes import get_random_prime

    prime = get_random_prime(64)
    g = find_primitive_root(32, prime)
    return g, prime


get_diffie_hellman_params()
print("built diffie-hellman parameters")


class RealWorld(World):
    def __init__(self, database: SqliteDatabase) -> None:
        super().__init__()
        self.db = database

    def has_user(self, username: str) -> bool:
        return self.db.find_user(username) is not None

    def get_diffie_params(self, username: str) -> tuple[int, int]:
        return get_diffie_hellman_params()

    def get_user_password_hash(self, username: str) -> PasswordHash:
        user = self.db.find_user(username)
        assert user is not None
        return user.password_hash


world = RealWorld(database)


async def handle_client(reader, writer):
    connection = PassiveConnection(reader, writer, world, verbose=True)

    try:
        ok = await connection.handshake()
    except Exception as e:
        print(e)
        return

    print(f"initiated connection with {ok.username}, shared key is {ok.shared_key}")

    while True:
        maybe_message = await connection.read_message()
        if maybe_message is None:
            break
        print(ok.username, "==>", maybe_message)

    print(f"closed connection with {ok.username}")


async def main():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 4433)

    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Serving on {addrs}")

    async with server:
        await server.serve_forever()


asyncio.run(main())

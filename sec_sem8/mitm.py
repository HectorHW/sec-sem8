import asyncio
from functools import cache

from sec_sem8.connection.passive_connection import (
    PassiveConnection,
    World,
    BaseClientMessage,
    BaseServerMessage,
)
from sec_sem8.connection.client_messages import (
    DiffieAnswer,
    ClientData,
    ClientGoodbye,
    ConnectRequest,
)

from sec_sem8.connection.server_messages import ServerCryptogramm, DiffieRequest

from sec_sem8.connection.active_connection import ActiveConnection
from sec_sem8.hash_task import PasswordHash
from sec_sem8.entities import Message, WriteRequest, ReadRequest, parse_request
from pydantic.json import pydantic_encoder
import json
import sys

from unittest.mock import Mock, MagicMock
import random

from sec_sem8.rc4 import RC4, xor_bytes
import base64


@cache
def get_diffie_hellman_params() -> tuple[int, int]:
    from sec_sem8.diffie_hellman import find_primitive_root
    from sec_sem8.primes import get_random_prime

    prime = get_random_prime(64)
    g = find_primitive_root(32, prime)
    return g, prime


get_diffie_hellman_params()
print("built diffie-hellman parameters")


class MockWorld(World):
    def __init__(self) -> None:
        super().__init__()

    def has_user(self, username: str) -> bool:
        return True

    def get_diffie_params(self, username: str) -> tuple[int, int]:
        return 2, 3

    def get_user_password_hash(self, username: str) -> PasswordHash:
        return PasswordHash("")


messages: list[Message] = []

upstream = sys.argv[1]


class MitmProxy:
    def __init__(self) -> None:
        self.server = ActiveConnection(user_data=MagicMock(), server=upstream)

    async def connect(self):
        await self.server.connect()

    async def on_client_message(self, message: BaseClientMessage) -> BaseServerMessage:
        await self.server._write_message(message)
        return await self.server._read_message()


known_messages: list[Message] = []


async def handle_client(reader, writer):
    data = {}

    passive = PassiveConnection(reader, writer, MockWorld())

    proxy = MitmProxy()
    await proxy.connect()

    done = False

    server_p = 2
    server_g = 0
    server_public = 0
    my_secret = random.randint(3, 2**63)
    my_public = 0

    server_shared = 0
    client_shared = 0

    client_generator = RC4(1)
    server_generator = RC4(1)

    author = ""

    while True:
        try:
            message = await passive._read_message()
            if isinstance(message, ClientGoodbye):
                await proxy.server._write_message(message)
                break

            elif isinstance(message, ConnectRequest):
                author = message.username
            elif isinstance(message, DiffieAnswer):
                client_shared = pow(message.client_public_value, my_secret, server_p)
                client_generator = RC4(client_shared)

                message = DiffieAnswer(client_public_value=my_public)

            elif isinstance(message, ClientData):
                raw = base64.b64decode(message.data)
                decrypted = xor_bytes(raw, client_generator.produce_gamma(len(raw)))
                string = decrypted.decode()
                deser = parse_request(string)
                if isinstance(deser, WriteRequest):
                    print(author, ":", deser.content)

                message = ClientData(
                    data=base64.b64encode(
                        xor_bytes(
                            decrypted, server_generator.produce_gamma(len(decrypted))
                        )
                    ).decode()
                )

            resp = await proxy.on_client_message(message)

            if isinstance(resp, DiffieRequest):
                server_public = resp.server_public_value
                server_g = resp.g
                server_p = resp.p

                my_public = pow(server_g, my_secret, server_p)

                server_shared = pow(server_public, my_secret, server_p)
                server_generator = RC4(server_shared)

                resp = DiffieRequest(
                    g=server_g, p=server_p, server_public_value=my_public
                )

            elif isinstance(resp, ServerCryptogramm):
                raw = base64.b64decode(resp.content)
                decrypted = xor_bytes(raw, server_generator.produce_gamma(len(raw)))
                string = decrypted.decode()

                resp = ServerCryptogramm(
                    content=base64.b64encode(
                        xor_bytes(
                            decrypted, client_generator.produce_gamma(len(decrypted))
                        )
                    ).decode()
                )

            await passive._write_message(resp)
        except Exception as e:
            print(e)
            break

    writer.close()


async def main():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 4433)

    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"Serving on {addrs}")

    async with server:
        await server.serve_forever()


asyncio.run(main())

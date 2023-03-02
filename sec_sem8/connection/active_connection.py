from sec_sem8.connection.client_states import (
    UserData,
    BaseClientState,
    ErrorState,
    DiffieDone,
    StartState,
    NonceRequested,
)
from sec_sem8.connection.server_messages import (
    BaseServerMessage,
    parse,
    ServerError,
    UnknownMessage,
)

from sec_sem8.connection.client_messages import BaseClientMessage

from typing import NoReturn
import asyncio


class UnknownUserError(ValueError):
    pass


class IncorrectPasswordError(ValueError):
    pass


class ActiveConnection:
    def __init__(
        self,
        user_data: UserData,
        server: str = "127.0.0.1",
        port: int = 4433,
    ) -> None:
        self.loop = asyncio.get_event_loop()
        reader, writer = self.loop.run_until_complete(
            asyncio.open_connection(server, port)
        )
        self.reader = reader
        self.writer = writer
        self.user_data = user_data
        self.state: BaseClientState = StartState()

    async def error_bailout(self, message: str) -> NoReturn:
        self.state = ErrorState(message=message)
        self.writer.close()
        await self.writer.wait_closed()
        if "wrong hash answer" in message:
            raise IncorrectPasswordError(message)
        if "user does not exist" in message:
            raise UnknownUserError(message)

        raise ValueError(message)

    async def read_message(self) -> BaseServerMessage:
        try:
            raw = await self.reader.readline()
            message = raw.decode().strip(" \n")
            decoded = parse(message)
            if isinstance(decoded, ServerError):
                await self.error_bailout(decoded.text)
            if isinstance(decoded, UnknownMessage):
                await self.error_bailout("got unknown message")
            return decoded
        except UnicodeDecodeError:
            await self.error_bailout("decode error")

    async def write_message(self, message: BaseClientMessage):
        self.writer.write((message.json() + "\n").encode())
        await self.writer.drain()

    def _adapt(self, coro):
        return self.loop.run_until_complete(coro)

    def handshake(self) -> DiffieDone:
        message, new_state = self.state.on_init(self.user_data)
        if not isinstance(new_state, NonceRequested):
            self.loop.run_until_complete(
                self.error_bailout("failure setting up connection at username transfer")
            )
        self.state = new_state
        self.loop.run_until_complete(self.write_message(message))

        while True:
            server_message: BaseServerMessage = self._adapt(self.read_message())
            answer, new_state = self.state.on_message(server_message, self.user_data)
            self._adapt(self.write_message(answer))
            self.state = new_state
            if isinstance(self.state, ErrorState):
                self._adapt(self.error_bailout(self.state.message))
            if isinstance(self.state, DiffieDone):
                return self.state

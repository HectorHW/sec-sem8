import asyncio
import base64
from typing import NoReturn

from sec_sem8.connection.client_messages import (
    BaseClientMessage,
    ClientData,
    ClientGoodbye,
)
from sec_sem8.connection.client_states import (
    BaseClientState,
    Closed,
    DiffieDone,
    ErrorState,
    NonceRequested,
    StartState,
    UserData,
)
from sec_sem8.connection.server_messages import (
    BaseServerMessage,
    ServerError,
    UnknownMessage,
    parse,
)
from sec_sem8.rc4 import xor_bytes


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

    async def _error_bailout(self, message: str) -> NoReturn:
        self.state = ErrorState(message=message)
        self.writer.close()
        await self.writer.wait_closed()
        if "wrong hash answer" in message:
            raise IncorrectPasswordError(message)
        if "user does not exist" in message:
            raise UnknownUserError(message)

        raise ValueError(message)

    def _sync_bailout(self, message: str) -> NoReturn:  # type: ignore
        self._adapt(self._error_bailout(message))

    async def _read_message(self) -> BaseServerMessage:
        try:
            raw = await self.reader.readline()
            message = raw.decode().strip(" \n")
            decoded = parse(message)
            if isinstance(decoded, ServerError):
                await self._error_bailout(decoded.text)
            if isinstance(decoded, UnknownMessage):
                await self._error_bailout("got unknown message")
            return decoded
        except UnicodeDecodeError:
            await self._error_bailout("decode error")

    async def _write_message(self, message: BaseClientMessage):
        self.writer.write((message.json() + "\n").encode())
        await self.writer.drain()

    def _adapt(self, coro):
        return self.loop.run_until_complete(coro)

    def handshake(self) -> DiffieDone:
        message, new_state = self.state.on_init(self.user_data)
        if not isinstance(new_state, NonceRequested):
            self._sync_bailout("failure setting up connection at username transfer")
        self.state = new_state
        self.loop.run_until_complete(self._write_message(message))

        while True:
            server_message: BaseServerMessage = self._adapt(self._read_message())
            answer, new_state = self.state.on_message(server_message, self.user_data)
            self._adapt(self._write_message(answer))
            self.state = new_state
            if isinstance(self.state, ErrorState):
                self._sync_bailout(self.state.message)
            if isinstance(self.state, DiffieDone):
                return self.state

    def write(self, text: str):
        if not isinstance(self.state, DiffieDone):
            self._sync_bailout(
                f"called write in wrong state ({self.state.__class__.__name__})"
            )
        raw_message = text.encode()
        gamma = self.state.rc4.produce_gamma(len(raw_message))

        encrypted = xor_bytes(raw_message, gamma)
        enc_str = base64.b64encode(encrypted).decode()
        message = ClientData(data=enc_str)
        self._adapt(self._write_message(message))

    def say_goodbye(self):
        if not isinstance(self.state, DiffieDone):
            self._sync_bailout(
                f"called goodbye in wrong state ({self.state.__class__.__name__})"
            )
        self._adapt(self._write_message(ClientGoodbye()))
        self.state = Closed()
        self.writer.close()
        self._adapt(self.writer.wait_closed())

    def is_open(self) -> bool:
        return isinstance(self.state, DiffieDone)

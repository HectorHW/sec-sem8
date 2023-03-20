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
    ServerCryptogramm,
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
        verbose: bool = False,
    ) -> None:
        self.reader = None
        self.writer = None
        self.user_data = user_data
        self.state: BaseClientState = StartState()
        self.conn_params = (server, port)
        self.verbose = verbose

    def _log(self, *message):
        if self.verbose:
            print(*message)

    async def connect(self):
        self._log("called connect")
        self.reader, self.writer = await asyncio.open_connection(*self.conn_params)

    async def _error_bailout(self, message: str) -> NoReturn:
        assert self.reader is not None
        assert self.writer is not None
        self.state = ErrorState(message=message)
        self.writer.close()
        await self.writer.wait_closed()
        if "wrong hash answer" in message:
            raise IncorrectPasswordError(message)
        if "user does not exist" in message:
            raise UnknownUserError(message)

        raise ValueError(message)

    async def _read_message(self) -> BaseServerMessage:
        assert self.reader is not None
        assert self.writer is not None
        try:
            raw = await self.reader.readline()
            message = raw.decode().strip(" \n")
            decoded = parse(message)
            self._log("got message of type", decoded.__class__.__name__)

            if isinstance(decoded, ServerError):
                await self._error_bailout(decoded.text)
            if isinstance(decoded, UnknownMessage):
                await self._error_bailout("got unknown message")
            return decoded
        except UnicodeDecodeError:
            await self._error_bailout("decode error")

    async def _write_message(self, message: BaseClientMessage):
        assert self.reader is not None
        assert self.writer is not None
        self.writer.write((message.json() + "\n").encode())
        await self.writer.drain()
        self._log("wrote message:", message)

    async def handshake(self) -> DiffieDone:
        message, new_state = self.state.on_init(self.user_data)
        if not isinstance(new_state, NonceRequested):
            await self._error_bailout(
                "failure setting up connection at username transfer"
            )
        self.state = new_state
        await self._write_message(message)

        while True:
            server_message: BaseServerMessage = await self._read_message()
            answer, new_state = self.state.on_message(server_message, self.user_data)
            await self._write_message(answer)
            self.state = new_state
            if isinstance(self.state, ErrorState):
                await self._error_bailout(self.state.message)
            if isinstance(self.state, DiffieDone):
                await self._read_message()  # drop ok from server
                return self.state

    async def read(self) -> str:
        if not isinstance(self.state, DiffieDone):
            await self._error_bailout(
                f"called read in wrong state ({self.state.__class__.__name__})"
            )
        server_message: BaseServerMessage = await self._read_message()
        if not isinstance(server_message, ServerCryptogramm):
            raise ValueError(
                f"unexpected data when trying to read server response: {server_message}"
            )

        b64 = base64.b64decode(server_message.content)
        gamma = self.state.rc4.produce_gamma(len(b64))
        decrypted = xor_bytes(b64, gamma)
        return decrypted.decode()

    async def write(self, text: str):
        if not isinstance(self.state, DiffieDone):
            await self._error_bailout(
                f"called write in wrong state ({self.state.__class__.__name__})"
            )
        raw_message = text.encode()
        gamma = self.state.rc4.produce_gamma(len(raw_message))

        encrypted = xor_bytes(raw_message, gamma)
        enc_str = base64.b64encode(encrypted).decode()
        message = ClientData(data=enc_str)
        await self._write_message(message)

    async def say_goodbye(self):
        if not isinstance(self.state, DiffieDone):
            await self._error_bailout(
                f"called goodbye in wrong state ({self.state.__class__.__name__})"
            )
        assert self.reader is not None
        assert self.writer is not None
        await self._write_message(ClientGoodbye())
        self.state = Closed()
        self.writer.close()
        await self.writer.wait_closed()

    def is_open(self) -> bool:
        return isinstance(self.state, DiffieDone)


class SyncActiveConnection:
    def __init__(
        self,
        user_data: UserData,
        server: str = "127.0.0.1",
        port: int = 4433,
        verbose: bool = False,
    ):
        self.connection = ActiveConnection(user_data, server, port, verbose)
        self.loop = asyncio.get_event_loop()

    def _adapt(self, coro):
        return self.loop.run_until_complete(coro)

    def connect(self):
        return self._adapt(self.connection.connect())

    def handshake(self) -> DiffieDone:
        return self._adapt(self.connection.handshake())

    def read(self) -> str:
        return self._adapt(self.connection.read())

    def write(self, text: str):
        return self._adapt(self.connection.write(text))

    def say_goodbye(self):
        self._adapt(self.connection.say_goodbye())

    def is_open(self) -> bool:
        return isinstance(self.connection.state, DiffieDone)

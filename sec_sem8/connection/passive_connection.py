import base64
from asyncio.streams import StreamReader, StreamWriter
from typing import NoReturn, Optional, Callable

from sec_sem8.connection.client_messages import (
    BaseClientMessage,
    ClientData,
    ClientError,
    ClientGoodbye,
    UnknownAnswer,
    parse,
)
from sec_sem8.connection.server_messages import BaseServerMessage, ServerCryptogramm
from sec_sem8.connection.server_states import (
    BaseState,
    Closed,
    DiffieDone,
    ErrorState,
    Start,
    World,
)
from sec_sem8.rc4 import xor_bytes


class PassiveConnection:
    def __init__(
        self,
        reader: StreamReader,
        writer: StreamWriter,
        world: World,
        verbose: bool = False,
        intercept_callback: Optional[
            Callable[[BaseClientMessage | BaseServerMessage], None]
        ] = None,
    ) -> None:
        self.verbose = verbose
        self.state: BaseState = Start()
        self.reader = reader
        self.writer = writer
        self.world = world
        self.intercept_callback = intercept_callback or (lambda _: None)

    async def _error_bailout(self, message: str) -> NoReturn:
        self.state = ErrorState(message=message)

        self.writer.close()
        await self.writer.wait_closed()
        raise ValueError(message)

    async def _read_message(self) -> BaseClientMessage:
        try:
            raw = await self.reader.readline()
            message = raw.decode().strip(" \n")
            decoded = parse(message)

            if self.verbose:
                print("got message:", decoded)

            if isinstance(decoded, ClientError):
                await self._error_bailout(decoded.message)
            if isinstance(decoded, UnknownAnswer):
                await self._error_bailout("got unknown message")

            self.intercept_callback(decoded)
            return decoded
        except UnicodeDecodeError:
            await self._error_bailout("decode error")

    async def _write_message(self, message: BaseServerMessage):
        self.intercept_callback(message)
        self.writer.write((message.json() + "\n").encode())
        if self.verbose:
            print("sent message:", message)
        await self.writer.drain()

    async def handshake(self) -> DiffieDone:
        if self.verbose:
            print("begin handshake")
        while True:
            message = await self._read_message()
            answer, new_state = self.state.on_message(message, self.world)
            await self._write_message(answer)
            self.state = new_state
            if isinstance(self.state, ErrorState):
                await self._error_bailout(self.state.message)
            if isinstance(self.state, DiffieDone):
                return self.state

    async def read_message(self) -> Optional[str]:
        if not isinstance(self.state, DiffieDone):
            await self._error_bailout("called read in wrong state ()")
        message = await self._read_message()
        if isinstance(message, ClientGoodbye):
            self.state = Closed()
            self.writer.close()
            await self.writer.wait_closed()
            return None
        if isinstance(message, ClientData):
            b64 = base64.b64decode(message.data)
            gamma = self.state.rc4.produce_gamma(len(b64))
            decrypted = xor_bytes(b64, gamma)
            return decrypted.decode()

        await self._error_bailout(
            f"unexpected message type {message.__class__.__name__} after key exchange"
        )

    async def write_message(self, message: str):
        if not isinstance(self.state, DiffieDone):
            await self._error_bailout("called read in wrong state ()")

        encoded = message.encode()
        gamma = self.state.rc4.produce_gamma(len(encoded))
        encrypted = xor_bytes(encoded, gamma)
        b64 = base64.b64encode(encrypted)
        msg = ServerCryptogramm(content=b64.decode())
        await self._write_message(msg)

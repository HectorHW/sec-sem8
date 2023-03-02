from asyncio.streams import StreamReader, StreamWriter

from sec_sem8.connection.server_states import (
    Start,
    ErrorState,
    BaseState,
    World,
    DiffieDone,
    Closed,
)
from sec_sem8.connection.client_messages import (
    parse,
    ClientError,
    UnknownAnswer,
    BaseClientMessage,
    ClientData,
    ClientGoodbye,
)

from sec_sem8.connection.server_messages import BaseServerMessage

from typing import NoReturn, Optional
import base64
from sec_sem8.rc4 import xor_bytes


class PassiveConnection:
    def __init__(
        self,
        reader: StreamReader,
        writer: StreamWriter,
        world: World,
        verbose: bool = False,
    ) -> None:
        self.verbose = verbose
        self.state: BaseState = Start()
        self.reader = reader
        self.writer = writer
        self.world = world

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
            return decoded
        except UnicodeDecodeError:
            await self._error_bailout("decode error")

    async def _write_message(self, message: BaseServerMessage):
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

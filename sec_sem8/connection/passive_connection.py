import asyncio
from asyncio.streams import StreamReader, StreamWriter

from sec_sem8.connection.server_states import (
    Start,
    ErrorState,
    BaseState,
    World,
    DiffieDone,
)
from sec_sem8.connection.client_messages import (
    parse,
    ClientError,
    UnknownAnswer,
    BaseClientMessage,
)

from sec_sem8.connection.server_messages import BaseServerMessage

from typing import NoReturn


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

    async def error_bailout(self, message: str) -> NoReturn:
        self.state = ErrorState(message=message)

        self.writer.close()
        await self.writer.wait_closed()
        raise ValueError(message)

    async def read_message(self) -> BaseClientMessage:
        try:
            raw = await self.reader.readline()
            message = raw.decode().strip(" \n")
            decoded = parse(message)

            if self.verbose:
                print("got message:", decoded)

            if isinstance(decoded, ClientError):
                await self.error_bailout(decoded.message)
            if isinstance(decoded, UnknownAnswer):
                await self.error_bailout("got unknown message")
            return decoded
        except UnicodeDecodeError:
            await self.error_bailout("decode error")

    async def write_message(self, message: BaseServerMessage):
        self.writer.write((message.json() + "\n").encode())
        if self.verbose:
            print("sent message:", message)
        await self.writer.drain()

    async def handshake(self) -> DiffieDone:
        if self.verbose:
            print("begin handshake")
        while True:
            message = await self.read_message()
            answer, new_state = self.state.on_message(message, self.world)
            await self.write_message(answer)
            self.state = new_state
            if isinstance(self.state, ErrorState):
                await self.error_bailout(self.state.message)
            if isinstance(self.state, DiffieDone):
                return self.state

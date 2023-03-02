from typing import Literal, Union
from pydantic import BaseModel, parse_raw_as
from sec_sem8.hash_task import PasswordHash


class BaseClientMessage(BaseModel, extra="forbid"):
    id: int


class ConnectRequest(BaseClientMessage, extra="forbid"):
    id: Literal[0] = 0
    username: str


class HashAnswer(BaseClientMessage, extra="forbid"):
    id: Literal[1] = 1
    answer: PasswordHash


class DiffieAnswer(BaseClientMessage, extra="forbid"):
    id: Literal[2] = 2
    client_public_value: int


class ClientError(BaseClientMessage):
    id: Literal[100] = 100
    message: str


class UnknownAnswer(BaseModel):
    pass


AnyMessage = Union[  # type: ignore
    tuple([*BaseClientMessage.__subclasses__(), UnknownAnswer])  # type: ignore
]


def parse(data: str) -> BaseClientMessage:
    return parse_raw_as(AnyMessage, data)  # type: ignore

from pydantic import BaseModel, parse_raw_as
from typing import Literal, Union


class BaseServerMessage(BaseModel, extra="forbid"):
    id: int


class Nonce(BaseServerMessage, extra="forbid"):
    id: Literal[0] = 0
    nonce: str


class DiffieRequest(BaseServerMessage, extra="forbid"):
    id: Literal[1] = 1
    g: int
    p: int
    server_public_value: int


class DiffieOk(BaseServerMessage, extra="forbid"):
    id: Literal[2] = 2
    message: Literal["ok"] = "ok"


class ServerError(BaseServerMessage):
    id: Literal[10] = 10
    text: str


class UnknownMessage(BaseModel):
    pass


AnyMessage = Union[  # type: ignore
    tuple([*BaseServerMessage.__subclasses__(), UnknownMessage])  # type: ignore
]


def parse(data: str) -> BaseServerMessage:
    return parse_raw_as(AnyMessage, data)  # type: ignore


if __name__ == "__main__":
    data = input()
    result = parse(data)
    print(type(result), result)

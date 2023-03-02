import random
from abc import ABC, abstractmethod

from pydantic import BaseModel

from sec_sem8.connection import client_messages, server_messages
from sec_sem8.hash_task import PasswordHash, solve_task
from sec_sem8.rc4 import RC4

TransitionResult = tuple[server_messages.BaseServerMessage, "BaseState"]


class World(ABC):
    @abstractmethod
    def has_user(self, username: str) -> bool:
        ...

    @abstractmethod
    def get_user_password_hash(self, username: str) -> PasswordHash:
        ...

    @abstractmethod
    def get_diffie_params(self, username: str) -> tuple[int, int]:
        """
        Returns:
            tuple[int, int]: g, p
        """


class BaseState(BaseModel):
    def on_message(
        self, message: client_messages.BaseClientMessage, world: World
    ) -> TransitionResult:
        if isinstance(message, client_messages.ConnectRequest):
            return self.on_connect_request(message, world)
        elif isinstance(message, client_messages.HashAnswer):
            return self.on_hash_answer(message, world)
        elif isinstance(message, client_messages.DiffieAnswer):
            return self.on_diffie_answer(message, world)
        else:
            return self.on_unknown_message(message, world)

    def on_connect_request(
        self, message: client_messages.ConnectRequest, world: World
    ) -> TransitionResult:
        return error("did not expect connect request", self)

    def on_hash_answer(
        self, message: client_messages.HashAnswer, world: World
    ) -> TransitionResult:
        return error("did not expect hash answer", self)

    def on_diffie_answer(
        self, message: client_messages.DiffieAnswer, world: World
    ) -> TransitionResult:
        return error("did not expect diffie answer", self)

    def on_unknown_message(self, message, world: World):
        return error("got unknown message", self)


class ErrorState(BaseState):
    message: str


def error(message: str, state: BaseState) -> TransitionResult:
    return server_messages.ServerError(
        text=f"error: {message}; was in {state.__class__.__name__}"
    ), ErrorState(message=message)


class Start(BaseState):
    def on_connect_request(
        self, message: client_messages.ConnectRequest, world: World
    ) -> TransitionResult:
        if world.has_user(message.username):
            nonce = random.randbytes(32).hex()
            return server_messages.Nonce(nonce=nonce), TaskRequested(
                nonce=nonce, username=message.username
            )
        else:
            return error("user does not exist", self)


class TaskRequested(BaseState):
    nonce: str
    username: str

    def on_hash_answer(
        self, message: client_messages.HashAnswer, world: World
    ) -> TransitionResult:
        pass_hash = world.get_user_password_hash(self.username)
        expected = solve_task(pass_hash, self.nonce)
        if message.answer == expected:
            g, p = world.get_diffie_params(self.username)
            server_secret = random.randint(a=2, b=p - 1)
            server_public = pow(g, server_secret, p)
            response = server_messages.DiffieRequest(
                g=g, p=p, server_public_value=server_public
            )
            new_state = PasswordSolved(
                username=self.username, g=g, p=p, server_secret=server_secret
            )
            return response, new_state
        else:
            return error("wrong hash answer", self)


class PasswordSolved(BaseState):
    username: str
    g: int
    p: int
    server_secret: int

    def on_diffie_answer(
        self, message: client_messages.DiffieAnswer, world: World
    ) -> TransitionResult:
        shared_key = pow(message.client_public_value, self.server_secret, self.p)
        return server_messages.DiffieOk(), DiffieDone(
            username=self.username, shared_key=shared_key, rc4=RC4(shared_key)
        )


class DiffieDone(BaseState, arbitrary_types_allowed=True):
    username: str
    shared_key: int
    rc4: RC4


class Closed(BaseState):
    pass

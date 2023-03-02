from sec_sem8.connection import server_messages
from pydantic import BaseModel
from abc import ABC, abstractmethod
from sec_sem8.connection import client_messages
from sec_sem8.hash_task import PasswordHash, solve_task
import random


class UserData(ABC):
    @property
    @abstractmethod
    def username(self) -> str:
        ...

    @property
    @abstractmethod
    def password_hash(self) -> PasswordHash:
        ...


Transition = tuple[client_messages.BaseClientMessage, "BaseClientState"]


def error(message: str, obj: "BaseClientState") -> Transition:
    return client_messages.ClientError(
        message=f" client error: {message}; was in {obj.__class__.__name__}"
    ), ErrorState(message=message)


class BaseClientState(BaseModel):
    def error(self, message: str) -> Transition:
        return error(message, self)

    def on_init(self, user: UserData) -> Transition:
        return error("did not expect init here", self)

    def on_message(
        self, message: server_messages.BaseServerMessage, user: UserData
    ) -> Transition:
        if isinstance(message, server_messages.Nonce):
            return self.on_nonce(message, user)
        elif isinstance(message, server_messages.DiffieRequest):
            return self.on_diffie_request(message, user)
        elif isinstance(message, server_messages.DiffieOk):
            return self.on_diffie_ok(message, user)
        else:
            return self.error(
                f"got unexpected message of type {message.__class__.__name__}"
            )

    def on_nonce(self, message: server_messages.Nonce, user: UserData) -> Transition:
        return self.error("did not expect nonce")

    def on_diffie_request(
        self, message: server_messages.DiffieRequest, user: UserData
    ) -> Transition:
        return self.error("did not expect diffie request")

    def on_diffie_ok(
        self, message: server_messages.DiffieOk, user: UserData
    ) -> Transition:
        return self.error("did not expect diffie ok")


class ErrorState(BaseClientState):
    message: str


class StartState(BaseClientState):
    def on_init(self, user: UserData) -> Transition:
        message = client_messages.ConnectRequest(username=user.username)
        return message, NonceRequested()


class NonceRequested(BaseClientState):
    def on_nonce(self, message: server_messages.Nonce, user: UserData) -> Transition:
        answer = solve_task(user.password_hash, message.nonce)
        answer_message = client_messages.HashAnswer(answer=answer)
        return answer_message, DiffieStarted()


class DiffieStarted(BaseClientState):
    def on_diffie_request(
        self, message: server_messages.DiffieRequest, user: UserData
    ) -> Transition:
        g = message.g
        p = message.p
        server_public = message.server_public_value

        client_secret = random.randint(a=2, b=p - 1)
        client_public = pow(g, client_secret, p)

        key = pow(server_public, client_secret, p)

        return client_messages.DiffieAnswer(
            client_public_value=client_public
        ), DiffieDone(key=key)


class DiffieDone(BaseClientState):
    key: int

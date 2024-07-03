import socket
from enum import Enum
from typing import Any
from abc import ABC, abstractmethod
from .protocol import SOCKS5ProtocolError, receive


class AuthMethod(Enum):
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    CHALLENGE_HANDSHAKE = 0x03
    UNASSIGNED = 0x04
    CHALLENGE_RESPONSE = 0x05
    SSL = 0x06
    NDS = 0x07
    MULTI_AUTHENTICATION_FRAMEWORK = 0x08
    JSON_PARAMETER_BLOCK = 0x09

    @classmethod
    def from_int(cls, integer: int) -> "AuthMethod":
        dictionary = {
            0x00: cls.NO_AUTH,
            0x01: cls.GSSAPI,
            0x02: cls.USERNAME_PASSWORD,
            0x03: cls.CHALLENGE_HANDSHAKE,
            0x04: cls.UNASSIGNED,
            0x05: cls.CHALLENGE_RESPONSE,
            0x06: cls.SSL,
            0x07: cls.NDS,
            0x08: cls.MULTI_AUTHENTICATION_FRAMEWORK,
            0x09: cls.JSON_PARAMETER_BLOCK,
        }
        if integer not in dictionary:
            raise SOCKS5ProtocolError(f"Unknown auth method: {hex(integer)}")
        return dictionary[integer]


class Auth(ABC):
    @abstractmethod
    def verify(self, *args: Any, **kwargs: Any) -> bool:
        pass

    @abstractmethod
    def handshake(self, sock: socket.socket) -> bool:
        pass


class NoAuth(Auth):
    method: AuthMethod = AuthMethod.NO_AUTH

    def verify(self, *args: Any, **kwargs: Any) -> bool:
        return True

    def handshake(self, sock: socket.socket) -> bool:
        return True


class UsernamePassword(Auth):
    method: AuthMethod = AuthMethod.USERNAME_PASSWORD

    def __init__(self, login: str, password: str):
        self.login = login
        self.password = password

    def verify(self, *args: Any, **kwargs: Any) -> bool:
        login, password = args
        return (login, password) == (self.login, self.password)

    def handshake(self, sock: socket.socket) -> bool:
        if receive(sock, 1) != b"\x01":
            return False
        login = UsernamePassword.recv_string(sock)
        password = UsernamePassword.recv_string(sock)
        status = self.verify(login, password)
        sock.send(bytes([0x01, not status]))
        return status

    @staticmethod
    def recv_string(sock: socket.socket) -> str:
        length = int.from_bytes(receive(sock, 1))
        return receive(sock, length).decode()


def client_greeting(sock: socket.socket) -> list[AuthMethod]:
    if receive(sock, 1) != b"\x05":
        raise SOCKS5ProtocolError(f"Wrong protocol version {repr(data)}")
    nauth = int.from_bytes(receive(sock, 1))
    auth = receive(sock, nauth)
    return [AuthMethod.from_int(i) for i in auth]

import socket
from enum import Enum
from typing import Any
from abc import ABC, abstractmethod
from .protocol import Socks5ProtocolError


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
            raise Socks5ProtocolError(f"Unknown auth method: {hex(integer)}")
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
        if sock.recv(1) != b"\x01":
            return False
        login = UsernamePassword.recv_string(sock)
        password = UsernamePassword.recv_string(sock)
        return self.verify(login, password)

    @staticmethod
    def recv_string(sock: socket.socket) -> str:
        length_data = sock.recv(1)
        if len(length_data) != 1:
            raise Socks5ProtocolError("Cannot read string length")
        length = int.from_bytes(length_data)
        return sock.recv(length).decode()


def client_greeting(sock: socket.socket) -> list[AuthMethod]:
    if sock.recv(1) != b"\x05":
        raise Socks5ProtocolError("Wrong protocol version")
    nauth_data = sock.recv(1)
    if len(nauth_data) != 1:
        raise Socks5ProtocolError("Cannot read count of auth method")
    nauth = int.from_bytes(nauth_data)
    auth = sock.recv(nauth)
    if len(auth) != nauth:
        raise Socks5ProtocolError("Wrong")
    return [AuthMethod.from_int(i) for i in auth]

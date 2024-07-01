import socket
import select
import socketserver
from abc import ABC
from typing import Any, Iterator
from .address import Address
from .protocol import Socks5ProtocolError
from .handshake import Auth, NoAuth, client_greeting


BUFFER_SIZE = 4096


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class BaseSOCKS5Handler(socketserver.BaseRequestHandler):
    server: Any = None

    def handle(self) -> None:
        user = self.request
        methods = client_greeting(user)
        for method in self.server.handle_auth():
            if method in methods:
                if method.handshake(user):
                    break
                else:
                    return
        else:
            return
        address = self.server.handle_auth(Address.read(user))
        remote = socket.socket()
        remote.connect((address.host, address.port))
        while True:
            ready, _, _ = select.select([user, remote], [], [])
            if user in ready:
                if remote.send(self.server.handle_send(user.recv(BUFFER_SIZE))) <= 0:
                    break
            if remote in ready:
                if user.send(self.server.handle_receive(remote.recv(BUFFER_SIZE))) <= 0:
                    break


class SOCKS5Server:
    def init_context(self):
        return {}

    def handle_auth(self, ctx: Any) -> Iterator[Auth]:
        yield NoAuth()

    def handle_address(self, address: Address, ctx: Any) -> Address:
        return address

    def handle_send(self, data: bytes, ctx: Any, tcp: bool = False) -> bytes:
        return data

    def handle_receive(self, data: bytes, Any, tcp: bool = False) -> bytes:
        return data

    def start(self, host, port):
        class Handler(BaseSOCKS5Handler):
            server: SOCKS5Server = server

    return Handler
        ThreadedTCPServer((host, port), )

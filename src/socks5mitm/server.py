import socket
import select
import socketserver
from typing import Any, Iterator
from .proxy import Proxy
from .address import Address
from .protocol import SOCKS5ProtocolError, receive
from .handshake import Auth, NoAuth, client_greeting


BUFFER_SIZE = 4096


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


class BaseSOCKS5Handler(socketserver.BaseRequestHandler):
    socks5server: Any = None

    def handle(self) -> None:
        ctx = self.socks5server.init_context()
        user = self.request
        methods = client_greeting(user)
        for method in self.socks5server.handle_auth(ctx):
            if method.method in methods:
                user.send(bytes([0x05, method.method.value]))
                if method.handshake(user):
                    break
                else:
                    return
        else:
            user.send(bytes([0x05, 0xFF]))
            return
        if receive(user, 1) != b"\x05":
            raise SOCKS5ProtocolError("Wrong protocol version")
        receive(user, 1)
        if receive(user, 1) != b"\x00":
            raise SOCKS5ProtocolError("Reserved, must be 0x00")
        address = self.socks5server.handle_address(Address.read(user), ctx)
        user.send(b"\x05\x00\x00\x01\x01\x01\x01\x01\x01\x01")
        proxy = self.socks5server.use_proxy(ctx)
        if proxy:
            remote = proxy.connect(address)
        else:
            remote = socket.socket()
            remote.connect((address.host, address.port))
        while True:
            read, _, _ = select.select([user, remote], [], [])
            if user in read:
                data = user.recv(4096)
                data = self.socks5server.handle_send(data, ctx)
                if remote.send(data) <= 0:
                    break
            if remote in read:
                data = remote.recv(4096)
                data = self.socks5server.handle_receive(data, ctx)
                if user.send(data) <= 0:
                    break
        self.socks5server.handle_end(ctx)


class SOCKS5Server:
    def init_context(self) -> Any:
        return {}

    def handle_auth(self, ctx: Any) -> Iterator[Auth]:
        return [NoAuth()]

    def handle_address(self, address: Address, ctx: Any) -> Address:
        return address

    def use_proxy(self, ctx) -> Proxy | None:
        return None

    def handle_send(self, data: bytes, ctx: Any) -> bytes:
        return data

    def handle_receive(self, data: bytes, ctx: Any) -> bytes:
        return data

    def handle_end(self, ctx) -> None:
        pass

    def start(self, host: str, port: int) -> None:
        class Handler(BaseSOCKS5Handler):
            socks5server: SOCKS5Server = self

        try:
            ThreadedTCPServer((host, port), Handler).serve_forever()
        except KeyboardInterrupt:
            pass

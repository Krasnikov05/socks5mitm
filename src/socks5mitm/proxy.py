import socks
import socket
import urllib.parse
from typing import Tuple
from abc import ABC, abstractmethod
from .address import Address


type Socket = socket.socket | socks.socksocket


class Proxy(ABC):
    def __init__(
        self, host: str, port: int, auth: Tuple[str, str] | None = None
    ) -> None:
        """Initialize the proxy with host, port, and optional authentication."""
        self.host = host
        self.port = port
        self.auth = auth

    @abstractmethod
    def connect(self, target: Address) -> Socket:
        """Establish a connection to the target address through the proxy."""
        pass


class SOCKS5Proxy(Proxy):
    def connect(self, target: Address) -> Socket:
        """Connect to the target address using a SOCKS5 proxy."""
        sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        if self.auth:
            username, password = self.auth
            sock.set_proxy(
                socks.SOCKS5,
                self.host,
                self.port,
                username=username,
                password=password,
            )
        else:
            sock.set_proxy(socks.SOCKS5, self.host, self.port)
        sock.connect((target.host, target.port))
        return sock


class HTTPProxy(Proxy):
    def connect(self, target: Address) -> Socket:
        """Connect to the target address using an HTTP proxy."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.host, self.port))
        connect_request = (
            f"CONNECT {target.host}:{target.port} HTTP/1.1\r\n"
            f"Host: {target.host}:{target.port}\r\n"
        )
        if self.auth:
            auth = urllib.parse.quote(":".join(self.auth))
            connect_request += f"Proxy-Authorization: Basic {auth}\r\n"
        connect_request += "\r\n"
        sock.sendall(connect_request.encode())
        response = sock.recv(4096).decode()
        if "200 Connection established" not in response:
            raise Exception("Can not connect to HTTP proxy")
        return sock

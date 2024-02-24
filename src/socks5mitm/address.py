import socket
from enum import Enum, auto

from .protocol import Socks5ProtocolError


class AddressType(Enum):
    IPV4 = auto()
    IPV6 = auto()
    DOMAIN = auto()

    @classmethod
    def from_int(cls, number: int) -> "AddressType":
        """Convert an integer to the corresponding AddressType."""
        if number not in (1, 3, 4):
            raise Socks5ProtocolError("Unknown address type")
        return {1: cls.IPV4, 3: cls.DOMAIN, 4: cls.IPV6}[number]

    @classmethod
    def read(cls, sock: socket.socket) -> "AddressType":
        """Read and return an AddressType from the socket."""
        number = int.from_bytes(sock.recv(1), "big")
        return cls.from_int(number)


class Address:
    def __init__(
        self, host: str, port: int, address_type: AddressType = AddressType.DOMAIN
    ):
        """Initialize an Address instance."""
        self.address_type = address_type
        self.host = host
        self.port = port

    @classmethod
    def read(cls, sock: socket.socket) -> "Address":
        """Read and return an Address instance from the socket."""
        address_type = AddressType.read(sock)
        match address_type:
            case AddressType.IPV4:
                host = cls._read_ipv4(sock)
            case AddressType.DOMAIN:
                host = cls._read_domain(sock)
            case AddressType.IPV6:
                host = cls._read_ipv6(sock)
        port_data = sock.recv(2)
        if len(port_data) != 2:
            raise Socks5ProtocolError("Cannot read port")
        port = int.from_bytes(port_data, "big")
        return cls(host, port, address_type)

    @staticmethod
    def _read_ipv4(sock: socket.socket) -> str:
        """Read and return an IPv4 address from the socket."""
        host_data = sock.recv(4)
        if len(host_data) != 4:
            raise Socks5ProtocolError("IPv4 address must be 4 bytes")
        return socket.inet_ntoa(host_data)

    @staticmethod
    def _read_domain(sock: socket.socket) -> str:
        """Read and return a domain address from the socket."""
        length_data = sock.recv(1)
        if len(length_data) != 1:
            raise Socks5ProtocolError("Cannot read domain length")
        length = int.from_bytes(length_data, "big")
        try:
            host = sock.recv(length).decode()
        except UnicodeDecodeError:
            raise Socks5ProtocolError("Error decoding domain")

        if length != len(host):
            raise Socks5ProtocolError("Domain length doesn't match")
        return host

    @staticmethod
    def _read_ipv6(sock: socket.socket) -> str:
        """Read and return an IPv6 address from the socket."""
        host_data = sock.recv(16)
        if len(host_data) != 16:
            raise Socks5ProtocolError("IPv6 address must be 16 bytes")
        return socket.inet_ntop(socket.AF_INET6, host_data)

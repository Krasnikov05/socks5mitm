import socket
from enum import Enum, auto
from .protocol import SOCKS5ProtocolError, receive


class AddressType(Enum):
    IPV4 = auto()
    IPV6 = auto()
    DOMAIN = auto()

    @classmethod
    def from_int(cls, number: int) -> "AddressType":
        """Convert an integer to the corresponding AddressType."""
        if number not in (1, 3, 4):
            raise SOCKS5ProtocolError("Unknown address type")
        return {1: cls.IPV4, 3: cls.DOMAIN, 4: cls.IPV6}[number]

    @classmethod
    def read(cls, sock: socket.socket) -> "AddressType":
        """Read and return an AddressType from the socket."""
        number = int.from_bytes(receive(sock, 1))
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
        # TODO: normal way to generate packet
        address_type = AddressType.read(sock)
        full_packet = sock.recv(1024)
        packet = full_packet[:-2]
        port = int.from_bytes(full_packet[-2:], "big")
        match address_type:
            case AddressType.IPV4:
                host = cls._read_ipv4(packet)
            case AddressType.DOMAIN:
                host = cls._read_domain(packet)
            case AddressType.IPV6:
                host = cls._read_ipv6(packet)
        output = cls(host, port, address_type)
        output.packet = full_packet
        print(output)
        return output

    @staticmethod
    def _read_ipv4(packet: bytes) -> str:
        """Read and return an IPv4 address from the socket."""
        return socket.inet_ntoa(packet)

    @staticmethod
    def _read_domain(packet: bytes) -> str:
        """Read and return a domain address from the socket."""
        try:
            host = packet[1:].decode()
        except UnicodeDecodeError:
            raise SOCKS5ProtocolError("Error decoding domain")
        return host

    @staticmethod
    def _read_ipv6(packet: bytes) -> str:
        """Read and return an IPv6 address from the socket."""
        return socket.inet_ntop(socket.AF_INET6, packet)

import socket
import pytest
from unittest.mock import MagicMock

from socks5mitm import Address, AddressType, Socks5ProtocolError


@pytest.fixture
def mock_socket():
    return MagicMock(spec=socket.socket)


def test_address_type(mock_socket):
    mock_socket.recv.side_effect = [b"\x01", b"\x03", b"\x04"]

    assert AddressType.read(mock_socket) == AddressType.IPV4
    assert AddressType.read(mock_socket) == AddressType.DOMAIN
    assert AddressType.read(mock_socket) == AddressType.IPV6

    with pytest.raises(Socks5ProtocolError):
        AddressType.from_int(2)


def test_address_ipv4(mock_socket):
    mock_socket.recv.side_effect = [b"\x01", b"\x01\x02\x03\x04", b"\x05\x39"]
    address = Address.read(mock_socket)
    assert address.address_type == AddressType.IPV4
    assert address.host == "1.2.3.4"
    assert address.port == 1337


def test_address_domain(mock_socket):
    mock_socket.recv.side_effect = [b"\x03", b"\x0a", b"github.com", b"\x05\x39"]
    address = Address.read(mock_socket)
    assert address.address_type == AddressType.DOMAIN
    assert address.host == "github.com"
    assert address.port == 1337


def test_address_domain_length_error(mock_socket):
    mock_socket.recv.side_effect = [b"\x03", b"\x05", b"domain"]
    with pytest.raises(Socks5ProtocolError):
        Address.read(mock_socket)


def test_address_ipv6(mock_socket):
    mock_socket.recv.side_effect = [
        b"\x04",
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10",
        b"\x05\x39",
    ]
    address = Address.read(mock_socket)
    assert address.address_type == AddressType.IPV6
    assert address.host == "102:304:506:708:90a:b0c:d0e:f10"
    assert address.port == 1337


def test_address_read_ipv6_length_mismatch(mock_socket):
    mock_socket.recv.side_effect = [
        b"\x04",
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11",
        b"\x05\x39",
    ]
    with pytest.raises(Socks5ProtocolError):
        Address.read(mock_socket)

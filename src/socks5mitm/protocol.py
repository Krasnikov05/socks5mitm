import socket

TIMEOUT = 1.0


class SOCKS5ProtocolError(Exception):
    """Custom exception class for representing errors related to the SOCKS5 protocol."""

    pass


def receive(sock: socket.socket, length: int, timeout: float = TIMEOUT):
    data = b""
    while len(data) < length:
        new_data = sock.recv(length - len(data))
        if new_data == b"":
            raise SOCKS5ProtocolError(f"Expected {length} bytes, got {len(data)}")
        data += new_data
    return data

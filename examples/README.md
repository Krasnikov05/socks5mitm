Examples
========

## Auth

```python
import sys
import socks5mitm


class Server(socks5mitm.SOCKS5Server):
    def handle_auth(self, ctx):
        return [socks5mitm.UsernamePassword("user", "12345")]

    def handle_address(self, address, ctx):
        print(f"REQUEST {address.host}:{address.port}")
        return address


if __name__ == "__main__":
    port = 9090 if len(sys.argv) != 2 else int(sys.argv[1])
    print(f"Listening on 127.0.0.1:{port}")
    Server().start("127.0.0.1", port)
```

## Multiple accounts

```python
import sys
import socks5mitm


ACCOUNTS = [("user1", "pass1"), ("user2", "pass2")]


class Auth(socks5mitm.UsernamePassword):
    def __init__(self):
        pass

    def verify(self, login, password):
        return (login, password) in ACCOUNTS


class Server(socks5mitm.SOCKS5Server):
    def handle_auth(self, ctx):
        return [Auth()]

    def handle_address(self, address, ctx):
        print(f"REQUEST {address.host}:{address.port}")
        return address


if __name__ == "__main__":
    port = 9090 if len(sys.argv) != 2 else int(sys.argv[1])
    print(f"Listening on 127.0.0.1:{port}")
    Server().start("127.0.0.1", port)
```

## Local domain

```python
import sys
import socks5mitm


class Server(socks5mitm.SOCKS5Server):
    def handle_address(self, address, ctx):
        print(f"REQUEST {address.host}:{address.port}")
        if address.host == "hello.local":
            return socks5mitm.Address("127.0.0.1", 8080)
        return address


if __name__ == "__main__":
    port = 9090 if len(sys.argv) != 2 else int(sys.argv[1])
    print(f"Listening on 127.0.0.1:{port}")
    Server().start("127.0.0.1", port)
```

## HTTP spy

```python
import sys
import socks5mitm


class Server(socks5mitm.SOCKS5Server):
    def handle_address(self, address, ctx):
        ctx["address"] = address.host
        return address

    def handle_send(self, data, ctx):
        if data.startswith(b"GET ") or data.startswith(b"POST "):
            print(ctx["address"], data.split(b"\n")[0].decode())
        return data


if __name__ == "__main__":
    port = 9090 if len(sys.argv) != 2 else int(sys.argv[1])
    print(f"Listening on 127.0.0.1:{port}")
    Server().start("127.0.0.1", port)
```


## TORify

```python
import sys
import socks5mitm


class Server(socks5mitm.SOCKS5Server):
    def handle_address(self, address, ctx):
        ctx["torify"] = address.host.endswith(".onion")
        return address

    def use_proxy(self, ctx):
        if ctx["torify"]:
            return socks5mitm.SOCKS5Proxy("127.0.0.1", 9050)
        return None


if __name__ == "__main__":
    port = 9090 if len(sys.argv) != 2 else int(sys.argv[1])
    print(f"Listening on 127.0.0.1:{port}")
    Server().start("127.0.0.1", port)
```

## `SOCKS5Server` structure

```python
class SOCKS5Server:
    """Defines the SOCKS5 server behavior."""

    def init_context(self) -> Any:
        """Initializes the connection context."""
        return {}

    def handle_auth(self, ctx: Any) -> List[Auth]:
        """Handles authentication methods."""
        return [NoAuth()]

    def handle_address(self, address: Address, ctx: Any) -> Address:
        """Processes the client-requested address."""
        return address

    def use_proxy(self, ctx: Any) -> Proxy | None:
        """Returns a proxy instance if applicable."""
        return None

    def handle_send(self, data: bytes, ctx: Any) -> bytes:
        """Handles data before sending it to the remote host."""
        return data

    def handle_receive(self, data: bytes, ctx: Any) -> bytes:
        """Handles data received from the remote host."""
        return data

    def handle_end(self, ctx: Any) -> None:
        """Handles cleanup at the end of a connection."""
        pass

    def start(self, host: str, port: int) -> None:
        """Starts the SOCKS5 server."""
        ...
```

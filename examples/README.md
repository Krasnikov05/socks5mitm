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

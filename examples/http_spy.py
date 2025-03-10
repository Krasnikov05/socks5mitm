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

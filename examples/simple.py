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

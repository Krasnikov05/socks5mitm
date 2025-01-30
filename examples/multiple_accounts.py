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

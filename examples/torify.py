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

<div align="center">
<h1>socks5mitm</h1>
<a href="https://opensource.org/licenses/MIT)"><img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge"></a>
<img src="https://img.shields.io/github/v/tag/krasnikov05/socks5mitm?style=for-the-badge&label=version">
</div>

This library implements a basic SOCKS5 server with [Man-in-the-middle attack](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) features.

Features
--------
- [x] IPv4 and IPv6 support
- [x] Address spoofing
- [x] Authorization
- [x] Connection through other proxy servers
- [x] Message inspection and modification
- [ ] TLS interception

Examples
--------

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

Take a look at the [examples](https://github.com/Krasnikov05/socks5mitm/tree/main/examples).

Installation
------------
Ensure you have Python 3 installed. Install the library using the pip package manager:
```shell
pip install git+https://github.com/krasnikov05/socks5mitm.git
```

Contribution
------------

Please follow the guidelines outlined below:

### Setting up a Virtual Environment

Before you start contributing, create and activate a virtual environment using the following command:

```shell
python3 -m venv .venv
source .venv/bin/activate   # On Linux or macOS
.venv\Scripts\activate      # On Windows
pip install '.[dev]'
```

### Tools

For maintaining code quality, use the following commands:

```shell
ruff check src
ruff format .
mypy src --strict
pytest
```

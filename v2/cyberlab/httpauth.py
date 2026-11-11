"""A deliberately weak HTTP login target for the dictionary-attack lab.

It listens on 127.0.0.1 only and is started by `cyberlab start` as its own
process:

    python3 -m cyberlab.httpauth --port 8091 --home ~/cyberlab

Routes:
    GET  /login   login form
    POST /login   dictionary-attack target: the password is compared in
                  plain text (no rate limiting, no lockout), so hydra with a
                  wordlist can find it. On success the flag is shown.

This is intentionally different from the web-sqli target: there is no SQL
injection here, only a plain password check, so it practices brute-force /
dictionary attacks rather than injection.
"""

from __future__ import annotations

import argparse
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from cyberlab.workspace import Workspace

HOST = "127.0.0.1"  # never listen anywhere else

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title} - Lab Login</title>
<style>
 body {{ font-family: sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }}
 input {{ display: block; margin: .3rem 0 1rem; padding: .4rem; width: 16rem; }}
 .flag {{ font-family: monospace; background: #eef; padding: .5rem; }}
 .error {{ color: #a00; font-family: monospace; }}
</style></head><body><h1>Lab Login</h1>{body}</body></html>
"""

LOGIN_FORM = """\
<form method="post" action="/login">
  <label>Username <input name="username" autocomplete="off"></label>
  <label>Password <input name="password" type="password"></label>
  <button type="submit">Log in</button>
</form>
"""


def make_credentials(ws: Workspace):
    """A fixed username and a per-workspace random password."""
    return "admin", ws.derive("dict-hydra:password", 24)


class Handler(BaseHTTPRequestHandler):
    server_version = "LabHTTP/1.0"
    ws: Workspace  # set by serve()

    def _send(self, status: int, title: str, body: str) -> None:
        data = PAGE.format(title=title, body=body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/":
            self._send(200, "Home", '<p>Dictionary-attack lab. <a href="/login">Log in</a>.</p>')
        elif path == "/login":
            self._send(200, "Log in", LOGIN_FORM)
        else:
            self._send(404, "Not found", "<p>Not found.</p>")

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/login":
            self._send(404, "Not found", "<p>Not found.</p>")
            return
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]

        expected_user, expected_pw = make_credentials(self.ws)
        if username == expected_user and password == expected_pw:
            body = (f"<p>Welcome back, {html.escape(username)}.</p>"
                    f'<p>Admin console unlocked.</p>'
                    f'<p class="flag">{self.ws.flag("dict-hydra")}</p>')
            self._send(200, "Welcome", body)
            return
        self._send(401, "Log in", f'<p class="error">Invalid username or password.</p>{LOGIN_FORM}')


def make_server(port: int, ws: Workspace) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"ws": ws})
    server = ThreadingHTTPServer((HOST, port), handler)
    assert server.server_address[0] == HOST, "the auth app must only listen on 127.0.0.1"
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="cyberlab dictionary-attack login target (127.0.0.1 only)")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--home", type=str, default=None)
    args = parser.parse_args()
    server = make_server(args.port, Workspace(Path(args.home) if args.home else None))
    print(f"listening on http://{HOST}:{server.server_address[1]}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

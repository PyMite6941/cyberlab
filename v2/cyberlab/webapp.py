"""The deliberately vulnerable web app the web challenges run against.

It listens on 127.0.0.1 only and is started by `cyberlab start` as its own
process:

    python3 -m cyberlab.webapp --port 8080 --home ~/cyberlab

Routes:
    GET  /          landing page
    GET  /login     login form
    POST /login     web-sqli: the query is built by pasting the username and
                    password into the SQL string, so `admin' --` logs in as
                    admin. The admin's welcome page shows the flag.
"""

from __future__ import annotations

import argparse
import html
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

from cyberlab.workspace import Workspace

HOST = "127.0.0.1"  # never listen anywhere else

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title} - Northwind Intranet</title>
<style>
 body {{ font-family: sans-serif; max-width: 40rem; margin: 3rem auto; padding: 0 1rem; }}
 input {{ display: block; margin: .3rem 0 1rem; padding: .4rem; width: 16rem; }}
 .flag {{ font-family: monospace; background: #eef; padding: .5rem; }}
 .error {{ color: #a00; font-family: monospace; }}
</style></head>
<body><h1>Northwind Intranet</h1>{body}</body></html>
"""


def make_users(ws: Workspace) -> sqlite3.Connection:
    """A fresh in-memory user table. admin's password is random per student."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    db.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [
        ("admin", ws.derive("admin-password", 24), "admin"),
        ("alice", "wonderland", "staff"),
        ("bob", "builder", "staff"),
    ])
    return db


class Handler(BaseHTTPRequestHandler):
    server_version = "NorthwindHTTP/1.0"
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
            self._send(200, "Home", '<p>Staff portal. <a href="/login">Log in</a>.</p>')
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

        # VULNERABLE ON PURPOSE (web-sqli): user input pasted into SQL.
        query = ("SELECT username, role FROM users "
                 f"WHERE username = '{username}' AND password = '{password}'")
        db = make_users(self.ws)
        try:
            row = db.execute(query).fetchone()
        except sqlite3.Error as e:
            self._send(500, "Error", f'<p class="error">Database error: {html.escape(str(e))}</p>' + LOGIN_FORM)
            return
        finally:
            db.close()

        if row is None:
            self._send(401, "Log in", '<p class="error">Invalid username or password.</p>' + LOGIN_FORM)
            return
        name, role = row
        body = f"<p>Welcome back, {html.escape(name)} ({html.escape(role)}).</p>"
        if role == "admin":
            body += f'<p>Admin console unlocked.</p><p class="flag">{self.ws.flag("web-sqli")}</p>'
        self._send(200, "Welcome", body)


LOGIN_FORM = """
<form method="post" action="/login">
  <label>Username <input name="username" autocomplete="off"></label>
  <label>Password <input name="password" type="password"></label>
  <button type="submit">Log in</button>
</form>
"""


def make_server(port: int, ws: Workspace) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"ws": ws})
    server = ThreadingHTTPServer((HOST, port), handler)
    assert server.server_address[0] == HOST, "the web app must only listen on 127.0.0.1"
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="cyberlab vulnerable web app (127.0.0.1 only)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--home", type=Path, default=None)
    args = parser.parse_args()
    server = make_server(args.port, Workspace(args.home))
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

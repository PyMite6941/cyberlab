"""A small public website with a forgotten directory, for the gobuster lab.

It listens on 127.0.0.1 only and is started by `cyberlab start` as its own
process:

    python3 -m cyberlab.webdirs --port 8092 --home ~/cyberlab

Routes:
    GET  /, /about, /contact   the public site (linked from the home page)
    GET  /robots.txt           "Disallow: /admin": a map of what to look at
    GET  /admin                403: it exists, but you're not allowed
    GET  /static               200: found by brute force, nothing in it
    GET  /<leftover>           200: a directory listing nobody linked to. Its
                               name is different for each student and is one
                               ordinary word in the wordlist.
    GET  /<leftover>/db-backup.sql
                               a database dump: the flag is in it

Nothing links to the leftover directory, so the only way to find it is to ask
for many names and watch the status codes, which is what gobuster does.
"""

from __future__ import annotations

import argparse
import html
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from cyberlab import pages, wordlists
from cyberlab.pages import HOST
from cyberlab.workspace import Workspace

SITE = "Northwind Traders"
DUMP_NAME = "db-backup.sql"

PUBLIC = {
    "/": ("Welcome",
          "<p>Northwind Traders: speciality foods, shipped worldwide.</p>"
          '<nav><a href="/about">About</a> <a href="/contact">Contact</a></nav>'),
    "/about": ("About", "<p>Family-run since 1994. This is our new website.</p>"),
    "/contact": ("Contact", "<p>Email sales@northwind.example or call 555-0100.</p>"),
}

ROBOTS = "User-agent: *\nDisallow: /admin\n"


def dump(ws: Workspace) -> str:
    """The forgotten database backup. The flag is the admin's API token."""
    return (
        "-- Northwind site backup (taken before the redesign)\n"
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, api_token TEXT);\n"
        "INSERT INTO users VALUES (1, 'admin', 'it@northwind.example', "
        f"'{ws.flag('web-gobuster')}');\n"
        "INSERT INTO users VALUES (2, 'alice', 'alice@northwind.example', NULL);\n"
        "INSERT INTO users VALUES (3, 'bob', 'bob@northwind.example', NULL);\n"
    )


class Handler(pages.LabHandler):
    server_version = "nginx/1.18.0"
    sys_version = ""
    site = SITE

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        leftover = "/" + wordlists.hidden_directory(self.ws)
        if path in PUBLIC:
            title, body = PUBLIC[path]
            self.send_page(200, title, body)
        elif path == "/robots.txt":
            self.send_bytes(200, ROBOTS.encode(), "text/plain; charset=utf-8")
        elif path.rstrip("/") == "/admin":
            self.send_page(403, "Forbidden", "<p>You don't have permission to view this page.</p>")
        elif path.rstrip("/") == "/static":
            self.send_page(200, "Index of /static/", '<p class="muted">(empty)</p>')
        elif path.rstrip("/") == leftover:
            self.send_page(200, f"Index of {leftover}/", self.listing(leftover))
        elif path == f"{leftover}/{DUMP_NAME}":
            self.send_bytes(200, dump(self.ws).encode(), "text/plain; charset=utf-8")
        else:
            self.not_found()

    def listing(self, leftover: str) -> str:
        href = html.escape(f"{leftover}/{DUMP_NAME}", quote=True)
        body = (f'<table><tr><th>Name</th><th>Size</th></tr>'
                f'<tr><td><a href="{href}">{DUMP_NAME}</a></td>'
                f"<td>{len(dump(self.ws))} bytes</td></tr></table>")
        return body + pages.challenge_lesson("web-gobuster",
            "What you found",
            [f"Nothing on the site links to {leftover}/, but the server hands it to anyone "
             "who asks for it by name. \"Nobody knows the URL\" isn't access control: a "
             "wordlist of a few thousand common names finds a directory like this in seconds.",
             "It holds a database backup left behind during a redesign. The flag is in it."],
            [("Read the backup", f"curl -s {self.base_url}{leftover}/{DUMP_NAME}"),
             ("The status codes are the map: 200 is readable, 403 exists but is locked, "
              "404 isn't there",
              f"curl -s -o /dev/null -w '%{{http_code}}\\n' {self.base_url}/admin")],
        )


def make_server(port: int, ws: Workspace) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((HOST, port), pages.bind(Handler, ws))
    assert server.server_address[0] == HOST, "the web dirs app must only listen on 127.0.0.1"
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description="cyberlab web directory target (127.0.0.1 only)")
    parser.add_argument("--port", type=int, default=8092)
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

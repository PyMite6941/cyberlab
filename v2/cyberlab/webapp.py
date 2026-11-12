"""The deliberately vulnerable web app the web challenges run against.

It listens on 127.0.0.1 only and is started by `cyberlab start` as its own
process:

    python3 -m cyberlab.webapp --port 8080 --home ~/cyberlab

Every route is vulnerable on purpose; each shows a flag when exploited.

    GET  /          landing page
    GET  /login     login form
    POST /login     web-sqli: username/password are pasted into the SQL query,
                    so `admin' --` logs in as admin. Sets session + role cookies.
    GET  /search    web-xss: ?q= is reflected into the page unescaped.
    GET  /invoice   web-idor: ?id= returns any invoice; no per-object check.
    GET  /dashboard web-cookie: trusts a client-side `role` cookie.
    POST /upload    web-upload: filename blocklist that only blocks `.php`.
"""

from __future__ import annotations

import argparse
import html
import sqlite3
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlsplit

from cyberlab import lessons
from cyberlab.workspace import Workspace

HOST = "127.0.0.1"  # never listen anywhere else

# Alternate extensions a default Apache + mod_php setup still runs as PHP, so a
# blocklist of just ".php" doesn't actually stop a webshell.
PHP_EXECUTABLE = (".phtml", ".php3", ".php4", ".php5", ".pht", ".phar")

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


def invoices(ws: Workspace) -> Dict[int, Tuple[str, str]]:
    """Invoice id -> (owner, amount). 1001 is the admin's and holds the flag."""
    return {
        1001: ("admin", ws.flag("web-idor")),
        1002: ("alice", "$420.00"),
        1003: ("bob", "$75.50"),
    }


class _InjectionFinder(HTMLParser):
    """Did our reflected input become live markup (a <script> or an on* handler)?"""

    def __init__(self) -> None:
        super().__init__()
        self.injected = False

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag == "script" or any(name.lower().startswith("on") for name, _ in attrs):
            self.injected = True


def reflects_as_script(page_html: str) -> bool:
    """True if page_html contains an executable script/handler (real reflected XSS)."""
    finder = _InjectionFinder()
    finder.feed(page_html)
    return finder.injected


class Handler(BaseHTTPRequestHandler):
    server_version = "NorthwindHTTP/1.0"
    ws: Workspace  # set by make_server()

    # ----- helpers -----

    def _send(self, status: int, title: str, body: str, cookies: Optional[Dict[str, str]] = None) -> None:
        data = PAGE.format(title=title, body=body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (cookies or {}).items():
            self.send_header("Set-Cookie", f"{name}={value}; Path=/")
        self.end_headers()
        self.wfile.write(data)

    def _cookie(self, name: str) -> str:
        jar = SimpleCookie(self.headers.get("Cookie", ""))
        return jar[name].value if name in jar else ""

    def _query(self) -> Dict[str, List[str]]:
        return parse_qs(urlsplit(self.path).query)

    # ----- routes -----

    def do_GET(self) -> None:
        route = urlsplit(self.path).path
        if route == "/":
            self._send(200, "Home",
                       '<p>Staff portal: <a href="/login">log in</a> or '
                       '<a href="/search?q=widgets">search the catalog</a>.</p>')
        elif route == "/login":
            self._send(200, "Log in", LOGIN_FORM)
        elif route == "/search":
            self._get_search()
        elif route == "/invoice":
            self._get_invoice()
        elif route == "/dashboard":
            self._get_dashboard()
        elif route == "/learn" or route.startswith("/learn/"):
            self._get_learn()
        else:
            self._send(404, "Not found", "<p>Not found.</p>")

    def do_POST(self) -> None:
        route = urlsplit(self.path).path
        if route == "/login":
            self._post_login()
        elif route == "/upload":
            self._post_upload()
        else:
            self._send(404, "Not found", "<p>Not found.</p>")

    def _form(self) -> Dict[str, List[str]]:
        length = int(self.headers.get("Content-Length") or 0)
        return parse_qs(self.rfile.read(length).decode("utf-8", "replace"))

    def _post_login(self) -> None:
        form = self._form()
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
        # The role cookie is set from the login and trusted later (web-cookie).
        cookies = {"session": "ok", "role": role}
        body = (f"<p>Welcome back, {html.escape(name)} ({html.escape(role)}).</p>"
                '<p><a href="/dashboard">Dashboard</a> · '
                '<a href="/invoice?id=1002">Your invoice</a></p>')
        if role == "admin":
            body += f'<p>Admin console unlocked.</p><p class="flag">{self.ws.flag("web-sqli")}</p>'
        self._send(200, "Welcome", body, cookies=cookies)

    def _get_search(self) -> None:
        q = self._query().get("q", [""])[0]
        # VULNERABLE ON PURPOSE (web-xss): q is reflected without escaping.
        results = f'<h2>Search</h2><p>No products match "{q}".</p>'
        page = PAGE.format(title="Search", body=results)
        if reflects_as_script(page):
            results += (f'<p>Reflected-XSS confirmed: your markup executes here.</p>'
                        f'<p class="flag">{self.ws.flag("web-xss")}</p>')
        self._send(200, "Search", results)

    def _get_invoice(self) -> None:
        if not self._cookie("session"):
            self._send(401, "Log in", '<p class="error">Log in first.</p>' + LOGIN_FORM)
            return
        try:
            invoice_id = int(self._query().get("id", ["0"])[0])
        except ValueError:
            self._send(400, "Invoice", "<p>Bad invoice id.</p>")
            return
        table = invoices(self.ws)
        if invoice_id not in table:
            self._send(404, "Invoice", "<p>No such invoice.</p>")
            return
        # VULNERABLE ON PURPOSE (web-idor): any logged-in user can read any
        # invoice; the app never checks the invoice belongs to them.
        owner, amount = table[invoice_id]
        self._send(200, "Invoice",
                   f"<h2>Invoice #{invoice_id}</h2><p>Account: {html.escape(owner)}</p>"
                   f'<p>Amount due: <span class="flag">{html.escape(amount)}</span></p>')

    def _get_dashboard(self) -> None:
        if not self._cookie("session"):
            self._send(401, "Log in", '<p class="error">Log in first.</p>' + LOGIN_FORM)
            return
        # VULNERABLE ON PURPOSE (web-cookie): the role comes from a cookie the
        # client can edit, not from the server's session record.
        role = self._cookie("role")
        if role == "admin":
            self._send(200, "Dashboard",
                       '<h2>Admin dashboard</h2><p>Full access.</p>'
                       f'<p class="flag">{self.ws.flag("web-cookie")}</p>')
        else:
            self._send(200, "Dashboard",
                       f"<h2>Staff dashboard</h2><p>You are '{html.escape(role or 'staff')}'. "
                       "Only admins see the admin dashboard.</p>")

    def _get_learn(self) -> None:
        route = urlsplit(self.path).path
        challenge_id = route[len("/learn/"):] if route.startswith("/learn/") else ""
        lesson = lessons.LESSONS.get(challenge_id)
        key = self._query().get("key", [""])[0]
        if lesson is None:
            self._send(404, "Not found",
                       f"<p>No debrief for {html.escape(challenge_id or '(none)')}.</p>")
            return
        if not lessons.unlocked(self.ws, challenge_id, key):
            self._send(200, "Locked",
                f"<p>The debrief for {html.escape(challenge_id)} unlocks once you solve the challenge.</p>"
                f"<p>cyberlab submit {challenge_id} <answer></p>")
            return
        self._send(200, lesson.title, lessons.render_html_body(lesson))

    def _post_upload(self) -> None:
        name = (self._query().get("file", [""])[0] or self._form().get("file", [""])[0]).strip()
        if not name:
            self._send(400, "Upload", "<p>usage: POST /upload?file=&lt;name&gt;</p>")
            return
        lower = name.lower()
        # VULNERABLE ON PURPOSE (web-upload): a blocklist of exactly ".php".
        if lower.endswith(".php"):
            self._send(403, "Upload", f"<p class='error'>'{html.escape(name)}' rejected: .php not allowed.</p>")
        elif lower.endswith(PHP_EXECUTABLE):
            self._send(200, "Upload",
                       f"<p>Stored /uploads/{html.escape(name)} — and the server still runs it as PHP.</p>"
                       f'<p class="flag">{self.ws.flag("web-upload")}</p>')
        else:
            self._send(200, "Upload", f"<p>Stored /uploads/{html.escape(name)}.</p>")


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

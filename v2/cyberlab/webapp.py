"""The deliberately vulnerable web app the web challenges run against.

It listens on 127.0.0.1 only and is started by `cyberlab start` as its own
process:

    python3 -m cyberlab.webapp --port 8080 --home ~/cyberlab

Routes:
    GET  /                landing page
    GET  /login           login form
    POST /login           web-sqli: the query is built by pasting the username
                          and password into the SQL string, so `admin' --`
                          logs in as admin. The admin page shows the flag.
    GET  /search?q=       web-xss: the search term is echoed into the page
                          without escaping, so markup in it becomes part of the
                          page and its script runs in the visitor's browser.
    /secure/login, /secure/search
                          the same two pages written correctly (a parameterized
                          query, escaped output), so students can run the same
                          attack against the fix and watch it fail.
"""

from __future__ import annotations

import argparse
import html
import sqlite3
from html.parser import HTMLParser
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlsplit

from cyberlab import pages
from cyberlab.pages import HOST
from cyberlab.workspace import Workspace

SITE = "Northwind Intranet"

STAFF = [
    ("admin", "IT administrator", "ext. 100"),
    ("alice", "Accounts", "ext. 214"),
    ("bob", "Facilities", "ext. 307"),
    ("carol", "Reception", "ext. 101"),
]


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


class _ScriptProbe(HTMLParser):
    """Finds the ways a fragment of HTML would run script in a browser."""

    URL_ATTRS = ("href", "src", "action", "formaction", "data")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        if tag == "script":
            self.found.append("a <script> element")
        for name, value in attrs:
            if name.startswith("on"):
                self.found.append(f"an {name}= event handler on <{tag}>")
            elif name in self.URL_ATTRS and (value or "").strip().lower().startswith("javascript:"):
                self.found.append(f"a javascript: URL in <{tag} {name}=...>")


def script_in(fragment: str) -> List[str]:
    """How `fragment`, placed in a page as HTML, would execute script.

    Empty when it's inert: plain text, harmless tags like <b>, or markup that
    was escaped. This is what makes web-xss checkable without a browser: the
    server parses the term the way a browser would and reports what would run.
    """
    probe = _ScriptProbe()
    probe.feed(fragment)
    probe.close()
    return probe.found


class Handler(pages.LabHandler):
    server_version = "NorthwindHTTP/1.0"
    site = SITE

    # ----- routing -----

    def do_GET(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        query = parse_qs(url.query, keep_blank_values=True)
        if url.path == "/":
            self.send_page(200, "Staff portal", HOME)
        elif url.path in ("/login", "/secure/login"):
            self.send_page(200, "Log in", login_form(url.path))
        elif url.path in ("/search", "/secure/search"):
            self.search(url.path, query.get("q", [None])[0])
        else:
            self.not_found()

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path not in ("/login", "/secure/login"):
            self.not_found()
            return
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        if path == "/login":
            self.login_vulnerable(username, password)
        else:
            self.login_secure(username, password)

    # ----- web-sqli -----

    def login_vulnerable(self, username: str, password: str) -> None:
        # VULNERABLE ON PURPOSE (web-sqli): user input pasted into SQL.
        query = ("SELECT username, role FROM users "
                 f"WHERE username = '{username}' AND password = '{password}'")
        db = make_users(self.ws)
        try:
            row = db.execute(query).fetchone()
        except sqlite3.Error as e:
            self.send_page(500, "Error", f'<p class="error">Database error: {html.escape(str(e))}</p>'
                           + login_form("/login"))
            return
        finally:
            db.close()

        if row is None:
            self.send_page(401, "Log in", '<p class="error">Invalid username or password.</p>'
                           + login_form("/login"))
            return
        name, role = row
        body = f"<p>Welcome back, {html.escape(name)} ({html.escape(role)}).</p>"
        if role == "admin":
            body += "<p>Admin console unlocked.</p>" + pages.flag_box(self.ws.flag("web-sqli"))
            body += self.sqli_lesson(query)
        self.send_page(200, "Welcome", body)

    def sqli_lesson(self, query: str) -> str:
        return pages.challenge_lesson("web-sqli",
            "What just happened",
            ["The server pasted what you typed straight into its SQL, then ran this:",
             "Your quote ended the username string early, so the rest of your input was read "
             "as SQL instead of as a name. The password check was commented out or made "
             "always true, and the database returned the admin row without anyone knowing "
             "the password."],
            [("Do it again from a terminal",
              f"curl -s {self.base_url}/login --data-urlencode \"username=admin' --\" -d password=x"),
             ("Let sqlmap find it and dump the users table (passwords included)",
              f"sqlmap -u {self.base_url}/login --data 'username=a&password=b' --batch --dump"),
             ("Run the same attack against the fixed login and watch it fail",
              f"curl -s {self.base_url}/secure/login --data-urlencode \"username=admin' --\" -d password=x")],
            submit="cyberlab submit web-sqli " + self.ws.flag("web-sqli"),
            code=query,
        )

    def login_secure(self, username: str, password: str) -> None:
        # The fix: placeholders. The driver sends the values separately from the
        # SQL text, so no input can change the shape of the query.
        query = "SELECT username, role FROM users WHERE username = ? AND password = ?"
        db = make_users(self.ws)
        try:
            row = db.execute(query, (username, password)).fetchone()
        finally:
            db.close()
        if row is not None:
            name, role = row
            self.send_page(200, "Welcome", f"<p>Welcome back, {html.escape(name)} "
                                           f"({html.escape(role)}). This is the fixed login: "
                                           "there's no flag here.</p>")
            return
        body = '<p class="error">Invalid username or password.</p>' + login_form("/secure/login")
        body += pages.challenge_lesson("web-sqli",
            "Why that didn't work here",
            ["This copy of the login uses a parameterized query:",
             f"The database was asked for a user literally named  {username}  and found none. "
             "Quotes and -- in a parameter are just characters in a value; they can't end the "
             "string or comment anything out, because the values never become part of the SQL text."],
            code=query,
        )
        self.send_page(401, "Log in", body)

    # ----- web-xss -----

    def search(self, path: str, term: Optional[str]) -> None:
        secure = path == "/secure/search"
        # A session cookie readable from script (no HttpOnly), so that
        # alert(document.cookie) shows what a real attacker would be after.
        cookie = {"Set-Cookie": f"nw_session=staff-{self.ws.derive('web-xss:session', 16)}; Path=/"}
        body = search_form(path, term or "")
        if term is None:
            self.send_page(200, "Staff directory", body, cookie)
            return

        # VULNERABLE ON PURPOSE (web-xss): on /search the term goes into the
        # page as-is. /secure/search escapes it, which is the whole fix.
        echoed = html.escape(term) if secure else term
        body += f"<p>Results for: {echoed}</p>"
        rows = [s for s in STAFF if term.lower() in " ".join(s).lower()] if term else []
        if rows:
            body += "<table><tr><th>Name</th><th>Team</th><th>Phone</th></tr>" + "".join(
                "<tr>" + "".join(f"<td>{html.escape(cell)}</td>" for cell in row) + "</tr>"
                for row in rows) + "</table>"
        else:
            body += '<p class="muted">No staff match that search.</p>'

        ran = script_in(term)
        if ran and not secure:
            body += pages.flag_box(self.ws.flag("web-xss")) + self.xss_lesson(term, ran)
        elif ran:
            body += pages.challenge_lesson("web-xss",
                "Why that didn't work here",
                ["This copy of the search escapes the term before putting it in the page: "
                 "< becomes &lt; and > becomes &gt;, so the browser shows your markup as text "
                 "instead of building elements from it. View the page source to see it.",
                 "Escaped: " + html.escape(term)],
            )
        self.send_page(200, "Staff directory", body, cookie)

    def xss_lesson(self, term: str, ran: List[str]) -> str:
        return pages.challenge_lesson("web-xss",
            "What just happened",
            [f"The page echoed your search term without escaping it, so the browser found "
             f"{ran[0]} in the page and treats it as part of the site. In a browser your "
             "script has already run (that's the alert, if you used one).",
             "The script runs as this site, for whoever opens the link. It can read the "
             "page, the session cookie (nw_session here, which isn't HttpOnly), and send "
             "requests as the victim. The attacker never touches the server: they only "
             "have to get someone to click."],
            [("The link you would send a victim: opening it is the whole attack",
              self.base_url + "/search?q=" + _quote(term)),
             ("Show what a script can steal: the session cookie",
              f"{self.base_url}/search?q=" + _quote("<script>alert(document.cookie)</script>")),
             ("Other tags work when <script> is filtered",
              "<img src=x onerror=alert(document.domain)>\n<svg onload=alert(1)>"),
             ("Run the same payload against the fixed search and watch it stay text",
              self.base_url + "/secure/search?q=" + _quote(term))],
            submit="cyberlab submit web-xss " + self.ws.flag("web-xss"),
        )


def _quote(text: str) -> str:
    return quote(text, safe="")


HOME = """
<p>Staff portal for Northwind Traders.</p>
<nav><a href="/login">Log in</a> <a href="/search">Staff directory</a></nav>
"""


def login_form(action: str) -> str:
    return f"""
<form method="post" action="{action}">
  <label>Username <input name="username" autocomplete="off"></label>
  <label>Password <input name="password" type="password"></label>
  <button type="submit">Log in</button>
</form>
"""


def search_form(action: str, term: str) -> str:
    return f"""
<form method="get" action="{action}">
  <label>Search staff by name or team
    <input name="q" value="{html.escape(term, quote=True)}" autocomplete="off"></label>
  <button type="submit">Search</button>
</form>
"""


def make_server(port: int, ws: Workspace) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((HOST, port), pages.bind(Handler, ws))
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

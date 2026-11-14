"""A deliberately weak HTTP login target for the dictionary-attack lab.

It listens on 127.0.0.1 only and is started by `cyberlab start` as its own
process:

    python3 -m cyberlab.httpauth --port 8091 --home ~/cyberlab

Routes:
    GET  /login   login form
    POST /login   dictionary-attack target: any number of guesses is allowed
                  (no rate limiting, no lockout), and the admin password is a
                  weak one from the wordlist, so hydra finds it. The success
                  page shows the flag and explains what went wrong.

This is intentionally different from the web-sqli target: there is no SQL
injection here, only a guessable password and nothing slowing the guessing.
"""

from __future__ import annotations

import argparse
import html
import shlex
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Tuple
from urllib.parse import parse_qs, urlsplit

from cyberlab import pages, wordlists
from cyberlab.pages import HOST
from cyberlab.workspace import Workspace

SITE = "Northwind Timesheets"
FAILURE = "Invalid username or password"  # what hydra's F= condition looks for

LOGIN_FORM = """
<form method="post" action="/login">
  <label>Username <input name="username" autocomplete="off"></label>
  <label>Password <input name="password" type="password"></label>
  <button type="submit">Log in</button>
</form>
"""


def make_credentials(ws: Workspace) -> Tuple[str, str]:
    """A fixed username and this workspace's password from its wordlist."""
    return "admin", wordlists.chosen_password(ws, "dict-hydra")


class Handler(pages.LabHandler):
    server_version = "LabHTTP/1.0"
    site = SITE
    attempts = 0  # failed logins since this process started, shared by all requests
    _lock = threading.Lock()

    def do_GET(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path == "/":
            self.send_page(200, "Timesheets", '<p>Staff timesheets. <a href="/login">Log in</a>.</p>')
        elif path == "/login":
            self.send_page(200, "Log in", LOGIN_FORM)
        else:
            self.not_found()

    def do_POST(self) -> None:  # noqa: N802
        if urlsplit(self.path).path != "/login":
            self.not_found()
            return
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]

        cls = type(self)
        expected_user, expected_pw = make_credentials(self.ws)
        if username != expected_user or password != expected_pw:
            with cls._lock:
                cls.attempts += 1
            self.send_page(401, "Log in", f'<p class="error">{FAILURE}.</p>{LOGIN_FORM}')
            return

        with cls._lock:
            failed = cls.attempts
        body = (f"<p>Welcome back, {html.escape(username)}.</p><p>Admin console unlocked.</p>"
                + pages.flag_box(self.ws.flag("dict-hydra")) + self.lesson(password, failed))
        self.send_page(200, "Welcome", body)

    def lesson(self, password: str, failed: int) -> str:
        wordlist = shlex.quote(str(self.ws.home / "dict-hydra" / "wordlist.txt"))
        return pages.challenge_lesson("dict-hydra",
            "What just happened",
            [f"This login took {failed} wrong guesses before the right one, and never "
             "slowed down, locked the account, or told anyone. The password was a word and "
             "a number, so it was in a list of common passwords, and trying a whole list "
             "against a login takes seconds.",
             "Nothing was broken or bypassed: the login worked exactly as written. That's "
             "why this is the most common way real accounts are taken over: leaked and "
             "common passwords replayed against logins that allow unlimited attempts."],
            [("The attack, with hydra",
              f"hydra -l admin -P {wordlist} -s {self.port} {HOST} "
              f"http-post-form '/login:username=^USER^&password=^PASS^:F={FAILURE}'"),
             ("The same attack with nothing but curl and a loop",
              "while read -r pw; do\n"
              f"  curl -s {self.base_url}/login -d username=admin --data-urlencode \"password=$pw\" \\\n"
              f"    | grep -q '{FAILURE}' || {{ echo \"found: $pw\"; break; }}\n"
              f"done < {wordlist}")],
            submit=f"cyberlab submit dict-hydra {password}",
        )


def make_server(port: int, ws: Workspace) -> ThreadingHTTPServer:
    # A subclass per server, so each server counts its own failed attempts.
    handler = pages.bind(Handler, ws)
    handler._lock = threading.Lock()
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

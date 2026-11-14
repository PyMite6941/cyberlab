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
    GET  /account?id=     web-idor: a simulated Alice session can read any
                          account record by changing its identifier.
    GET  /session         web-session: an unsigned JWT role claim is trusted.
    POST /upload          web-upload: trusts a double extension and client MIME type.
    /secure/login, /secure/search, /secure/account
                          fixed versions for direct comparison.
    /secure/session      verifies the JWT signature before trusting claims.
    /secure/upload       validates images and stores them outside the public directory.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import hmac
import html
import json
import re
import secrets
import sqlite3
import time
from email.parser import BytesParser
from email.policy import default
from http.cookies import CookieError, SimpleCookie
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
        elif url.path in ("/account", "/secure/account"):
            self.account(url.path, query.get("id", ["101"])[0])
        elif url.path in ("/session", "/secure/session"):
            self.session(url.path)
        elif url.path in ("/upload", "/secure/upload"):
            self.upload_form(url.path)
        elif url.path.startswith("/uploads/"):
            self.serve_upload(url.path.removeprefix("/uploads/"))
        else:
            self.not_found()

    def do_POST(self) -> None:  # noqa: N802
        path = urlsplit(self.path).path
        if path in ("/upload", "/secure/upload"):
            self.upload(path)
            return
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

    # ----- web-idor -----

    def account(self, path: str, requested_id: str) -> None:
        accounts = {
            "100": ("admin", "IT administrator"),
            "101": ("alice", "Accounts"),
            "102": ("bob", "Facilities"),
        }
        account = accounts.get(requested_id)
        if account is None:
            self.not_found()
            return

        secure = path == "/secure/account"
        if secure and requested_id != "101":
            body = ('<p class="error">You may only view your own account.</p>'
                    + pages.challenge_lesson(
                        "web-idor",
                        "Why that request was denied",
                        ["The fixed route checks that the requested record belongs to "
                         "the signed-in user before returning it. Knowing an identifier "
                         "does not grant permission to access that object."],
                    ))
            self.send_page(403, "Forbidden", body)
            return

        name, role = account
        body = (f"<p>Signed in as Alice. Account {requested_id}: "
                f"{html.escape(name)} ({html.escape(role)}).</p>")
        if requested_id == "100" and not secure:
            body += pages.flag_box(self.ws.flag("web-idor"))
            body += pages.challenge_lesson(
                "web-idor",
                "What just happened",
                ["The page accepted an account ID supplied by the browser but never "
                 "checked whether Alice was allowed to read that account. Changing 101 "
                 "to 100 returned the administrator's record."],
                [("Read Alice's own account",
                  f"curl -i '{self.base_url}/account?id=101'"),
                 ("Change only the object ID in this local lab",
                  f"curl -i '{self.base_url}/account?id=100'"),
                 ("Compare with the fixed route",
                  f"curl -i '{self.base_url}/secure/account?id=100'")],
                submit="cyberlab submit web-idor " + self.ws.flag("web-idor"),
            )
        self.send_page(200, "Account", body)

    # ----- web-session -----

    def session(self, path: str) -> None:
        secure = path == "/secure/session"
        token = self.session_cookie()
        if token is None:
            token = create_session_token("staff", self.ws, signed=secure)
            body = ('<p>Signed in as Alice (staff). The session cookie is ready; '
                    'inspect it with curl -i, then compare the vulnerable and fixed routes.</p>')
            self.send_page(200, "Staff session", body, {
                "Set-Cookie": f"nw_auth={token}; Path=/; HttpOnly; SameSite=Lax",
            })
            return

        claims = read_session_token(token, self.ws, verify_signature=secure)
        if claims is None:
            body = '<p class="error">Session token rejected.</p>'
            if secure:
                body += pages.challenge_lesson(
                    "web-session",
                    "Why this token was rejected",
                    ["The fixed route verifies the HS256 signature before trusting any "
                     "claim. A changed role, an unsigned token, or an invalid signature "
                     "cannot create an administrator session."],
                )
            self.send_page(401, "Session rejected", body)
            return

        role = claims["role"]
        body = f"<p>Signed in as {html.escape(claims['sub'])} ({html.escape(role)}).</p>"
        if role == "admin":
            body += pages.flag_box(self.ws.flag("web-session"))
            body += pages.challenge_lesson(
                "web-session",
                "What just happened",
                ["The vulnerable endpoint decoded the JWT payload but did not verify its "
                 "signature. Changing the role claim from staff to admin was enough to "
                 "forge an administrator session.",
                 "A JWT payload is encoded, not encrypted. Anyone holding the token can "
                 "read its claims; the signature proves they were issued by a trusted signer "
                 "but does not hide them."],
                [("Compare with the fixed endpoint",
                  f"curl -i -H 'Cookie: nw_auth={token}' "
                  f"{self.base_url}/secure/session")],
                submit="cyberlab submit web-session " + self.ws.flag("web-session"),
            )
        self.send_page(200, "Staff session", body)

    def session_cookie(self) -> Optional[str]:
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
        except CookieError:
            return None
        morsel = cookies.get("nw_auth")
        return morsel.value if morsel else None

    # ----- web-upload -----

    def upload_form(self, path: str) -> None:
        action = html.escape(path, quote=True)
        body = (f'<form method="post" action="{action}" enctype="multipart/form-data">'
                '<label>Profile image <input type="file" name="file"></label>'
                '<button type="submit">Upload</button></form>')
        self.send_page(200, "Profile image upload", body)

    def upload(self, path: str) -> None:
        uploaded = self.read_upload()
        if uploaded is None:
            return
        filename, media_type, contents = uploaded
        secure = path == "/secure/upload"
        upload_id = secrets.token_hex(16)

        if secure:
            rejection = self.validate_image_upload(filename, media_type, contents)
            if rejection:
                body = ('<p class="error">Upload rejected: '
                        + html.escape(rejection) + '</p>')
                body += pages.challenge_lesson(
                    "web-upload",
                    "Why this upload was blocked",
                    ["The fixed route checks the filename, declared media type, and file "
                     "signature before storing an image. A user-controlled extension or "
                     "Content-Type is not proof of what the bytes contain."],
                )
                self.send_page(415, "Upload rejected", body)
                return

            private_path = self.ws.path("web-upload", "private", upload_id)
            private_path.write_bytes(contents)
            self.send_page(
                201,
                "Upload stored safely",
                '<p>Image accepted and stored outside the public web directory. '
                'It is not addressable as a same-origin page.</p>',
            )
            return

        public_path = self.ws.path("web-upload", "public", upload_id)
        public_path.write_bytes(contents)
        metadata_path = self.ws.path("web-upload", "public", upload_id + ".json")
        metadata_path.write_text(
            json.dumps({"filename": filename, "media_type": media_type}),
            encoding="utf-8",
        )
        body = f'<p>Upload accepted. <a href="/uploads/{upload_id}">View uploaded file</a>.</p>'
        is_html_bypass = (
            filename.lower().endswith(".jpg.html")
            and media_type.lower() == "image/jpeg"
            and contents.lstrip().lower().startswith((b"<!doctype html", b"<html"))
        )
        if is_html_bypass:
            body += pages.flag_box(self.ws.flag("web-upload"))
            body += pages.challenge_lesson(
                "web-upload",
                "What just happened",
                ["The upload accepted an HTML file named with a double extension and trusted "
                 "the browser-supplied image/jpeg media type. The public file is then served "
                 "inline from the same site, where active HTML can run in that site's origin.",
                 "A file extension or Content-Type header is only a claim from the client; "
                 "neither validates the actual content."],
                [("Open the uploaded file on this local target",
                  f"curl -i {self.base_url}/uploads/{upload_id}"),
                 ("Try the same upload against the fixed validator",
                  f"curl -i -F 'file=@avatar.jpg.html;type=image/jpeg;"
                  f"filename=avatar.jpg.html' {self.base_url}/secure/upload")],
                submit="cyberlab submit web-upload " + self.ws.flag("web-upload"),
            )
        self.send_page(201, "Upload accepted", body, {
            "Location": f"/uploads/{upload_id}",
        })

    def read_upload(self) -> Optional[Tuple[str, str, bytes]]:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_page(400, "Invalid upload", '<p class="error">Invalid Content-Length.</p>')
            return None
        if length <= 0:
            self.send_page(400, "Invalid upload", '<p class="error">Upload is empty.</p>')
            return None
        if length > 1_048_576 + 16_384:
            self.send_page(413, "Upload too large", '<p class="error">Maximum upload size is 1 MiB.</p>')
            return None

        content_type = self.headers.get("Content-Type", "")
        envelope = (
            b"Content-Type: " + content_type.encode("latin-1")
            + b"\r\nMIME-Version: 1.0\r\n\r\n"
        )
        message = BytesParser(policy=default).parsebytes(envelope + self.rfile.read(length))
        if not message.is_multipart():
            self.send_page(400, "Invalid upload", '<p class="error">Expected multipart form data.</p>')
            return None

        files = []
        for part in message.iter_parts():
            if (part.get_content_disposition() == "form-data"
                    and part.get_param("name", header="content-disposition") == "file"
                    and part.get_filename() is not None):
                contents = part.get_payload(decode=True)
                files.append((
                    part.get_filename(),
                    part.get_content_type(),
                    contents if contents is not None else b"",
                ))
        if len(files) != 1:
            self.send_page(400, "Invalid upload", '<p class="error">Upload exactly one file.</p>')
            return None
        filename, media_type, contents = files[0]
        if len(contents) > 1_048_576:
            self.send_page(413, "Upload too large", '<p class="error">Maximum upload size is 1 MiB.</p>')
            return None
        return filename, media_type, contents

    @staticmethod
    def validate_image_upload(filename: str, media_type: str, contents: bytes) -> Optional[str]:
        if (not filename or len(filename) > 128 or "/" in filename
                or "\\" in filename or filename in (".", "..")):
            return "Use a simple image filename."
        extension = Path(filename).suffix.lower()
        expected = {
            ".png": ("image/png", b"\x89PNG\r\n\x1a\n"),
            ".jpg": ("image/jpeg", b"\xff\xd8\xff"),
            ".jpeg": ("image/jpeg", b"\xff\xd8\xff"),
        }.get(extension)
        if expected is None:
            return "Only PNG and JPEG images are allowed."
        expected_type, signature = expected
        if media_type.lower() != expected_type:
            return "The declared media type does not match the image extension."
        if not contents.startswith(signature):
            return "The file bytes do not match an image signature."
        return None

    def serve_upload(self, upload_id: str) -> None:
        if not re.fullmatch(r"[0-9a-f]{32}", upload_id):
            self.not_found()
            return
        public_dir = self.ws.path("web-upload", "public", ".placeholder").parent
        try:
            metadata = json.loads(
                (public_dir / (upload_id + ".json")).read_text(encoding="utf-8"),
            )
            contents = (public_dir / upload_id).read_bytes()
        except FileNotFoundError:
            self.not_found()
            return
        filename = metadata.get("filename", "")
        media_type = "text/html; charset=utf-8" if filename.lower().endswith(".html") else (
            metadata.get("media_type", "application/octet-stream")
        )
        self.send_bytes(200, contents, media_type)


def _quote(text: str) -> str:
    return quote(text, safe="")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _session_signing_key(ws: Workspace) -> bytes:
    return bytes.fromhex(ws.derive("web-session:signing-key", 64))


def create_session_token(
    role: str, ws: Workspace, *, signed: bool, expires_at: Optional[int] = None,
) -> str:
    header = {"alg": "HS256" if signed else "none", "typ": "JWT"}
    payload = {
        "iss": "northwind",
        "sub": "alice",
        "role": role,
        "exp": expires_at if expires_at is not None else int(time.time()) + 3600,
    }
    signing_input = ".".join((
        _b64url_encode(json.dumps(header, separators=(",", ":")).encode()),
        _b64url_encode(json.dumps(payload, separators=(",", ":")).encode()),
    ))
    signature = (
        _b64url_encode(hmac.new(_session_signing_key(ws), signing_input.encode("ascii"),
                                hashlib.sha256).digest())
        if signed else ""
    )
    return f"{signing_input}.{signature}"


def read_session_token(token: str, ws: Workspace, *, verify_signature: bool) -> Optional[dict]:
    try:
        header_part, payload_part, signature = token.split(".")
        header = json.loads(_b64url_decode(header_part))
        claims = json.loads(_b64url_decode(payload_part))
        if not isinstance(header, dict) or not isinstance(claims, dict):
            return None
        if verify_signature:
            if header.get("alg") != "HS256":
                return None
            signing_input = f"{header_part}.{payload_part}".encode("ascii")
            expected = _b64url_encode(hmac.new(
                _session_signing_key(ws), signing_input, hashlib.sha256,
            ).digest())
            if not hmac.compare_digest(signature, expected):
                return None
        if (claims.get("iss") != "northwind"
                or claims.get("role") not in ("staff", "admin")
                or not isinstance(claims.get("sub"), str)
                or not isinstance(claims.get("exp"), int)
                or claims["exp"] <= int(time.time())):
            return None
        return claims
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error):
        return None


HOME = """
<p>Staff portal for Northwind Traders.</p>
<nav><a href="/login">Log in</a> <a href="/search">Staff directory</a>
<a href="/account?id=101">My account</a></nav>
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

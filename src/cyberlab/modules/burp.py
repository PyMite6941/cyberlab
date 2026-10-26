"""Simulated intercepting proxy (BurpSuite-style), fully offline.

Provides a mock vulnerable web application and a local intercepting proxy that
lets you inspect and modify HTTP requests and responses before they are
forwarded. All traffic lives in memory - no real network is used.

To launch from cyberterminal:

    cyberterminal> burp

Inside the Burp shell:

    burp> targets
    burp> intercept GET /login
    burp> modify header Content-Type application/x-www-form-urlencoded
    burp> modify body username=admin&password=password
    burp> forward
    burp> show response
    burp> quit
"""

from __future__ import annotations

import argparse
import cmd
import html
import shlex
import sys
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Simulated target application
# ---------------------------------------------------------------------------

class MockTarget:
    """A pretend vulnerable web application served by the simulated target."""

    def __init__(self, base_url: str = "http://lab.local") -> None:
        self.base_url = base_url
        self.users = {
            "admin": {"password": "s3cr3t", "role": "admin"},
            "user1": {"password": "password123", "role": "user"},
        }
        self.sessions: Dict[str, str] = {}  # session_token -> username

    def handle(self, method: str, path: str, headers: Dict[str, str],
               body: str) -> Dict:
        """Return a mock HTTP response dict for the given request."""
        status = "200 OK"
        body_text = ""
        content_type = "text/html"

        if method == "GET" and path == "/":
            body_text = (
                "<html><body><h1>Lab Target</h1>"
                "<p>Endpoints: /login /search /profile /admin</p>"
                "</body></html>"
            )
        elif method == "GET" and path == "/login":
            body_text = (
                "<html><body><h2>Login</h2>"
                '<form method="POST" action="/login">'
                "user: <input name='username'><br>"
                "pass: <input name='password' type='password'><br>"
                "<input type='submit'></form></body></html>"
            )
        elif method == "POST" and path == "/login":
            user = self._parse_form(body).get("username", "")
            pwd = self._parse_form(body).get("password", "")
            u = self.users.get(user)
            if u and u["password"] == pwd:
                token = "sess-" + user
                self.sessions[token] = user
                body_text = f"<html><body>Logged in as {user}. <a href='/profile'>profile</a></body></html>"
                headers_out = {"Set-Cookie": f"session={token}"}
            else:
                status = "401 Unauthorized"
                body_text = "<html><body>Invalid credentials.</body></html>"
                headers_out = {}
            return {
                "status": status,
                "headers": {"Content-Type": "text/html", **headers_out},
                "body": body_text,
            }
        elif method == "GET" and path.split("?")[0] == "/search":
            q = self._parse_qs(path).get("q", "")
            body_text = (
                "<html><body><h2>Search results for: "
                + html.escape(q) + "</h2><p>(simulated)</p></body></html>"
            )
        elif method == "GET" and path == "/profile":
            token = self._session_token(headers)
            user = self.sessions.get(token)
            if not user:
                status = "302 Found"
                body_text = ""
                return {"status": status, "headers": {"Location": "/login"}, "body": body_text}
            body_text = (
                f"<html><body><h2>Profile: {user}</h2>"
                f"<p>Role: {self.users[user]['role']}</p></body></html>"
            )
        elif method == "GET" and path == "/admin":
            token = self._session_token(headers)
            user = self.sessions.get(token)
            if not user or self.users[user]["role"] != "admin":
                status = "403 Forbidden"
                body_text = "<html><body>Admin access denied.</body></html>"
            else:
                body_text = (
                    "<html><body><h2>Admin Panel</h2>"
                    "<p>Users: admin, user1</p>"
                    "<p>Flag: CTF{offline_burp_sim}</p></body></html>"
                )
        else:
            status = "404 Not Found"
            body_text = "<html><body>Not found.</body></html>"

        return {
            "status": status,
            "headers": {"Content-Type": content_type},
            "body": body_text,
        }

    @staticmethod
    def _parse_form(body: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for part in body.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k] = v.replace("+", " ")
        return out

    @staticmethod
    def _parse_qs(path: str) -> Dict[str, str]:
        out: Dict[str, str] = {}
        if "?" in path:
            qs = path.split("?", 1)[1]
            for part in qs.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    out[k] = v
        return out

    @staticmethod
    def _session_token(headers: Dict[str, str]) -> Optional[str]:
        cookie = headers.get("Cookie", "")
        for part in cookie.split(";"):
            if part.strip().startswith("session="):
                return part.strip().split("=", 1)[1]
        return None


def format_request(method: str, path: str, headers: Dict[str, str], body: str) -> str:
    """Render an intercepted HTTP request as a raw text block.

    Args:
        method: HTTP method (GET, POST, etc.).
        path: Request path including query string.
        headers: Request headers as a dict.
        body: Request body string.

    Returns:
        A formatted raw HTTP request string.
    """
    lines = [f"{method} {path} HTTP/1.1"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


def format_response(status: str, headers: Dict[str, str], body: str) -> str:
    """Render an HTTP response as a raw text block.

    Args:
        status: Status line (e.g. "200 OK").
        headers: Response headers as a dict.
        body: Response body string.

    Returns:
        A formatted raw HTTP response string.
    """
    lines = [f"HTTP/1.1 {status}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Interactive Burp simulator shell
# ---------------------------------------------------------------------------

class BurpShell(cmd.Cmd):
    intro = (
        "=== cyberlab BurpSuite simulator (offline) ===\n"
        "Type 'help' or '?' to list commands. Type 'quit' to exit.\n"
    )
    prompt = "burp> "

    def __init__(self, target: MockTarget) -> None:
        super().__init__()
        self.target = target
        self._pending: Optional[Dict] = None  # captured request awaiting action
        self._last_response: Optional[Dict] = None

    # -- command helpers --
    def do_targets(self, arg: str) -> None:
        """List simulated target endpoints.

        usage: targets
        """
        print("Target:", self.target.base_url)
        print(" Endpoints: GET /  GET /login  POST /login  GET /search  GET /profile  GET /admin")

    def do_intercept(self, arg: str) -> None:
        """Capture a simulated request for inspection/modification.

        usage: intercept <METHOD> <path> [body]
        Example: intercept POST /login username=admin&password=wrong
        """
        tokens = shlex.split(arg)
        if len(tokens) < 2:
            print("usage: intercept <METHOD> <path> [body]")
            return
        method = tokens[0].upper()
        path = tokens[1]
        body = " ".join(tokens[2:]) if len(tokens) > 2 else ""
        headers = {
            "Host": "lab.local",
            "User-Agent": "cyberlab-burp-sim/0.1",
            "Accept": "*/*",
        }
        if body:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body))
        self._pending = {
            "method": method,
            "path": path,
            "headers": dict(headers),
            "body": body,
        }
        self._last_response = None
        print("Request intercepted:")
        print(format_request(method, path, headers, body))

    def do_modify(self, arg: str) -> None:
        """Modify the intercepted request or last response.

        usage: modify header <Name> <Value>
        usage: modify body <text>
        usage: modify response body <text>
        """
        tokens = shlex.split(arg)
        if len(tokens) < 2:
            print("usage: modify header <Name> <Value> | body <text> | response body <text>")
            return
        if tokens[0] == "header" and len(tokens) >= 3:
            if self._pending is None:
                print("No intercepted request. Use 'intercept' first.")
                return
            name, value = tokens[1], " ".join(tokens[2:])
            self._pending["headers"][name] = value
            print(f"Set header {name}: {value}")
        elif tokens[0] == "body" and len(tokens) >= 2:
            if self._pending is None:
                print("No intercepted request. Use 'intercept' first.")
                return
            self._pending["body"] = " ".join(tokens[1:])
            self._pending["headers"]["Content-Length"] = str(len(self._pending["body"]))
            print("Request body updated.")
        elif tokens[0] == "response" and len(tokens) >= 3 and tokens[1] == "body":
            if self._last_response is None:
                print("No response captured yet. Use 'forward' first.")
                return
            self._last_response["body"] = " ".join(tokens[2:])
            self._last_response["headers"]["Content-Length"] = str(len(self._last_response["body"]))
            print("Response body updated.")
        else:
            print("usage: modify header <Name> <Value> | body <text> | response body <text>")

    def do_show(self, arg: str) -> None:
        """Show the intercepted request or last response.

        usage: show request
        usage: show response
        """
        if arg == "request":
            if self._pending is None:
                print("No intercepted request.")
            else:
                print(format_request(
                    self._pending["method"], self._pending["path"],
                    self._pending["headers"], self._pending["body"]))
        elif arg == "response":
            if self._last_response is None:
                print("No response captured yet.")
            else:
                print(format_response(
                    self._last_response["status"], self._last_response["headers"],
                    self._last_response["body"]))
        else:
            print("usage: show request | response")

    def do_forward(self, arg: str) -> None:
        """Forward the intercepted request to the simulated target.

        usage: forward
        """
        if self._pending is None:
            print("No intercepted request. Use 'intercept' first.")
            return
        resp = self.target.handle(
            self._pending["method"], self._pending["path"],
            self._pending["headers"], self._pending["body"],
        )
        self._last_response = resp
        print("Forwarded to target. Response:")
        print(format_response(resp["status"], resp["headers"], resp["body"]))

    def do_response(self, arg: str) -> None:
        """Alias for show response."""
        self.do_show("response")

    def do_quit(self, arg: str) -> None:
        """Exit the Burp simulator."""
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        """Exit the Burp simulator."""
        return self.do_quit(arg)

    def do_help(self, arg: str) -> None:
        """List commands."""
        super().do_help(arg)


def run_burp(args: argparse.Namespace) -> int:
    target = MockTarget(base_url=args.target)
    shell = BurpShell(target)
    shell.cmdloop()
    return 0


# Self-register with the lab registry so `cyberlab labs` / `cyberlab run` work.
from cyberlab.core import Scenario, registry as _registry  # noqa: E402


def _burp_lab() -> int:
    return run_burp(argparse.Namespace(target="http://lab.local"))


_registry.register(
    Scenario(
        id="burp-01",
        title="Intercepting proxy basics",
        description="Practice inspecting and modifying HTTP requests/responses "
        "against a simulated vulnerable target, BurpSuite-style, offline.",
        module="burp",
        run=_burp_lab,
        tags=["web", "proxy", "burp", "offline"],
    )
)

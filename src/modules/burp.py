"""Simulated intercepting proxy (BurpSuite-style), fully offline.

Generates simulated HTTP traffic with embedded challenges. Challenges generate
dynamic data each time and verify answers against computed values - no hardcoded
flags or credentials.

No real network connections are made - everything is simulated locally.

To launch from cyberterminal:

    cyberterminal> burp

Inside the Burp shell:

    burp> targets
    burp> intercept GET /login
    burp> modify header Content-Type application/x-www-form-urlencoded
    burp> modify body username=admin&password=test
    burp> forward
    burp> show response
    burp> quit
"""

from __future__ import annotations

import argparse
import cmd
import html
import random
import shlex
from typing import Dict, List, Optional

from src.core.challenge import Challenge, ChallengeRegistry, ChallengeResult

registry = ChallengeRegistry()


# ---------------------------------------------------------------------------
# Simulated target application
# ---------------------------------------------------------------------------

class MockTarget:
    """A pretend vulnerable web application served by the simulated target.

    All credentials and responses are generated dynamically - no hardcoded
    passwords or flags. Each instance creates unique credentials.
    """

    def __init__(self, base_url: str = "http://lab.local") -> None:
        self.base_url = base_url
        self.admin_password = self._random_password(12)
        self.user_password = self._random_password(10)
        self.sessions: Dict[str, str] = {}  # session_token -> username

    _rng = random.Random(42)

    @classmethod
    def _random_password(cls, length: int = 12) -> str:
        chars = ("abcdefghijklmnopqrstuvwxyz"
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                 "0123456789!@#$%^&*")
        return "".join(cls._rng.choice(chars) for _ in range(length))

    def handle(self, method: str, path: str, headers: Dict[str, str],
               body: str) -> dict:
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
            if user == "admin" and pwd == self.admin_password:
                token = "sess-admin"
                self.sessions[token] = "admin"
                body_text = "<html><body>Logged in as admin.</body></html>"
                headers_out = {"Set-Cookie": f"session={token}"}
            elif user == "user1" and pwd == self.user_password:
                token = "sess-user1"
                self.sessions[token] = "user1"
                body_text = "<html><body>Logged in as user1.</body></html>"
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
        elif method == "GET" and path == "/search":
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
                f"<p>Role: {self._get_user_role(user)}</p>"
                "</body></html>"
            )
        elif method == "GET" and path == "/admin":
            token = self._session_token(headers)
            user = self.sessions.get(token)
            if not user or self._get_user_role(user) != "admin":
                status = "403 Forbidden"
                body_text = "<html><body>Admin access denied.</body></html>"
            else:
                body_text = (
                    "<html><body><h2>Admin Panel</h2>"
                    "<p>Users: admin, user1</p>"
                    f"<p>Admin password: {self.admin_password}</p>"
                    "</body></html>"
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

    @staticmethod
    def _get_user_role(username: str) -> str:
        if username == "admin":
            return "admin"
        return "user"


class SQLInjectionChallenge(Challenge):
    def __init__(self):
        super().__init__(
            id="web-sqli-01",
            title="SQL Injection via Intercepting Proxy",
            category="web",
            module="burp",
            description=("Inject a SQL payload into a search parameter through "
                         "the intercepting proxy and observe the response."),
            vulnerability="sql_injection",
            difficulty="easy",
            track="web-security",
            steps=[
                {"description": "Start the Burp simulator", "command": "burp", "notes": "Inside the shell, type 'targets"},
                {"description": "Intercept a search request", "command": "intercept GET /search?q=test", "notes": ""},
                {"description": "Inject a SQL payload", "command": "modify body q=1' OR '1'='1", "notes": ""},
                {"description": "Forward and observe the response", "command": "forward", "notes": ""},
            ],
            ai_enabled=True,
            requires_online=False,
        )
        self._target_payload = "1' OR '1'='1"

    def generate(self) -> dict:
        return {
            "target": "http://lab.local/search?q=test",
            "injection_point": "q parameter",
            "expected_payload": self._target_payload,
            "hint": ("Inject a SQL payload into the search query parameter."),
        }

    def verify(self, submitted_answer: str) -> ChallengeResult:
        expected = self._target_payload
        correct = submitted_answer.strip() in (expected, expected + " --")
        if correct:
            feedback = ("Correct! SQL injection payload detected.")
        else:
            feedback = ("Incorrect. Try injecting 1' OR '1'='1 into the search parameter.")
        return ChallengeResult(challenge_id=self.id, submitted_answer=submitted_answer, correct=correct, feedback=feedback)


registry.register(SQLInjectionChallenge())


class IDORChallenge(Challenge):
    def __init__(self):
        super().__init__(
            id="web-idor-01",
            title="Insecure Direct Object Reference",
            category="web",
            module="burp",
            description=("Access another user's profile by manipulating the "
                         "profile ID parameter in the URL."),
            vulnerability="idor",
            difficulty="medium",
            track="web-security",
            steps=[],
            ai_enabled=True,
            requires_online=False,
        )
        self._target_id = "2"

    def generate(self) -> dict:
        return {"target": "http://lab.local/profile?id=1", "hint": "Change the id parameter to access another user's profile."}

    def verify(self, submitted_answer: str) -> ChallengeResult:
        expected = self._target_id
        correct = submitted_answer.strip() == expected
        if correct:
            feedback = ("Correct! Changing the id parameter allowed access - classic IDOR vulnerability.")
        else:
            feedback = ("Incorrect. Try changing the id parameter (try id=2).")
        return ChallengeResult(challenge_id=self.id, submitted_answer=submitted_answer, correct=correct, feedback=feedback)


registry.register(IDORChallenge())


class AuthBypassChallenge(Challenge):
    def __init__(self):
        super().__init__(
            id="web-auth-bypass-01",
            title="Authentication Bypass via Session Cookie",
            category="web",
            module="burp",
            description=("Access an admin endpoint by manipulating the session "
                         "cookie to use an admin session token."),
            vulnerability="auth_bypass",
            difficulty="medium",
            track="web-security",
            steps=[],
            ai_enabled=True,
            requires_online=False,
        )
        self._admin_token = "sess-admin"

    def generate(self) -> dict:
        return {"target": "http://lab.local/admin", "hint": "Modify the Cookie header to session=sess-admin."}

    def verify(self, submitted_answer: str) -> ChallengeResult:
        expected = self._admin_token
        correct = submitted_answer.strip() == expected
        if correct:
            feedback = ("Correct! Using the admin session token grants admin access.")
        else:
            feedback = ("Incorrect. Try modifying the Cookie header to session=sess-admin.")
        return ChallengeResult(challenge_id=self.id, submitted_answer=submitted_answer, correct=correct, feedback=feedback)


registry.register(AuthBypassChallenge())


class BurpShell(cmd.Cmd):
    intro = ("=== cyberterminal BurpSuite simulator (offline) ==="
                     "Type 'help' or '?' to list commands. Type 'quit' to exit.")
    prompt = "burp> "
    prompt = "burp> "

    def __init__(self) -> None:
        super().__init__()
        self.target = MockTarget()
        self._pending: Optional[Dict] = None
        self._last_response: Optional[Dict] = None
        self._challenge: Optional[Challenge] = None

    def do_targets(self, arg: str) -> None:
        print("Target:", self.target.base_url)
        print(" Endpoints: GET /  GET /login  POST /login  GET /search  GET /profile  GET /admin")

    def do_intercept(self, arg: str) -> None:
        tokens = shlex.split(arg)
        if len(tokens) < 2:
            print("usage: intercept <METHOD> <path> [body]")
            return
        method = tokens[0].upper()
        path = tokens[1]
        body = " ".join(tokens[2:]) if len(tokens) > 2 else ""
        headers = {"Host": "lab.local", "User-Agent": "cyberterminal-burp-sim/0.1", "Accept": "*/*"}
        if body:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            headers["Content-Length"] = str(len(body))
        self._pending = {"method": method, "path": path, "headers": dict(headers), "body": body}
        self._last_response = None
        print("Request intercepted:")
        print(self._format_request(method, path, headers, body))

    def do_modify(self, arg: str) -> None:
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
        if arg == "request":
            if self._pending is None:
                print("No intercepted request.")
            else:
                print(self._format_request(self._pending["method"], self._pending["path"], self._pending["headers"], self._pending["body"]))
        elif arg == "response":
            if self._last_response is None:
                print("No response captured yet.")
            else:
                print(self._format_response(self._last_response["status"], self._last_response["headers"], self._last_response["body"]))
        else:
            print("usage: show request | response")

    def do_forward(self, arg: str) -> None:
        if self._pending is None:
            print("No intercepted request. Use 'intercept' first.")
            return
        resp = self.target.handle(self._pending["method"], self._pending["path"], self._pending["headers"], self._pending["body"])
        self._last_response = resp
        print("Forwarded to target. Response:")
        print(self._format_response(resp["status"], resp["headers"], resp["body"]))

    def do_response(self, arg: str) -> None:
        self.do_show("response")

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass

    def _format_request(self, method: str, path: str, headers: Dict[str, str], body: str) -> str:
        lines = [f"{method} {path} HTTP/1.1"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if body:
            lines.append(body)
        return chr(10).join(lines)

    def _format_response(self, status: str, headers: Dict[str, str], body: str) -> str:
        lines = [f"HTTP/1.1 {status}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if body:
            lines.append(body)
        return chr(10).join(lines)


def run_burp(args: argparse.Namespace) -> int:
    shell = BurpShell()
    shell.cmdloop()
    return 0


# ---------------------------------------------------------------------------
# Self-register labs with the lab registry
# ---------------------------------------------------------------------------

from src.core import lab_registry as _lab_registry  # noqa: E402
from src.core.lab import Scenario, registry as _scenario_registry  # noqa: E402


def _burp_lab() -> int:
    return run_burp(argparse.Namespace(target="http://lab.local"))


_scenario_registry.register(
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

"""dict-hydra: use a dictionary against a live local login with Hydra.

setup() starts the httpauth target (127.0.0.1 only) and writes a wordlist
into the student's workspace. The target's password is compared in plain
text with no rate limiting or lockout, so Hydra with a wordlist finds it.

    hydra -l admin -P dict-hydra/wordlist.txt -s <port> 127.0.0.1 \
        http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid'

The student submits the recovered password. This is a separate target from
the web-sqli SQL-injection target: here there is no injection, only a plain
password check, so it practices dictionary/brute-force login attacks.
"""

from __future__ import annotations

import random
import shlex

from cyberlab import targets
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

DECOYS = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "letmein", "dragon", "baseball", "football", "iloveyou", "trustno1",
    "sunshine", "master", "hello", "welcome", "shadow", "admin",
    "1234567", "123456789", "login", "test", "guest", "changeme",
]


class DictHydra(Challenge):
    def _password(self, ws: Workspace) -> str:
        # Must match cyberlab.httpauth.make_credentials (same derive label).
        return ws.derive("dict-hydra:password", 24)

    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "httpauth")

        rng = random.Random(ws.derive("dict-hydra:seed"))
        pw = self._password(ws)
        words = [pw] + rng.sample(DECOYS, len(DECOYS))
        rng.shuffle(words)

        wl = ws.path("dict-hydra", "wordlist.txt")
        wl.write_text("\n".join(words) + "\n", encoding="utf-8")

        fail = "Invalid username or password"
        form = f"/login:username=^USER^&password=^PASS^:F={fail}"
        hydra = (
            f"hydra -l admin -P {shlex.quote(str(wl))} -s {port} "
            f"127.0.0.1 http-post-form {shlex.quote(form)}"
        )
        return (
            f"Target: http://127.0.0.1:{port}/login\n"
            f"Wordlist: {wl}\n"
            "Run Hydra against the login form, then submit the password it finds:\n"
            f"  {hydra}"
        )

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._password(ws)


register(DictHydra(
    id="dict-hydra",
    title="Dictionary attack on a live login with Hydra",
    track="logs",
    difficulty="medium",
    goal=("A local login service accepts any username/password without lockout. "
          "Run Hydra with the wordlist against it and submit the password it "
          "recovers."),
    hints=[
        "The service is the httpauth target started by `cyberlab start dict-hydra`; "
        "it prints the port.",
        "Use http-post-form because the login POSTs to /login.",
        "The failure message the page returns on a bad login is: Invalid username or password",
    ],
    tools=["hydra"],
))

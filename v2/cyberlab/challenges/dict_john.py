"""dict-john: crack a password hash with John the Ripper (dictionary attack).

setup() writes, inside the student's workspace:

    dict-john/
      wordlist.txt   one candidate password per line (the password is in it)
      hashes.txt     one line:  admin:<md5-of-the-password>

The student cracks it with real John the Ripper:

    john --format=raw-md5 --wordlist=dict-john/wordlist.txt dict-john/hashes.txt
    john --show dict-john/hashes.txt

and submits the recovered password.

The hash is MD5 so John's `raw-md5` format handles it with nothing but the
standard library on our side (we just write the hex digest). John itself comes
from the offline tools pack; the challenge works without it installed because
check() only verifies the submitted password.
"""

from __future__ import annotations

import hashlib
import random
import shlex

from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

DECOYS = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "letmein", "dragon", "baseball", "football", "iloveyou", "trustno1",
    "sunshine", "master", "hello", "welcome", "shadow", "admin",
    "1234567", "123456789", "login", "test", "guest", "changeme",
]


class DictJohn(Challenge):
    def _password(self, ws: Workspace) -> str:
        return ws.derive("dict-john:password", 16)

    def _hash(self, ws: Workspace) -> str:
        return hashlib.md5(self._password(ws).encode()).hexdigest()

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("dict-john:seed"))
        pw = self._password(ws)
        words = [pw] + rng.sample(DECOYS, len(DECOYS))
        rng.shuffle(words)

        wl = ws.path("dict-john", "wordlist.txt")
        wl.write_text("\n".join(words) + "\n", encoding="utf-8")

        hs = ws.path("dict-john", "hashes.txt")
        hs.write_text(f"admin:{self._hash(ws)}\n", encoding="utf-8")

        return (
            f"Hash file: {hs}\n"
            f"Wordlist:  {wl}\n"
            "Crack it with John the Ripper, then submit the password:\n"
            f"  john --format=raw-md5 {shlex.quote('--wordlist=' + str(wl))} "
            f"{shlex.quote(str(hs))}\n"
            f"  john --show {shlex.quote(str(hs))}"
        )

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._password(ws)


register(DictJohn(
    id="dict-john",
    title="Crack a password hash with John the Ripper",
    track="logs",
    difficulty="easy",
    goal=("A password hash was captured from a weak service. Recover the "
          "plaintext password with a dictionary attack in John the Ripper "
          "and submit it."),
    hints=[
        "The hash file is one line:  admin:<md5 hex digest>.  John's raw-md5 "
        "format expects exactly that.",
        "Run:  john --format=raw-md5 --wordlist=dict-john/wordlist.txt dict-john/hashes.txt",
        "Then:  john --show dict-john/hashes.txt   (shows the cracked password).",
    ],
    tools=["john"],
))

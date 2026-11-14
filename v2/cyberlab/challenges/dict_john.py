"""dict-john: crack password hashes with John the Ripper (dictionary attack).

setup() writes, inside the student's workspace:

    dict-john/
      wordlist.txt   400 weak passwords, one per line
      hashes.txt     user:<md5 hex> for admin, alice and bob

Every password is in the wordlist and looks like every other line of it, so
the only way to tell which is which is to hash the candidates and compare:

    john --format=raw-md5 --wordlist=dict-john/wordlist.txt dict-john/hashes.txt
    john --show --format=raw-md5 dict-john/hashes.txt

The student submits admin's password. The hashes are unsalted MD5 so John's
raw-md5 format reads them and the standard library can write them; check()
only compares the submitted password, so the lab works without John (a
md5sum loop does the same job).
"""

from __future__ import annotations

import hashlib
import shlex
from typing import List, Tuple

from cyberlab import wordlists
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

USERS = ["admin", "alice", "bob"]


class DictJohn(Challenge):
    def _user_password(self, ws: Workspace, user: str) -> str:
        return wordlists.chosen_password(ws, "dict-john", slot="pick:" + user)

    def _password(self, ws: Workspace) -> str:
        return self._user_password(ws, "admin")

    def _hash(self, ws: Workspace, user: str = "admin") -> str:
        return hashlib.md5(self._user_password(ws, user).encode()).hexdigest()

    def _paths(self, ws: Workspace) -> Tuple[str, str]:
        folder = ws.home / "dict-john"
        return shlex.quote(str(folder / "hashes.txt")), shlex.quote(str(folder / "wordlist.txt"))

    def setup(self, ws: Workspace) -> str:
        wl = ws.path("dict-john", "wordlist.txt")
        wl.write_text("\n".join(wordlists.password_candidates(ws, "dict-john")) + "\n",
                      encoding="utf-8")
        hs = ws.path("dict-john", "hashes.txt")
        hs.write_text("".join(f"{u}:{self._hash(ws, u)}\n" for u in USERS), encoding="utf-8")

        return (
            f"Hash file: {hs}\n"
            f"Wordlist:  {wl}\n"
            "Crack the hashes with John the Ripper, then submit admin's password:\n"
            f"  john --format=raw-md5 {shlex.quote('--wordlist=' + str(wl))} "
            f"{shlex.quote(str(hs))}\n"
            f"  john --show --format=raw-md5 {shlex.quote(str(hs))}"
        )

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._password(ws)

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        hashes, wordlist = self._paths(ws)
        return [
            ("Hash every word in the list and compare with the stolen hashes",
             f"john --format=raw-md5 --wordlist={wordlist} {hashes}"),
            ("Show what's been cracked (John remembers results in ~/.john/john.pot)",
             f"john --show --format=raw-md5 {hashes}"),
            ("What John is doing, by hand: hash a guess, compare it with the file",
             f"echo -n 'summer2024' | md5sum\ncat {hashes}"),
            ("The whole attack as a loop, no John needed",
             "while read -r word; do\n"
             "  hash=$(printf '%s' \"$word\" | md5sum | cut -d' ' -f1)\n"
             f"  grep \"$hash\" {hashes} && echo \"  is: $word\"\n"
             f"done < {wordlist}"),
            ("Real passwords are rarely exactly in a list: rules try variations "
             "(Summer2024 -> summer2024!, Summer2025 ...)",
             f"john --format=raw-md5 --wordlist={wordlist} --rules {hashes}"),
        ]


register(DictJohn(
    id="dict-john",
    title="Crack password hashes with John the Ripper",
    track="passwords",
    difficulty="easy",
    goal=("A database leak included three password hashes. A hash can't be reversed, "
          "but it can be guessed: recover the passwords with a dictionary attack in "
          "John the Ripper and submit admin's."),
    hints=[
        "Each line of the hash file is user:<32 hex characters>. That length is MD5; "
        "John calls the format raw-md5.",
        "Run:  john --format=raw-md5 --wordlist=<wordlist.txt> <hashes.txt>   "
        "(the full paths are in the start output).",
        "Then:  john --show --format=raw-md5 <hashes.txt>   lists user:password. If John "
        "says 'No password hashes left to crack', it already cracked them: --show prints them.",
    ],
    tools=["john"],
    learned=("A hash can't be turned back into a password, but nothing stops you hashing "
             "guesses and comparing. John hashed 400 candidate passwords and matched three of "
             "them in well under a second. The passwords fell because they were guessable, "
             "and because unsalted MD5 is so fast that a laptop tries billions of guesses "
             "a second."),
    real_world=("This is what happens after every database breach. The attacker has the "
                "hashes offline, so no lockout or rate limit applies, and runs them against "
                "lists of billions of real leaked passwords. Cracked passwords are then tried "
                "on email, banking and work accounts, because people reuse them. That's why "
                "one site's breach becomes your problem everywhere."),
    defend=[
        "Store passwords with a slow, salted algorithm made for it: argon2, bcrypt or scrypt. "
        "Never plain MD5 or SHA-1/SHA-256.",
        "A salt (random, per user) means the same password hashes differently for each user, "
        "so one guess can't be checked against every account at once.",
        "As a user: long and not in any list beats clever. A password manager makes every "
        "password random and different.",
        "Turn on two-factor authentication, so a cracked password alone isn't enough.",
    ],
    ap_unit="Units 4 and 5",
    ap_topic="4.2 Authentication; 5.2 Access Controls",
    ap_skill=["Analyze Risk", "Mitigate Risk"],
))

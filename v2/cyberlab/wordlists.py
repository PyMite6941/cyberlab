"""Per-workspace wordlists for the password and directory labs.

The answers have to look like every other line. A wordlist where the real
password is the only odd-looking entry teaches students to read the file
instead of running the attack, so the password is drawn from the same
generator as the decoys, and the hidden directory is an ordinary name.

Everything is derived from the workspace secret: each student gets a different
list and a different answer, and a target process works out the same answer
as the challenge that checks it.
"""

from __future__ import annotations

import random
from typing import List

from cyberlab.workspace import Workspace

_BASES = [
    "summer", "winter", "autumn", "spring", "dragon", "monkey", "soccer", "football",
    "baseball", "shadow", "sunshine", "princess", "welcome", "northwind", "password",
    "letmein", "master", "qwerty", "freedom", "flower", "tigers", "eagles", "mustang",
    "harley", "ranger", "buster", "cookie", "pepper", "ginger", "hunter", "jordan",
    "maggie", "charlie", "thunder", "silver", "orange", "banana", "coffee", "guitar",
    "purple",
]


def _one_password(rng: random.Random) -> str:
    word = rng.choice(_BASES)
    style = rng.randrange(4)
    if style == 0:
        return f"{word}{rng.randint(1, 99)}"
    if style == 1:
        return f"{word.capitalize()}{rng.randint(1990, 2026)}"
    if style == 2:
        return f"{word.capitalize()}{rng.randint(1, 99)}!"
    return f"{word}{rng.randint(100, 999)}"


def password_candidates(ws: Workspace, label: str, count: int = 400) -> List[str]:
    """This workspace's wordlist for `label`: `count` distinct weak passwords,
    the kind people really choose (a word, a year, maybe a `!`)."""
    rng = random.Random(ws.derive(label + ":seed"))
    seen, out = set(), []
    while len(out) < count:
        candidate = _one_password(rng)
        if candidate not in seen:
            seen.add(candidate)
            out.append(candidate)
    return out


def chosen_password(ws: Workspace, label: str, slot: str = "pick") -> str:
    """The entry of the `label` wordlist that is the real password."""
    candidates = password_candidates(ws, label)
    return candidates[int(ws.derive(f"{label}:{slot}", 8), 16) % len(candidates)]


# Names a real directory wordlist (dirb's common.txt, SecLists) is full of.
DIRECTORY_WORDS = [
    "about", "account", "admin", "api", "app", "archive", "assets", "auth", "backup",
    "backups", "bak", "bin", "blog", "cache", "cart", "cgi-bin", "cms", "config",
    "contact", "content", "core", "css", "dashboard", "data", "db", "debug", "demo",
    "dev", "docs", "download", "downloads", "dump", "email", "error", "export", "faq",
    "feed", "files", "fonts", "forum", "help", "home", "images", "img", "import",
    "inc", "include", "includes", "index", "info", "install", "internal", "js", "lib",
    "legacy", "login", "logout", "logs", "mail", "media", "members", "misc", "mobile",
    "modules", "news", "old", "pages", "panel", "partners", "php", "plugins", "portal",
    "private", "products", "profile", "public", "register", "reports", "resources",
    "robots.txt", "rss", "save", "scripts", "search", "secure", "server-status",
    "services", "settings", "setup", "shop", "sitemap", "sql", "staging", "static",
    "stats", "status", "store", "styles", "support", "sys", "system", "temp",
    "templates", "test", "themes", "tmp", "tools", "upload", "uploads", "user",
    "users", "vendor", "web", "webmail", "wp-admin", "xml",
]

# The forgotten directory is one of these: all plausible, none linked anywhere.
LEFTOVER_DIRS = [
    "archive", "backup", "backups", "bak", "data", "db", "dev", "dump", "export",
    "files", "internal", "legacy", "old", "private", "save", "sql", "staging",
    "temp", "test", "tmp",
]


def hidden_directory(ws: Workspace) -> str:
    """The unlinked directory holding the database dump in web-gobuster."""
    return LEFTOVER_DIRS[int(ws.derive("web-gobuster:dir", 8), 16) % len(LEFTOVER_DIRS)]


def directory_wordlist(ws: Workspace) -> List[str]:
    words = list(DIRECTORY_WORDS)
    random.Random(ws.derive("web-gobuster:seed")).shuffle(words)
    return words

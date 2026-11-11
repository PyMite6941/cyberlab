"""log-web-scan: find the one hidden path a scanner actually got into."""

from __future__ import annotations

import random

from cyberlab import logs
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

# Paths a directory scanner probes; almost all 404 on this server.
SCAN_PATHS = ["/admin", "/wp-login.php", "/.git/config", "/phpmyadmin/", "/.env",
              "/server-status", "/config.php.bak", "/old/", "/test/", "/backup.zip",
              "/api/v1/users", "/.ssh/id_rsa", "/robots.txt", "/login", "/uploads/"]
NORMAL_PATHS = ["/", "/index.html", "/about", "/products", "/contact", "/static/app.css"]
AGENTS = ["Mozilla/5.0 (X11; Linux x86_64)", "Mozilla/5.0 (Windows NT 10.0)"]


class LogWebScan(Challenge):
    def _secret_path(self, ws: Workspace) -> str:
        return "/backup-" + ws.derive("log-web-scan:path", 6) + "/"

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("log-web-scan:seed"))
        n = int(ws.derive("log-web-scan:ip", 4), 16) % 250 + 2
        scanner = f"198.51.100.{n}"
        secret = self._secret_path(ws)
        lines = []

        def line(t, ip, path, status, agent):
            return (t, f'{ip} - - [{logs.clf_time(t)}] "GET {path} HTTP/1.1" '
                       f'{status} {rng.randint(120, 5000)} "-" "{agent}"')

        # Normal visitors browsing real pages.
        for _ in range(40):
            t = rng.uniform(0, 3600)
            ip = f"10.0.0.{rng.randint(20, 60)}"
            lines.append(line(t, ip, rng.choice(NORMAL_PATHS), 200, rng.choice(AGENTS)))
        # The scan: one IP walking a wordlist, nearly all 404...
        start = rng.uniform(1000, 1500)
        paths = SCAN_PATHS + [secret]
        rng.shuffle(paths)
        for i, path in enumerate(paths):
            t = start + i * rng.uniform(0.1, 0.4)
            # ...except the one path that exists and returns 200.
            status = 200 if path == secret else rng.choice([404, 404, 403])
            lines.append(line(t, scanner, path, status, "curl/8.5.0"))
        path = ws.path("log-web-scan", "access.log")
        logs.write_log(path, lines)
        return (f"Log: {path}\n"
                f"A scanner ({scanner}) probed the web server for hidden paths. Almost "
                "every request got a 404 — except one, which it found. Submit that path.")

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip().rstrip("/").lower() == self._secret_path(ws).rstrip("/").lower()


register(LogWebScan(
    id="log-web-scan",
    title="Find what the web scan uncovered",
    track="logs",
    difficulty="medium",
    goal=("An nginx access.log caught a scanner brute-forcing paths on the web server. "
          "Most requests returned 404, but one hidden path returned 200 — that's what "
          "they found. Submit that path."),
    hints=[
        "The scanner is the client with a flood of requests and a curl user agent.",
        "In the access log, the HTTP status is the number after the request. You want the "
        "scanner's request that returned 200, not 404.",
        "awk '$9==200' access.log | grep curl   —   the surviving path is the answer "
        "(e.g. /backup-abc123/).",
    ],
    tools=["grep", "awk"],
))

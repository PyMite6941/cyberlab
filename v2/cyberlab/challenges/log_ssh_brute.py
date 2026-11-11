"""log-ssh-brute: find the IP that brute-forced SSH."""

from __future__ import annotations

import random

from cyberlab import logs
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

USERS = ["root", "admin", "ubuntu", "git", "postgres", "test", "oracle", "pi"]


class LogSshBrute(Challenge):
    def _attacker_ip(self, ws: Workspace) -> str:
        n = int(ws.derive("log-ssh-brute:ip", 4), 16) % 250 + 2
        return f"203.0.113.{n}"

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("log-ssh-brute:seed"))
        attacker = self._attacker_ip(ws)
        lines = []
        # A bit of normal, successful logins from staff workstations.
        for _ in range(8):
            t = rng.uniform(0, 3600)
            ip = f"10.0.0.{rng.randint(20, 40)}"
            lines.append((t, f"{logs.syslog_time(t)} {logs.HOST} sshd[{rng.randint(1000, 9999)}]: "
                             f"Accepted password for alice from {ip} port {rng.randint(40000, 60000)} ssh2"))
        # The brute force: one IP, dozens of failures against many usernames...
        start = rng.uniform(1200, 2000)
        for i in range(60):
            t = start + i * rng.uniform(0.3, 1.2)
            user = rng.choice(USERS)
            tag = "Failed password for " + (user if user == "root" else f"invalid user {user}")
            lines.append((t, f"{logs.syslog_time(t)} {logs.HOST} sshd[{rng.randint(1000, 9999)}]: "
                             f"{tag} from {attacker} port {rng.randint(40000, 60000)} ssh2"))
        # ...and then it gets in.
        t = start + 60 * 1.2 + 1
        lines.append((t, f"{logs.syslog_time(t)} {logs.HOST} sshd[{rng.randint(1000, 9999)}]: "
                         f"Accepted password for root from {attacker} port {rng.randint(40000, 60000)} ssh2"))
        path = ws.path("log-ssh-brute", "auth.log")
        logs.write_log(path, lines)
        return (f"Log: {path}\n"
                "An attacker guessed an SSH password by trying over and over. "
                "Submit the IP address they came from.")

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._attacker_ip(ws)


register(LogSshBrute(
    id="log-ssh-brute",
    title="SSH brute force in auth.log",
    track="logs",
    difficulty="easy",
    goal=("The SSH server's auth.log is full of login attempts. One IP tried many "
          "passwords until it got in. Submit that attacker's IP address."),
    hints=[
        "Failed logins look like 'Failed password ... from <IP>'. Pull those out with grep.",
        "Count the failures per source IP; one address dwarfs the rest.",
        "grep 'Failed password' auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head",
    ],
    tools=["grep", "awk", "sort"],
))

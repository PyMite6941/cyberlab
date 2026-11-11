"""log-sudo-esc: find the user who escalated to root via sudo."""

from __future__ import annotations

import random

from cyberlab import logs
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

ADMINS = ["alice", "dsingh"]  # expected to use sudo
STAFF = ["mwilson", "tchen", "jdoe", "rkumar", "bford", "lgarcia", "pokoye", "snguyen"]
ADMIN_CMDS = ["/usr/bin/apt update", "/usr/bin/systemctl restart nginx", "/bin/journalctl -u ssh"]


class LogSudoEsc(Challenge):
    def _culprit(self, ws: Workspace) -> str:
        return STAFF[int(ws.derive("log-sudo-esc:user", 4), 16) % len(STAFF)]

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("log-sudo-esc:seed"))
        culprit = self._culprit(ws)
        lines = []

        def sudo(t, user, cmd, pwd=None):
            pwd = pwd or f"/home/{user}"
            return (t, f"{logs.syslog_time(t)} {logs.HOST} sudo: {user} : TTY=pts/{rng.randint(0, 3)} ; "
                       f"PWD={pwd} ; USER=root ; COMMAND={cmd}")

        # Routine admin sudo use throughout the day.
        for _ in range(18):
            t = rng.uniform(0, 3600)
            lines.append(sudo(t, rng.choice(ADMINS), rng.choice(ADMIN_CMDS)))
        # The escalation: a non-admin opens a root shell.
        t = rng.uniform(1500, 2500)
        lines.append(sudo(t, culprit, "/bin/bash", pwd=f"/home/{culprit}"))
        lines.append((t + 1, f"{logs.syslog_time(t + 1)} {logs.HOST} sudo: pam_unix(sudo:session): "
                             f"session opened for user root by {culprit}(uid=0)"))
        path = ws.path("log-sudo-esc", "auth.log")
        logs.write_log(path, lines)
        return (f"Log: {path}\n"
                "Admins alice and dsingh use sudo routinely. Someone else used sudo to open "
                "a root shell. Submit that user's username.")

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip().lower() == self._culprit(ws)


register(LogSudoEsc(
    id="log-sudo-esc",
    title="Privilege escalation via sudo",
    track="logs",
    difficulty="hard",
    goal=("auth.log records every sudo command. The admins (alice, dsingh) use it all day, "
          "but one other user escalated to a root shell. Submit that user's username."),
    hints=[
        "sudo lines name the user before the colon:  sudo: <user> : ... COMMAND=...",
        "List who ran sudo and ignore the known admins (alice, dsingh); one staff name is left.",
        "The giveaway is a sudo COMMAND of /bin/bash (a root shell), "
        "or 'session opened for user root by <user>'.",
    ],
    tools=["grep", "awk", "sort"],
))

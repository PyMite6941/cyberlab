"""log-sudo-esc: find the user who escalated to root via sudo."""

from __future__ import annotations

import random
import shlex
from typing import List, Tuple

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

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        log = shlex.quote(str(ws.home / "log-sudo-esc" / "auth.log"))
        return [
            ("List who ran sudo", f"grep 'sudo:' {log} | awk '{{print $5}}' | sort | uniq -c"),
            ("The giveaway: a sudo command that opens a root shell",
             f"grep 'COMMAND=/bin/bash' {log}"),
            ("Or: a root session opened by a non-admin",
             f"grep 'session opened for user root' {log}"),
        ]


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
    learned=("You listed every user who ran sudo, set aside the known admins, and found a "
             "non-admin who opened a root shell — privilege escalation recorded plainly in "
             "auth.log."),
    real_world=("sudo is logged, which makes those logs a key source for catching misuse. A "
                "normal user spawning a root shell is a strong escalation signal, though "
                "legitimate break-glass access exists — confirm the user was authorised "
                "before treating it as an incident."),
    defend=[
        "Grant sudo narrowly (specific commands), not broad or shell access.",
        "Alert on sudo to interactive shells and on new users gaining root.",
        "Ship auth logs off-host so an attacker who escalates cannot erase them.",
    ],
    ap_unit="Unit 5",
    ap_topic="5.6 Detecting Attacks on Data and Applications",
    ap_skill=["Detect Attacks", "Analyze Risk"],
))

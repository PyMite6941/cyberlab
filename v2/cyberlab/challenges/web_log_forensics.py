"""web-log-forensics: cite the first directory-traversal attempt in a log."""

from __future__ import annotations

import shlex
from typing import List, Tuple

from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

EVIDENCE_LINE = 7


class WebLogForensics(Challenge):
    def _attacker_ip(self, ws: Workspace) -> str:
        octet = 10 + int(ws.derive("web-log-forensics:source", 4), 16) % 240
        return f"192.0.2.{octet}"

    def _lines(self, ws: Workspace) -> List[str]:
        attacker = self._attacker_ip(ws)
        return [
            '203.0.113.12 - - [13/Nov/2026:09:14:02 +0000] "GET / HTTP/1.1" 200 512',
            '203.0.113.18 - - [13/Nov/2026:09:14:05 +0000] "GET /products HTTP/1.1" 200 891',
            f'{attacker} - - [13/Nov/2026:09:14:12 +0000] "GET /robots.txt HTTP/1.1" 200 64',
            '203.0.113.12 - - [13/Nov/2026:09:14:17 +0000] "GET /search?q=tea HTTP/1.1" 200 340',
            f'{attacker} - - [13/Nov/2026:09:14:20 +0000] "GET /favicon.ico HTTP/1.1" 404 128',
            '203.0.113.18 - - [13/Nov/2026:09:14:23 +0000] "GET /about HTTP/1.1" 200 288',
            f'{attacker} - - [13/Nov/2026:09:14:29 +0000] "GET /download?file=..%2f..%2fetc%2fpasswd HTTP/1.1" 400 72',
            f'{attacker} - - [13/Nov/2026:09:14:31 +0000] "GET /download?file=..%2f..%2f..%2fetc%2fshadow HTTP/1.1" 400 72',
            '203.0.113.12 - - [13/Nov/2026:09:14:37 +0000] "GET /contact HTTP/1.1" 200 301',
        ]

    def setup(self, ws: Workspace) -> str:
        path = ws.path("web-log-forensics", "access.log")
        path.write_text("\n".join(self._lines(ws)) + "\n", encoding="utf-8")
        return (
            f"Access log: {path}\n"
            "Identify the source IP making the first directory-traversal request and "
            f"cite its line number. Submit as IP:{EVIDENCE_LINE}.\n"
            "The log is synthetic; the request is evidence to analyze, not a live attack."
        )

    def _answer(self, ws: Workspace) -> str:
        return f"{self._attacker_ip(ws)}:{EVIDENCE_LINE}"

    def check(self, ws: Workspace, answer: str) -> bool:
        normalized = answer.strip().lower().replace(" line ", ":").replace(" ", "")
        return normalized == self._answer(ws)

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        log = shlex.quote(str(ws.home / "web-log-forensics" / "access.log"))
        return [
            ("Find traversal indicators and keep their line numbers",
             f"grep -niE '(\\.\\./|%2e%2e|/etc/passwd)' {log}"),
            ("Show the cited evidence line with surrounding context",
             f"sed -n '5,8p' {log} | nl -ba -v5"),
            ("Count requests by source address to compare activity",
             f"awk '{{print $1}}' {log} | sort | uniq -c | sort -rn"),
        ]


register(WebLogForensics(
    id="web-log-forensics",
    title="Web access-log forensics",
    track="logs",
    difficulty="easy",
    goal=("Investigate a synthetic web access log. Identify the source IP making the "
          "first directory-traversal request and cite its exact line number."),
    hints=[
        "Use grep with line numbers to find requests containing ../, its URL-encoded form, "
        "or a sensitive path such as /etc/passwd.",
        "Compare the source IP on suspicious lines with nearby ordinary requests.",
        f"The first traversal request is on line {EVIDENCE_LINE}; submit that line's IP "
        f"and line as IP:{EVIDENCE_LINE}.",
    ],
    tools=["grep", "awk", "sed"],
    learned=("You used a specific access-log entry as evidence: line 7 contains an "
             "encoded traversal sequence targeting a sensitive system path. The source IP "
             "and request line together support the finding; a 400 response shows this "
             "request was rejected, not that data was successfully read."),
    real_world=("Web logs help responders distinguish probing from successful access and "
                "reconstruct timelines. A suspicious request alone is an indicator to "
                "investigate, not proof of compromise; correlate status codes, application "
                "logs and file or endpoint telemetry."),
    defend=[
        "Resolve requested files against an allowed base directory and reject paths that "
        "escape it; prefer fixed resource identifiers over user-supplied file paths.",
        "Record request IDs and relevant outcomes so responders can correlate web and "
        "application events.",
        "Preserve logs with access controls and reliable timestamps, and define retention "
        "before an incident occurs.",
        "Use detection and blocking controls as additional layers, not a replacement for "
        "safe path handling.",
    ],
    ap_unit="Unit 5",
    ap_topic="5.6 Detecting Attacks on Data and Applications",
    ap_skill=["Detect Attacks", "Analyze Risk", "Mitigate Risk"],
))

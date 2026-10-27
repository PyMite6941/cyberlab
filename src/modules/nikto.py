"""Simulated Nikto web server vulnerability scanner, fully offline.

Generates simulated web server scan results including outdated software,
missing headers, dangerous files, and common misconfigurations.

To launch from cyberterminal:

    cyberterminal> nikto
    cyberterminal> nikto --target http://lab.local
    cyberterminal> nikto --target http://lab.local --port 8080
"""

from __future__ import annotations

import argparse
import cmd
import shlex
import random
import zlib
from typing import Optional


# Simulated Nikto findings
NIKTO_FINDINGS: list[dict] = [
    {
        "id": "OSVDB-3092",
        "severity": "medium",
        "description": "/admin/ may reveal sensitive information",
        "url": "/admin/",
    },
    {
        "id": "OSVDB-3233",
        "severity": "info",
        "description": "/icons/ directory is accessible",
        "url": "/icons/",
    },
    {
        "id": "OSVDB-3268",
        "severity": "low",
        "description": "/robots.txt contains 3 entries which should be investigated",
        "url": "/robots.txt",
    },
    {
        "id": "OSVDB-4512",
        "severity": "high",
        "description": "Outdated Apache version detected (2.4.18)",
        "url": "/",
    },
    {
        "id": "OSVDB-6789",
        "severity": "medium",
        "description": "X-Frame-Options header is not set",
        "url": "/",
    },
    {
        "id": "OSVDB-9012",
        "severity": "low",
        "description": "Server leaks inodes via ETags",
        "url": "/",
    },
    {
        "id": "OSVDB-3421",
        "severity": "medium",
        "description": "/phpmyadmin/ may reveal sensitive information",
        "url": "/phpmyadmin/",
    },
    {
        "id": "OSVDB-5678",
        "severity": "high",
        "description": "SQL injection possible in /search.php",
        "url": "/search.php",
    },
]


def generate_scan(target: str, port: int = 80, seed: int = 42) -> dict:
    """Generate a simulated Nikto web scan result.

    Args:
        target: Target URL or hostname.
        port: Target port.
        seed: Random seed for deterministic output.

    Returns:
        A dict with scan findings, server info, and statistics.
    """
    # crc32, not hash(): str hashes are randomized per process, so hash()
    # gave different results every run.
    rng = random.Random(zlib.crc32(f"{target}{seed}".encode()))

    # Simulate server info
    servers = [
        "Apache/2.4.18 (Ubuntu)",
        "Apache/2.4.41 (Ubuntu)",
        "nginx/1.18.0",
        "Microsoft-IIS/10.0",
    ]
    server = rng.choice(servers)

    # Select a subset of findings
    findings = []
    for f in NIKTO_FINDINGS:
        if rng.random() < 0.6:  # 60% chance each finding appears
            findings.append(dict(f))

    return {
        "target": target,
        "port": port,
        "server": server,
        "start_time": "2026-01-15 10:00:00",
        "findings": findings,
        "findings_count": len(findings),
        "requests_sent": rng.randint(50, 200),
    }


def format_scan(scan: dict) -> str:
    """Format Nikto results as human-readable output."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("Nikto simulator (offline)")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Target: {scan['target']}")
    lines.append(f"Port: {scan['port']}")
    lines.append(f"Server: {scan['server']}")
    lines.append(f"Start Time: {scan['start_time']}")
    lines.append("")
    lines.append(f"Findings: {scan['findings_count']}")
    lines.append(f"Requests sent: {scan['requests_sent']}")
    lines.append("")
    lines.append("FINDINGS:")
    lines.append("-" * 60)

    if not scan["findings"]:
        lines.append("No findings.")
    else:
        for f in scan["findings"]:
            sev_color = {
                "high": "[HIGH]",
                "medium": "[MED]",
                "low": "[LOW]",
                "info": "[INFO]",
            }.get(f["severity"], "[UNK]")
            lines.append(f"  {sev_color} {f['id']}: {f['description']}")
            lines.append(f"       URL: {f['url']}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


class NiktoShell(cmd.Cmd):
    intro = "=== cyberterminal Nikto simulator (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "nikto> "

    def __init__(self) -> None:
        super().__init__()
        self.last_scan: Optional[dict] = None

    def do_scan(self, arg: str) -> None:
        """Scan a web target.

        usage: scan <target> [--port <port>]
        Example: scan http://lab.local
                 scan http://lab.local --port 8080
        """
        parser = argparse.ArgumentParser(prog="scan", add_help=False)
        parser.add_argument("target")
        parser.add_argument("--port", type=int, default=80)
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        scan = generate_scan(args.target, args.port)
        self.last_scan = scan
        print(format_scan(scan))

    def do_findings(self, arg: str) -> None:
        """Show findings from last scan.

        usage: findings [--severity high|medium|low|info]
        """
        if not self.last_scan:
            print("No scan results. Run 'scan <target>' first.")
            return
        parser = argparse.ArgumentParser(prog="findings", add_help=False)
        parser.add_argument("--severity", default=None)
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        findings = self.last_scan["findings"]
        if args.severity:
            findings = [f for f in findings if f["severity"] == args.severity]
        if not findings:
            print("No findings match.")
            return
        for f in findings:
            print(f"  [{f['severity'].upper()}] {f['id']}: {f['description']}")
            print(f"       {f['url']}")

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


def run_nikto(args: argparse.Namespace) -> int:
    shell = NiktoShell()
    shell.cmdloop()
    return 0


# Self-register tutorials with the track registry
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _nikto_lab() -> int:
    return run_nikto(argparse.Namespace())


_track_registry.register_tutorial(
    _Tutorial(
        id="web-nikto-01",
        title="Web Server Vulnerability Scanning with Nikto",
        category="web",
        module="nikto",
        description="Scan a web server for outdated software, missing headers, and misconfigurations.",
        vulnerability="web_misconfiguration",
        difficulty="easy",
        track="web-security",
        ai_enabled=True,
    )
)
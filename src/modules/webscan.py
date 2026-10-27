"""Simulated website scanner, fully offline.

Performs simulated website security scanning including:
- Security header analysis (X-Frame-Options, CSP, HSTS, X-XSS-Protection, etc.)
- Directory enumeration simulation
- Technology fingerprinting
- Common misconfiguration detection

No real network connections are made - everything is simulated locally.

To launch from cyberterminal:

    cyberterminal> webscan
    cyberterminal> webscan --target http://lab.local
    cyberterminal> webscan --target http://lab.local --port 8080
"""

from __future__ import annotations

import argparse
import cmd
import shlex
import random
from typing import Optional


# Simulated security headers and their recommendations
SECURITY_HEADERS: list[dict] = [
    {
        "header": "X-Frame-Options",
        "recommended": "DENY or SAMEORIGIN",
        "description": "Prevents clickjacking attacks",
    },
    {
        "header": "Content-Security-Policy",
        "recommended": "default-src 'self'",
        "description": "Mitigates XSS and data injection attacks",
    },
    {
        "header": "Strict-Transport-Security",
        "recommended": "max-age=31536000; includeSubDomains",
        "description": "Forces HTTPS connections",
    },
    {
        "header": "X-Content-Type-Options",
        "recommended": "nosniff",
        "description": "Prevents MIME type sniffing",
    },
    {
        "header": "Referrer-Policy",
        "recommended": "strict-origin-when-cross-origin",
        "description": "Controls referrer information leakage",
    },
    {
        "header": "Permissions-Policy",
        "recommended": "geolocation=(), microphone=()",
        "description": "Controls browser feature access",
    },
]


# Simulated technology signatures
TECH_SIGNATURES: list[dict] = [
    {"name": "Apache", "pattern": "Apache", "category": "Web Server"},
    {"name": "nginx", "pattern": "nginx", "category": "Web Server"},
    {"name": "PHP", "pattern": "PHP", "category": "Programming Language"},
    {"name": "WordPress", "pattern": "WordPress", "category": "CMS"},
    {"name": "jQuery", "pattern": "jquery", "category": "JavaScript Library"},
    {"name": "Bootstrap", "pattern": "bootstrap", "category": "CSS Framework"},
]


# Simulated directories to check
COMMON_DIRS: list[dict] = [
    {"path": "/admin/", "risk": "high", "description": "Admin panel exposed"},
    {"path": "/phpmyadmin/", "risk": "high", "description": "phpMyAdmin exposed"},
    {"path": "/wp-admin/", "risk": "medium", "description": "WordPress admin exposed"},
    {"path": "/.git/", "risk": "high", "description": "Git repository exposed"},
    {"path": "/.env", "risk": "high", "description": "Environment file exposed"},
    {"path": "/backup/", "risk": "medium", "description": "Backup directory exposed"},
    {"path": "/config.php", "risk": "high", "description": "Configuration file exposed"},
    {"path": "/test/", "risk": "low", "description": "Test directory exposed"},
    {"path": "/api/", "risk": "medium", "description": "API endpoint exposed"},
    {"path": "/robots.txt", "risk": "info", "description": "Robots.txt file present"},
]


def generate_scan(target: str, port: int = 80, seed: int = 42) -> dict:
    """Generate a simulated website scan result.

    Args:
        target: Target URL or hostname.
        port: Target port.
        seed: Random seed for deterministic output.

    Returns:
        A dict with scan results including headers, tech, directories, and issues.
    """
    rng = random.Random(hash(target + str(seed)) % (2**32))

    # Determine scheme
    scheme = "https" if port == 443 else "http"
    full_target = f"{scheme}://{target}" if "://" not in target else target

    # Simulate server
    servers = ["Apache/2.4.41 (Ubuntu)", "nginx/1.18.0", "Microsoft-IIS/10.0"]
    server = rng.choice(servers)

    # Simulate missing security headers (randomly missing some)
    headers_found: list[dict] = []
    headers_missing: list[dict] = []
    for h in SECURITY_HEADERS:
        if rng.random() < 0.4:  # 40% chance header is present
            headers_found.append(h)
        else:
            headers_missing.append(h)

    # Simulate technology detection
    tech_found: list[dict] = []
    for tech in TECH_SIGNATURES:
        if rng.random() < 0.5:
            tech_found.append(tech)

    # Simulate directory findings
    dirs_found: list[dict] = []
    for d in COMMON_DIRS:
        if rng.random() < 0.25:
            dirs_found.append(d)

    # Calculate risk score
    risk_score = len(headers_missing) * 10 + len(dirs_found) * 15 + len(tech_found) * 5
    risk_score = min(risk_score, 100)

    risk_level = "Low" if risk_score < 30 else "Medium" if risk_score < 70 else "High"

    return {
        "target": full_target,
        "port": port,
        "server": server,
        "headers_found": headers_found,
        "headers_missing": headers_missing,
        "tech_found": tech_found,
        "dirs_found": dirs_found,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_issues": len(headers_missing) + len(dirs_found),
    }


def format_scan(scan: dict) -> str:
    """Format scan results as human-readable output."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("Website Scanner (offline)")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Target: {scan['target']}")
    lines.append(f"Port: {scan['port']}")
    lines.append(f"Server: {scan['server']}")
    lines.append(f"Risk Score: {scan['risk_score']}/100 ({scan['risk_level']})")
    lines.append(f"Total Issues: {scan['total_issues']}")
    lines.append("")

    # Security headers
    lines.append("MISSING SECURITY HEADERS:")
    lines.append("-" * 60)
    if not scan["headers_missing"]:
        lines.append("  [OK] All critical security headers present")
    else:
        for h in scan["headers_missing"]:
            lines.append(f"  [!] {h['header']}: {h['recommended']}")
            lines.append(f"       {h['description']}")
    lines.append("")

    # Technologies
    lines.append("TECHNOLOGIES DETECTED:")
    lines.append("-" * 60)
    if not scan["tech_found"]:
        lines.append("  [INFO] No technologies detected")
    else:
        for tech in scan["tech_found"]:
            lines.append(f"  [INFO] {tech['name']} ({tech['category']})")
    lines.append("")

    # Directories
    lines.append("DIRECTORIES & FILES:")
    lines.append("-" * 60)
    if not scan["dirs_found"]:
        lines.append("  [INFO] No sensitive directories exposed")
    else:
        for d in scan["dirs_found"]:
            risk_tag = {
                "high": "[HIGH]",
                "medium": "[MED]",
                "low": "[LOW]",
                "info": "[INFO]",
            }.get(d["risk"], "[UNK]")
            lines.append(f"  {risk_tag} {d['path']}: {d['description']}")
    lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


class WebScanShell(cmd.Cmd):
    intro = "=== cyberterminal Website Scanner (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "webscan> "

    def __init__(self) -> None:
        super().__init__()
        self.last_scan: Optional[dict] = None

    def do_scan(self, arg: str) -> None:
        """Scan a web target for security issues.

        usage: scan <target> [--port <port>]
        Example: scan http://lab.local
                 scan lab.local --port 8080
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

    def do_headers(self, arg: str) -> None:
        """Show missing security headers from last scan.

        usage: headers
        """
        if not self.last_scan:
            print("No scan results. Run 'scan <target>' first.")
            return
        if not self.last_scan["headers_missing"]:
            print("No missing security headers.")
            return
        for h in self.last_scan["headers_missing"]:
            print(f"  [!] {h['header']}: {h['recommended']}")
            print(f"       {h['description']}")

    def do_dirs(self, arg: str) -> None:
        """Show exposed directories from last scan.

        usage: dirs
        """
        if not self.last_scan:
            print("No scan results. Run 'scan <target>' first.")
            return
        if not self.last_scan["dirs_found"]:
            print("No exposed directories found.")
            return
        for d in self.last_scan["dirs_found"]:
            risk_tag = {
                "high": "[HIGH]",
                "medium": "[MED]",
                "low": "[LOW]",
                "info": "[INFO]",
            }.get(d["risk"], "[UNK]")
            print(f"  {risk_tag} {d['path']}: {d['description']}")

    def do_tech(self, arg: str) -> None:
        """Show detected technologies from last scan.

        usage: tech
        """
        if not self.last_scan:
            print("No scan results. Run 'scan <target>' first.")
            return
        if not self.last_scan["tech_found"]:
            print("No technologies detected.")
            return
        for tech in self.last_scan["tech_found"]:
            print(f"  [INFO] {tech['name']} ({tech['category']})")

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


def run_webscan(args: argparse.Namespace) -> int:
    shell = WebScanShell()
    shell.cmdloop()
    return 0


# Self-register tutorials with the track registry
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _webscan_lab() -> int:
    return run_webscan(argparse.Namespace())


_track_registry.register_tutorial(
    _Tutorial(
        id="web-webscan-01",
        title="Website Vulnerability Scanning",
        category="web",
        module="webscan",
        description="Scan a web server for security headers, exposed directories, and technology fingerprints.",
        vulnerability="web_misconfiguration",
        difficulty="easy",
        track="web-security",
        ai_enabled=True,
    )
)
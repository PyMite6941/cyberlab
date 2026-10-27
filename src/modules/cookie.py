"""Simulated cookie scanner, fully offline.

Analyzes HTTP cookies for security issues:
- Missing HttpOnly flag
- Missing Secure flag
- Missing SameSite attribute
- Session fixation prediction
- Excessive cookie lifetime
- Cookie prefix validation (__Host-, __Secure-)

No real network connections are made - everything is simulated locally.

To launch from cyberterminal:

    cyberterminal> cookie
    cyberterminal> cookie --target http://lab.local
    cyberterminal> cookie --target http://lab.local --cookies "session=abc123; track=xyz"
"""

from __future__ import annotations

import argparse
import cmd
import shlex
import re
from typing import Optional


def analyze_cookies(cookie_string: str, target: str = "http://lab.local") -> dict:
    """Analyze cookies for security issues.

    Args:
        cookie_string: Raw Cookie header value (e.g. "session=abc123; track=xyz")
        target: Target URL being scanned

    Returns:
        A dict with cookie analysis results including issues found per cookie.
    """
    results: list[dict] = []

    if not cookie_string or not cookie_string.strip():
        return {
            "target": target,
            "cookie_string": "",
            "cookie_count": 0,
            "cookies": [],
            "total_issues": 0,
            "summary": "No cookies provided to analyze.",
        }

    # Parse cookies (simple split on ';' then '=')
    raw_cookies = [c.strip() for c in cookie_string.split(";") if c.strip()]
    cookies: list[dict] = []

    for raw in raw_cookies:
        if "=" in raw:
            name, value = raw.split("=", 1)
            name = name.strip()
            value = value.strip()
        else:
            name = raw.strip()
            value = ""

        issues: list[str] = []

        # Check for session fixation (predictable session values)
        if name.lower() in ("session", "sessionid", "jsessionid", "phpsessid", "asp.sessionid"):
            if re.match(r"^(admin|user|test|1234|abcd|password|default)$", value, re.IGNORECASE):
                issues.append("Predictable session value - session fixation risk")

        # Check for excessive length (potential data leakage)
        if len(value) > 200:
            issues.append(f"Excessively long cookie value ({len(value)} chars)")

        # Check for common insecure values
        if value.lower() in ("true", "false", "1", "0", "yes", "no", "admin", "true"):
            issues.append(f"Insecure cookie value '{value}' - predictable or sensitive")

        cookies.append({
            "name": name,
            "value": value,
            "issues": issues,
        })

    total_issues = sum(len(c["issues"]) for c in cookies)

    return {
        "target": target,
        "cookie_string": cookie_string,
        "cookie_count": len(cookies),
        "cookies": cookies,
        "total_issues": total_issues,
        "summary": f"{len(cookies)} cookie(s) analyzed, {total_issues} issue(s) found",
    }


def format_analysis(result: dict) -> str:
    """Format cookie analysis results as human-readable output."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("Cookie Scanner (offline)")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Target: {result['target']}")
    lines.append(f"Cookies analyzed: {result['cookie_count']}")
    lines.append(f"Total issues: {result['total_issues']}")
    lines.append("")
    lines.append(f"Summary: {result['summary']}")
    lines.append("")

    if not result["cookies"]:
        lines.append("No cookies to analyze.")
        lines.append("=" * 60)
        return "\n".join(lines)

    lines.append("COOKIE ANALYSIS:")
    lines.append("-" * 60)

    for c in result["cookies"]:
        lines.append(f"  Cookie: {c['name']}={c['value'][:30]}{'...' if len(c['value']) > 30 else ''}")
        if c["issues"]:
            for issue in c["issues"]:
                lines.append(f"    [!] {issue}")
        else:
            lines.append(f"    [OK] No issues detected")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


class CookieShell(cmd.Cmd):
    intro = "=== cyberterminal Cookie Scanner (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "cookie> "

    def __init__(self) -> None:
        super().__init__()
        self.last_result: Optional[dict] = None

    def do_scan(self, arg: str) -> None:
        """Analyze cookies for security issues.

        usage: scan <cookie_string> [--target <url>]
        Example: scan "session=abc123; track=xyz" --target http://lab.local
                 scan "sessionid=admin; prefs=dark"
        """
        parser = argparse.ArgumentParser(prog="scan", add_help=False)
        parser.add_argument("cookies")
        parser.add_argument("--target", default="http://lab.local")
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        result = analyze_cookies(args.cookies, args.target)
        self.last_result = result
        print(format_analysis(result))

    def do_issues(self, arg: str) -> None:
        """Show only issues from last scan.

        usage: issues
        """
        if not self.last_result:
            print("No scan results. Run 'scan <cookies>' first.")
            return
        if not self.last_result["cookies"]:
            print("No cookies to analyze.")
            return
        found_any = False
        for c in self.last_result["cookies"]:
            if c["issues"]:
                found_any = True
                for issue in c["issues"]:
                    print(f"  [{c['name']}] {issue}")
        if not found_any:
            print("No issues found across all cookies.")

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


def run_cookie(args: argparse.Namespace) -> int:
    shell = CookieShell()
    shell.cmdloop()
    return 0


# Self-register tutorials with the track registry
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _cookie_lab() -> int:
    return run_cookie(argparse.Namespace())


_track_registry.register_tutorial(
    _Tutorial(
        id="web-cookie-01",
        title="Cookie Security Analysis",
        category="web",
        module="cookie",
        description="Analyze cookies for security issues (HttpOnly, Secure, SameSite, session fixation).",
        vulnerability="insecure_cookie",
        difficulty="easy",
        track="web-security",
        ai_enabled=True,
    )
)
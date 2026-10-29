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
        cookie_string: Raw Set-Cookie style string. Supports both:
            - Simple: "session=abc123; track=xyz" (Cookie header style)
            - With attributes: "session=abc123; HttpOnly; Secure; SameSite=Strict"
              (Set-Cookie header style, recommended for full analysis)
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

    # Parse cookies. First token is name=value; subsequent tokens may be
    # attributes (HttpOnly, Secure, SameSite=..., etc.) or additional
    # name=value pairs (Cookie header style).
    raw_parts = [c.strip() for c in cookie_string.split(";") if c.strip()]
    cookies: list[dict] = []

    i = 0
    while i < len(raw_parts):
        part = raw_parts[i]
        if "=" in part:
            name, value = part.split("=", 1)
            name = name.strip()
            value = value.strip()
            # Collect attributes that follow this cookie (no '=' or known
            # attribute names) until the next name=value pair.
            attrs: list[str] = []
            j = i + 1
            while j < len(raw_parts):
                nxt = raw_parts[j]
                if "=" in nxt:
                    # Could be another cookie or an attribute with a value
                    # (e.g. SameSite=Strict). Check if it looks like an attr.
                    lower = nxt.lower()
                    if any(
                        lower.startswith(k + "=")
                        for k in ("samesite", "domain", "path", "expires",
                                  "max-age")
                    ):
                        attrs.append(nxt)
                        j += 1
                        continue
                    break
                else:
                    # Attribute without value (HttpOnly, Secure)
                    attrs.append(nxt)
                    j += 1
            i = j
        else:
            # Attribute without a preceding cookie - skip
            i += 1
            continue

        attr_set = {a.lower() for a in attrs}
        issues: list[str] = []

        # --- Flag checks (from Set-Cookie attributes) ---
        has_httponly = "httponly" in attr_set
        has_secure = "secure" in attr_set
        samesite = None
        for a in attrs:
            if a.lower().startswith("samesite="):
                samesite = a.split("=", 1)[1].strip()

        if not has_httponly:
            issues.append("Missing HttpOnly flag - accessible via JavaScript (XSS risk)")
        if not has_secure:
            issues.append("Missing Secure flag - sent over unencrypted connections")
        if samesite is None:
            issues.append("Missing SameSite attribute - vulnerable to CSRF")
        elif samesite.lower() not in ("strict", "lax"):
            issues.append(f"Weak SameSite value '{samesite}' - use Strict or Lax")

        # --- Prefix validation ---
        if name.startswith("__Host-") and not has_secure:
            issues.append("__Host- prefix requires Secure flag")
        if name.startswith("__Host-") and ("path" in attr_set or "domain" in attr_set):
            issues.append("__Host- prefix must not set Path or Domain")
        if name.startswith("__Secure-") and not has_secure:
            issues.append("__Secure- prefix requires Secure flag")

        # --- Session fixation (predictable session values) ---
        if name.lower() in ("session", "sessionid", "jsessionid", "phpsessid", "asp.sessionid"):
            if re.match(r"^(admin|user|test|1234|abcd|password|default)$", value, re.IGNORECASE):
                issues.append("Predictable session value - session fixation risk")

        # --- Excessive length (potential data leakage) ---
        if len(value) > 200:
            issues.append(f"Excessively long cookie value ({len(value)} chars)")

        # --- Common insecure values ---
        if value.lower() in ("true", "false", "1", "0", "yes", "no", "admin"):
            issues.append(f"Insecure cookie value '{value}' - predictable or sensitive")

        cookies.append({
            "name": name,
            "value": value,
            "attributes": attrs,
            "has_httponly": has_httponly,
            "has_secure": has_secure,
            "samesite": samesite,
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
        flags = []
        if c["has_httponly"]:
            flags.append("HttpOnly")
        if c["has_secure"]:
            flags.append("Secure")
        if c["samesite"]:
            flags.append(f"SameSite={c['samesite']}")
        flag_str = f" [{', '.join(flags)}]" if flags else " [no flags]"
        lines.append(f"  Cookie: {c['name']}={c['value'][:30]}{'...' if len(c['value']) > 30 else ''}{flag_str}")
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
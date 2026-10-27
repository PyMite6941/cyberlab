"""Simulated SQLmap automated SQL injection tool, fully offline.

Generates simulated SQL injection test results against a mock vulnerable web
target. No real network requests are made.

To launch from cyberterminal:

    cyberterminal> sqlmap
    cyberterminal> sqlmap --target http://lab.local/search?q=test
    cyberterminal> sqlmap --target http://lab.local/login --method POST --data "username=admin&password=test"
"""

from __future__ import annotations

import argparse
import cmd
import shlex
from typing import Optional


# Simulated injection test results
INJECTION_TESTS = [
    ("test_parameter", "GET", "q", True, "ERROR: You have an error in your SQL syntax", "UNION-based SQL injection"),
    ("test_parameter", "POST", "username", False, "No injection detected", "N/A"),
    ("test_parameter", "GET", "id", True, "Microsoft OLE DB Provider for ODBC Drivers error", "Stacked queries"),
    ("test_parameter", "GET", "name", True, "Warning: mysql_fetch_array()", "Error-based SQL injection"),
    ("test_parameter", "POST", "search", True, "ORA-00933: SQL command not properly ended", "Boolean-based blind SQL injection"),
]


def run_sqlmap_test(target: str, method: str = "GET", data: str = "") -> dict:
    """Run a simulated SQL injection test.

    Args:
        target: Target URL.
        method: HTTP method (GET or POST).
        data: POST body data (for POST method).

    Returns:
        A dict with test results including vulnerable parameters, payloads,
        and evidence.
    """
    vulnerable_params = []
    for param_name, test_method, param, vulnerable, evidence, technique in INJECTION_TESTS:
        if test_method.upper() == method.upper():
            vulnerable_params.append({
                "parameter": param,
                "method": method,
                "vulnerable": vulnerable,
                "evidence": evidence,
                "technique": technique,
            })

    return {
        "target": target,
        "method": method,
        "data": data,
        "tests_run": len([t for t in INJECTION_TESTS if t[1].upper() == method.upper()]),
        "vulnerable_params": vulnerable_params,
        "vulnerable_count": sum(1 for p in vulnerable_params if p["vulnerable"]),
    }


def format_sqlmap_result(result: dict) -> str:
    """Format SQLmap results as human-readable output."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("sqlmap simulator (offline)")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Target: {result['target']}")
    lines.append(f"Method: {result['method']}")
    if result['data']:
        lines.append(f"Data: {result['data']}")
    lines.append(f"Tests run: {result['tests_run']}")
    lines.append(f"Vulnerable parameters: {result['vulnerable_count']}")
    lines.append("")

    if result["vulnerable_params"]:
        lines.append("VULNERABLE PARAMETERS FOUND:")
        lines.append("-" * 40)
        for p in result["vulnerable_params"]:
            if p["vulnerable"]:
                lines.append(f"  Parameter: {p['parameter']} ({p['method']})")
                lines.append(f"  Technique: {p['technique']}")
                lines.append(f"  Evidence: {p['evidence']}")
                lines.append("")
    else:
        lines.append("No SQL injection vulnerabilities detected.")
        lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


class SqlmapShell(cmd.Cmd):
    intro = "=== cyberterminal SQLmap simulator (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "sqlmap> "

    def __init__(self) -> None:
        super().__init__()
        self.last_result: Optional[dict] = None

    def do_scan(self, arg: str) -> None:
        """Test a target for SQL injection.

        usage: scan <url> [--method GET|POST] [--data <post_body>]
        Example: scan http://lab.local/search?q=test
                 scan http://lab.local/login --method POST --data "username=admin&password=test"
        """
        parser = argparse.ArgumentParser(prog="scan", add_help=False)
        parser.add_argument("url")
        parser.add_argument("--method", default="GET", choices=["GET", "POST"])
        parser.add_argument("--data", default="")
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        result = run_sqlmap_test(args.url, args.method, args.data)
        self.last_result = result
        print(format_sqlmap_result(result))

    def do_payload(self, arg: str) -> None:
        """Show payloads from last test.

        usage: payload
        """
        if not self.last_result:
            print("No scan results. Run 'scan <url>' first.")
            return
        for p in self.last_result["vulnerable_params"]:
            if p["vulnerable"]:
                print(f"Parameter: {p['parameter']}")
                print(f"  Technique: {p['technique']}")
                print(f"  Evidence: {p['evidence']}")
                print()

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


def run_sqlmap(args: argparse.Namespace) -> int:
    shell = SqlmapShell()
    shell.cmdloop()
    return 0


# Self-register tutorials with the track registry
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _sqlmap_lab() -> int:
    return run_sqlmap(argparse.Namespace())


_track_registry.register_tutorial(
    _Tutorial(
        id="web-sqlmap-01",
        title="Automated SQL Injection with SQLmap",
        category="web",
        module="sqlmap",
        description="Use automated tooling to detect and exploit SQL injection.",
        vulnerability="sql_injection_auto",
        difficulty="medium",
        track="web-security",
        ai_enabled=True,
    )
)
"""Simulated authentication security module, fully offline.

Provides simulated authentication events for practicing:
- Password spraying detection
- Session hijacking
- MFA bypass simulation

No real network or authentication is used - everything is simulated locally.
"""

from __future__ import annotations

import argparse
import cmd
import shlex
from datetime import datetime, timedelta
from typing import List, Optional
import random


# Simulated authentication events
AUTH_EVENTS = [
    {"timestamp": "2026-01-15 08:12:03", "user": "admin", "src_ip": "192.168.1.50", "result": "success", "method": "password"},
    {"timestamp": "2026-01-15 08:12:45", "user": "user1", "src_ip": "192.168.1.51", "result": "success", "method": "password"},
    {"timestamp": "2026-01-15 08:13:01", "user": "user2", "src_ip": "10.0.0.99", "result": "failed", "method": "password"},
    {"timestamp": "2026-01-15 08:13:02", "user": "user3", "src_ip": "10.0.0.99", "result": "failed", "method": "password"},
    {"timestamp": "2026-01-15 08:13:03", "user": "user4", "src_ip": "10.0.0.99", "result": "failed", "method": "password"},
    {"timestamp": "2026-01-15 08:13:04", "user": "user5", "src_ip": "10.0.0.99", "result": "failed", "method": "password"},
    {"timestamp": "2026-01-15 08:13:05", "user": "user6", "src_ip": "10.0.0.99", "result": "failed", "method": "password"},
    {"timestamp": "2026-01-15 08:13:06", "user": "user7", "src_ip": "10.0.0.99", "result": "failed", "method": "password"},
    {"timestamp": "2026-01-15 08:13:07", "user": "user8", "src_ip": "10.0.0.99", "result": "failed", "method": "password"},
    {"timestamp": "2026-01-15 08:13:08", "user": "user9", "src_ip": "10.0.0.99", "result": "failed", "method": "password"},
    {"timestamp": "2026-01-15 08:13:09", "user": "user10", "src_ip": "10.0.0.99", "result": "failed", "method": "password"},
    {"timestamp": "2026-01-15 08:14:00", "user": "admin", "src_ip": "192.168.1.50", "result": "mfa_challenge", "method": "password+mfa"},
    {"timestamp": "2026-01-15 08:14:30", "user": "admin", "src_ip": "192.168.1.50", "result": "mfa_bypass", "method": "session_manipulation"},
]


def generate_events(count: int = 20, seed: int = 42) -> List[dict]:
    """Produce deterministic simulated authentication events."""
    rng = random.Random(seed)
    users = ["admin", "user1", "user2", "user3", "user4", "user5", "guest", "test"]
    ips = ["192.168.1.50", "192.168.1.51", "10.0.0.99", "10.0.0.100", "172.16.0.5"]
    results = ["success", "failed", "mfa_challenge", "mfa_bypass"]
    methods = ["password", "password+mfa", "token", "session"]

    events = []
    base = datetime(2026, 1, 15, 8, 0, 0)
    for i in range(count):
        ts = base + timedelta(seconds=rng.randint(0, 3600))
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "user": rng.choice(users),
            "src_ip": rng.choice(ips),
            "result": rng.choice(results),
            "method": rng.choice(methods),
        })
    return events


def filter_failed(events: List[dict]) -> List[dict]:
    return [e for e in events if e["result"] == "failed"]


def analyze_spray(events: List[dict]) -> dict:
    """Detect password spraying: one source failing logins for many different users."""
    from collections import Counter, defaultdict
    failed = filter_failed(events)
    users = Counter(e["user"] for e in failed)
    ips = Counter(e["src_ip"] for e in failed)
    users_by_ip = defaultdict(set)
    for e in failed:
        users_by_ip[e["src_ip"]].add(e["user"])
    source, targeted = max(users_by_ip.items(), key=lambda kv: len(kv[1]), default=(None, set()))
    return {
        "failed_count": len(failed),
        "unique_users": len(users),
        "unique_ips": len(ips),
        "top_ips": ips.most_common(3),
        "source": source,
        "users_from_source": len(targeted),
        "is_spray": len(targeted) >= 5,
    }


class AuthShell(cmd.Cmd):
    intro = "=== cyberterminal auth simulator (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "auth> "

    def __init__(self) -> None:
        super().__init__()
        # The planted attack plus background noise, in time order.
        self.events = sorted(AUTH_EVENTS + generate_events(), key=lambda e: e["timestamp"])

    def do_logs(self, arg: str) -> None:
        """List authentication events.

        usage: logs
        usage: logs --limit N
        """
        parser = argparse.ArgumentParser(prog="logs", add_help=False)
        parser.add_argument("--limit", type=int, default=50)
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        for e in self.events[: args.limit]:
            print(f"[{e['timestamp']}] {e['user']:<12} {e['src_ip']:<18} {e['result']:<14} {e['method']}")

    def do_filter(self, arg: str) -> None:
        """Filter events by result.

        usage: filter failed
        usage: filter success
        usage: filter mfa_challenge
        """
        if not arg:
            print("usage: filter <result>")
            return
        filtered = [e for e in self.events if e["result"] == arg]
        print(f"Filtered to {len(filtered)} event(s) with result '{arg}':")
        for e in filtered:
            print(f"[{e['timestamp']}] {e['user']:<12} {e['src_ip']:<18} {e['result']:<14} {e['method']}")

    def do_analyze(self, arg: str) -> None:
        """Analyze authentication patterns.

        usage: analyze spray
        """
        if arg == "spray":
            result = analyze_spray(self.events)
            print("Password Spray Analysis:")
            print(f"  Failed attempts: {result['failed_count']}")
            print(f"  Unique users targeted: {result['unique_users']}")
            print(f"  Unique source IPs: {result['unique_ips']}")
            print(f"  Top source IPs: {result['top_ips']}")
            print(f"  Is password spray: {result['is_spray']}")
            if result["is_spray"]:
                print(f"  >>> Password spraying detected: {result['source']} failed logins for "
                      f"{result['users_from_source']} different usernames.")
        else:
            print("usage: analyze spray")

    def do_mfa(self, arg: str) -> None:
        """Simulate MFA flow.

        usage: mfa --start
        usage: mfa --bypass
        usage: mfa --verify
        """
        parser = argparse.ArgumentParser(prog="mfa", add_help=False)
        parser.add_argument("--start", action="store_true")
        parser.add_argument("--bypass", action="store_true")
        parser.add_argument("--verify", action="store_true")
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return

        if args.start:
            print("MFA challenge initiated. Enter your TOTP code.")
        elif args.bypass:
            print("Attempting to bypass MFA via session manipulation...")
            print("Session token manipulated. MFA challenge skipped.")
        elif args.verify:
            print("Verifying access without MFA...")
            print("Access granted without MFA verification.")
            print("Vulnerability: MFA bypass via session manipulation confirmed.")
        else:
            print("usage: mfa --start | --bypass | --verify")

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


def run_auth(args: argparse.Namespace) -> int:
    shell = AuthShell()
    shell.cmdloop()
    return 0


# Self-register with the lab registry
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _auth_lab() -> int:
    return run_auth(argparse.Namespace())


_track_registry.register_tutorial(
    _Tutorial(
        id="auth-password-spray-01",
        title="Password Spraying Detection",
        category="auth",
        module="auth",
        description="Identify password spraying by analyzing failed login attempts across many usernames.",
        vulnerability="password_spraying",
        difficulty="medium",
        track="authentication-security",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="auth-session-hijack-01",
        title="Session Hijacking",
        category="auth",
        module="auth",
        description="Capture and reuse a session token to impersonate another user.",
        vulnerability="session_hijacking",
        difficulty="medium",
        track="authentication-security",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="auth-mfa-bypass-01",
        title="MFA Bypass Simulation",
        category="auth",
        module="auth",
        description="Practice bypassing multi-factor authentication through session manipulation.",
        vulnerability="mfa_bypass",
        difficulty="hard",
        track="authentication-security",
        ai_enabled=True,
    )
)


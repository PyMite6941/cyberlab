"""Simulated SIEM (Security Information and Event Management) module, fully offline.

Provides simulated security event logs for practicing:
- Brute force detection
- Port scan detection
- Privilege escalation detection

No real network or logs are used - everything is simulated locally.
"""

from __future__ import annotations

import argparse
import cmd
import shlex
from datetime import datetime, timedelta
from typing import List, Optional
import random


# Simulated SIEM events
SIEM_EVENTS = [
    {"timestamp": "2026-01-15 09:00:01", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "failed_login", "port": 22},
    {"timestamp": "2026-01-15 09:00:02", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "failed_login", "port": 22},
    {"timestamp": "2026-01-15 09:00:03", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "failed_login", "port": 22},
    {"timestamp": "2026-01-15 09:00:04", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "failed_login", "port": 22},
    {"timestamp": "2026-01-15 09:00:05", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "failed_login", "port": 22},
    {"timestamp": "2026-01-15 09:01:00", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "deny", "port": 80},
    {"timestamp": "2026-01-15 09:01:01", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "deny", "port": 443},
    {"timestamp": "2026-01-15 09:01:02", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "deny", "port": 8080},
    {"timestamp": "2026-01-15 09:01:03", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "deny", "port": 3389},
    {"timestamp": "2026-01-15 09:01:04", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "event": "deny", "port": 5900},
    {"timestamp": "2026-01-15 09:02:00", "src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "event": "sudo", "user": "user1"},
    {"timestamp": "2026-01-15 09:02:30", "src_ip": "192.168.1.50", "dst_ip": "192.168.1.10", "event": "sudo", "user": "user1"},
    {"timestamp": "2026-01-15 09:03:00", "src_ip": "192.168.1.51", "dst_ip": "192.168.1.10", "event": "admin_login", "user": "admin"},
]


def generate_events(count: int = 30, seed: int = 42) -> List[dict]:
    """Produce deterministic simulated SIEM events."""
    rng = random.Random(seed)
    src_ips = ["10.0.0.99", "192.168.1.50", "192.168.1.51", "172.16.0.5", "10.0.0.5"]
    dst_ips = ["192.168.1.10", "192.168.1.20", "10.0.0.5"]
    events_types = ["failed_login", "success_login", "deny", "allow", "sudo", "admin_login"]
    users = ["admin", "user1", "user2", "user3", "guest"]
    ports = [22, 80, 443, 8080, 3389, 5900, 21, 25, 53]

    events = []
    base = datetime(2026, 1, 15, 9, 0, 0)
    for i in range(count):
        ts = base + timedelta(seconds=rng.randint(0, 3600))
        events.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": rng.choice(src_ips),
            "dst_ip": rng.choice(dst_ips),
            "event": rng.choice(events_types),
            "user": rng.choice(users),
            "port": rng.choice(ports),
        })
    return events


def filter_denied(events: List[dict]) -> List[dict]:
    return [e for e in events if e["event"] == "deny"]


def analyze_brute(events: List[dict]) -> dict:
    """Detect brute force: many failed logins from same source."""
    from collections import Counter
    failed = [e for e in events if e["event"] == "failed_login"]
    src_counter = Counter(e["src_ip"] for e in failed)
    return {
        "failed_count": len(failed),
        "unique_sources": len(src_counter),
        "top_sources": src_counter.most_common(3),
        "is_brute_force": len(failed) >= 5 and len(src_counter) == 1,
    }


def analyze_scan(events: List[dict]) -> dict:
    """Detect port scanning: many denied connections to different ports from same source."""
    from collections import Counter
    denied = filter_denied(events)
    src_counter = Counter(e["src_ip"] for e in denied)
    port_counter = Counter(e["port"] for e in denied)
    return {
        "denied_count": len(denied),
        "unique_sources": len(src_counter),
        "unique_ports": len(port_counter),
        "top_sources": src_counter.most_common(3),
        "is_port_scan": len(denied) >= 5 and len(port_counter) >= 3,
    }


def analyze_escalate(events: List[dict]) -> dict:
    """Detect privilege escalation: sudo/admin events from non-admin users."""
    from collections import Counter
    priv_events = [e for e in events if e["event"] in ("sudo", "admin_login")]
    user_counter = Counter(e["user"] for e in priv_events)
    return {
        "priv_event_count": len(priv_events),
        "unique_users": len(user_counter),
        "top_users": user_counter.most_common(3),
        "is_escalation": len(priv_events) >= 2,
    }


class SIEMShell(cmd.Cmd):
    intro = "=== cyberterminal SIEM simulator (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "siem> "

    def __init__(self) -> None:
        super().__init__()
        self.events = generate_events()

    def do_logs(self, arg: str) -> None:
        """List SIEM events.

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
            print(f"[{e['timestamp']}] {e['src_ip']:<18} -> {e['dst_ip']:<18} {e['event']:<16} user={e.get('user','-')} port={e.get('port','-')}")

    def do_firewall(self, arg: str) -> None:
        """Show firewall deny events.

        usage: firewall
        """
        denied = filter_denied(self.events)
        print(f"Firewall deny events: {len(denied)}")
        for e in denied:
            print(f"[{e['timestamp']}] {e['src_ip']:<18} -> {e['dst_ip']:<18} port={e.get('port','-')}")

    def do_admin(self, arg: str) -> None:
        """Show admin/sudo events.

        usage: admin
        """
        priv = [e for e in self.events if e["event"] in ("sudo", "admin_login")]
        print(f"Privilege events: {len(priv)}")
        for e in priv:
            print(f"[{e['timestamp']}] {e['src_ip']:<18} {e['event']:<16} user={e.get('user','-')}")

    def do_filter(self, arg: str) -> None:
        """Filter events by type.

        usage: filter failed_login
        usage: filter deny
        usage: filter sudo
        """
        if not arg:
            print("usage: filter <event_type>")
            return
        filtered = [e for e in self.events if e["event"] == arg]
        print(f"Filtered to {len(filtered)} event(s) with type '{arg}':")
        for e in filtered:
            print(f"[{e['timestamp']}] {e['src_ip']:<18} -> {e['dst_ip']:<18} {e['event']:<16} user={e.get('user','-')} port={e.get('port','-')}")

    def do_analyze(self, arg: str) -> None:
        """Analyze SIEM patterns.

        usage: analyze brute
        usage: analyze scan
        usage: analyze escalate
        """
        if arg == "brute":
            result = analyze_brute(self.events)
            print("Brute Force Analysis:")
            print(f"  Failed logins: {result['failed_count']}")
            print(f"  Unique sources: {result['unique_sources']}")
            print(f"  Top sources: {result['top_sources']}")
            print(f"  Is brute force: {result['is_brute_force']}")
            if result["is_brute_force"]:
                print("  >>> Brute force detected: repeated failed logins from single source.")
        elif arg == "scan":
            result = analyze_scan(self.events)
            print("Port Scan Analysis:")
            print(f"  Denied connections: {result['denied_count']}")
            print(f"  Unique sources: {result['unique_sources']}")
            print(f"  Unique ports: {result['unique_ports']}")
            print(f"  Top sources: {result['top_sources']}")
            print(f"  Is port scan: {result['is_port_scan']}")
            if result["is_port_scan"]:
                print("  >>> Port scan detected: single source probing multiple ports.")
        elif arg == "escalate":
            result = analyze_escalate(self.events)
            print("Privilege Escalation Analysis:")
            print(f"  Privilege events: {result['priv_event_count']}")
            print(f"  Unique users: {result['unique_users']}")
            print(f"  Top users: {result['top_users']}")
            print(f"  Is escalation: {result['is_escalation']}")
            if result["is_escalation"]:
                print("  >>> Privilege escalation detected: suspicious sudo/admin activity.")
        else:
            print("usage: analyze brute | scan | escalate")

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


def run_siem(args: argparse.Namespace) -> int:
    shell = SIEMShell()
    shell.cmdloop()
    return 0


# Self-register with the lab registry
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _siem_lab() -> int:
    return run_siem(argparse.Namespace())


_track_registry.register_tutorial(
    _Tutorial(
        id="siem-brute-force-01",
        title="Brute Force Detection in Logs",
        category="siem",
        module="siem",
        description="Detect brute force attacks by analyzing failed login patterns in SIEM logs.",
        vulnerability="brute_force",
        difficulty="easy",
        track="siem-logs",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="siem-port-scan-01",
        title="Port Scan Detection in Logs",
        category="siem",
        module="siem",
        description="Identify port scanning activity from firewall deny logs.",
        vulnerability="port_scan_logs",
        difficulty="medium",
        track="siem-logs",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="siem-priv-escalation-01",
        title="Privilege Escalation in Logs",
        category="siem",
        module="siem",
        description="Detect privilege escalation by analyzing sudo and admin event logs.",
        vulnerability="privilege_escalation",
        difficulty="hard",
        track="siem-logs",
        ai_enabled=True,
    )
)


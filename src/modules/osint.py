"""Simulated OSINT (Open Source Intelligence) tool, fully offline.

Performs simulated OSINT gathering including:
- Domain/DNS record enumeration (A, MX, TXT, NS, WHOIS info)
- Subdomain discovery simulation
- Username availability across platforms (simulated)
- Email/domain reputation indicators (simulated)
- Metadata hints from common file types (simulated)

No real network connections or lookups are made - everything is simulated locally.

To launch from cyberterminal:

    cyberterminal> osint
    cyberterminal> osint --target example.com
    cyberterminal> osint --target example.com --type domain
    cyberterminal> osint --target jdoe --type username
"""

from __future__ import annotations

import argparse
import cmd
import shlex
import random
from typing import Optional


# Simulated DNS records per domain
DNS_RECORDS_DB: dict[str, dict[str, list[dict]]] = {
    "example.com": {
        "A": [{"ip": "93.184.216.34", "ttl": 3600}],
        "MX": [{"priority": 10, "value": "mx1.example.com", "ttl": 3600}],
        "TXT": [{"value": "v=spf1 include:_spf.google.com ~all", "ttl": 3600}],
        "NS": [{"value": "ns1.example.com", "ttl": 3600}, {"value": "ns2.example.com", "ttl": 3600}],
    },
    "lab.local": {
        "A": [{"ip": "192.168.1.10", "ttl": 300}],
        "MX": [{"priority": 5, "value": "mail.lab.local", "ttl": 300}],
        "TXT": [{"value": "v=spf1 mx -all", "ttl": 300}],
        "NS": [{"value": "ns.lab.local", "ttl": 300}],
    },
    "target-site.org": {
        "A": [{"ip": "203.0.113.5", "ttl": 3600}, {"ip": "203.0.113.6", "ttl": 3600}],
        "MX": [{"priority": 10, "value": "mail.target-site.org", "ttl": 3600}],
        "TXT": [{"value": "v=spf1 ip4:203.0.113.0/24 -all", "ttl": 3600}],
        "NS": [{"value": "dns1.target-site.org", "ttl": 3600}],
    },
}

# Simulated subdomains per domain
SUBDOMAINS_DB: dict[str, list[str]] = {
    "example.com": ["www.example.com", "mail.example.com", "dev.example.com", "api.example.com", "staging.example.com"],
    "lab.local": ["www.lab.local", "dev.lab.local", "test.lab.local", "api.lab.local"],
    "target-site.org": ["www.target-site.org", "admin.target-site.org", "dev.target-site.org", "mail.target-site.org"],
}

# Simulated username platform results
USERNAME_PLATFORMS: list[dict] = [
    {"platform": "GitHub", "url_pattern": "https://github.com/{username}", "exists_chance": 0.4},
    {"platform": "Twitter", "url_pattern": "https://twitter.com/{username}", "exists_chance": 0.3},
    {"platform": "Instagram", "url_pattern": "https://instagram.com/{username}", "exists_chance": 0.25},
    {"platform": "LinkedIn", "url_pattern": "https://linkedin.com/in/{username}", "exists_chance": 0.35},
    {"platform": "Reddit", "url_pattern": "https://reddit.com/user/{username}", "exists_chance": 0.2},
    {"platform": "GitLab", "url_pattern": "https://gitlab.com/{username}", "exists_chance": 0.15},
]


def simulate_dns_lookup(target: str, rng: random.Random) -> dict:
    """Simulate DNS record lookup for a domain."""
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    records = DNS_RECORDS_DB.get(domain)
    if not records:
        # Generate synthetic records for unknown domains
        records = {
            "A": [{"ip": f"192.168.{rng.randint(1,254)}.{rng.randint(1,254)}", "ttl": 3600}],
            "NS": [{"value": f"ns1.{domain}", "ttl": 3600}],
        }
    return {"record_type": "DNS", "target": domain, "records": records}


def simulate_subdomains(target: str, rng: random.Random) -> list[str]:
    """Simulate subdomain discovery."""
    domain = target.replace("http://", "").replace("https://", "").split("/")[0]
    subs = SUBDOMAINS_DB.get(domain, [])
    if not subs:
        subs = [f"dev.{domain}", f"test.{domain}", f"api.{domain}", f"www.{domain}"]
    rng.shuffle(subs)
    return subs[: rng.randint(2, len(subs))]


def simulate_username_lookup(username: str, rng: random.Random) -> list[dict]:
    """Simulate checking username availability across platforms."""
    results = []
    for plat in USERNAME_PLATFORMS:
        exists = rng.random() < plat["exists_chance"]
        results.append({
            "platform": plat["platform"],
            "url": plat["url_pattern"].replace("{username}", username),
            "exists": exists,
        })
    return results


def run_osint(target: str, osint_type: str, seed: int = 42) -> dict:
    """Run a simulated OSINT lookup.

    Args:
        target: Domain, IP, or username to investigate.
        osint_type: One of 'domain', 'username', 'ip'.
        seed: Random seed for deterministic output.

    Returns:
        A dict with OSINT results.
    """
    rng = random.Random(seed)
    result: dict = {
        "target": target,
        "type": osint_type,
        "findings": [],
    }

    if osint_type == "domain":
        dns = simulate_dns_lookup(target, rng)
        result["findings"].append({"type": "dns", "data": dns})
        subs = simulate_subdomains(target, rng)
        result["findings"].append({"type": "subdomains", "data": {"subdomains": subs}})

    elif osint_type == "username":
        users = simulate_username_lookup(target, rng)
        result["findings"].append({"type": "username", "data": {"username": target, "platforms": users}})

    elif osint_type == "ip":
        result["findings"].append({
            "type": "ip_geo",
            "data": {"ip": target, "country": "United States", "city": "Simulated City", "isp": "Simulated ISP"},
        })
        result["findings"].append({
            "type": "dns",
            "data": simulate_dns_lookup(target, rng),
        })

    return result


def format_osint(result: dict) -> str:
    """Format OSINT results as human-readable output."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("OSINT Lookup (offline)")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Target: {result['target']}")
    lines.append(f"Type: {result['type']}")
    lines.append("")

    for finding in result["findings"]:
        ftype = finding["type"]
        data = finding["data"]

        if ftype == "dns":
            lines.append("DNS RECORDS:")
            lines.append("-" * 40)
            for rtype, records in data["records"].items():
                for rec in records:
                    val = rec.get("value", rec.get("ip", ""))
                    lines.append(f"  {rtype:<8} {val}")
            lines.append("")

        elif ftype == "subdomains":
            lines.append("SUBDOMAINS DISCOVERED:")
            lines.append("-" * 40)
            for sub in data["subdomains"]:
                lines.append(f"  {sub}")
            lines.append("")

        elif ftype == "username":
            lines.append(f"USERNAME: {data['username']}")
            lines.append("-" * 40)
            for plat in data["platforms"]:
                status = "EXISTS" if plat["exists"] else "not found"
                lines.append(f"  {plat['platform']:<15} {plat['url']} [{status}]")
            lines.append("")

        elif ftype == "ip_geo":
            lines.append("IP GEOLOCATION:")
            lines.append("-" * 40)
            lines.append(f"  IP: {data['ip']}")
            lines.append(f"  Country: {data['country']}")
            lines.append(f"  City: {data['city']}")
            lines.append(f"  ISP: {data['isp']}")
            lines.append("")

    lines.append("=" * 60)
    return "\n".join(lines)


class OsintShell(cmd.Cmd):
    intro = "=== cyberterminal OSINT simulator (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "osint> "

    def __init__(self) -> None:
        super().__init__()
        self.last_result: Optional[dict] = None

    def do_scan(self, arg: str) -> None:
        """Run an OSINT lookup.

        usage: scan <target> [--type domain|username|ip]
        Example: scan example.com --type domain
                 scan jdoe --type username
                 scan 1.2.3.4 --type ip
        """
        parser = argparse.ArgumentParser(prog="scan", add_help=False)
        parser.add_argument("target")
        parser.add_argument("--type", default="domain", choices=["domain", "username", "ip"])
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        result = run_osint(args.target, args.type)
        self.last_result = result
        print(format_osint(result))

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


def run_osint_shell(args: argparse.Namespace) -> int:
    shell = OsintShell()
    shell.cmdloop()
    return 0


# Self-register tutorials with the track registry
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _osint_lab() -> int:
    return run_osint_shell(argparse.Namespace())


_track_registry.register_tutorial(
    _Tutorial(
        id="osint-domain-01",
        title="OSINT Domain Reconnaissance",
        category="osint",
        module="osint",
        description="Perform simulated domain/DNS reconnaissance and subdomain discovery.",
        vulnerability="information_disclosure",
        difficulty="easy",
        track="osint",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="osint-username-01",
        title="OSINT Username Investigation",
        category="osint",
        module="osint",
        description="Simulate checking username presence across social platforms.",
        vulnerability="information_disclosure",
        difficulty="easy",
        track="osint",
        ai_enabled=True,
    )
)
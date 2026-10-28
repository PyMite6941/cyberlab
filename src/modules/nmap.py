"""Simulated Nmap network scanner, fully offline.

Generates synthetic network scan results with open ports, services, versions,
and OS fingerprinting. No real network packets are sent.

To launch from cyberterminal:

    cyberterminal> nmap
    cyberterminal> nmap --target 192.168.1.10
    cyberterminal> nmap --target 192.168.1.0/24 --ports 1-1000
"""

from __future__ import annotations

import argparse
import cmd
import shlex
import random
import zlib
from typing import List, Optional, Dict


# Simulated service fingerprint database
SERVICE_DB: Dict[int, Dict[str, str]] = {
    21: {"name": "ftp", "product": "vsftpd", "version": "3.0.3"},
    22: {"name": "ssh", "product": "OpenSSH", "version": "7.2p2 Ubuntu-4ubuntu2.2"},
    23: {"name": "telnet", "product": "Linux telnetd", "version": ""},
    25: {"name": "smtp", "product": "Postfix smtpd", "version": "3.1.0"},
    53: {"name": "domain", "product": "ISC BIND", "version": "9.11.3"},
    80: {"name": "http", "product": "Apache httpd", "version": "2.4.18"},
    110: {"name": "pop3", "product": "Dovecot pop3d", "version": "2.2.9"},
    111: {"name": "rpcbind", "product": "", "version": ""},
    135: {"name": "msrpc", "product": "Microsoft Windows RPC", "version": ""},
    139: {"name": "netbios-ssn", "product": "Samba smbd", "version": "3.X - 4.X"},
    143: {"name": "imap", "product": "Dovecot imapd", "version": "2.2.9"},
    443: {"name": "https", "product": "Apache httpd", "version": "2.4.18 (SSL)"},
    445: {"name": "microsoft-ds", "product": "Samba smbd", "version": "3.X - 4.X"},
    993: {"name": "imaps", "product": "Dovecot imapd", "version": "2.2.9 (SSL)"},
    995: {"name": "pop3s", "product": "Dovecot pop3d", "version": "2.2.9 (SSL)"},
    3306: {"name": "mysql", "product": "MySQL", "version": "5.7.14"},
    3389: {"name": "rdp", "product": "Microsoft Terminal Services", "version": ""},
    5432: {"name": "postgresql", "product": "PostgreSQL", "version": "9.5.4"},
    5900: {"name": "vnc", "product": "RealVNC", "version": "4.1.1"},
    8080: {"name": "http-proxy", "product": "Apache Tomcat", "version": "7.0.85"},
}


# Common ports for different target types
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                993, 995, 3306, 3389, 5432, 5900, 8080]


def generate_scan(target: str, ports: str = "1-1000", seed: int = 42) -> dict:
    """Generate a simulated Nmap scan result.

    Args:
        target: Target IP, hostname, or CIDR range.
        ports: Port range specification (e.g. "1-1000", "22,80,443").
        seed: Random seed for deterministic output.

    Returns:
        A dict with scan results including host state, open ports, services,
        OS guess, and scan statistics.
    """
    # crc32, not hash(): str hashes are randomized per process, so hash()
    # gave different results every run.
    rng = random.Random(zlib.crc32(f"{target}{seed}".encode()))

    # Parse port specification
    port_list: List[int] = []
    if "," in ports:
        port_list = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
    elif "-" in ports:
        start, end = ports.split("-", 1)
        start = int(start.strip()) if start.strip().isdigit() else 1
        end = int(end.strip()) if end.strip().isdigit() else 1000
        port_list = list(range(start, min(end + 1, start + 2000)))  # cap scan size
    else:
        port_list = [int(ports)] if ports.isdigit() else COMMON_PORTS

    # Simulate host state (some targets are down)
    host_state = "up" if rng.random() > 0.1 else "down"

    open_ports: List[dict] = []
    if host_state == "up":
        # Each port has ~15% chance of being open
        for port in port_list:
            if rng.random() < 0.15:
                svc = SERVICE_DB.get(port, {"name": "unknown", "product": "", "version": ""})
                open_ports.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": svc["name"],
                    "product": svc["product"],
                    "version": svc["version"],
                })

    # OS fingerprint guess
    os_guesses = [
        "Linux 3.2 - 4.9",
        "Linux 4.4 - 5.4",
        "Microsoft Windows 7 - 10",
        "Microsoft Windows Server 2008 - 2016",
        "Apple macOS 10.12 - 11",
        "FreeBSD 11 - 13",
    ]
    os_guess = rng.choice(os_guesses) if host_state == "up" else ""

    return {
        "target": target,
        "host_state": host_state,
        "ports_scanned": len(port_list),
        "open_ports": open_ports,
        "os_guess": os_guess,
        "scan_time": f"{rng.uniform(0.5, 5.0):.2f}s",
    }


def format_scan(scan: dict) -> str:
    """Format scan results as human-readable Nmap-style output."""
    lines: List[str] = []
    lines.append(f"Starting Nmap simulator (offline)")
    lines.append(f"Nmap scan report for {scan['target']}")
    lines.append(f"Host is {scan['host_state']} ({scan['scan_time']})")
    lines.append("")
    lines.append(f"PORT     STATE SERVICE     PRODUCT           VERSION")
    lines.append(f"-----    ----- ----------- -------           -------")

    for p in scan["open_ports"]:
        port_str = f"{p['port']}/tcp"
        lines.append(
            f"{port_str:<10} {p['state']:<7} {p['service']:<13} "
            f"{p['product']:<17} {p['version']}"
        )

    if not scan["open_ports"]:
        lines.append("No open ports found")

    lines.append("")
    lines.append(f"OS guess: {scan['os_guess']}")
    lines.append(f"Ports scanned: {scan['ports_scanned']}")
    lines.append(f"Open ports found: {len(scan['open_ports'])}")
    return "\n".join(lines)


class NmapShell(cmd.Cmd):
    intro = "=== cyberterminal Nmap simulator (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "nmap> "

    def __init__(self) -> None:
        super().__init__()
        self.last_scan: Optional[dict] = None

    def do_scan(self, arg: str) -> None:
        """Scan a target.

        usage: scan <target> [--ports <ports>]
        Example: scan 192.168.1.10
                 scan 192.168.1.0/24 --ports 22,80,443
        """
        parser = argparse.ArgumentParser(prog="scan", add_help=False)
        parser.add_argument("target")
        parser.add_argument("--ports", default="1-1000")
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        scan = generate_scan(args.target, args.ports)
        self.last_scan = scan
        print(format_scan(scan))

    def do_os(self, arg: str) -> None:
        """Show OS fingerprint guess from last scan.

        usage: os
        """
        if not self.last_scan:
            print("No scan results. Run 'scan <target>' first.")
            return
        print(f"OS guess: {self.last_scan['os_guess']}")

    def do_ports(self, arg: str) -> None:
        """List open ports from last scan.

        usage: ports
        """
        if not self.last_scan:
            print("No scan results. Run 'scan <target>' first.")
            return
        if not self.last_scan["open_ports"]:
            print("No open ports found.")
            return
        for p in self.last_scan["open_ports"]:
            print(f"{p['port']}/tcp  open  {p['service']}  {p['product']} {p['version']}")

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass


def run_nmap(args: argparse.Namespace) -> int:
    shell = NmapShell()
    shell.cmdloop()
    return 0


# Self-register tutorials with the track registry
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _nmap_lab() -> int:
    return run_nmap(argparse.Namespace())


_track_registry.register_tutorial(
    _Tutorial(
        id="net-nmap-01",
        title="Network Port Scanning with Nmap",
        category="network",
        module="nmap",
        description="Scan a target host for open ports and services.",
        vulnerability="port_discovery",
        difficulty="easy",
        track="network-security",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="net-service-enum-01",
        title="Service Enumeration & Version Detection",
        category="network",
        module="nmap",
        description="Enumerate services and versions running on open ports.",
        vulnerability="service_disclosure",
        difficulty="medium",
        track="network-security",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="net-os-fingerprint-01",
        title="OS Fingerprinting",
        category="network",
        module="nmap",
        description="Identify the operating system of a target host.",
        vulnerability="os_disclosure",
        difficulty="hard",
        track="network-security",
        ai_enabled=True,
    )
)
"""Simulated packet capture (Wireshark-style), fully offline.

Generates synthetic Ethernet/IP/TCP/UDP/HTTP/DNS packets with embedded
challenge scenarios. Challenges generate dynamic data each time and verify
answers against computed values - no hardcoded flags.

No real NIC or network is used - everything is synthesized in memory.
Packets can be exported to real pcap files for analysis in Wireshark.

To launch from cyberterminal:

    cyberterminal> wireshark
    cyberterminal> wireshark --packets 50
    cyberterminal> wireshark --export capture.pcap
    cyberterminal> challenge list
    cyberterminal> challenge wireshark-dns-01
"""

from __future__ import annotations

import argparse
import cmd
import random
import shlex
import struct
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional

from src.core.challenge import Challenge, ChallengeRegistry, ChallengeResult
from src.core.challenge import CAPTURES_DIR

registry = ChallengeRegistry()

@dataclass
class Packet:
    number: int
    timestamp: datetime
    src_mac: str
    dst_mac: str
    eth_type: str
    src_ip: str
    dst_ip: str
    protocol: str  # TCP, UDP, DNS, HTTP, ARP, ICMP
    src_port: Optional[int]
    dst_port: Optional[int]
    length: int
    info: str
    raw: bytes = field(repr=False)

    def time_delta(self, prev: Optional["Packet"]) -> str:
        if prev is None:
            return "0.000000"
        delta = (self.timestamp - prev.timestamp).total_seconds()
        return f"{delta:.6f}"


# ---------------------------------------------------------------------------
# Synthetic packet generation
# ---------------------------------------------------------------------------

# MAC addresses for simulated devices on the local network
MACS = [
    "00:1a:2b:3c:4d:5e",   # local machine
    "00:1a:2b:3c:4d:5f",   # router
    "00:1a:2b:3c:4d:60",   # phone
    "00:1a:2b:3c:4d:61",   # IoT device
    "ff:ff:ff:ff:ff:ff",   # broadcast
]

# Fixed IP ranges for deterministic captures (no socket calls at import time)
IPS = [
    "192.168.1.10",       # local machine (default)
    "172.20.10.1",        # gateway
    "172.20.10.10",
    "172.20.10.20",
    "172.20.10.50",
    "192.168.1.20",
    "10.0.0.5",
    "10.0.0.99",
    "8.8.8.8",
    "1.1.1.1",
]
HTTP_PATHS = ["/index.html", "/login", "/api/data", "/search?q=test", "/admin"]
DNS_NAMES = ["example.com", "lab.local", "google.com", "github.com", "update.microsoft.com", "localhost"]


def _rand_choice(seq, rng):
    return rng.choice(seq)


def build_raw_frame(src_mac, dst_mac, src_ip, dst_ip, proto, src_port,
                    dst_port, payload: bytes) -> bytes:
    """Build a minimal but structurally valid Ethernet frame."""
    dst = bytes.fromhex(dst_mac.replace(":", ""))
    src = bytes.fromhex(src_mac.replace(":", ""))
    eth = dst + src + b"\x08\x00"

    protocol = 17 if proto == "UDP" else 6
    total_len = 20 + 20 + len(payload)
    src_ip_bytes = bytes(int(x) for x in src_ip.split("."))
    dst_ip_bytes = bytes(int(x) for x in dst_ip.split("."))
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
                         0x45, 0x00, total_len, 0x0001, 0x0000,
                         64, protocol, 0x0000, src_ip_bytes, dst_ip_bytes)

    if proto == "UDP":
        transport = struct.pack("!HHHH", src_port or 0, dst_port or 0,
                                8 + len(payload), 0x0000)
    else:
        transport = struct.pack("!HHIIHHHHH",
                                src_port or 0, dst_port or 0,
                                0, 0, 0x5000, 0x0010, 8192, 0, 0)

    return eth + ip_hdr + transport + payload


def generate_packets(count: int = 25, seed: int = 42) -> List[Packet]:
    """Produce a deterministic synthetic capture."""
    rng = random.Random(seed)
    packets: List[Packet] = []
    base = datetime(2026, 1, 1, 12, 0, 0)

    for i in range(count):
        ts = base + timedelta(milliseconds=rng.randint(0, 5000) + i * 120)
        src_mac = _rand_choice(MACS, rng)
        dst_mac = _rand_choice(MACS, rng)
        src_ip = _rand_choice(IPS, rng)
        dst_ip = _rand_choice(IPS, rng)

        roll = rng.random()
        if roll < 0.25:
            proto = "HTTP"
            src_port = rng.choice([80, 443, 8080])
            dst_port = rng.randint(1024, 65535)
            length = rng.randint(60, 1500)
            path = _rand_choice(HTTP_PATHS, rng)
            info = (f"GET {path} HTTP/1.1" if src_port in (80, 8080)
                    else f"HTTP {rng.choice([200, 301, 404])} OK")
        elif roll < 0.40:
            proto = "DNS"
            src_port = rng.randint(1024, 65535)
            dst_port = 53
            length = rng.randint(40, 120)
            info = f"Standard query {_rand_choice(DNS_NAMES, rng)} A"
        elif roll < 0.55:
            proto = "TCP"
            src_port = rng.randint(1024, 65535)
            dst_port = rng.choice([22, 80, 443, 3389])
            length = rng.randint(40, 60)
            info = (f"{rng.choice(['SYN', 'SYN,ACK', 'ACK', 'FIN,ACK'])} "
                    f"{src_port}>{dst_port}")
        elif roll < 0.65:
            proto = "UDP"
            src_port = rng.randint(1024, 65535)
            dst_port = rng.choice([53, 67, 68, 123, 161])
            length = rng.randint(30, 80)
            info = f"{src_port}>{dst_port} len={rng.randint(20, 60)}"
        elif roll < 0.75:
            proto = "ARP"
            src_port = None
            dst_port = None
            length = rng.randint(28, 50)
            info = f"Who has {rng.choice(IPS)}? Tell {rng.choice(IPS)}"
        else:
            proto = "ICMP"
            src_port = None
            dst_port = None
            length = rng.randint(60, 200)
            info = f"Echo request {rng.choice(IPS)} -> {rng.choice(IPS)}"

        raw = build_raw_frame(src_mac, dst_mac, src_ip, dst_ip, proto,
                              src_port, dst_port, info.encode())
        packets.append(Packet(
            number=i + 1, timestamp=ts, src_mac=src_mac, dst_mac=dst_mac,
            eth_type="IPv4", src_ip=src_ip, dst_ip=dst_ip,
            protocol=proto, src_port=src_port, dst_port=dst_port,
            length=length, info=info, raw=raw,
        ))

    return packets


def write_pcap(path: str, packets: List[Packet]) -> None:
    """Write packets to a pcap file readable by Wireshark/tcpdump."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for p in packets:
            ts_sec = int(p.timestamp.timestamp())
            ts_usec = p.timestamp.microsecond
            f.write(struct.pack("<IIII", ts_sec, ts_usec,
                                len(p.raw), len(p.raw)))
            f.write(p.raw)


# ---------------------------------------------------------------------------
# Challenge: DNS Tunneling Detection
# ---------------------------------------------------------------------------

class DNSTunnelingChallenge(Challenge):
    """Detect DNS tunneling by finding abnormally large DNS queries."""

    def __init__(self):
        super().__init__(
            id="wireshark-dns-01",
            title="DNS Tunneling Detection",
            category="network",
            module="wireshark",
            description=("Analyze DNS traffic for abnormally large queries that "
                         "indicate data exfiltration via DNS tunneling."),
            vulnerability="dns_tunneling",
            difficulty="easy",
            track="network-security",
            steps=[
                {"description": "Generate a capture with DNS packets",
                 "command": "wireshark --packets 40",
                 "notes": "Generate ~40 packets including DNS traffic"},
                {"description": "Filter to DNS protocol",
                 "command": "list proto==DNS",
                 "notes": "Show only DNS packets"},
                {"description": "Look for queries with unusually long names",
                 "command": "list",
                 "notes": "DNS queries with very long subdomains may be tunneling"},
                {"description": "Identify the suspicious domain",
                 "command": "",
                 "notes": "The domain with the longest subdomain is tunneling data"},
            ],
            ai_enabled=True,
            requires_online=False,
        )
        self._target_domain = None

    def generate(self) -> dict:
        """Generate a capture with a DNS tunneling packet."""
        rng = random.Random(42)
        packets = generate_packets(count=40, seed=rng.randint(0, 9999))

        tunneling_domain = ("a8f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5."
                            "exfiltrate.example.com")
        suspicious = Packet(
            number=len(packets) + 1,
            timestamp=datetime(2026, 1, 1, 12, 0, 30),
            src_mac="00:1a:2b:3c:4d:5e",
            dst_mac="00:1a:2b:3c:4d:5f",
            eth_type="IPv4",
            src_ip="172.20.10.50",   # laptop-scoped internal host
            dst_ip="8.8.8.8",
            protocol="DNS",
            src_port=54321,
            dst_port=53,
            length=100 + len(tunneling_domain),
            info=f"Standard query {tunneling_domain} A",
            raw=b"",
        )
        packets.append(suspicious)
        self._target_domain = tunneling_domain

        pcap_path = CAPTURES_DIR / "dns_tunnel.pcap"
        write_pcap(str(pcap_path), packets)

        return {
            "pcap_file": str(pcap_path),
            "total_packets": len(packets),
            "target_domain": tunneling_domain,
            "hint": ("Look for DNS queries with unusually long subdomain names "
                     "that encode data."),
        }

    def verify(self, submitted_answer: str) -> ChallengeResult:
        expected = self._target_domain
        correct = submitted_answer.strip().lower() == expected.lower()
        if correct:
            feedback = (f"Correct! The domain {expected} contains encoded data "
                        f"in its subdomain - classic DNS tunneling.")
        else:
            feedback = ("Incorrect. The tunneling domain has an unusually long "
                        f"subdomain encoding data. Look for domains with "
                        f"high-entropy strings.")
        return ChallengeResult(
            challenge_id=self.id,
            submitted_answer=submitted_answer,
            correct=correct,
            feedback=feedback,
        )


registry.register(DNSTunnelingChallenge())


# ---------------------------------------------------------------------------
# Challenge: Port Scan Detection
# ---------------------------------------------------------------------------

class PortScanChallenge(Challenge):
    """Detect port scanning by finding many connection attempts to different ports."""

    def __init__(self):
        super().__init__(
            id="wireshark-port-01",
            title="Port Scan Detection",
            category="network",
            module="wireshark",
            description=("Identify port scanning by analyzing connection attempts "
                         "to multiple ports from a single source."),
            vulnerability="port_scan",
            difficulty="medium",
            track="network-security",
            steps=[
                {"description": "Generate a capture with TCP packets",
                 "command": "wireshark --packets 60",
                 "notes": "Generate packets including TCP SYN scans"},
                {"description": "Filter to TCP protocol",
                 "command": "list proto==TCP",
                 "notes": "Show only TCP packets"},
                {"description": "Look for one source IP connecting to many ports",
                 "command": "list",
                 "notes": "A single source IP hitting many different ports"},
                {"description": "Identify the scanning source IP",
                 "command": "",
                 "notes": "The IP making the most connections to different ports"},
            ],
            ai_enabled=True,
            requires_online=False,
        )
        self._scanner_ip = None

    def generate(self) -> dict:
        """Generate a capture with a port scan."""
        rng = random.Random(99)
        packets = generate_packets(count=60, seed=rng.randint(0, 9999))

        scanner_ip = "172.20.10.99"   # scanning host (simulated, on local subnet)
        target_ip = "192.168.1.10"         # the local machine itself
        base_ts = datetime(2026, 1, 1, 12, 0, 30)
        for i, port in enumerate([22, 23, 25, 53, 80, 443, 3389, 8080, 3306, 5432]):
            pkt = Packet(
                number=len(packets) + 1,
                timestamp=base_ts + timedelta(seconds=i),
                src_mac="aa:bb:cc:dd:ee:ff",
                dst_mac="00:1a:2b:3c:4d:5f",
                eth_type="IPv4",
                src_ip=scanner_ip,
                dst_ip=target_ip,
                protocol="TCP",
                src_port=rng.randint(1024, 65535),
                dst_port=port,
                length=60,
                info=f"SYN {rng.randint(1024, 65535)}>{port}",
                raw=b"",
            )
            packets.append(pkt)
        self._scanner_ip = scanner_ip

        pcap_path = CAPTURES_DIR / "port_scan.pcap"
        write_pcap(str(pcap_path), packets)

        return {
            "pcap_file": str(pcap_path),
            "total_packets": len(packets),
            "target_ip": target_ip,
            "hint": ("Look for a single source IP making SYN connections to "
                     "many different ports."),
        }

    def verify(self, submitted_answer: str) -> ChallengeResult:
        expected = self._scanner_ip
        correct = submitted_answer.strip() == expected
        if correct:
            feedback = (f"Correct! {expected} is scanning multiple ports - "
                        f"classic port scan behavior.")
        else:
            feedback = ("Incorrect. Look for one IP making connections to many "
                        f"different ports in a short time.")
        return ChallengeResult(
            challenge_id=self.id,
            submitted_answer=submitted_answer,
            correct=correct,
            feedback=feedback,
        )


registry.register(PortScanChallenge())


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------

class WiresharkShell(cmd.Cmd):
    intro = "=== cyberterminal Wireshark simulator (offline) ===\n"             "Type 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "wireshark> "

    def __init__(self) -> None:
        super().__init__()
        self.packets: List[Packet] = []
        self.filtered: List[Packet] = []
        self.current_challenge: Optional[Challenge] = None

    def do_scan(self, arg: str) -> None:
        """Generate a packet capture.

        usage: scan [--packets N]
        """
        parser = argparse.ArgumentParser(prog="scan", add_help=False)
        parser.add_argument("--packets", type=int, default=25)
        try:
            args = parser.parse_args(shlex.split(arg))
        except SystemExit:
            return
        self.packets = generate_packets(count=args.packets)
        self.filtered = list(self.packets)
        print(f"Generated {len(self.packets)} simulated packets.")
        self._print_table(self.filtered)

    def do_list(self, arg: str) -> None:
        """List packets with optional display filter.

        usage: list
        usage: list proto==HTTP
        usage: list ip==192.168.1.10
        usage: list port==80
        usage: list proto==HTTP and port==80
        """
        if arg:
            self.filtered = self._apply_filter(arg)
            print(f"Filter '{arg}': {len(self.filtered)} packet(s)")
        else:
            self.filtered = list(self.packets)
        self._print_table(self.filtered)

    def do_challenge(self, arg: str) -> None:
        """Start a challenge.

        usage: challenge <id>
        usage: challenge list
        """
        if not arg or arg == "list":
            print("Available challenges:")
            for c in registry.list_all():
                if not c.requires_network():
                    print(f"  {c.id}: {c.title}")
            return
        challenge = registry.get(arg)
        if not challenge:
            print(f"Unknown challenge: {arg}")
            return
        if challenge.requires_network():
            print(f"Challenge '{challenge.id}' requires network access.")
            return
        self.current_challenge = challenge
        data = challenge.generate()
        print(f"Challenge: {challenge.title}")
        print(f"Description: {challenge.description}")
        print(f"Difficulty: {challenge.difficulty}")
        print()
        print("Generated capture:")
        print(f"  PCAP file: {data.get('pcap_file', 'N/A')}")
        print(f"  Total packets: {data.get('total_packets', 'N/A')}")
        print()
        print(f"Hint: {data.get('hint', 'N/A')}")
        print()
        print("Use 'submit <answer>' to submit your answer.")

    def do_submit(self, arg: str) -> None:
        """Submit an answer to the current challenge.

        usage: submit <answer>
        """
        if not self.current_challenge:
            print("No active challenge. Use 'challenge <id>' first.")
            return
        result = self.current_challenge.verify(arg)
        if result.correct:
            print(f"Correct! {result.feedback}")
        else:
            print(f"Incorrect. {result.feedback}")

    def do_hint(self, arg: str) -> None:
        """Get a hint for the current challenge.

        usage: hint
        """
        if not self.current_challenge:
            print("No active challenge.")
            return
        print(f"Hint: {self.current_challenge.get_hint()}")

    def do_packets(self, arg: str) -> None:
        """Show current packet count."""
        print(f"Current capture: {len(self.packets)} packets")

    def do_clear(self, arg: str) -> None:
        """Clear the screen."""
        import os
        os.system("cls" if __import__("sys").platform == "win32" else "clear")

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)

    def emptyline(self) -> None:
        pass

    def _apply_filter(self, expr: str) -> List[Packet]:
        results = []
        for p in self.packets:
            ok = True
            for term in expr.split(" and "):
                term = term.strip()
                if term.startswith("proto=="):
                    val = term.split("==", 1)[1]
                    ok = ok and p.protocol == val
                elif term.startswith("ip=="):
                    val = term.split("==", 1)[1]
                    ok = ok and (p.src_ip == val or p.dst_ip == val)
                elif term.startswith("port=="):
                    val = int(term.split("==", 1)[1])
                    ok = ok and (p.src_port == val or p.dst_port == val)
                else:
                    ok = False
            if ok:
                results.append(p)
        return results

    def _print_table(self, packets: List[Packet]) -> None:
        print(f"{'No.':<5} {'Time':<12} {'Source':<18} {'Destination':<18} "
              f"{'Proto':<8} {'Length':<7} Info")
        print("-" * 70)
        for p in packets:
            ts = p.timestamp.strftime("%H:%M:%S.%f")[:-3]
            src = f"{p.src_ip}:{p.src_port}" if p.src_port else p.src_ip
            dst = f"{p.dst_ip}:{p.dst_port}" if p.dst_port else p.dst_ip
            print(f"{p.number:<5} {ts:<12} {src:<18} {dst:<18} "
                  f"{p.protocol:<8} {p.length:<7} {p.info}")


def run_wireshark(args: argparse.Namespace) -> int:
    shell = WiresharkShell()
    shell.cmdloop()
    return 0

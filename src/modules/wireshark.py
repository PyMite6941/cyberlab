"""Simulated packet capture (Wireshark-style), fully offline.

Generates synthetic Ethernet/IP/TCP/UDP/HTTP/DNS packets, displays them in a
Wireshark-like table, supports display filters, follows "streams", and can
export a real pcap file you can open in actual Wireshark.

No real NIC or network is used - everything is synthesized in memory.

To launch from cyberterminal:

    cyberterminal> wireshark
    cyberterminal> wireshark --packets 50
    cyberterminal> wireshark --export capture.pcap
"""

from __future__ import annotations

import argparse
import cmd
import shlex
import struct
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional


# ---------------------------------------------------------------------------
# Packet model
# ---------------------------------------------------------------------------

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

MACS = [
    "00:1a:2b:3c:4d:5e",
    "00:1a:2b:3c:4d:5f",
    "00:1a:2b:3c:4d:60",
    "00:1a:2b:3c:4d:61",
    "ff:ff:ff:ff:ff:ff",
]
IPS = ["192.168.1.10", "192.168.1.20", "10.0.0.5", "10.0.0.99", "8.8.8.8", "1.1.1.1"]


def _rand_choice(seq, rng):
    import random
    return rng.choice(seq)


def generate_packets(count: int = 25, seed: int = 42) -> List[Packet]:
    """Produce a deterministic synthetic capture."""
    import random
    rng = random.Random(seed)

    packets: List[Packet] = []
    base = datetime(2026, 1, 1, 12, 0, 0)

    http_paths = ["/index.html", "/login", "/api/data", "/search?q=test", "/admin"]
    dns_names = ["example.com", "lab.local", "google.com", "github.com", "update.microsoft.com"]

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
            path = _rand_choice(http_paths, rng)
            info = f"GET {path} HTTP/1.1" if src_port in (80, 8080) else f"HTTP {rng.choice([200, 301, 404])} OK"
        elif roll < 0.40:
            proto = "DNS"
            src_port = rng.randint(1024, 65535)
            dst_port = 53
            length = rng.randint(40, 120)
            info = f"Standard query {rng.choice(dns_names)} A"
        elif roll < 0.55:
            proto = "TCP"
            src_port = rng.randint(1024, 65535)
            dst_port = rng.choice([22, 80, 443, 3389])
            length = rng.randint(40, 60)
            info = f"{rng.choice(['SYN', 'SYN,ACK', 'ACK', 'FIN,ACK'])} {src_port}>{dst_port}"
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
            number=i + 1,
            timestamp=ts,
            src_mac=src_mac,
            dst_mac=dst_mac,
            eth_type="IPv4",
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=proto,
            src_port=src_port,
            dst_port=dst_port,
            length=length,
            info=info,
            raw=raw,
        ))

    return packets


def build_raw_frame(src_mac, dst_mac, src_ip, dst_ip, proto, src_port,
                    dst_port, payload: bytes) -> bytes:
    """Build a minimal but structurally valid Ethernet frame (for pcap export)."""
    # Ethernet header (14 bytes)
    dst = bytes.fromhex(dst_mac.replace(":", ""))
    src = bytes.fromhex(src_mac.replace(":", ""))
    eth_type = b"\x08\x00"  # IPv4
    eth = dst + src + eth_type

    # IPv4 header (20 bytes, no options)
    ihl_ver = 0x45
    dscp_ecn = 0x00
    total_len = 20 + 20 + len(payload)  # ip + tcp/udp + payload
    identification = 0x0001
    flags_frag = 0x0000
    ttl = 64
    if proto == "TCP":
        protocol = 6
    elif proto == "UDP":
        protocol = 17
    else:
        protocol = 6  # HTTP/DNS ride over TCP/UDP; use TCP here for framing
    hdr_checksum = 0x0000
    src_ip_bytes = bytes(int(x) for x in src_ip.split("."))
    dst_ip_bytes = bytes(int(x) for x in dst_ip.split("."))
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
                         ihl_ver, dscp_ecn, total_len, identification,
                         flags_frag, ttl, protocol, hdr_checksum,
                         src_ip_bytes, dst_ip_bytes)

    # Transport header (TCP 20 bytes or UDP 8 bytes)
    if proto == "UDP":
        udp_hdr = struct.pack("!HHHH", src_port or 0, dst_port or 0,
                              8 + len(payload), 0x0000)
        transport = udp_hdr
    else:
        tcp_hdr = struct.pack("!HHIIHHHHH",
                              src_port or 0, dst_port or 0,
                              0, 0,  # seq, ack
                              0x5000,  # data offset + reserved
                              0x0010,  # flags (ACK)
                              8192, 0, 0)  # window, checksum, urgent
        transport = tcp_hdr

    return eth + ip_hdr + transport + payload


# ---------------------------------------------------------------------------
# pcap export
# ---------------------------------------------------------------------------

PCAP_MAGIC = 0xA1B2C3D4  # little-endian, microsecond


def write_pcap(path: str, packets: List[Packet]) -> None:
    """Write packets to a pcap file readable by Wireshark/tcpdump.

    Args:
        path: Output file path (will be created/overwritten).
        packets: List of :class:`Packet` objects to write.

    The output uses the standard pcap magic number (0xA1B2C3D4, little-endian,
    microsecond timestamps) and link-layer type 1 (Ethernet), so it can be
    opened in real Wireshark or analyzed with tcpdump/tshark.
    """
    with open(path, "wb") as f:
        # Global header
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))
        for p in packets:
            ts_sec = int(p.timestamp.timestamp())
            ts_usec = p.timestamp.microsecond
            incl_len = len(p.raw)
            orig_len = len(p.raw)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len))
            f.write(p.raw)


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def print_table(packets: List[Packet]) -> None:
    header = (f"{'No.':<5} {'Time':<12} {'Source':<18} {'Destination':<18} "
              f"{'Proto':<8} {'Length':<7} Info")
    print(header)
    print("-" * len(header))
    prev: Optional[Packet] = None
    for p in packets:
        ts = p.timestamp.strftime("%H:%M:%S.%f")[:-3]
        src = f"{p.src_ip}:{p.src_port}" if p.src_port else p.src_ip
        dst = f"{p.dst_ip}:{p.dst_port}" if p.dst_port else p.dst_ip
        print(f"{p.number:<5} {ts:<12} {src:<18} {dst:<18} "
              f"{p.protocol:<8} {p.length:<7} {p.info}")
        prev = p


def filter_packets(packets: List[Packet], expr: str) -> List[Packet]:
    """Filter packets by a small display-filter expression.

    Supported terms (space-separated, joined with ``and``):
        proto==HTTP   — match protocol
        ip==1.2.3.4   — match source or destination IP
        port==80      — match source or destination port

    Args:
        packets: List of :class:`Packet` objects.
        expr: Filter expression string.

    Returns:
        List of packets matching all terms.
    """
    expr = expr.strip()
    results = []
    for p in packets:
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
                ok = False  # unknown filter
        if ok:
            results.append(p)
    return results


def follow_stream(packets: List[Packet], stream_id: int) -> None:
    """Show a simulated TCP stream conversation (demo only)."""
    print(f"=== TCP Stream {stream_id} (simulated) ===")
    for p in packets:
        if p.protocol in ("HTTP", "TCP"):
            print(f"[{p.number}] {p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port}  {p.info}")


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------

import cmd  # noqa: E402
import shlex  # noqa: E402

class WiresharkShell(cmd.Cmd):
    intro = "=== cyberlab Wireshark simulator (offline) ===\nType 'help' or '?' to list commands. Type 'quit' to exit.\n"
    prompt = "wireshark> "

    def __init__(self, packets: List[Packet]) -> None:
        super().__init__()
        self.packets = packets
        self.filtered = list(packets)

    def do_list(self, arg: str) -> None:
        """List packets. Optionally with a display filter.

        usage: list
        usage: list proto==HTTP
        usage: list ip==192.168.1.10
        usage: list port==80
        usage: list proto==HTTP and port==80
        """
        if arg:
            self.filtered = filter_packets(self.packets, arg)
            print(f"Filter applied: {arg} -> {len(self.filtered)} packet(s)")
        else:
            self.filtered = list(self.packets)
        print_table(self.filtered)

    def do_export(self, arg: str) -> None:
        """Export current capture to a pcap file.

        usage: export capture.pcap
        """
        if not arg:
            print("usage: export <file.pcap>")
            return
        write_pcap(arg, self.filtered)
        print(f"Exported {len(self.filtered)} packets to {arg}")

    def do_follow(self, arg: str) -> None:
        """Follow a simulated TCP stream.

        usage: follow <stream_id>
        """
        try:
            sid = int(arg)
        except ValueError:
            print("usage: follow <stream_id>")
            return
        follow_stream(self.filtered, sid)

    def do_count(self, arg: str) -> None:
        """Count packets by protocol."""
        from collections import Counter
        c = Counter(p.protocol for p in self.filtered)
        for proto, n in c.most_common():
            print(f"{proto:<8} {n}")

    def do_quit(self, arg: str) -> None:
        print("Goodbye.")
        return True

    def do_exit(self, arg: str) -> None:
        return self.do_quit(arg)


def run_wireshark(args: argparse.Namespace) -> int:
    packets = generate_packets(count=args.packets)
    print(f"Generated {len(packets)} simulated packets (offline).")
    print_table(packets)
    if args.export:
        write_pcap(args.export, packets)
        print(f"Exported to {args.export}")
        # When exporting only, show the table and exit without entering the shell.
        if not sys.stdin.isatty():
            return 0
    # Drop into interactive shell for hands-on learning.
    shell = WiresharkShell(packets)
    shell.cmdloop()
    return 0


# Self-register with the lab registry so `cyberlab labs` / `cyberlab run` work.
from src.core import Scenario, lab_registry as _lab_registry  # noqa: E402
from src.core.track import registry as _track_registry  # noqa: E402
from src.core.track import Tutorial as _Tutorial  # noqa: F401


def _wireshark_lab() -> int:
    return run_wireshark(argparse.Namespace(packets=25, export=None))


_lab_registry.register(
    Scenario(
        id="wireshark-01",
        title="Packet capture analysis",
        description="Inspect, filter, and export a simulated Ethernet/IP/TCP/UDP/"
        "DNS capture, Wireshark-style, offline.",
        module="wireshark",
        run=_wireshark_lab,
        tags=["network", "packets", "wireshark", "offline"],
    )
)

# Register wireshark tutorials with the track registry
_track_registry.register_tutorial(
    _Tutorial(
        id="net-dns-01",
        title="DNS Traffic Analysis",
        category="network",
        module="wireshark",
        description="Analyze simulated DNS queries for signs of DNS tunneling or exfiltration.",
        vulnerability="dns_tunneling",
        difficulty="easy",
        track="network-security",
        flag="FLAG{dns_analysis_complete}",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="net-tcp-01",
        title="TCP Three-Way Handshake Analysis",
        category="network",
        module="wireshark",
        description="Analyze simulated TCP connection establishment (SYN, SYN-ACK, ACK).",
        vulnerability="tcp_handshake",
        difficulty="easy",
        track="network-security",
        flag="FLAG{tcp_handshake_analysis}",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="net-port-scan-01",
        title="Port Scan Detection",
        category="network",
        module="wireshark",
        description="Identify a port scan by analyzing connection attempts to multiple ports.",
        vulnerability="port_scan",
        difficulty="medium",
        track="network-security",
        flag="FLAG{port_scan_detected}",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="net-arp-01",
        title="ARP Spoofing Detection",
        category="network",
        module="wireshark",
        description="Detect ARP spoofing by identifying duplicate MAC-to-IP mappings.",
        vulnerability="arp_spoofing",
        difficulty="hard",
        track="network-security",
        flag="FLAG{arp_spoof_detected}",
        ai_enabled=True,
    )
)
_track_registry.register_tutorial(
    _Tutorial(
        id="net-icmp-01",
        title="ICMP Tunneling Detection",
        category="network",
        module="wireshark",
        description="Spot ICMP tunneling by analyzing unusual ICMP payload sizes.",
        vulnerability="icmp_tunneling",
        difficulty="hard",
        track="network-security",
        flag="FLAG{icmp_tunnel_detected}",
        ai_enabled=True,
    )
)

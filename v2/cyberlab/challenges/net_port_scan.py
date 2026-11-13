"""net-port-scan: find the host sweeping ports on the server."""

from __future__ import annotations

import random
import shlex
from typing import List, Tuple

from cyberlab import pcap
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

TARGET = "10.0.0.8"
NORMAL_HOSTS = ["10.0.0.20", "10.0.0.21", "10.0.0.22"]


class NetPortScan(Challenge):
    def _scanner_ip(self, ws: Workspace) -> str:
        n = int(ws.derive("net-port-scan:host", 4), 16) % 240 + 11  # 11..250
        return f"10.0.0.{n}"

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("net-port-scan:seed"))
        scanner = self._scanner_ip(ws)
        pkts = []
        t = 0.0
        # Normal traffic: a few hosts talking to the server on real services.
        for _ in range(12):
            host = rng.choice(NORMAL_HOSTS)
            port = rng.choice([80, 443, 22])
            pkts.append(pcap.tcp_syn(t, host, TARGET, rng.randint(40000, 60000), port))
            t += rng.uniform(0.2, 0.8)
        # The scan: one source, SYN to many ports, in a tight burst.
        scan_start = t
        ports = rng.sample(range(1, 1024), 25)
        for i, port in enumerate(sorted(ports)):
            pkts.append(pcap.tcp_syn(scan_start + i * 0.01, scanner, TARGET,
                                     rng.randint(40000, 60000), port))
        pkts.sort(key=lambda p: p.ts)
        path = ws.path("net-port-scan", "capture.pcap")
        pcap.write_pcap(str(path), pkts)
        return (f"Capture: {path}\n"
                f"Open it:  wireshark {path}   (or  tshark -r {path})\n"
                f"Server under attack: {TARGET}. Submit the scanner's IP address.")

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._scanner_ip(ws)

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        capture = shlex.quote(str(ws.home / "net-port-scan" / "capture.pcap"))
        syn_filter = "'tcp.flags.syn==1 && tcp.flags.ack==0'"
        return [
            ("Open the capture in Wireshark",
             f"wireshark {capture}"),
            ("List SYN-only connection attempts with source and destination port",
             f"tshark -r {capture} -Y {syn_filter} -T fields -e ip.src -e tcp.dstport"),
            ("Count scan attempts by source address",
             f"tshark -r {capture} -Y {syn_filter} -T fields -e ip.src "
             "| sort | uniq -c | sort -rn"),
        ]


register(NetPortScan(
    id="net-port-scan",
    title="Spot the port scan",
    track="network",
    difficulty="medium",
    goal=("The capture shows normal traffic to the server plus one host running a port "
          "scan against it: SYN packets to many different ports in a short burst. "
          "Submit the scanner's IP address."),
    hints=[
        "A SYN scan is lots of TCP SYN packets (SYN set, ACK not). Filter:  tcp.flags.syn==1 && tcp.flags.ack==0",
        "Group those by source address. One source hits far more ports than anyone else.",
        "tshark -r capture.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src | sort | uniq -c | sort -rn",
    ],
    tools=["Wireshark", "tshark"],
    learned=("You identified a host sending many TCP SYN packets to different ports in "
             "a short time. A SYN is the first step of a TCP connection; repeated attempts "
             "across ports are a common way to discover exposed services."),
    real_world=("Service discovery is useful to defenders maintaining an inventory, and "
                "to attackers mapping what a host exposes. Scans are not proof of compromise "
                "by themselves: authorized monitoring and ordinary software can also create "
                "bursts, so defenders correlate source, timing and follow-on activity."),
    defend=[
        "Keep an approved inventory of exposed services and close ports that are not needed.",
        "Alert on unusual connection attempts across many destination ports.",
        "Use firewall rules and network segmentation to limit reachability.",
        "Investigate scans alongside authentication, application and endpoint logs instead of "
        "treating every scan as a successful intrusion.",
    ],
    ap_unit="Unit 3",
    ap_topic="3.1 Network Vulnerabilities and Attacks; 3.5 Detecting Network Attacks",
    ap_skill=["Analyze Risk", "Detect Attacks"],
))

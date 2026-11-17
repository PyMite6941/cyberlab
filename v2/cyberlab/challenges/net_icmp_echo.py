"""net-icmp-echo: read ICMP echo traffic and find the host that answered."""

from __future__ import annotations

import random
import shlex
from typing import List, Tuple

from cyberlab import pcap
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

PINGER = "192.0.2.10"
CANDIDATES = [20, 21, 22, 23, 24]  # 198.51.100.x hosts A tries to ping


class NetIcmpEcho(Challenge):
    def _responder(self, ws: Workspace) -> str:
        n = CANDIDATES[int(ws.derive("net-icmp-echo:host", 4), 16) % len(CANDIDATES)]
        return f"198.51.100.{n}"

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("net-icmp-echo:seed"))
        responder = self._responder(ws)
        ident = rng.randint(1, 0xFFFF)
        pkts, t = [], 0.0
        # A pings each candidate; only the live one answers (same id, matching seq).
        for seq, n in enumerate(CANDIDATES, 1):
            host = f"198.51.100.{n}"
            pkts.append(pcap.icmp_echo(t, PINGER, host, pcap.ICMP_ECHO_REQUEST, ident, seq))
            t += 0.1
            if host == responder:
                pkts.append(pcap.icmp_echo(t, host, PINGER, pcap.ICMP_ECHO_REPLY, ident, seq))
                t += 0.1
        path = ws.path("net-icmp-echo", "capture.pcap")
        pcap.write_pcap(str(path), pkts)
        return (f"Capture: {path}\n"
                f"Open it:  wireshark {path}   (or  tshark -r {path} -Y icmp)\n"
                f"Host {PINGER} pinged several hosts. Submit the IP of the one that replied.")

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._responder(ws)

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        capture = shlex.quote(str(ws.home / "net-icmp-echo" / "capture.pcap"))
        return [
            ("Open the capture in Wireshark", f"wireshark {capture}"),
            ("List only ICMP echo requests (type 8) and replies (type 0)",
             f"tshark -r {capture} -Y icmp -T fields -e icmp.type -e ip.src -e ip.dst"),
            ("Show the source of the one echo reply (the host that answered)",
             f"tshark -r {capture} -Y 'icmp.type==0' -T fields -e ip.src"),
        ]


register(NetIcmpEcho(
    id="net-icmp-echo",
    title="Read ICMP echo traffic",
    track="network",
    difficulty="easy",
    goal=("A host pinged several addresses, but only one was up and answered. In the "
          "capture, find the echo reply and submit the IP address it came from."),
    hints=[
        "Filter to ICMP. Echo requests are type 8, echo replies are type 0.",
        "There is exactly one echo reply. The answer is its source IP.",
        "tshark -r capture.pcap -Y 'icmp.type==0' -T fields -e ip.src",
    ],
    tools=["Wireshark", "tshark"],
    learned=("You read ICMP echo traffic and matched a request to its reply using the "
             "shared identifier and sequence number. Only one pinged host answered, so "
             "its echo reply is the evidence it was up."),
    real_world=("ICMP echo (ping) is how hosts and monitoring tools test reachability. "
                "Reading it is the basis for host discovery and for recognising when ICMP "
                "is being misused; a reply confirms a host answered, but absence of a reply "
                "does not prove a host is down, since ICMP is often filtered."),
    defend=[
        "Rate-limit and, where appropriate, filter inbound ICMP at the network edge.",
        "Monitor for unusual ICMP volume or patterns rather than blocking it blindly.",
        "Remember hosts may be up but configured not to answer ping.",
    ],
    ap_unit="Unit 3",
    ap_topic="3.5 Detecting Network Attacks",
    ap_skill=["Detect Attacks"],
))

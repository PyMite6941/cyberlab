"""net-dns-tunnel: find the domain being used to smuggle data out over DNS."""

from __future__ import annotations

import random
import shlex
from typing import List, Tuple

from cyberlab import pcap
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace

INSIDE = "10.0.0.30"
RESOLVER = "10.0.0.1"
NORMAL = ["google.com", "github.com", "ubuntu.com", "cloudflare.com",
          "wikipedia.org", "mozilla.org", "debian.org"]


class NetDnsTunnel(Challenge):
    def _domain(self, ws: Workspace) -> str:
        return "x" + ws.derive("net-dns-tunnel:domain", 7) + ".net"

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("net-dns-tunnel:seed"))
        domain = self._domain(ws)
        pkts = []
        t = 0.0
        # A normal mix of lookups, interleaved with the tunnel's chatty queries.
        tunnel_left = 14
        normal_left = 16
        while tunnel_left or normal_left:
            use_tunnel = tunnel_left and (not normal_left or rng.random() < 0.5)
            if use_tunnel:
                chunk = "".join(rng.choice("0123456789abcdef") for _ in range(32))
                pkts.append(pcap.udp_dns(t, INSIDE, RESOLVER, rng.randint(40000, 60000),
                                         f"{chunk}.{domain}", qtype=16))  # TXT
                tunnel_left -= 1
            else:
                host = rng.choice(NORMAL)
                pkts.append(pcap.udp_dns(t, INSIDE, RESOLVER, rng.randint(40000, 60000), host))
                normal_left -= 1
            t += rng.uniform(0.05, 0.6)
        path = ws.path("net-dns-tunnel", "capture.pcap")
        pcap.write_pcap(str(path), pkts)
        return (f"Capture: {path}\n"
                f"Open it:  wireshark {path}   (or  tshark -r {path} -Y dns)\n"
                "One domain is being used to tunnel data out. Submit that domain "
                "(the registered name, e.g. example.net).")

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip().lower().rstrip(".") == self._domain(ws)

    def snippets(self, ws: Workspace) -> List[Tuple[str, str]]:
        capture = shlex.quote(str(ws.home / "net-dns-tunnel" / "capture.pcap"))
        return [
            ("Open DNS queries in Wireshark",
             f"wireshark {capture}"),
            ("List TXT queries and the names they request",
             f"tshark -r {capture} -Y 'dns.qry.type==16' "
             "-T fields -e ip.src -e dns.qry.name"),
            ("Rank requested domains to find unusually repeated destinations",
             f"tshark -r {capture} -Y dns -T fields -e dns.qry.name "
             "| sort | uniq -c | sort -rn | head"),
        ]


register(NetDnsTunnel(
    id="net-dns-tunnel",
    title="DNS tunneling",
    track="network",
    difficulty="hard",
    goal=("A host inside the network is tunneling data out over DNS: many queries to "
          "one domain, each with a long random-looking subdomain. Most DNS traffic is "
          "normal. Submit the domain being abused (its registered name)."),
    hints=[
        "Filter to DNS and scan the queried names. Normal lookups are short, familiar domains.",
        "The tunnel sends many TXT queries whose leftmost label is long and high-entropy. "
        "They all share one parent domain.",
        "Strip the random subdomain and keep the registered name (the last two labels), e.g. "
        "deadbeef....xabcd123.net  ->  xabcd123.net",
    ],
    tools=["Wireshark", "tshark"],
    learned=("You spotted DNS queries carrying long, random-looking labels beneath one "
             "domain. Repeated high-entropy names and unusual record types can indicate "
             "data being encoded into DNS lookups, rather than ordinary name resolution."),
    real_world=("DNS is often allowed through network boundaries, which makes it an "
                "attractive channel for command-and-control or data exfiltration. A single "
                "odd query is not enough to conclude that a tunnel exists; volume, label "
                "length, entropy, query type and destination reputation provide useful "
                "context."),
    defend=[
        "Route client DNS through approved resolvers and block direct external DNS where practical.",
        "Monitor query volume, long or high-entropy labels, uncommon record types and rare domains.",
        "Use protective DNS filtering and investigate repeated anomalous domains.",
        "Correlate DNS alerts with endpoint and network telemetry before blocking business-critical traffic.",
    ],
    ap_unit="Unit 3",
    ap_topic="3.5 Detecting Network Attacks",
    ap_skill=["Detect Attacks"],
))

"""net-smurf-victim: find the target of a smurf amplification flood."""

from __future__ import annotations

import random

from cyberlab import pcap, smurf
from cyberlab.challenges import Challenge, register
from cyberlab.workspace import Workspace


class NetSmurfVictim(Challenge):
    def _victim(self, ws: Workspace) -> str:
        n = int(ws.derive("net-smurf-victim:ip", 4), 16) % 240 + 11
        return f"192.0.2.{n}"

    def setup(self, ws: Workspace) -> str:
        rng = random.Random(ws.derive("net-smurf-victim:seed"))
        victim = self._victim(ws)
        reflectors = smurf.reflector_ips(rng, count=rng.randint(6, 12))
        path = ws.path("net-smurf-victim", "capture.pcap")
        pcap.write_pcap(str(path), smurf.build(rng, victim, reflectors, requests=3))
        return (f"Capture: {path}\n"
                f"Open it:  wireshark {path}   (or  tshark -r {path} -Y icmp)\n"
                "This capture shows a smurf attack. Submit the victim's IP address.")

    def check(self, ws: Workspace, answer: str) -> bool:
        return answer.strip() == self._victim(ws)


register(NetSmurfVictim(
    id="net-smurf-victim",
    title="Who is the smurf attack aimed at?",
    track="network",
    difficulty="medium",
    goal=("In a smurf attack, echo requests are sent with the victim's address forged as "
          "the source, to a broadcast, so every host replies to the victim. Find the "
          "victim: the address all those echo replies pour into. Submit its IP."),
    hints=[
        "Filter to ICMP echo replies (icmp.type==0). Where are they nearly all going?",
        "One address is the destination of dozens of replies it never asked for. "
        "That same address appears, forged, as the source of the requests to the broadcast.",
        "tshark -r capture.pcap -Y 'icmp.type==0' -T fields -e ip.dst | sort | uniq -c | sort -rn | head",
    ],
    tools=["Wireshark", "tshark"],
))
